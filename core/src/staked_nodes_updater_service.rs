use {
    firedancer_sys::tango::{fd_stake_t, fd_stake_deser, fd_stake_version},
    solana_runtime::bank_forks::BankForks,
    solana_sdk::pubkey::Pubkey,
    solana_streamer::streamer::StakedNodes,
    std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicBool, Ordering, compiler_fence},
            Arc, RwLock,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

const STAKE_REFRESH_CYCLE: Duration = Duration::from_secs(5);

pub struct FdStake(pub *mut fd_stake_t);
unsafe impl Send for FdStake {}
unsafe impl Sync for FdStake {}

pub struct StakedNodesUpdaterService {
    thread_hdl: JoinHandle<()>,
}

impl StakedNodesUpdaterService {
    pub fn new(
        exit: Arc<AtomicBool>,
        bank_forks: Arc<RwLock<BankForks>>,
        staked_nodes: Arc<RwLock<StakedNodes>>,
        staked_nodes_overrides: Arc<RwLock<HashMap<Pubkey, u64>>>,
        fd_stake: FdStake,
    ) -> Self {
        let thread_hdl = Builder::new()
            .name("solStakedNodeUd".to_string())
            .spawn(move || {
                let _ = &fd_stake;
                while !exit.load(Ordering::Relaxed) {
                    let mut stakes = {
                        let root_bank = bank_forks.read().unwrap().root_bank();
                        root_bank.staked_nodes()
                    };
                    let mut overrides = staked_nodes_overrides.read().unwrap().clone();
                    if overrides.is_empty() {
                        for i in 1..=16 {
                            let mut pubkey = [0; 32];
                            pubkey[0] = i;
                            overrides.insert(Pubkey::from(pubkey), i as u64);
                        }
                    }

                    let mut stakes_no_arc_mut = HashMap::new();
                    for (pubkey, stake) in stakes.iter() {
                        stakes_no_arc_mut.insert(*pubkey, *stake);
                    }
                    stakes_no_arc_mut.extend(overrides.iter());

                    *staked_nodes.write().unwrap() = StakedNodes::new(stakes, overrides);

                    let mut ser = Vec::new();
                    for (pubkey, stake) in stakes_no_arc_mut {
                        println!("{}: {}", pubkey, stake);
                        ser.extend(bincode::serialize(&pubkey.to_bytes()).unwrap());
                        ser.extend(bincode::serialize(&stake).unwrap());
                    }
                    println!("writing {:?} {} bytes", ser, ser.len());

                    unsafe {
                        fd_stake_deser(fd_stake.0, ser.as_mut_ptr(), ser.len() as u64);
                    };

                    std::thread::sleep(STAKE_REFRESH_CYCLE);
                }
            })
            .unwrap();

        Self { thread_hdl }
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }
}
