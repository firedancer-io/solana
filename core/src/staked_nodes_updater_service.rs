use {
    solana_firedancer::{GlobalAddress, Mvcc, Pod},
    solana_runtime::bank_forks::BankForks,
    solana_sdk::pubkey::Pubkey,
    solana_streamer::streamer::StakedNodes,
    std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

const STAKE_REFRESH_CYCLE: Duration = Duration::from_secs(5);

pub struct StakedNodesUpdaterService {
    thread_hdl: JoinHandle<()>,
}

fn firedancer_write_stake(
    mvcc: &mut Mvcc,
    staked_nodes: &HashMap<Pubkey, u64>,
    staked_nodes_overrides: &HashMap<Pubkey, u64>,
) {
    let mut values = staked_nodes.iter().filter(|(pubkey, _)| !staked_nodes_overrides.contains_key(pubkey)).collect::<Vec<_>>();
    values.extend(staked_nodes_overrides.iter());

    // Sort by descending stake in case there are too many to fit in the mvcc,
    // so we can send the highest staked nodes.
    values.sort_by(|a, b| b.cmp(a));

    // The format here is just a length prefixed list of (stake, pubkey) pairs,
    // all appended directly into a binary serialization, on the wire it looks like
    //
    //  [ 8 byte num entries, N, LE ] [ 40 byte entry 0 ] [ 40 byte entry 1 ] .. [ 40 byte entry N ]
    //
    // where each entry is,
    //
    //  [ 8 byte stake, LE ] [ 32 byte pubkey ]
    let mvcc_data = mvcc.begin_write();
    mvcc_data[0..8].copy_from_slice(&(values.len() as u64).to_le_bytes());

    let max_elements = (mvcc_data.len() - 8) / 40;
    if values.len() > max_elements {
        warn!("staked_nodes len {} exceeds max_elements {}", values.len(), max_elements);
    }
    for (i, value) in values.iter().enumerate().take(max_elements) {
        let offset = 8 + i * 40;
        mvcc_data[offset..offset + 8].copy_from_slice(&value.1.to_le_bytes());
        mvcc_data[offset + 8..offset + 40].copy_from_slice(&value.0.to_bytes());
    }
    mvcc.end_write();
}

impl StakedNodesUpdaterService {
    pub fn new(
        exit: Arc<AtomicBool>,
        bank_forks: Arc<RwLock<BankForks>>,
        staked_nodes: Arc<RwLock<StakedNodes>>,
        staked_nodes_overrides: Arc<RwLock<HashMap<Pubkey, u64>>>,
        firedancer_app_name: String,
    ) -> Self {
        let thread_hdl = Builder::new()
            .name("solStakedNodeUd".to_string())
            .spawn(move || {
                let out_pod = unsafe { Pod::join_default(format!("{}_quic_verify0.wksp", firedancer_app_name)).unwrap() };
                let mut out_mvcc = unsafe { Mvcc::join::<GlobalAddress>(out_pod.try_query(format!("stake_weights")).unwrap()).unwrap() };

                while !exit.load(Ordering::Relaxed) {
                    let stakes = {
                        let root_bank = bank_forks.read().unwrap().root_bank();
                        root_bank.staked_nodes()
                    };

                    firedancer_write_stake(
                        &mut out_mvcc,
                        &*stakes,
                        &staked_nodes_overrides.read().unwrap());

                    let overrides = staked_nodes_overrides.read().unwrap().clone();
                    *staked_nodes.write().unwrap() = StakedNodes::new(stakes, overrides);
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
