//! `sigverify_frank_stage` is a drop-in replacement for `sigverify_stage`
//! powered by the Firedancer SigVerify modules.

use {
    crate::{banking_stage, find_packet_sender_stake_stage},
    crossbeam_channel::TryRecvError,
    firedancer::{
        fd_ffi,
        fd_shm_channel::{ShmChannel, ShmChannelHandle},
    },
    solana_perf::packet::{
        Meta, Packet, PacketBatch, PacketBatchRecycler, PacketFlags, PACKET_DATA_SIZE,
    },
    std::{
        ffi::{c_char, c_int, CString},
        net::{IpAddr, Ipv4Addr},
        ops::Range,
        os::unix::io::AsRawFd,
        thread::{self, Builder, JoinHandle},
    },
};

#[derive(Clone)]
pub struct SigVerifyFrankConfig {
    pub root_pod: String, // e.g. frank.wksp:4190208
    pub app_name: String, // e.g. "Frank"
    pub verify_tiles: Range<usize>,
}

impl SigVerifyFrankConfig {
    pub(crate) fn get_shm_name(&self, flow_name: &str) -> String {
        format!("firedancer_shim.{}.{}", self.app_name, flow_name)
    }
}

pub struct SigVerifyFrankStage {
    pub(crate) thread_hdl: JoinHandle<()>,
}

impl SigVerifyFrankStage {
    // Signature fields in mcache identifying flow
    const MAGIC_USER: u64 = 0x5553455275736572;
    const MAGIC_VOTE: u64 = 0x564f5445766f7465;

    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        user_tx: banking_stage::BankingPacketSender,
        vote_tx: banking_stage::BankingPacketSender,
        user_rx: find_packet_sender_stake_stage::FindPacketSenderStakeReceiver,
        vote_rx: find_packet_sender_stake_stage::FindPacketSenderStakeReceiver,
        config: SigVerifyFrankConfig,
    ) -> Self {
        // POSIX shared memory segments (allocated on first use)

        // Unverified txns from Rust to C. (outgoing from the perspective of this module)
        let shim_vin_name = config.get_shm_name("feeder");
        let shim_vin_hdl = ShmChannelHandle::create(&shim_vin_name).unwrap();

        // Verified txns from C to Rust.
        let shim_vout_name = config.get_shm_name("pack");
        let shim_vout_hdl = ShmChannelHandle::create(&shim_vout_name).unwrap();

        // feeder:
        //
        //   Labs Fetch => Shim => Firedancer SigVerify
        //                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        //
        // Launch a thread running the Firedancer SigVerify feeder loop, transferring control over to C.
        // Internally, reads packets from the Rust => C shim FFI and forwards them to the Firedancer workspace.
        let config_ = config.clone();
        let shim_vin_hdl_cside = shim_vin_hdl.try_clone().unwrap();
        Builder::new()
            .name("frank-feeder-cside".to_owned())
            .spawn(move || Self::feeder_cside(&config_, shim_vin_hdl_cside))
            .unwrap();

        // feeder:
        //
        //   Labs Fetch => Shim => Firedancer SigVerify
        //   ^^^^^^^^^^^^^^^^^^
        //
        // Launch the Rust relay service that passes transactions to the C feeder via common language 'shm'
        let shim_vin_hdl_rside = shim_vin_hdl.try_clone().unwrap();
        let thread_handle_snd = Builder::new()
            .name("frank-feeder-rside".to_owned())
            .spawn(move || Self::feeder_rside(vote_rx, user_rx, shim_vin_hdl_rside))
            .unwrap();

        // pack:
        //
        //   Firedancer Pack => Shim => Labs Banking Stage
        //   ^^^^^^^^^^^^^^^^^^^^^^^
        //
        // Launch another thread running the Firedancer pack return loop.
        // As the counterpart to the above, reads scheduled transactions from the Firedancer workspace,
        // and inserts them into the C => Rust shim FFI.
        let shim_vout_hdl_cside = shim_vout_hdl.try_clone().unwrap();
        Builder::new()
            .name("frank-pack-cside".to_owned())
            .spawn(move || Self::pack_cside(&config, shim_vout_hdl_cside))
            .unwrap();

        // pack:
        //
        //   Firedancer Pack => Shim => Labs Banking Stage
        //                      ^^^^^^^^^^^^^^^^^^^^^^^^^^
        let shim_vout_hdl_rside = shim_vout_hdl.try_clone().unwrap();
        Builder::new()
            .name("frank-pack-rside".to_owned())
            .spawn(move || {
                let recycler = PacketBatchRecycler::default();
                Self::pack_rside(recycler, vote_tx, user_tx, shim_vout_hdl_rside)
            })
            .unwrap();

        SigVerifyFrankStage {
            thread_hdl: thread_handle_snd,
        }
    }

    pub fn wait_thread_done(self) {
        // for thread_hdl in self.thread_handles {
        //     thread_hdl.join().unwrap();
        // }
        self.thread_hdl.join().unwrap();
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }

    fn feeder_cside(config: &SigVerifyFrankConfig, shim_vin_hdl: ShmChannelHandle) {
        let shim_ctl_fd_cstr = CString::new(shim_vin_hdl.ctl_fd.as_raw_fd().to_string()).unwrap();
        let shim_msg_fd_cstr = CString::new(shim_vin_hdl.msg_fd.as_raw_fd().to_string()).unwrap();

        let root_pod_cstr = CString::new(config.root_pod.to_owned()).unwrap();
        let app_name_cstr = CString::new(config.app_name.to_owned()).unwrap();
        let mut verifier_names = Vec::<CString>::with_capacity(config.verify_tiles.len());
        for i in config.verify_tiles.clone() {
            verifier_names.push(CString::new(format!("v{}in", i)).unwrap());
        }

        let mut argv_vec = Vec::<*const c_char>::with_capacity(3 + verifier_names.len());

        // Init argv buffer
        argv_vec.push(shim_ctl_fd_cstr.as_ptr()); // argv[0]
        argv_vec.push(shim_msg_fd_cstr.as_ptr()); // argv[1]
        argv_vec.push(root_pod_cstr.as_ptr()); // argv[2]
        argv_vec.push(app_name_cstr.as_ptr()); // argv[3]
        for name in &verifier_names {
            argv_vec.push(name.as_ptr());
        }

        let argv_ptr = argv_vec.as_ptr(); // *const *const i8
        let argv = argv_ptr as *mut *mut c_char; // *mut   *mut   i8;
        let argc = argv_vec.len() as c_int; // i32
        let rc: c_int;

        info!(
            "Invoking fd_cshim_verify_feeder(root_pod={:?}, app_name={:?}, verifiers={:?})",
            config.root_pod, config.app_name, config.verify_tiles,
        );

        unsafe {
            rc = fd_ffi::fd_cshim_verify_feeder(argc, argv);
        }
        info!("fd_cshim_verify_feeder exited with code {}", rc);
        assert_eq!(rc, 0);
    }

    fn pack_cside(config: &SigVerifyFrankConfig, shim_vout_hdl: ShmChannelHandle) {
        let shim_ctl_fd_cstr = CString::new(shim_vout_hdl.ctl_fd.as_raw_fd().to_string()).unwrap();
        let shim_msg_fd_cstr = CString::new(shim_vout_hdl.msg_fd.as_raw_fd().to_string()).unwrap();

        let root_pod_cstr = CString::new(config.root_pod.to_owned()).unwrap();
        let app_name_cstr = CString::new(config.app_name.to_owned()).unwrap();

        let argv_vec = vec![
            shim_ctl_fd_cstr.as_ptr(),
            shim_msg_fd_cstr.as_ptr(),
            root_pod_cstr.as_ptr(),
            app_name_cstr.as_ptr(),
        ];

        let argv_ptr = argv_vec.as_ptr();
        let argv = argv_ptr as *mut *mut c_char;
        let argc = argv_vec.len() as c_int;

        info!(
            "Invoking fd_cshim_pack_return(root_pod={:?}, app_name={:?})",
            config.root_pod, config.app_name,
        );

        let rc: c_int = unsafe { fd_ffi::fd_cshim_pack_return(argc, argv) };
        info!("fd_cshim_pack_return exited with code {}", rc);
        assert_eq!(rc, 0);
    }

    fn feeder_rside(
        vote_rx: find_packet_sender_stake_stage::FindPacketSenderStakeReceiver,
        user_rx: find_packet_sender_stake_stage::FindPacketSenderStakeReceiver,
        shim_vin_hdl: ShmChannelHandle,
    ) {
        let mut tx = shim_vin_hdl.open().unwrap();

        let mut send_batches = |mut batches: Vec<PacketBatch>, magic: u64| {
            let mut buf = [0u8; 4096];
            for _i in 0..batches.len() {
                if let Some(batch) = batches.pop() {
                    for (_k, pkt) in batch.iter().enumerate() {
                        if pkt.meta().discard() {
                            continue;
                        }
                        if let Some(pkt_buff) = pkt.data(..) {
                            // TODO spin?
                            // TODO could eliminate copy
                            buf[0..8].copy_from_slice(&magic.to_le_bytes()[..]);
                            buf[8..8 + pkt_buff.len()].copy_from_slice(pkt_buff);
                            let send_res = unsafe { tx.try_sendmsg(&buf[..8 + pkt_buff.len()]) };
                            if !send_res {
                                trace!("Sending msg to sigverify failed");
                            }
                        }
                    }
                }
            }
        };

        // Poll both crossbeam channels
        loop {
            let vote_msg = vote_rx.try_recv();
            match vote_msg {
                Ok(batches) => {
                    send_batches(batches, Self::MAGIC_VOTE);
                    continue;
                }
                Err(TryRecvError::Empty) => (),
                Err(TryRecvError::Disconnected) => break,
            };

            let user_msg = user_rx.try_recv();
            match user_msg {
                Ok(batches) => {
                    send_batches(batches, Self::MAGIC_USER);
                    continue;
                }
                Err(TryRecvError::Empty) => (),
                Err(TryRecvError::Disconnected) => break,
            };

            thread::yield_now();
        }
    }

    fn pack_rside(
        recycler: PacketBatchRecycler,
        vote_tx: banking_stage::BankingPacketSender,
        user_tx: banking_stage::BankingPacketSender,
        shim_vout_hdl: ShmChannelHandle,
    ) {
        let mut worker = PackRside::new(recycler, vote_tx, user_tx, shim_vout_hdl);
        worker.run();
    }
}

struct PackRside {
    recycler: PacketBatchRecycler,
    vote_tx: banking_stage::BankingPacketSender,
    user_tx: banking_stage::BankingPacketSender,
    rx: ShmChannel,
    batch: Option<PacketBatch>,
}

impl PackRside {
    const BATCH_DEPTH: usize = 64;

    fn new(
        recycler: PacketBatchRecycler,
        vote_tx: banking_stage::BankingPacketSender,
        user_tx: banking_stage::BankingPacketSender,
        shim_vout_hdl: ShmChannelHandle,
    ) -> Self {
        Self {
            recycler,
            vote_tx,
            user_tx,
            rx: shim_vout_hdl.open().unwrap(),
            batch: None,
        }
    }

    fn run(&mut self) {
        let mut buf = [0u8; fd_ffi::FD_SHIM_MSG_SZ as usize];
        loop {
            let msg = match unsafe { self.rx.try_recvmsg(&mut buf) } {
                None => {
                    self.flush();
                    thread::yield_now();
                    continue;
                }
                Some(msg_sz) => &buf[..msg_sz],
            };
            self.process_packet(msg);
        }
    }

    fn process_packet(&mut self, msg: &[u8]) {
        if msg.len() < 16 {
            warn!("Skipping packet that's too small ({} bytes)", msg.len());
            return;
        }

        //let txn_sz = u64::from_le_bytes((&msg[0..8]).try_into().unwrap());
        let txn_sz = msg.len() - 16;
        if txn_sz > PACKET_DATA_SIZE {
            warn!("Skipping oversize packet ({} bytes)", txn_sz);
            return;
        }
        //let sig = u64::from_le_bytes((&msg[8..16]).try_into().unwrap());

        let mut packet_buf = [0u8; PACKET_DATA_SIZE];
        packet_buf[..txn_sz].clone_from_slice(&msg[16..]);
        let packet = Packet::new(
            packet_buf,
            Meta {
                size: txn_sz,
                // Make up some fake metadata
                addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                port: 8000,
                flags: PacketFlags::empty(),
                sender_stake: 0u64,
            },
        );

        if self.batch.is_none() {
            self.batch = Some(PacketBatch::new_unpinned_with_recycler(
                self.recycler.clone(),
                Self::BATCH_DEPTH,
                "frank_pack",
            ));
        }

        // TODO Support flow steering to vote tx
        let batch = self.batch.as_mut().unwrap();
        batch.push(packet);
        if batch.len() >= Self::BATCH_DEPTH {
            self.flush();
        }
    }

    fn flush(&mut self) {
        let batch = match self.batch.take() {
            None => return,
            Some(b) => b,
        };
        if batch.is_empty() {
            return;
        }
        self.user_tx.send((vec![batch], None)).unwrap();
    }
}
