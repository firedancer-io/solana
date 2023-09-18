//! The `tpu` module implements the Transaction Processing Unit, a
//! multi-stage transaction processing pipeline in software.

use solana_ledger::shred::Shred;
pub use solana_sdk::net::DEFAULT_TPU_COALESCE;
use {
    crate::{
        banking_stage::BankingStage,
        banking_trace::{BankingTracer, TracerThread},
        // broadcast_stage::{BroadcastStage, BroadcastStageType, RetransmitSlotsReceiver},
        cluster_info_vote_listener::{
            ClusterInfoVoteListener, GossipDuplicateConfirmedSlotsSender,
            GossipVerifiedVoteHashSender, VerifiedVoteSender, VoteTracker,
        },
        fetch_stage::FetchStage,
        sigverify::TransactionSigVerifier,
        sigverify_stage::SigVerifyStage,
        staked_nodes_updater_service::StakedNodesUpdaterService,
        // tpu_entry_notifier::TpuEntryNotifier,
        validator::GeneratorConfig,
    },
    crossbeam_channel::{unbounded/* , Receiver*/},
    solana_client::connection_cache::{ConnectionCache, Protocol},
    solana_firedancer::*,
    solana_gossip::cluster_info::ClusterInfo,
    solana_ledger::{
        blockstore::Blockstore, blockstore_processor::TransactionStatusSender,
        // entry_notifier_service::EntryNotifierSender,
    },
    solana_poh::poh_recorder::{PohRecorder/*, WorkingBankEntry*/},
    solana_rpc::{
        optimistically_confirmed_bank_tracker::BankNotificationSender,
        rpc_subscriptions::RpcSubscriptions,
    },
    solana_runtime::{
        bank_forks::BankForks,
        prioritization_fee_cache::PrioritizationFeeCache,
        vote_sender_types::{ReplayVoteReceiver, ReplayVoteSender},
    },
    solana_sdk::{pubkey::Pubkey, signature::Keypair},
    solana_streamer::{
        nonblocking::quic::DEFAULT_WAIT_FOR_CHUNK_TIMEOUT,
        quic::{spawn_server, MAX_STAKED_CONNECTIONS, MAX_UNSTAKED_CONNECTIONS},
        streamer::StakedNodes,
    },
    std::{
        collections::HashMap,
        net::UdpSocket,
        sync::{atomic::AtomicBool, Arc, RwLock},
        thread,
        time::Duration,
    },
};

// allow multiple connections for NAT and any open/close overlap
pub const MAX_QUIC_CONNECTIONS_PER_PEER: usize = 8;

pub struct TpuSockets {
    pub transactions: Vec<UdpSocket>,
    pub transaction_forwards: Vec<UdpSocket>,
    pub vote: Vec<UdpSocket>,
    // pub broadcast: Vec<UdpSocket>,
    pub transactions_quic: Option<UdpSocket>,
    pub transactions_forwards_quic: Option<UdpSocket>,
}

pub struct Tpu {
    fetch_stage: FetchStage,
    sigverify_stage: SigVerifyStage,
    vote_sigverify_stage: SigVerifyStage,
    banking_stage: BankingStage,
    cluster_info_vote_listener: ClusterInfoVoteListener,
    // broadcast_stage: BroadcastStage,
    tpu_quic_t: Option<thread::JoinHandle<()>>,
    tpu_forwards_quic_t: Option<thread::JoinHandle<()>>,
    // tpu_entry_notifier: Option<TpuEntryNotifier>,
    staked_nodes_updater_service: StakedNodesUpdaterService,
    tracer_thread_hdl: TracerThread,
    firedancer_insert_blockstore: thread::JoinHandle<()>,
}

impl Tpu {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cluster_info: &Arc<ClusterInfo>,
        poh_recorder: &Arc<RwLock<PohRecorder>>,
        // entry_receiver: Receiver<WorkingBankEntry>,
        // retransmit_slots_receiver: RetransmitSlotsReceiver,
        sockets: TpuSockets,
        subscriptions: &Arc<RpcSubscriptions>,
        transaction_status_sender: Option<TransactionStatusSender>,
        // entry_notification_sender: Option<EntryNotifierSender>,
        blockstore: &Arc<Blockstore>,
        // broadcast_type: &BroadcastStageType,
        exit: &Arc<AtomicBool>,
        // shred_version: u16,
        vote_tracker: Arc<VoteTracker>,
        bank_forks: Arc<RwLock<BankForks>>,
        verified_vote_sender: VerifiedVoteSender,
        gossip_verified_vote_hash_sender: GossipVerifiedVoteHashSender,
        replay_vote_receiver: ReplayVoteReceiver,
        replay_vote_sender: ReplayVoteSender,
        bank_notification_sender: Option<BankNotificationSender>,
        tpu_coalesce: Duration,
        cluster_confirmed_slot_sender: GossipDuplicateConfirmedSlotsSender,
        connection_cache: &Arc<ConnectionCache>,
        keypair: &Keypair,
        log_messages_bytes_limit: Option<usize>,
        staked_nodes: &Arc<RwLock<StakedNodes>>,
        shared_staked_nodes_overrides: Arc<RwLock<HashMap<Pubkey, u64>>>,
        banking_tracer: Arc<BankingTracer>,
        tracer_thread_hdl: TracerThread,
        tpu_enable_udp: bool,
        prioritization_fee_cache: &Arc<PrioritizationFeeCache>,
        _generator_config: Option<GeneratorConfig>, /* vestigial code for replay invalidator */
        firedancer_app_name: String,
    ) -> Self {
        let TpuSockets {
            transactions: transactions_sockets,
            transaction_forwards: tpu_forwards_sockets,
            vote: tpu_vote_sockets,
            //broadcast: broadcast_sockets,
            transactions_quic: transactions_quic_sockets,
            transactions_forwards_quic: transactions_forwards_quic_sockets,
        } = sockets;

        let (packet_sender, packet_receiver) = unbounded();
        let (vote_packet_sender, vote_packet_receiver) = unbounded();
        let (forwarded_packet_sender, forwarded_packet_receiver) = unbounded();
        let fetch_stage = FetchStage::new_with_sender(
            transactions_sockets,
            tpu_forwards_sockets,
            tpu_vote_sockets,
            exit,
            &packet_sender,
            &vote_packet_sender,
            &forwarded_packet_sender,
            forwarded_packet_receiver,
            poh_recorder,
            tpu_coalesce,
            Some(bank_forks.read().unwrap().get_vote_only_mode_signal()),
            tpu_enable_udp,
        );

        let staked_nodes_updater_service = StakedNodesUpdaterService::new(
            exit.clone(),
            bank_forks.clone(),
            staked_nodes.clone(),
            shared_staked_nodes_overrides,
            firedancer_app_name.clone(),
        );

        let (non_vote_sender, non_vote_receiver) = banking_tracer.create_channel_non_vote();

        let tpu_quic_t = if let Some(transactions_quic_sockets) = transactions_quic_sockets {
            let (_, tpu_quic_t) = spawn_server(
                "quic_streamer_tpu",
                transactions_quic_sockets,
                keypair,
                cluster_info
                    .my_contact_info()
                    .tpu(Protocol::QUIC)
                    .expect("Operator must spin up node with valid (QUIC) TPU address")
                    .ip(),
                packet_sender,
                exit.clone(),
                MAX_QUIC_CONNECTIONS_PER_PEER,
                staked_nodes.clone(),
                MAX_STAKED_CONNECTIONS,
                MAX_UNSTAKED_CONNECTIONS,
                DEFAULT_WAIT_FOR_CHUNK_TIMEOUT,
                tpu_coalesce,
            )
            .unwrap();
            Some(tpu_quic_t)
        } else {
            None
        };

        let tpu_forwards_quic_t = if let Some(transactions_forwards_quic_sockets) = transactions_forwards_quic_sockets {
            let (_, tpu_forwards_quic_t) = spawn_server(
                "quic_streamer_tpu_forwards",
                transactions_forwards_quic_sockets,
                keypair,
                cluster_info
                    .my_contact_info()
                    .tpu_forwards(Protocol::QUIC)
                    .expect("Operator must spin up node with valid (QUIC) TPU-forwards address")
                    .ip(),
                forwarded_packet_sender,
                exit.clone(),
                MAX_QUIC_CONNECTIONS_PER_PEER,
                staked_nodes.clone(),
                MAX_STAKED_CONNECTIONS.saturating_add(MAX_UNSTAKED_CONNECTIONS),
                0, // Prevent unstaked nodes from forwarding transactions
                DEFAULT_WAIT_FOR_CHUNK_TIMEOUT,
                tpu_coalesce,
            )
            .unwrap();
            Some(tpu_forwards_quic_t)
        } else {
            None
        };

        let sigverify_stage = {
            let verifier = TransactionSigVerifier::new(non_vote_sender);
            SigVerifyStage::new(packet_receiver, verifier, "tpu-verifier")
        };

        let (tpu_vote_sender, tpu_vote_receiver) = banking_tracer.create_channel_tpu_vote();

        let vote_sigverify_stage = {
            let verifier = TransactionSigVerifier::new_reject_non_vote(tpu_vote_sender);
            SigVerifyStage::new(vote_packet_receiver, verifier, "tpu-vote-verifier")
        };

        let (gossip_vote_sender, gossip_vote_receiver) =
            banking_tracer.create_channel_gossip_vote();
        let cluster_info_vote_listener = ClusterInfoVoteListener::new(
            exit.clone(),
            cluster_info.clone(),
            gossip_vote_sender,
            poh_recorder.clone(),
            vote_tracker,
            bank_forks.clone(),
            subscriptions.clone(),
            verified_vote_sender,
            gossip_verified_vote_hash_sender,
            replay_vote_receiver,
            blockstore.clone(),
            bank_notification_sender,
            cluster_confirmed_slot_sender,
        );

        let banking_stage = BankingStage::new(
            cluster_info,
            poh_recorder,
            non_vote_receiver,
            tpu_vote_receiver,
            gossip_vote_receiver,
            transaction_status_sender,
            replay_vote_sender,
            log_messages_bytes_limit,
            connection_cache.clone(),
            bank_forks.clone(),
            prioritization_fee_cache,
            firedancer_app_name.clone(),
        );

        // let (entry_receiver, tpu_entry_notifier) =
        //     if let Some(entry_notification_sender) = entry_notification_sender {
        //         let (broadcast_entry_sender, broadcast_entry_receiver) = unbounded();
        //         let tpu_entry_notifier = TpuEntryNotifier::new(
        //             entry_receiver,
        //             entry_notification_sender,
        //             broadcast_entry_sender,
        //             exit.clone(),
        //         );
        //         (broadcast_entry_receiver, Some(tpu_entry_notifier))
        //     } else {
        //         (entry_receiver, None)
        //     };

        // let broadcast_stage = broadcast_type.new_broadcast_stage(
        //     broadcast_sockets,
        //     cluster_info.clone(),
        //     entry_receiver,
        //     retransmit_slots_receiver,
        //     exit.clone(),
        //     blockstore.clone(),
        //     bank_forks,
        //     shred_version,
        // );

        let blockstore = blockstore.clone();
        let firedancer_insert_blockstore = std::thread::Builder::new()
            .name("solBroadcastRec".to_string())
            .spawn(move || unsafe {
                #[cfg(target_arch = "x86_64")]
                use core::arch::x86_64::_rdtsc as rdtsc;
                #[cfg(target_arch = "x86")]
                use core::arch::x86::_rdtsc as rdtsc;

                let in_pod = Pod::join_default(format!("{}_shred_store0.wksp", firedancer_app_name)).unwrap();
                let pod = Pod::join_default(format!("{}_store0.wksp", firedancer_app_name)).unwrap();
                let mut in_mcache = MCache::join::<GlobalAddress>(in_pod.try_query("mcache").unwrap()).unwrap();
                let in_dcache = DCache::join::<GlobalAddress>(in_pod.try_query("dcache").unwrap(), 0).unwrap(); /* MTU doesn't matter, we are only a reader */
                let in_fseq = FSeq::join::<GlobalAddress>(in_pod.try_query("fseq").unwrap()).unwrap();

                in_fseq.set(FSeqDiag::PublishedCount as u64, 0);
                in_fseq.set(FSeqDiag::PublishedSize as u64, 0);
                in_fseq.set(FSeqDiag::FilteredCount as u64, 0);
                in_fseq.set(FSeqDiag::FilteredSize as u64, 0);
                in_fseq.set(FSeqDiag::OverrunPollingCount as u64, 0);
                in_fseq.set(FSeqDiag::OverrunReadingCount as u64, 0);
                in_fseq.set(FSeqDiag::SlowCount as u64, 0);
                let mut in_accum_pub_cnt: u64 = 0;
                let mut in_accum_pub_sz: u64 = 0;
                let mut in_accum_ovrnp_cnt: u64 = 0;
                let mut in_accum_ovrnr_cnt: u64 = 0;

                let lazy: i64 = in_pod.query("lazy");
                let lazy = if lazy <= 0 { housekeeping_default_interval_nanos(in_mcache.depth()) } else { lazy };
                let async_min = minimum_housekeeping_tick_interval(lazy);

                let cnc = Cnc::join::<GlobalAddress>(pod.try_query("cnc").unwrap()).unwrap();
                if cnc.query() != CncSignal::Boot as u64 {
                    panic!("cnc not in boot state");
                }

                cnc.set(CncDiag::InBackpressure as u64, 0);
                cnc.set(CncDiag::BackpressureCount as u64, 0);

                let seed = pod.try_query("seed").unwrap_or(0);
                let mut rng = Rng::new(seed, 0).unwrap();

                let mut now = rdtsc();
                let mut then = now;

                cnc.signal(CncSignal::Run as u64);
                loop {
                    if now >= then {
                        // Send flow control credits
                        in_fseq.rx_cr_return(&in_mcache);

                        // Send synchronization info
                        in_fseq.increment(FSeqDiag::PublishedCount as u64, in_accum_pub_cnt);
                        in_fseq.increment(FSeqDiag::PublishedSize as u64, in_accum_pub_sz);
                        in_fseq.increment(FSeqDiag::OverrunPollingCount as u64, in_accum_ovrnp_cnt);
                        in_fseq.increment(FSeqDiag::OverrunReadingCount as u64, in_accum_ovrnr_cnt);
                        in_accum_pub_cnt = 0;
                        in_accum_pub_sz = 0;
                        in_accum_ovrnp_cnt = 0;
                        in_accum_ovrnr_cnt = 0;

                        // Send diagnostic info
                        cnc.heartbeat(now as i64);

                        // Receive command-and-control signals
                        let s = cnc.query();
                        if s != CncSignal::Run as u64 {
                            if s != CncSignal::Halt as u64 {
                                panic!("unexpected signal");
                            }
                            break;
                        }

                        // Reload housekeeping timer
                        then = now + rng.async_reload(async_min);
                    }

                    match in_mcache.poll() {
                        Poll::CaughtUp => {
                            core::hint::spin_loop();
                            now = rdtsc();
                            continue;
                        },
                        Poll::Overrun => {
                            in_accum_ovrnp_cnt += 1;
                        },
                        Poll::Ready => (),
                    };

                    now = rdtsc();

                    let size = in_mcache.size();
                    let chunk = in_mcache.chunk();

                    let shred_cnt = u64::from_le_bytes(in_dcache.slice(chunk.into(), 0, 8).try_into().unwrap());
                    let stride = u64::from_le_bytes(in_dcache.slice(chunk.into(), 8, 8).try_into().unwrap());
                    let offset = u64::from_le_bytes(in_dcache.slice(chunk.into(), 16, 8).try_into().unwrap());
                    let shred_sz = u64::from_le_bytes(in_dcache.slice(chunk.into(), 24, 8).try_into().unwrap());

                    assert!(shred_sz < stride);
                    assert!((shred_cnt==0) || (offset + stride*(shred_cnt-1) + shred_sz < size.into()));

                    let shreds = (0..shred_cnt).map(|i| {
                        let shred_bytes = in_dcache.slice(chunk.into(), offset + stride*i, shred_sz);
                        Shred::new_from_serialized_shred(shred_bytes.to_vec()).unwrap() // Does .to_vec() do a copy?
                    }).collect();

                    // Check that we weren't overrun while processing
                    match in_mcache.advance() {
                        Advance::Overrun => {
                            in_accum_ovrnr_cnt += 1;
                            now = rdtsc();
                            continue;
                        },
                        Advance::Normal => (),
                    }

                    blockstore
                        .insert_shreds(
                            shreds, /*leader_schedule:*/ None, /*is_trusted:*/ true,
                        )
                        .expect("Failed to insert shreds in blockstore");

                    in_accum_pub_cnt += shred_cnt as u64;
                    in_accum_pub_sz += size as u64;
                }
            })
            .unwrap();

        Self {
            fetch_stage,
            sigverify_stage,
            vote_sigverify_stage,
            banking_stage,
            cluster_info_vote_listener,
            // broadcast_stage,
            tpu_quic_t,
            tpu_forwards_quic_t,
            // tpu_entry_notifier,
            staked_nodes_updater_service,
            tracer_thread_hdl,
            firedancer_insert_blockstore,
        }
    }

    pub fn join(self) -> thread::Result<()> {
        let results = vec![
            self.fetch_stage.join(),
            self.sigverify_stage.join(),
            self.vote_sigverify_stage.join(),
            self.cluster_info_vote_listener.join(),
            self.banking_stage.join(),
            self.staked_nodes_updater_service.join(),
            self.tpu_quic_t.map_or(Ok(()), |x| x.join()),
            self.tpu_forwards_quic_t.map_or(Ok(()), |x| x.join()),
            self.firedancer_insert_blockstore.join(),
        ];
        // let broadcast_result = self.broadcast_stage.join();
        for result in results {
            result?;
        }
        // if let Some(tpu_entry_notifier) = self.tpu_entry_notifier {
        //     tpu_entry_notifier.join()?;
        // }
        // let _ = broadcast_result?;
        if let Some(tracer_thread_hdl) = self.tracer_thread_hdl {
            if let Err(tracer_result) = tracer_thread_hdl.join()? {
                error!(
                    "banking tracer thread returned error after successful thread join: {:?}",
                    tracer_result
                );
            }
        }
        Ok(())
    }
}
