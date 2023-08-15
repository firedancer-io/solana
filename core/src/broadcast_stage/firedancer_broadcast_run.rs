use {
    super::{
        broadcast_utils::{self, ReceiveResults},
        *,
    },
    crate::{
        broadcast_stage::broadcast_utils::UnfinishedSlotInfo, cluster_nodes::ClusterNodesCache,
    },
    firedancer::*,
    solana_entry::entry::Entry,
    solana_ledger::{
        blockstore,
        shred::{shred_code, ProcessShredsStats, ReedSolomonCache, Shred, ShredFlags, Shredder},
    },
    solana_sdk::{
        genesis_config::ClusterType,
        signature::Keypair,
        timing::{duration_as_us, AtomicInterval},
    },
    std::{mem::transmute_copy, sync::RwLock, time::Duration},
};

#[derive(Clone)]
struct FiredancerTurbineState {
    pub slot: Slot,
    pub data_idx_offset: u64,
    pub parity_idx_offset: u64,
}

#[derive(Clone)]
pub struct FiredancerBroadcastRun {
    turbine_state: Option<FiredancerTurbineState>,
    current_slot_and_parent: Option<(u64, u64)>,
    shred_version: u16,
    out_mcache: Arc<MCache>,
    out_dcache: Arc<DCache>,
    out_fseq: Arc<FSeq>,
}



impl FiredancerBroadcastRun {
    pub(super) fn new(shred_version: u16, firedancer_app_name: &String) -> Self {

        let out_pod = unsafe { Pod::join_default(format!("{}_bank_shred0.wksp", firedancer_app_name)).unwrap() };
        let id = 0usize;

        unsafe {
        let out_mcache = MCache::join::<GlobalAddress>(out_pod.try_query(format!("mcache{}", id)).unwrap()).unwrap();
        let out_dcache = DCache::join::<GlobalAddress>(out_pod.try_query(format!("dcache{}", id)).unwrap()).unwrap();
        let out_fseq = FSeq::join::<GlobalAddress>(out_pod.try_query(format!("fseq{}", id)).unwrap()).unwrap();

        out_fseq.set(FSeqDiag::SlowCount as u64, 0); // Managed by the fctl
     

        let cr_max: u64 = out_mcache.depth(); // pod.query("cr_max");
        let cr_resume: u64 = out_pod.query("cr_resume");
        let cr_refill: u64 = out_pod.query("cr_refill");
        let lazy: i64 = out_pod.query("lazy");

        let out_fctl = FCtl::new(1, cr_max, cr_resume, cr_refill, &out_fseq).unwrap();
        let lazy = if lazy <= 0 { housekeeping_default_interval_nanos(out_mcache.depth()) } else { lazy };

        Self {
            turbine_state: None,
            current_slot_and_parent: None,
            shred_version,
            out_mcache: Arc::new(out_mcache),
            out_dcache: Arc::new(out_dcache),
            out_fseq: Arc::new(out_fseq)
        }
    }
    }

    fn process_receive_results_firedancer(
        &mut self,
        keypair: &Keypair,
        blockstore: &Blockstore,
        socket_sender: &Sender<(Arc<Vec<Shred>>, Option<BroadcastShredBatchInfo>)>,
        blockstore_sender: &Sender<(Arc<Vec<Shred>>, Option<BroadcastShredBatchInfo>)>,
        receive_results: ReceiveResults,
    ) -> Result<()> {
        // Skip the "last slot interrupted check"

        #[repr(C)]
        struct fd_entry_batch_meta {
            pub slot: u64,
            pub data_idx_offset: u64,
            pub parity_idx_offset: u64,
            pub version: u16,
            pub parent_offset: u16,
            pub reference_tick: u8,
            pub block_complete: i32,
        }

        {
            let bank = receive_results.bank.clone();

            if self.current_slot_and_parent.is_none()
                || bank.slot() != self.current_slot_and_parent.unwrap().0
            {
                let slot = bank.slot();
                let parent_slot = bank.parent_slot();

                self.current_slot_and_parent = Some((slot, parent_slot));
            }

            let last_tick_height = receive_results.last_tick_height;
            let is_last_in_slot = last_tick_height == bank.max_tick_height();
            let reference_tick = bank.tick_height() % bank.ticks_per_slot();
            let (slot, parent_slot) = self.current_slot_and_parent.unwrap();
            let version = self.shred_version;

            let (mut data_idx_offset, mut parity_idx_offset) =
                if let Some(fd_turbine_state) = &self.turbine_state {
                    if fd_turbine_state.slot == slot {
                        (
                            fd_turbine_state.data_idx_offset,
                            fd_turbine_state.parity_idx_offset,
                        )
                    } else {
                        (0, 0)
                    }
                } else {
                    (0, 0)
                };

            let meta = fd_entry_batch_meta {
                slot,
                data_idx_offset,
                parity_idx_offset,
                version,
                parent_offset: (slot - parent_slot) as u16,
                reference_tick: reference_tick as u8,
                block_complete: is_last_in_slot.into(),
            };
            let meta_sz = std::mem::size_of::<fd_entry_batch_meta>();
            let entry_batch_sz = bincode::serialized_size(&receive_results.entries)?;

            let mut entry_batch_with_meta = vec![0u8; meta_sz + entry_batch_sz as usize];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &meta as *const fd_entry_batch_meta as *const u8,
                    entry_batch_with_meta.as_mut_ptr() as *mut u8,
                    meta_sz,
                );
            }
            bincode::serialize_into(
                &mut entry_batch_with_meta[meta_sz..],
                &receive_results.entries,
            )?;

            unsafe {
                // tango_tx.publish(&entry_batch_with_meta);
            }
            unsafe {
                data_idx_offset += firedancer::ballet::fd_shredder_count_data_shreds(entry_batch_sz);
                parity_idx_offset += firedancer::ballet::fd_shredder_count_parity_shreds(entry_batch_sz);
            }
            self.turbine_state = Some(FiredancerTurbineState {
                slot,
                data_idx_offset,
                parity_idx_offset,
            });
        }
        Ok(())
    }
}

impl BroadcastRun for FiredancerBroadcastRun {
    fn run(
        &mut self,
        keypair: &Keypair,
        blockstore: &Blockstore,
        receiver: &Receiver<WorkingBankEntry>,
        socket_sender: &Sender<(Arc<Vec<Shred>>, Option<BroadcastShredBatchInfo>)>,
        blockstore_sender: &Sender<(Arc<Vec<Shred>>, Option<BroadcastShredBatchInfo>)>,
    ) -> Result<()> {
        let receive_results = broadcast_utils::recv_slot_entries(receiver)?;

        self.process_receive_results_firedancer(
            keypair,
            blockstore,
            socket_sender,
            blockstore_sender,
            receive_results,
        )
    }

    fn transmit(
        &mut self,
        receiver: &Mutex<TransmitReceiver>,
        cluster_info: &ClusterInfo,
        sock: &UdpSocket,
        bank_forks: &RwLock<BankForks>,
    ) -> Result<()> {
        panic!("Shreds are transmitted directly from Firedancer");
    }
    fn record(&mut self, receiver: &Mutex<RecordReceiver>, blockstore: &Blockstore) -> Result<()> {
        panic!("Not implemented yet");
    }
}
