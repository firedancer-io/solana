use {
    clap::Parser,
    crossbeam_channel,
    log::*,
    rand::{thread_rng, Rng},
    solana_clap_utils::input_parsers,
    solana_core::sigverify_frank_stage::{SigVerifyFrankConfig, SigVerifyFrankStage},
    solana_perf::{
        packet::{to_packet_batches, PacketBatch},
        test_tx::test_tx,
    },
    solana_sdk::{
        hash::Hash, signature::Signer, signer::keypair::Keypair, system_transaction, timing,
    },
    std::{mem::forget, thread, time::Instant},
};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = {"0".to_owned()})]
    sigverify_tiles: String,

    #[arg(long)]
    wksp: String,

    #[arg(long, default_value_t = {"frank".to_owned()})]
    app_name: String,

    #[arg(long, default_value_t = 4096)]
    packet_cnt: usize,
}

fn main() {
    let args = Args::parse();
    solana_logger::setup_with_default("solana=info");

    let (out_vote_tx, out_vote_rx) = crossbeam_channel::bounded(16);
    let (out_user_tx, out_user_rx) = crossbeam_channel::bounded(16);

    let (in_vote_tx, in_vote_rx) = crossbeam_channel::bounded(16);
    let (in_user_tx, in_user_rx) = crossbeam_channel::bounded(16);

    // Discard sigverify results
    thread::spawn(move || {
        let mut iter = out_user_rx.iter();
        while iter.next().is_some() {}
    });

    // Prevent unused channels from being closed
    forget(in_vote_tx);
    forget(out_vote_rx);

    let frank_config = SigVerifyFrankConfig {
        root_pod: args.wksp,
        app_name: args.app_name,
        verify_tiles: args
            .sigverify_tiles
            .parse::<input_parsers::Range>()
            .unwrap()
            .into(),
    };

    let frank_stage = SigVerifyFrankStage::new(
        out_user_tx,
        out_vote_tx,
        in_user_rx,
        in_vote_rx,
        frank_config,
    );
    forget(frank_stage);

    let now = Instant::now();
    let use_same_tx = false;
    let packets_per_batch = 64usize;
    let gen_txn_batches_max_packets = 1920usize; // max gen_txn_batches() supports
    let total_packets = args.packet_cnt;
    let batch_cnt = (total_packets + packets_per_batch - 1) / packets_per_batch;
    let mut batches: Vec<PacketBatch> = Vec::with_capacity(batch_cnt);
    let iter_num = (total_packets + gen_txn_batches_max_packets - 1) / gen_txn_batches_max_packets;
    for _ in 0..iter_num {
        batches.append(&mut gen_txn_batches(
            use_same_tx,
            packets_per_batch,
            gen_txn_batches_max_packets,
        ));
    }
    info!(
        "starting... took {} ms  to generate {} batches for total_packets of {} and packets_per_batch of {}",
        timing::duration_as_ms(&now.elapsed()),
        batches.len(),
        total_packets,
        packets_per_batch
    );

    loop {
        for batch in &batches {
            in_user_tx.send(vec![batch.clone()]).unwrap();
            trace!("sent batch");
        }
    }
}

// 50ms/(25us/packet) = 2000 packets
const MAX_SIGVERIFY_BATCH: usize = 2_000;
fn gen_txn_batches(
    use_same_tx: bool,
    packets_per_batch: usize,
    total_packets: usize,
) -> Vec<PacketBatch> {
    assert!(total_packets < MAX_SIGVERIFY_BATCH);
    if use_same_tx {
        let tx = test_tx();
        to_packet_batches(&vec![tx; total_packets], packets_per_batch)
    } else {
        let from_keypair = Keypair::new();
        let to_keypair = Keypair::new();
        let txs: Vec<_> = (0..total_packets)
            .map(|_| {
                let amount = thread_rng().gen();
                system_transaction::transfer(
                    &from_keypair,
                    &to_keypair.pubkey(),
                    amount,
                    Hash::default(),
                )
            })
            .collect();
        to_packet_batches(&txs, packets_per_batch)
    }
}
