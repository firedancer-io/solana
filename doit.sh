#!/bin/bash -f

export RUST_BACKTRACE=1

pushd programs/vote
  ~/repos/solana/cargo test --package solana-vote-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-vote-program.json
popd

pushd programs/bpf_loader
  ~/repos/solana/cargo test --package solana-bpf-loader-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-bpf-loader-program.json
popd

pushd programs/compute-budget
  ~/repos/solana/cargo test --package solana-compute-budget-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-compute-budget-program.json
popd

pushd programs/config
  ~/repos/solana/cargo test --package solana-config-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-config-program.json
popd

pushd programs/loader-v4
  ~/repos/solana/cargo test --package solana-loader-v4-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-loader-v4-program.json
popd

pushd programs/sbf
  ~/repos/solana/cargo test --package solana-sbf-programs --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-sbf-programs.json
popd

pushd programs/stake
  ~/repos/solana/cargo test --package solana-stake-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-stake-program.json
popd

pushd programs/system
  ~/repos/solana/cargo test --package solana-system-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-system-program.json
popd

pushd programs/vote
  ~/repos/solana/cargo test --package solana-vote-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-vote-program.json
popd

pushd programs/zk-token-proof
  ~/repos/solana/cargo test --package solana-zk-token-proof-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-zk-token-proof-program.json
popd


export MAINNET=1

pushd programs/vote
  ~/repos/solana/cargo test --package solana-vote-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-vote-program-mainnet.json
popd

pushd programs/bpf_loader
  ~/repos/solana/cargo test --package solana-bpf-loader-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-bpf-loader-program-mainnet.json
popd

pushd programs/compute-budget
  ~/repos/solana/cargo test --package solana-compute-budget-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-compute-budget-program-mainnet.json
popd

pushd programs/config
  ~/repos/solana/cargo test --package solana-config-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-config-program-mainnet.json
popd

pushd programs/loader-v4
  ~/repos/solana/cargo test --package solana-loader-v4-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-loader-v4-program-mainnet.json
popd

pushd programs/sbf
  ~/repos/solana/cargo test --package solana-sbf-programs --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-sbf-programs-mainnet.json
popd

pushd programs/stake
  ~/repos/solana/cargo test --package solana-stake-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-stake-program-mainnet.json
popd

pushd programs/system
  ~/repos/solana/cargo test --package solana-system-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-system-program-mainnet.json
popd

pushd programs/vote
  ~/repos/solana/cargo test --package solana-vote-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-vote-program-mainnet.json
popd

pushd programs/zk-token-proof
  ~/repos/solana/cargo test --package solana-zk-token-proof-program --lib -- --nocapture |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/repos/firedancer-testbins/solana-zk-token-proof-program-mainnet.json
popd




#./cargo test --package solana-vote-program --lib -- --nocapture |& grep test_case_json out | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > solana-vote-program-mainnet.json
