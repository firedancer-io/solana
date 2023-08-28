#!/bin/bash -f

export RUST_BACKTRACE=1

pushd programs/vote
  cargo test --package solana-vote-program --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-vote-program.json
popd

pushd programs/bpf_loader
  cargo test --package solana-bpf-loader-program --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-bpf-loader-program.json
popd

pushd programs/compute-budget
  cargo test --package solana-compute-budget-program --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-compute-budget-program.json
popd

pushd programs/config
  cargo test --package solana-config-program --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-config-program.json
popd

pushd programs/loader-v4
  cargo test --package solana-loader-v4-program --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-loader-v4-program.json
popd

pushd programs/sbf
  cargo test --package solana-sbf-programs --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-sbf-programs.json
popd

pushd programs/stake
  cargo test --package solana-stake-program --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-stake-program.json
popd

pushd programs/system
  cargo test --package solana-system-program --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-system-program.json
popd

pushd programs/zk-token-proof
  cargo test --package solana-zk-token-proof-program --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-zk-token-proof-program.json
popd


export MAINNET=1

pushd programs/vote
  cargo test --package solana-vote-program --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-vote-program-mainnet.json
popd

pushd programs/bpf_loader
  cargo test --package solana-bpf-loader-program --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-bpf-loader-program-mainnet.json
popd

pushd programs/compute-budget
  cargo test --package solana-compute-budget-program --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-compute-budget-program-mainnet.json
popd

pushd programs/config
  cargo test --package solana-config-program --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-config-program-mainnet.json
popd

pushd programs/loader-v4
  cargo test --package solana-loader-v4-program --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-loader-v4-program-mainnet.json
popd

pushd programs/sbf
  cargo test --package solana-sbf-programs --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-sbf-programs-mainnet.json
popd

pushd programs/stake
  cargo test --package solana-stake-program --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-stake-program-mainnet.json
popd

pushd programs/system
  cargo test --package solana-system-program --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-system-program-mainnet.json
popd

pushd programs/vote
  cargo test --package solana-vote-program --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-vote-program-mainnet.json
popd

pushd programs/zk-token-proof
  cargo test --package solana-zk-token-proof-program --lib -- --nocapture --test-threads=1 |& grep test_case_json  | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > ~/firedancer-testbins/solana-zk-token-proof-program-mainnet.json
popd




#./cargo test --package solana-vote-program --lib -- --nocapture --test-threads=1 |& grep test_case_json out | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > solana-vote-program-mainnet.json
