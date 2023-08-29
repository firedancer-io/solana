#!/bin/bash -f

export RUST_BACKTRACE=1

pushd programs/vote
  PKG_NAME=solana-vote-program cargo test --package solana-vote-program --lib -- --nocapture
popd

pushd programs/bpf_loader
  PKG_NAME=solana-bpf-loader-program cargo test --package solana-bpf-loader-program --lib -- --nocapture
popd

pushd programs/compute-budget
  PKG_NAME=solana-compute-budget-program cargo test --package solana-compute-budget-program --lib -- --nocapture
popd

pushd programs/config
  PKG_NAME=solana-config-program cargo test --package solana-config-program --lib -- --nocapture
popd

pushd programs/loader-v4
  PKG_NAME=solana-loader-v4-program cargo test --package solana-loader-v4-program --lib -- --nocapture
popd

pushd programs/sbf
  PKG_NAME=solana-sbf-programs cargo test --package solana-sbf-programs --lib -- --nocapture
popd

pushd programs/stake
  PKG_NAME=solana-stake-program cargo test --package solana-stake-program --lib -- --nocapture
popd

pushd programs/system
  PKG_NAME=solana-system-program cargo test --package solana-system-program --lib -- --nocapture
popd

pushd programs/zk-token-proof
  PKG_NAME=solana-zk-token-proof-program cargo test --package solana-zk-token-proof-program --lib -- --nocapture
popd


export MAINNET=1

pushd programs/vote
  PKG_NAME=solana-vote-program cargo test --package solana-vote-program --lib -- --nocapture
popd

pushd programs/bpf_loader
  PKG_NAME=solana-bpf-loader-program cargo test --package solana-bpf-loader-program --lib -- --nocapture
popd

pushd programs/compute-budget
  PKG_NAME=solana-compute-budget-program cargo test --package solana-compute-budget-program --lib -- --nocapture
popd

pushd programs/config
  PKG_NAME=solana-config-program cargo test --package solana-config-program --lib -- --nocapture
popd

pushd programs/loader-v4
  PKG_NAME=solana-loader-v4-program cargo test --package solana-loader-v4-program --lib -- --nocapture
popd

pushd programs/sbf
  PKG_NAME=solana-sbf-programs cargo test --package solana-sbf-programs --lib -- --nocapture
popd

pushd programs/stake
  PKG_NAME=solana-stake-program cargo test --package solana-stake-program --lib -- --nocapture
popd

pushd programs/system
  PKG_NAME=solana-system-program cargo test --package solana-system-program --lib -- --nocapture
popd

pushd programs/vote
  PKG_NAME=solana-vote-program cargo test --package solana-vote-program --lib -- --nocapture
popd

pushd programs/zk-token-proof
  PKG_NAME=solana-zk-token-proof-program cargo test --package solana-zk-token-proof-program --lib -- --nocapture
popd




#./cargo test --package solana-vote-program --lib -- --nocapture --test-threads=1 |& grep test_case_json out | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > solana-vote-program-mainnet.json
