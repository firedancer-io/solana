#!/bin/bash -f

export RUST_BACKTRACE=1

PKG_NAME=solana-vote-program ./cargo test --package solana-vote-program --lib -- --nocapture

PKG_NAME=solana-bpf-loader-program ./cargo test --package solana-bpf-loader-program --lib -- --nocapture
#
PKG_NAME=solana-compute-budget-program ./cargo test --package solana-compute-budget-program --lib -- --nocapture
#
PKG_NAME=solana-config-program ./cargo test --package solana-config-program --lib -- --nocapture
#
PKG_NAME=solana-loader-v4-program ./cargo test --package solana-loader-v4-program --lib -- --nocapture
#
PKG_NAME=solana-sbf-programs ./cargo test --package solana-sbf-programs --lib -- --nocapture
#
PKG_NAME=solana-stake-program ./cargo test --package solana-stake-program --lib -- --nocapture
#
PKG_NAME=solana-system-program ./cargo test --package solana-system-program --lib -- --nocapture
#
PKG_NAME=solana-zk-token-proof-program ./cargo test --package solana-zk-token-proof-program --lib -- --nocapture
#
#
export MAINNET=1
#
PKG_NAME=solana-vote-program ./cargo test --package solana-vote-program --lib -- --nocapture
#
PKG_NAME=solana-bpf-loader-program ./cargo test --package solana-bpf-loader-program --lib -- --nocapture
#
PKG_NAME=solana-compute-budget-program ./cargo test --package solana-compute-budget-program --lib -- --nocapture
#
PKG_NAME=solana-config-program ./cargo test --package solana-config-program --lib -- --nocapture
#
PKG_NAME=solana-loader-v4-program ./cargo test --package solana-loader-v4-program --lib -- --nocapture
#
PKG_NAME=solana-sbf-programs ./cargo test --package solana-sbf-programs --lib -- --nocapture
#
PKG_NAME=solana-stake-program ./cargo test --package solana-stake-program --lib -- --nocapture
#
PKG_NAME=solana-system-program ./cargo test --package solana-system-program --lib -- --nocapture
#
PKG_NAME=solana-vote-program ./cargo test --package solana-vote-program --lib -- --nocapture
#
PKG_NAME=solana-zk-token-proof-program ./cargo test --package solana-zk-token-proof-program --lib -- --nocapture
#
#
#
#
# #././cargo test --package solana-vote-program --lib -- --nocapture --test-threads=1 |& grep test_case_json out | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort -u > solana-vote-program-mainnet.json