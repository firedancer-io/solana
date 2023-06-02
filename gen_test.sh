

PKG_CONFIG_PATH=/opt/rh/gcc-toolset-12/root/usr/lib64/pkgconfig:/usr/lib64/pkgconfig
export PKG_CONFIG_PATH

./cargo nightly test --package solana-runtime --lib -- system_instruction_processor::tests::test_process_withdraw_ix_no_acc_data_fail --nocapture > out
#./cargo nightly test --package solana-runtime --lib -- system_instruction_processor::tests::test_create_from_account_is_nonce_fail --nocapture > out
#./cargo nightly test --workspace --lib -- tests --nocapture > out

#grep test_case_json out | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort > out.json

# grep test_transfer_lamports out.json
