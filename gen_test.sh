

PKG_CONFIG_PATH=/opt/rh/gcc-toolset-12/root/usr/lib64/pkgconfig:/usr/lib64/pkgconfig
export PKG_CONFIG_PATH

./cargo nightly test --workspace --lib -- tests --nocapture > out

grep test_case_json out | sed -e 's/.*test_case_json//' -e 's/$/,/' | sort > out.json

