TARGET_NAME=tls-enclave
# FIXME: using --release to work around linker errors due to "compressed sections"
TARGET_DIR=ra-enclave/target/x86_64-fortanix-unknown-sgx/release/examples
TARGET=$TARGET_DIR/$TARGET_NAME.sgxs

# Run enclave with the default runner
ftxsgx-runner --signature coresident $TARGET &

# Run client
(cd ra-client && cargo run -Zfeatures=itarget --example tls-client --features verbose) &

# Run SP
(cd ra-sp && cargo run -Zfeatures=itarget --example tls-sp --features "verbose")
