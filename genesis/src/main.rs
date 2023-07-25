pub fn main() -> Result<(), Box<dyn error::Error>> {
    solana_validator::main1::main(std::env::args_os())
}
