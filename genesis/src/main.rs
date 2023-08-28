use std::error;

pub fn main() -> Result<(), Box<dyn error::Error>> {
    solana_genesis::main1::main(std::env::args_os())
}
