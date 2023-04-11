
extern crate hex;
extern crate serde_json;

use {
    solana_sdk::{
        stake::{
            config::Config
        }
    }
};

fn main() {
    let s = Config::default();

    let d2: Vec<u8> = bincode::serialize(&s).unwrap();
    println!("Account: {} {}", serde_json::to_string(&s).unwrap(), hex::encode(d2));

}
