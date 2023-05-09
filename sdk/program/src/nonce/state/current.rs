use {
    super::Versions,
    crate::{
        fee_calculator::FeeCalculator,
        hash::{hashv, Hash},
        pubkey::Pubkey,
    },
    serde_derive::{Deserialize, Serialize},
};
use std::backtrace::Backtrace;
use log::info;

const DURABLE_NONCE_HASH_PREFIX: &[u8] = "DURABLE_NONCE".as_bytes();

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct DurableNonce(Hash);

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone)]
pub struct Data {
    pub authority: Pubkey,
    /// Durable nonce value derived from a valid previous blockhash.
    pub durable_nonce: DurableNonce,
    pub fee_calculator: FeeCalculator,
}

impl Data {
    pub fn new(
        authority: Pubkey,
        durable_nonce: DurableNonce,
        lamports_per_signature: u64,
    ) -> Self {
        let bt = Backtrace::capture();
        info!("nonce::state::new lamps: {} bt: {}", bt, lamports_per_signature);

        Data {
            authority,
            durable_nonce,
            fee_calculator: FeeCalculator::new(lamports_per_signature),
        }
    }

    /// Hash value used as recent_blockhash field in Transactions.
    /// Named blockhash for legacy reasons, but durable nonce and blockhash
    /// have separate domains.
    pub fn blockhash(&self) -> Hash {
        self.durable_nonce.0
    }

    pub fn get_lamports_per_signature(&self) -> u64 {
        let bt = Backtrace::capture();
        info!("get_lamports_per_signature lamps: {} bt: {}", bt, self.fee_calculator.lamports_per_signature);

        self.fee_calculator.lamports_per_signature
    }
}

impl DurableNonce {
    pub fn from_blockhash(blockhash: &Hash, separate_domains: bool) -> Self {
        Self(
            if separate_domains {
                let  ret = hashv(&[DURABLE_NONCE_HASH_PREFIX, blockhash.as_ref()]);
                info!("DurableNonce::from_blockhash = {} <= {} {}", ret, bs58::encode(DURABLE_NONCE_HASH_PREFIX).into_string(), bs58::encode(blockhash.as_ref()).into_string());
                ret
            } else {
                let ret = *blockhash;
//                info!("DurableNonce::from_blockhash = {} <= {}", ret, blockhash.as_ref());
                ret
            }
        )
    }

    /// Hash value used as recent_blockhash field in Transactions.
    pub fn as_hash(&self) -> &Hash {
        &self.0
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum State {
    Uninitialized,
    Initialized(Data),
}

impl Default for State {
    fn default() -> Self {
        State::Uninitialized
    }
}

impl State {
    pub fn new_initialized(
        authority: &Pubkey,
        durable_nonce: DurableNonce,
        lamports_per_signature: u64,
    ) -> Self {
        Self::Initialized(Data::new(*authority, durable_nonce, lamports_per_signature))
    }
    pub fn size() -> usize {
        let data = Versions::new(
            State::Initialized(Data::default()),
            true, // separate_domains
        );
        bincode::serialized_size(&data).unwrap() as usize
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn default_is_uninitialized() {
        assert_eq!(State::default(), State::Uninitialized)
    }
}
