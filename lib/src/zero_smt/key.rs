use alloy::hex;
use alloy_primitives::{U256, U64};
// use sha3::{Digest, Keccak256};
use sha2::{Digest, Sha256};

pub enum LeafValue {
    Balance(u128),
    Nonce(u64),
}

pub fn compute_leaf_key(user_address: &[u8], value: &LeafValue, chain_id: Option<U64>) -> String {
    let mut hasher = Sha256::new();
    let mut padded_input = vec![0u8; 32];

    match value {
        LeafValue::Balance(_) => {
            // identifier 0 for balance
            padded_input[0] = 0;
            padded_input[1..1 + user_address.len()].copy_from_slice(user_address);
        }
        LeafValue::Nonce(_) => {
            // identifier 1 for nonce
            padded_input[0] = 1;
            padded_input[1..1 + user_address.len()].copy_from_slice(user_address);
            if let Some(cid) = chain_id {
                padded_input[21..21 + 8].copy_from_slice(&cid.to_be_bytes::<8>());
            }
        }
    }

    hasher.update(padded_input);
    let leaf_key = hasher.finalize();
    hex::encode(leaf_key)
}

pub fn compute_balance_key(user_address: &[u8]) -> String {
    let mut hasher = Sha256::new();
    let mut padded_input = vec![0u8; 32];
    // identifier 0 for balance
    padded_input[0] = 0;
    padded_input[1..1 + user_address.len()].copy_from_slice(user_address);
    hasher.update(padded_input);
    let leaf_key = hasher.finalize();
    hex::encode(leaf_key)
}

pub fn compute_nonce_key(user_address: &[u8], chain_id: U64) -> String {
    let mut hasher = Sha256::new();
    let mut padded_input = vec![0u8; 32];
    // identifier 1 for nonce
    padded_input[0] = 1;
    padded_input[1..1 + user_address.len()].copy_from_slice(user_address);
    padded_input[21..21 + 8].copy_from_slice(&chain_id.to_be_bytes::<8>());
    hasher.update(padded_input);
    let leaf_key = hasher.finalize();
    hex::encode(leaf_key)
}

pub fn key_to_index(key: String) -> U256 {
    let truncated_str = &key[key.len() - 64..];
    U256::from_str_radix(truncated_str, 16).expect("Invalid hex string")
}

#[cfg(test)]
mod tests {
    use crate::conversions::addr_hex_to_bytes;

    use super::*;

    #[test]
    fn key_compute_test() {
        let hex_address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
        let user_address = addr_hex_to_bytes(hex_address);
        let balance = LeafValue::Balance(1000);
        let nonce = LeafValue::Nonce(1001);
        let chain_id = U64::from(42);

        let balance_key = compute_leaf_key(&user_address, &balance, None);
        println!("Balance Key: {:?}", balance_key);

        let nonce_key = compute_leaf_key(&user_address, &nonce, Some(chain_id));
        println!("Nonce Key: {:?}", nonce_key);

        let balance_key2 = compute_balance_key(&user_address);
        println!("Balance Key2: {:?}", balance_key2);

        let nonce_key2 = compute_nonce_key(&user_address, chain_id);
        println!("Nonce Key2: {:?}", nonce_key2);

        assert_eq!(balance_key, balance_key2);
        assert_eq!(nonce_key, nonce_key2);
    }
}
