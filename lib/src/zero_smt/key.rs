use sha3::{Digest, Keccak256};

enum LeafValue {
    Balance(u128),
    Nonce(u64),
}

fn compute_leaf_key(user_address: &[u8], value: &LeafValue, chain_id: Option<u64>) -> Vec<u8> {
    let mut hasher = Keccak256::new();
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
                padded_input[21..21 + 8].copy_from_slice(&cid.to_be_bytes());
            }
        }
    }

    hasher.update(padded_input);
    hasher.finalize().to_vec()
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
        let chain_id = 42;

        let balance_key = compute_leaf_key(&user_address, &balance, None);
        println!("Balance Key: {:?}", balance_key);

        let nonce_key = compute_leaf_key(&user_address, &nonce, Some(chain_id));
        println!("Nonce Key: {:?}", nonce_key);
    }
}
