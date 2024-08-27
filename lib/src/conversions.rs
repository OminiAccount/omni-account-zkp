use alloy::{hex, primitives::Address};
use k256::ecdsa::VerifyingKey;
use sha3::{Digest, Keccak256};

pub fn verifying_key_to_ethereum_address(verifying_key: &VerifyingKey) -> String {
    // uncompressed pubkey, 0x04 prefix, x, y
    let encoded_point = verifying_key.to_encoded_point(false);

    // remove 0x04 to keep 64 bytes
    let public_key_bytes = &encoded_point.as_bytes()[1..];

    let hash = Keccak256::digest(public_key_bytes);

    let address_bytes = &hash[hash.len() - 20..];

    format!("0x{}", hex::encode(address_bytes))
}

// Compatible with hexadecimal strings with or without a 0x prefix
pub fn addr_hex_to_bytes(hex_address: &str) -> [u8; 20] {
    let bytes_addr = hex::decode(hex_address).expect("Invalid hex string");
    let address_bytes: [u8; 20] = bytes_addr.try_into().expect("Slice with incorrect length");
    address_bytes
}

// Compatible with hexadecimal strings with or without a 0x prefix
pub fn hex_to_alloy_address(hex_address: &str) -> Address {
    let address_bytes = addr_hex_to_bytes(hex_address);
    Address::from(address_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::hex;
    use k256::ecdsa::SigningKey;

    #[test]
    fn test_verifying_key_to_ethereum_address() {
        // public known private key for address 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
        let private_key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let private_key_bytes = hex::decode(private_key_hex).expect("Invalid hex string");

        let private_key_array: [u8; 32] = private_key_bytes
            .as_slice()
            .try_into()
            .expect("Expected a 32-byte private key");

        let signing_key =
            SigningKey::from_bytes(&private_key_array.into()).expect("Invalid private key");

        let verifying_key = signing_key.verifying_key();

        let expected_address = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
        let actual_address = verifying_key_to_ethereum_address(verifying_key);

        assert_eq!(expected_address, actual_address);
    }
}
