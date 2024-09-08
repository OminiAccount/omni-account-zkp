use alloy::hex::{self, FromHex};
use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::SolStruct;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

use crate::{conversions::hex_to_alloy_address, types::UserOperation};

pub fn create_mock_signed_user_operation(
    address: String,
    private_key_hex: &str,
    chain_id: u64,
    nonce: U256,
) -> (UserOperation, Signature, RecoveryId, VerifyingKey) {
    // we share chain_id and eth_addr between user_op and app domain for convenience
    let eth_address = hex_to_alloy_address(&address);
    let user_operation = UserOperation {
        sender: eth_address,
        nonce,
        chainId: chain_id, //U64::from(chain_id),
        initCode: Bytes::from_hex("0x").unwrap(),
        callData: Bytes::from_hex("0x").unwrap(),
        callGasLimit: U256::from_str_radix("20000", 10).unwrap(),
        verificationGasLimit: U256::from_str_radix("20000", 10).unwrap(),
        preVerificationGas: U256::from_str_radix("10000", 10).unwrap(),
        maxFeePerGas: U256::from_str_radix("20000000000", 10).unwrap(),
        maxPriorityFeePerGas: U256::from_str_radix("0", 10).unwrap(),
        paymasterAndData: Bytes::from_hex("0x").unwrap(),
    };

    let my_domain = alloy_sol_types::eip712_domain!(
        name: "OMNI-ACCOUNT",
        version: "1.0",
        chain_id: chain_id,
        verifying_contract: eth_address,
    );

    let mut digest_input = [0u8; 2 + 32 + 32];
    digest_input[0] = 0x19;
    digest_input[1] = 0x01;
    digest_input[2..34].copy_from_slice(&my_domain.hash_struct()[..]);
    digest_input[34..66].copy_from_slice(&user_operation.eip712_hash_struct()[..]);

    // let digest_test = Keccak256::new_with_prefix(digest_input);
    // let result = digest_test.finalize();
    // println!("digest: {}", hex::encode(result));
    let digest = Keccak256::new_with_prefix(digest_input);

    let private_key_bytes = hex::decode(private_key_hex).expect("Invalid hex string");
    let private_key_array: [u8; 32] = private_key_bytes
        .as_slice()
        .try_into()
        .expect("Expected a 32-byte private key");

    let signing_key =
        SigningKey::from_bytes(&private_key_array.into()).expect("Invalid private key");

    let (sig, recid) = signing_key.sign_digest_recoverable(digest.clone()).unwrap();

    // println!("signature: {}", sig.clone());
    let verifying_key = VerifyingKey::recover_from_digest(digest.clone(), &sig, recid).unwrap();

    (user_operation, sig, recid, verifying_key)
}

pub fn recover_public_key_from_userop_signature(
    user_op: UserOperation,
    domain_chain_id: u64,
    domain_contract_addr: Address,
    sig: Signature,
    recid: RecoveryId,
) -> VerifyingKey {
    // domain for omni-account dapp
    let omni_account_domain = alloy_sol_types::eip712_domain!(
        name: "OMNI-ACCOUNT",
        version: "1.0",
        chain_id: domain_chain_id,
        verifying_contract: domain_contract_addr,
    );

    let mut digest_input = [0u8; 2 + 32 + 32];
    digest_input[0] = 0x19;
    digest_input[1] = 0x01;
    digest_input[2..34].copy_from_slice(&omni_account_domain.hash_struct()[..]);
    digest_input[34..66].copy_from_slice(&user_op.eip712_hash_struct()[..]);

    let digest = Keccak256::new_with_prefix(digest_input);

    VerifyingKey::recover_from_digest(digest.clone(), &sig, recid)
        .expect("Failed to recover public key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversions::{hex_to_alloy_address, verifying_key_to_ethereum_address};
    // use k256::ecdsa::signature::DigestVerifier;

    #[test]
    fn test_eip_712_sig() {
        let hex_address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
        let eth_address = hex_to_alloy_address(hex_address);
        let private_key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let chain_id = 42161;

        let (user_operation, sig, recid, expected_verifying_key) =
            create_mock_signed_user_operation(
                hex_address.to_string(),
                private_key_hex,
                chain_id,
                U256::from(8),
            );

        let verifying_key = recover_public_key_from_userop_signature(
            user_operation,
            chain_id,
            eth_address,
            sig,
            recid,
        );

        println!("recovery id: {:?}", recid.to_byte());
        let eth_addr = verifying_key_to_ethereum_address(&verifying_key);
        println!("ETH Address: {}", eth_addr);

        assert!(verifying_key == expected_verifying_key);
    }
}
