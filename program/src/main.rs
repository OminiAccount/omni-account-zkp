//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy::{hex, primitives::Address};
use alloy_sol_types::SolType;
use k256::ecdsa::{RecoveryId, Signature};
use omni_account_lib::{
    conversions::{addr_hex_to_bytes, hex_to_alloy_address, verifying_key_to_ethereum_address},
    types::{ProofInputs, ProofOutputs, UserOperationRust},
    user_operation::recover_public_key_from_userop_signature,
    zero_smt::{
        key::{compute_balance_key, compute_nonce_key, key_to_index},
        smt::{
            verify_delta_merkle_proof, verify_merkle_proof, DeltaMerkleProof, MerkleNodeValue,
            MerkleProof,
        },
    },
};

pub fn main() {
    let proof_inputs = sp1_zkvm::io::read::<ProofInputs>();
    let old_smt_root = sp1_zkvm::io::read::<MerkleNodeValue>();
    let merkle_proof = sp1_zkvm::io::read::<MerkleProof>();
    let delta_merkle_proof = sp1_zkvm::io::read::<DeltaMerkleProof>();
    let delta_merkle_proof_nonce = sp1_zkvm::io::read::<DeltaMerkleProof>();

    let user_op = proof_inputs.user_operation;

    let sender = user_op.sender;
    let nonce = user_op.nonce;
    let chain_id = user_op.chain_id;
    let init_code = user_op.init_code;
    let call_data = user_op.call_data;
    let call_gas_limit = user_op.call_gas_limit;
    let verification_gas_limit = user_op.verification_gas_limit;
    let pre_verification_gas = user_op.pre_verification_gas;
    let max_fee_per_gas = user_op.max_fee_per_gas;
    let max_priority_fee_per_gas = user_op.max_priority_fee_per_gas;
    let paymaster_and_data = user_op.paymaster_and_data;

    let sig_bytes = proof_inputs.sig_bytes;
    let recovery_id_byte = proof_inputs.eth_reconvery_id;
    let domain_chain_id = proof_inputs.domain_info.domain_chain_id;
    let domain_contract_addr_bytes = proof_inputs.domain_info.domain_contract_addr_bytes;

    // 1. get signature and recovery id
    let sig_bytes_fixed_size: [u8; 64] = sig_bytes
        .try_into()
        .expect("fail to convert sig_bytes to [u8; 64]");
    let sig = Signature::from_bytes(&sig_bytes_fixed_size.into()).unwrap();

    // convert eth recovery_id to k256 format
    let is_y_odd = (recovery_id_byte - 27) == 1;
    let is_x_reduced = false; // negligible probability that is_x_reduced = true
    let recovery_id = RecoveryId::new(is_y_odd, is_x_reduced);

    // 2. get the raw message, which is the user_op
    let user_op = UserOperationRust {
        sender: sender.clone(),
        nonce,
        chain_id,
        init_code,
        call_data,
        call_gas_limit,
        verification_gas_limit,
        pre_verification_gas,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        paymaster_and_data,
    }
    .to_user_operation();

    // 3. get the domain info
    let domain_contract_addr_arr: [u8; 20] = domain_contract_addr_bytes
        .try_into()
        .expect("fail to convert domain_contract_addr_bytes to [u8;20]");

    let domain_contract_addr = Address::from_slice(&domain_contract_addr_arr);
    let verifying_key = recover_public_key_from_userop_signature(
        user_op,
        domain_chain_id,
        domain_contract_addr,
        sig,
        recovery_id,
    );

    let user_addr_str = verifying_key_to_ethereum_address(&verifying_key);

    let user_addr = hex_to_alloy_address(&user_addr_str);

    // example to use merkle proof
    println!("old smt root in zk program: {}", old_smt_root.clone());

    let mut current_smt_root = old_smt_root;
    let sender_balance_key = compute_balance_key(&addr_hex_to_bytes(&sender));

    assert!(
        verify_merkle_proof(merkle_proof.clone()),
        "Invalid Merkle Proof!"
    );
    assert!(
        current_smt_root == merkle_proof.root,
        "Mismatch Merkle Proof!"
    );

    let valid_value1 = merkle_proof.value;
    let valid_index1 = merkle_proof.index;

    println!(
        "value1 and index1 is valid now! Feel free to use: value: {}, index: {}",
        valid_value1, valid_index1
    );

    assert_eq!(key_to_index(sender_balance_key.clone()), valid_index1);

    let sender_balance = u128::from_str_radix(&valid_value1, 16).unwrap();

    println!("old sender balance in zk program: {}", sender_balance);

    // example to use delta proof to update smt_root
    let remaining_balance = sender_balance
        - (call_gas_limit + verification_gas_limit + pre_verification_gas)
            * (max_fee_per_gas + max_priority_fee_per_gas);

    assert!(
        verify_delta_merkle_proof(delta_merkle_proof.clone()),
        "Invalid Delta Merkle Proof!"
    );
    assert!(
        current_smt_root == delta_merkle_proof.old_root,
        "Mismatch Delta Merkle Proof!"
    );

    println!(
        "new state root is valid now! Feel free to use: {}",
        delta_merkle_proof.new_root.clone()
    );

    current_smt_root = delta_merkle_proof.new_root;

    // we know the smt is updated at index from old value to new value
    // we need to ensure that the index is the sender balance index and the old value is the old balance, new value is the new balance
    assert_eq!(
        delta_merkle_proof.new_value,
        format!("{:0>64x}", remaining_balance)
    );
    assert_eq!(
        delta_merkle_proof.old_value,
        format!("{:0>64x}", sender_balance)
    );
    assert_eq!(delta_merkle_proof.index, key_to_index(sender_balance_key));

    println!("new sender balance in zk program: {}", remaining_balance);

    // Example: delta proof is all you need
    assert!(
        verify_delta_merkle_proof(delta_merkle_proof_nonce.clone()),
        "Invalid Delta Merkle Proof!"
    );
    assert!(
        current_smt_root == delta_merkle_proof_nonce.old_root,
        "Mismatch Delta Merkle Proof!"
    );
    // again, we know the smt is updated at index from old value to new value
    // we need to ensure that the index is the sender nonce index and the old value is the old nonce, new value is new nonce
    let nonce_key = compute_nonce_key(&addr_hex_to_bytes(&sender), chain_id);
    assert_eq!(delta_merkle_proof_nonce.index, key_to_index(nonce_key));
    assert_eq!(
        u64::from_str_radix(&delta_merkle_proof_nonce.old_value, 16).unwrap(),
        nonce - 1
    );
    assert_eq!(
        u64::from_str_radix(&delta_merkle_proof_nonce.new_value, 16).unwrap(),
        nonce
    );

    current_smt_root = delta_merkle_proof_nonce.new_root;

    println!("old sender nonce in zk program: {}", nonce - 1);
    println!("new sender nonce in zk program: {}", nonce); // nonce in UserOp, which is aligned with the delta proof

    println!("final smt root in zk program: {}", current_smt_root.clone());
    let new_smt_root: [u8; 32] = hex::decode(current_smt_root).unwrap().try_into().unwrap();
    let output_bytes = ProofOutputs::abi_encode(&ProofOutputs {
        user_addr,
        new_smt_root: new_smt_root.into(),
    });

    sp1_zkvm::io::commit_slice(&output_bytes);
}
