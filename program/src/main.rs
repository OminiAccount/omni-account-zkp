//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy::hex;
use alloy_primitives::{Address, U256, U64};
use alloy_sol_types::SolType;
use k256::ecdsa::{RecoveryId, Signature};
use omni_account_lib::{
    conversions::{addr_hex_to_bytes, hex_to_alloy_address, verifying_key_to_ethereum_address},
    types::{ProofInputs, ProofOutputs, UserOperation},
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
    let sig_bytes = proof_inputs.sig_bytes;
    let recovery_id_byte = proof_inputs.eth_reconvery_id;
    let domain_chain_id = proof_inputs.domain_info.domain_chain_id;
    let domain_contract_addr_bytes = proof_inputs.domain_info.domain_contract_addr_bytes;

    // let user_op = user_op_rust.to_user_operation();

    let user_addr = recover_eip712_userop_signature(
        sig_bytes,
        recovery_id_byte,
        user_op.clone(),
        domain_contract_addr_bytes,
        domain_chain_id,
    );

    println!("old smt root in zk program: {}", old_smt_root.clone());

    let mut current_smt_root = old_smt_root;

    current_smt_root =
        update_balance_smt_by_userop(delta_merkle_proof, user_op.clone(), current_smt_root);

    current_smt_root =
        update_nonce_smt_by_userop(delta_merkle_proof_nonce, user_op, current_smt_root);
    println!("final smt root in zk program: {}", current_smt_root.clone());
    let new_smt_root: [u8; 32] = hex::decode(current_smt_root).unwrap().try_into().unwrap();
    let output_bytes = ProofOutputs::abi_encode(&ProofOutputs {
        user_addr,
        new_smt_root: new_smt_root.into(),
    });

    sp1_zkvm::io::commit_slice(&output_bytes);
}

fn recover_eip712_userop_signature(
    sig_bytes: Vec<u8>,
    recovery_id_byte: u8,
    user_op: UserOperation,
    domain_contract_addr_bytes: Vec<u8>,
    domain_chain_id: u64,
) -> Address {
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
    // let user_op = user_op_rust.to_user_operation();

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

    let user_addr = verifying_key_to_ethereum_address(&verifying_key);
    hex_to_alloy_address(&user_addr)
}

// update smt in circuit, return the new smt root
fn update_nonce_smt(
    delta_proof: DeltaMerkleProof,
    userop_sender: Address,
    userop_nonce: U256,
    userop_chainid: U64,
    current_smt_root: String,
) -> String {
    assert!(
        verify_delta_merkle_proof(delta_proof.clone()),
        "Invalid Nonce Delta Merkle Proof!"
    );
    assert!(
        current_smt_root == delta_proof.old_root,
        "Mismatch Delta Merkle Proof!"
    );

    // we know the smt is updated at index from old value to new value
    // we need to ensure that the index is the sender nonce index and the old value is userop_nonce - 1, new value is userop_nonce
    let nonce_key = compute_nonce_key(userop_sender.as_ref(), userop_chainid);
    assert_eq!(delta_proof.index, key_to_index(nonce_key));
    let userop_nonce_neg_one = userop_nonce
        .checked_sub(U256::from(1))
        .expect("Sub overflow");
    assert_eq!(
        U256::from_str_radix(&delta_proof.old_value, 16).unwrap(),
        userop_nonce_neg_one,
    );
    assert_eq!(
        U256::from_str_radix(&delta_proof.new_value, 16).unwrap(),
        userop_nonce
    );

    println!("old sender nonce in zk program: {}", userop_nonce_neg_one);
    println!("new sender nonce in zk program: {}", userop_nonce);
    delta_proof.new_root
}

fn update_nonce_smt_by_userop(
    delta_proof: DeltaMerkleProof,
    user_op: UserOperation,
    current_smt_root: String,
) -> String {
    let sender = user_op.sender;
    let nonce = user_op.nonce;
    let chain_id = user_op.chainId;
    update_nonce_smt(
        delta_proof,
        sender,
        nonce,
        U64::from(chain_id),
        current_smt_root,
    )
}
// update smt in circuit, return the new smt root
#[allow(clippy::too_many_arguments)]
fn update_balance_smt(
    delta_proof: DeltaMerkleProof,
    userop_sender: Address,
    call_gas_limit: U256,
    verification_gas_limit: U256,
    pre_verification_gas: U256,
    max_fee_per_gas: U256,
    max_priority_fee_per_gas: U256,
    current_smt_root: String,
) -> String {
    assert!(
        verify_delta_merkle_proof(delta_proof.clone()),
        "Invalid Balance Delta Merkle Proof!"
    );
    assert!(
        current_smt_root == delta_proof.old_root,
        "Mismatch Delta Merkle Proof!"
    );
    // we know the smt is updated at index from old value to new value
    // we need to ensure that the index is the sender balance index and the old value is the old balance, new value is the new balance
    let balance_key = compute_balance_key(userop_sender.as_ref());
    assert_eq!(delta_proof.index, key_to_index(balance_key));
    let old_balance = delta_proof.old_value;
    println!("old sender balance in zk program: {}", old_balance);
    let total_gas = call_gas_limit
        .checked_add(verification_gas_limit)
        .expect("Add overflow")
        .checked_add(pre_verification_gas)
        .expect("Add overflow");
    let total_gas_coeff = max_fee_per_gas
        .checked_add(max_priority_fee_per_gas)
        .expect("Add overflow");

    let total_gas_cost = total_gas
        .checked_mul(total_gas_coeff)
        .expect("Mul overflow");
    // let total_gas = call_gas_limit + verification_gas_limit + pre_verification_gas;
    // let total_gas_coeff = max_fee_per_gas + max_priority_fee_per_gas;
    let new_balance = U256::from_str_radix(&old_balance, 16)
        .unwrap()
        .checked_sub(total_gas_cost)
        .expect("Sub overflow");

    assert_eq!(
        U256::from_str_radix(&delta_proof.new_value, 16).unwrap(),
        new_balance
    );

    println!("old sender balance in zk program: {}", old_balance);
    println!("new sender balance in zk program: {}", new_balance);
    delta_proof.new_root
}

fn update_balance_smt_by_userop(
    delta_proof: DeltaMerkleProof,
    user_op: UserOperation,
    current_smt_root: String,
) -> String {
    let sender = user_op.sender;
    let call_gas_limit = user_op.callGasLimit;
    let verification_gas_limit = user_op.verificationGasLimit;
    let pre_verification_gas = user_op.preVerificationGas;
    let max_fee_per_gas = user_op.maxFeePerGas;
    let max_priority_fee_per_gas = user_op.maxPriorityFeePerGas;
    update_balance_smt(
        delta_proof,
        sender,
        call_gas_limit,
        verification_gas_limit,
        pre_verification_gas,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        current_smt_root,
    )
}
