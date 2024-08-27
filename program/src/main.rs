//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy::primitives::Address;
use alloy_sol_types::SolType;
use k256::ecdsa::{RecoveryId, Signature};
use omni_account_lib::{
    conversions::{hex_to_alloy_address, verifying_key_to_ethereum_address},
    types::{ProofInputs, ProofOutputs, UserOperationRust},
    user_operation::recover_public_key_from_userop_signature,
};

pub fn main() {
    let proof_inputs = sp1_zkvm::io::read::<ProofInputs>();
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
        sender,
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

    let output_bytes = ProofOutputs::abi_encode(&ProofOutputs { user_addr });

    sp1_zkvm::io::commit_slice(&output_bytes);
}
