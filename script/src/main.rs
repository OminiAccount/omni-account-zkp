//! A simple script to generate and verify the proof of a given program.

use sp1_sdk::{ProverClient, SP1Stdin};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

use omni_account_lib::{
    conversions::{addr_hex_to_bytes, hex_to_alloy_address},
    types::{DomainInfo, ProofInputs, ProofOutputs},
    user_operation::create_mock_signed_user_operation,
    zero_smt::{
        key::{compute_balance_key, compute_nonce_key, key_to_index},
        smt::{
            verify_delta_merkle_proof, verify_merkle_proof, DeltaMerkleProof, MerkleNodeValue,
            MerkleProof, ZeroMerkleTree,
        },
    },
};

use alloy_sol_types::SolType;

fn main() {
    sp1_sdk::utils::setup_logger();
    // Prepare Proof Inputs
    let mut stdin = SP1Stdin::new();

    let domain_contract_addr_bytes =
        addr_hex_to_bytes("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").into();
    let domain_info = DomainInfo {
        domain_chain_id: 42161,
        domain_contract_addr_bytes,
    };

    let private_key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let chain_id = 42161;
    let sender = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    let (user_op, sig, reconvery_id, verifying_key) =
        create_mock_signed_user_operation(sender.to_string(), private_key_hex, chain_id);
    // sig_bytes is 64 bytes
    let sig_bytes = sig.to_bytes().to_vec();

    let recovery_id_byte = reconvery_id.to_byte();
    // ecdsa gives us 0 or 1. Convert it into eth recovery id since the program handle eth rid
    let eth_reconvery_id = recovery_id_byte + 27;
    let proof_inputs = ProofInputs {
        user_operation: user_op,
        sig_bytes,
        eth_reconvery_id,
        domain_info,
    };
    stdin.write(&proof_inputs);

    // mock smt input write
    let smt = prepare_mock_user_smt();
    let old_smt_root = smt.get_root();
    println!("old smt root in script: {}", old_smt_root);
    let (old_bal_get_proof, new_bal_set_proof, new_nonce_set_proof) = mock_user_op_smt(smt);
    stdin.write(&old_smt_root);
    stdin.write(&old_bal_get_proof);
    stdin.write(&new_bal_set_proof);
    stdin.write(&new_nonce_set_proof);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let proof = client
        .prove(&pk, stdin)
        .run()
        .expect("failed to generate proof");

    client.verify(&proof, &vk).expect("failed to verify proof");
    println!("Successfully verified proof!");

    let public_values = proof.public_values.raw();
    println!("Public Values: {:?}", public_values);

    let output_bytes = proof.public_values.as_slice();
    let ProofOutputs {
        user_addr,
        new_smt_root,
    } = ProofOutputs::abi_decode(output_bytes, false).unwrap();
    println!("abi decoded Public Values: {:?}", user_addr);
    println!("abi decoded new_smt_root: {:?}", new_smt_root);
}

fn prepare_mock_smt() -> (MerkleNodeValue, MerkleProof, DeltaMerkleProof) {
    //current index is u32, 50 height is sufficient
    let mut tree = ZeroMerkleTree::new(50);
    // TODO: should not use usize here, 999_999_999_999 cannot be set in the zkvm usize
    let delta_a = tree.set_leaf(
        999_999,
        "0000000000000000000000000000000000000000000000000000000000000008".to_string(),
    );

    let proof_a = tree.get_leaf(999_999);

    let delta_b = tree.set_leaf(
        1337,
        "0000000000000000000000000000000000000000000000000000000000000007".to_string(),
    );

    let proof_b = tree.get_leaf(1337);

    println!(
        "verifyDeltaMerkleProof(deltaA): {}",
        verify_delta_merkle_proof(delta_a.clone())
    );
    println!(
        "verifyDeltaMerkleProof(deltaB): {}",
        verify_delta_merkle_proof(delta_b.clone())
    );
    println!(
        "deltaA.newRoot == deltaB.oldRoot: {}",
        delta_a.new_root == delta_b.old_root
    );

    println!(
        "verifyMerkleProof(proofA): {}",
        verify_merkle_proof(proof_a.clone())
    );
    println!(
        "verifyMerkleProof(proofB): {}",
        verify_merkle_proof(proof_b.clone())
    );

    println!("proofA: {:#?}", proof_a);
    println!("proofB: {:#?}", proof_b);

    let old_smt_root = delta_a.new_root;
    let merkle_proof = proof_a;
    let delta_proof = delta_b;
    (old_smt_root, merkle_proof, delta_proof)
}

fn prepare_mock_user_smt() -> (ZeroMerkleTree) {
    let mut tree = ZeroMerkleTree::new(50);

    let sender_addr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    let balance_key = compute_balance_key(&addr_hex_to_bytes(sender_addr));

    // init 1 ETH balance for mock user
    let _ = tree.set_leaf(
        key_to_index(balance_key),
        "0000000000000000000000000000000000000000000000000de0b6b3a7640000".to_string(),
    );
    let chain_id = 42161;
    let nonce_key = compute_nonce_key(&addr_hex_to_bytes(sender_addr), chain_id);

    let _ = tree.set_leaf(
        key_to_index(nonce_key),
        "0000000000000000000000000000000000000000000000000000000000000007".to_string(),
    );

    tree
}

fn mock_user_op_smt(mut tree: ZeroMerkleTree) -> (MerkleProof, DeltaMerkleProof, DeltaMerkleProof) {
    let hex_address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    let eth_address = hex_to_alloy_address(hex_address);
    let private_key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let chain_id = 42161;

    // Note the nonce in the mock msg must be 8, which is 1 + current nonce in tree
    let (user_operation, sig, recid, expected_verifying_key) =
        create_mock_signed_user_operation(hex_address.to_string(), private_key_hex, chain_id);

    let sender_addr = user_operation.sender;
    let balance_key = compute_balance_key(&addr_hex_to_bytes(&sender_addr));
    let balance_index = key_to_index(balance_key);
    let balance_merkle_proof = tree.get_leaf(balance_index);
    let balance = balance_merkle_proof.clone().value;
    println!(
        "init balance (should be 1ETH, 0xde0b6b3a7640000): {}",
        balance
    );
    let chain_id = user_operation.chain_id;
    let nonce_key = compute_nonce_key(&addr_hex_to_bytes(&sender_addr), chain_id);
    let nonce_index = key_to_index(nonce_key);
    let nonce_merkle_proof = tree.get_leaf(nonce_index);
    let nonce = nonce_merkle_proof.clone().value;
    println!("init nonce (should be 7): {}", nonce);

    // here, we compute the balance and nonce outside the zk program
    // the balance&nonce computation here must align with that in the program
    // nonce could be computed by userOp or by smt tree, we use only smt tree here, and use both userOp and tree in zk program
    let total_gas = user_operation.call_gas_limit
        + user_operation.verification_gas_limit
        + user_operation.pre_verification_gas;
    let total_gas_coeff = user_operation.max_fee_per_gas + user_operation.max_priority_fee_per_gas;
    let new_balance = u128::from_str_radix(&balance, 16).unwrap() - total_gas * total_gas_coeff;
    let new_nonce = u64::from_str_radix(&nonce, 16).unwrap() + 1;

    println!("new sender balance in script: {}", new_balance);
    println!("new sender nonce in script: {}", new_nonce);
    let old_bal_get_proof = tree.get_leaf(balance_index);
    let new_bal_set_proof = tree.set_leaf(balance_index, format!("{:0>64x}", new_balance));

    let new_nonce_set_proof = tree.set_leaf(nonce_index, format!("{:0>64x}", new_nonce));
    println!("final smt root in script: {}", tree.get_root());
    (old_bal_get_proof, new_bal_set_proof, new_nonce_set_proof)
}
