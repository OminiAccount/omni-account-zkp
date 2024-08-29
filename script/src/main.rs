//! A simple script to generate and verify the proof of a given program.

use sp1_sdk::{ProverClient, SP1Stdin};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

use omni_account_lib::{
    conversions::addr_hex_to_bytes,
    types::{DomainInfo, ProofInputs, ProofOutputs},
    user_operation::create_mock_signed_user_operation,
    zero_smt::smt::{
        verify_delta_merkle_proof, verify_merkle_proof, DeltaMerkleProof, MerkleNodeValue,
        MerkleProof, ZeroMerkleTree,
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
    let (old_smt_root, merkle_proof, delta_proof) = prepare_mock_smt();
    stdin.write(&old_smt_root);
    stdin.write(&merkle_proof);
    stdin.write(&delta_proof);
    println!("SMT write end!");

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
    let ProofOutputs { user_addr } = ProofOutputs::abi_decode(output_bytes, false).unwrap();
    println!("abi decoded Public Values: {:?}", user_addr);
}

fn prepare_mock_smt() -> (MerkleNodeValue, MerkleProof, DeltaMerkleProof) {
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
