//! A simple script to generate and verify the proof of a given program.

use std::path::PathBuf;

use alloy::hex;
use sp1_sdk::{HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

use omni_account_lib::{
    conversions::addr_hex_to_bytes,
    types::{DomainInfo, ProofInputs, ProofOutputs},
    user_operation::create_mock_signed_user_operation,
};

use alloy_sol_types::SolType;

use serde::{Deserialize, Serialize};

/// A fixture that can be used to test the verification of SP1 zkVM proofs inside Solidity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1ProofFixture {
    user_addr: Vec<u8>,
    vkey: String,
    public_values: String,
    proof: String,
}

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

    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);

    let proof = client.prove(&pk, stdin).plonk().run().unwrap();

    println!("generated proof");

    // Get the public values as bytes.
    let public_values = proof.public_values.raw();
    println!("public values: {:?}", public_values);

    // Get the proof as bytes.
    let solidity_proof = proof.raw();
    println!("solidity_proof: {:?}", solidity_proof);

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");

    // Save the proof.
    proof
        .save("proof-with-pis.bin")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!");

    create_plonk_fixture(&proof, &vk)
}

/// Create a fixture for the given proof.
fn create_plonk_fixture(proof: &SP1ProofWithPublicValues, vk: &SP1VerifyingKey) {
    // Deserialize the public values.

    let output_bytes = proof.public_values.as_slice();
    let ProofOutputs {
        user_addr,
        new_smt_root,
    } = ProofOutputs::abi_decode(output_bytes, false).unwrap();
    println!(
        "abi decoded user address: {:?}",
        user_addr.to_checksum(None)
    );
    println!("abi decoded new_smt_root: {:?}", hex::encode(new_smt_root));
    let user_addr_bytes = user_addr.to_vec();

    // Create the testing fixture so we can test things end-to-end.
    let fixture = SP1ProofFixture {
        user_addr: user_addr_bytes,
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(output_bytes)),
        proof: format!("0x{}", hex::encode(proof.bytes())),
    };

    // The verification key is used to verify that the proof corresponds to the execution of the
    // program on the given input.
    //
    // Note that the verification key stays the same regardless of the input.
    println!("Verification Key: {}", fixture.vkey);

    // The public values are the values which are publicly committed to by the zkVM.
    //
    // If you need to expose the inputs or outputs of your program, you should commit them in
    // the public values.
    println!("Public Values: {}", fixture.public_values);

    // The proof proves to the verifier that the program was executed with some inputs that led to
    // the give public values.
    println!("Proof Bytes: {}", fixture.proof);

    // Save the fixture to a file.
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures");
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    std::fs::write(
        fixture_path.join("fixture.json"),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");
}
