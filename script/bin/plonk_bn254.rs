//! A simple script to generate and verify the proof of a given program.

use std::{fs::File, io::BufReader, path::PathBuf};

use alloy::hex;
use alloy_primitives::{Address, FixedBytes};
use sp1_sdk::{HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

use omni_account_lib::types::{PackedUserOperation, ProofInputs, ProofOutputs, Ticket};

use alloy_sol_types::SolType;

use serde::{Deserialize, Serialize};

/// A fixture that can be used to test the verification of SP1 zkVM proofs inside Solidity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1ProofFixture {
    user_ops: Vec<PackedUserOperation>,
    new_smt_root: FixedBytes<32>,
    d_tickets: Vec<Ticket>,
    w_tickets: Vec<Ticket>,
    vkey: String,
    public_values: String,
    proof: String,
}

fn main() {
    sp1_sdk::utils::setup_logger();

    let mut stdin = SP1Stdin::new();

    let proof_inputs: ProofInputs = load_proof_inputs_from_file("proof_inputs.json")
        .expect("Failed to load proof inputs from file");

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
        user_ops,
        new_smt_root,
        d_tickets,
        w_tickets,
    } = ProofOutputs::abi_decode(output_bytes, false).unwrap();
    // println!(
    //     "abi decoded user address: {:?}",
    //     user_addrs.to_checksum(None)
    // );
    // println!("abi decoded new_smt_root: {:?}", hex::encode(new_smt_root));
    // let user_addr_bytes = user_addrs.to_vec();

    // Create the testing fixture so we can test things end-to-end.
    let fixture = SP1ProofFixture {
        user_ops,
        new_smt_root,
        d_tickets,
        w_tickets,
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(output_bytes)),
        proof: format!("0x{}", hex::encode(proof.bytes())),
    };

    // The verification key is used to verify that the proof corresponds to the execution of the
    // program on the given input.
    //
    // Note that the verification key stays the same regardless of the input.
    // println!("Verification Key: {}", fixture.vkey);

    // The public values are the values which are publicly committed to by the zkVM.
    //
    // If you need to expose the inputs or outputs of your program, you should commit them in
    // the public values.
    // println!("Public Values: {}", fixture.public_values);

    // The proof proves to the verifier that the program was executed with some inputs that led to
    // the give public values.
    // println!("Proof Bytes: {}", fixture.proof);

    // Save the fixture to a file.
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures");
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    std::fs::write(
        fixture_path.join("fixture.json"),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");
}

fn load_proof_inputs_from_file(file_path: &str) -> std::io::Result<ProofInputs> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let proof_inputs = serde_json::from_reader(reader)?;
    Ok(proof_inputs)
}
