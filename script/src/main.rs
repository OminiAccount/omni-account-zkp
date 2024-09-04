//! A simple script to generate and verify the proof of a given program.

use std::{fs::File, io::BufReader};

use sp1_sdk::{ProverClient, SP1Stdin};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

use omni_account_lib::types::{ProofInputs, ProofOutputs};

use alloy_sol_types::SolType;

fn main() {
    sp1_sdk::utils::setup_logger();
    // Prepare Proof Inputs
    let mut stdin = SP1Stdin::new();

    let proof_inputs: ProofInputs = load_proof_inputs_from_file("proof_inputs.json")
        .expect("Failed to load proof inputs from file");

    stdin.write(&proof_inputs);

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
        user_ops,
        new_smt_root,
        d_tickets,
        w_tickets,
    } = ProofOutputs::abi_decode(output_bytes, false).unwrap();
    println!("Packed UserOps: {:?}", user_ops);
    println!("abi decoded new_smt_root: {:?}", new_smt_root);
    println!("abi decoded d_tickets: {:?}", d_tickets);
    println!("abi decoded w_tickets: {:?}", w_tickets);
}

fn load_proof_inputs_from_file(file_path: &str) -> std::io::Result<ProofInputs> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let proof_inputs = serde_json::from_reader(reader)?;
    Ok(proof_inputs)
}
