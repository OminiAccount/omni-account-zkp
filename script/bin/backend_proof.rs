use alloy::hex;
use omni_account_lib::{types::ProofInputs, types_intermediate::ProofInputsIntermediate};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sp1_sdk::{HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};
use std::io::Write;
use std::path::PathBuf;
use std::{error::Error, fs::File};
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[derive(Serialize, Deserialize)]
struct ProofInputRequest {
    jsonrpc: String,
    method: String,
    params: Vec<serde_json::Value>,
    id: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProofInputsIntermediateResponse {
    jsonrpc: String,
    result: Option<ProofInputsIntermediate>,
    id: u32,
}

#[derive(Serialize, Deserialize)]
struct ProofOutputRequest {
    jsonrpc: String,
    method: String,
    params: Vec<ProofData>,
    id: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProofData {
    number: u32,
    proof: String,
    public_values: String,
}

async fn fetch_proof_task(
    client: &Client,
    url: &str,
    id: u32,
) -> Result<Option<ProofInputsIntermediate>, Box<dyn Error>> {
    let request_body = ProofInputRequest {
        jsonrpc: "2.0".to_string(),
        method: "eth_getBatchProof".to_string(),
        params: vec![],
        id,
    };

    let response = client.post(url).json(&request_body).send().await?;

    let response_text = response.text().await?;

    // println!("Response Text: {}", response_text);
    let mut file = File::create("response_text.txt")?;
    writeln!(file, "Response Text: {}", response_text)?;
    // let response_text = client
    //     .post(url)
    //     .json(&request_body)
    //     .send()
    //     .await?
    //     .text()
    //     .await?;

    let response_json: Result<ProofInputsIntermediateResponse, serde_json::Error> =
        serde_json::from_str(&response_text);
    match response_json {
        Ok(parsed_response) => Ok(parsed_response.result),
        Err(e) => {
            println!("Failed to parse JSON: {}", e);
            Err(Box::new(e))
        }
    }
    // Ok(response.result)

    // let response = client
    //     .post(url)
    //     .json(&request_body)
    //     .send()
    //     .await?
    //     .json::<ProofInputResponse>()
    //     .await?; // explicitly define the type for clarity

    // Ok(response.result)
}

async fn send_proof_result(
    client: &Client,
    url: &str,
    proof_data: ProofData,
    id: u32,
) -> Result<(), Box<dyn Error>> {
    let request_body = ProofOutputRequest {
        jsonrpc: "2.0".to_string(),
        method: "eth_setBatchProofResult".to_string(),
        params: vec![proof_data],
        id,
    };

    client.post(url).json(&request_body).send().await?;

    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Application error: {}", e);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let client = Client::new();
    let url = "https://api.omni-account.com";
    let mut id = 1;

    loop {
        // Step 1: Fetch proof task from backend
        if let Some(proof_inputs_intermediate) = fetch_proof_task(&client, url, id).await? {
            let proof_inputs = proof_inputs_intermediate.to_actual();
            // println!("Proof inputs: {:?}", proof_inputs);
            let proof_inputs_json = serde_json::to_string_pretty(&proof_inputs)?;

            let mut proof_file = File::create("proof_inputs.json")?;
            writeln!(proof_file, "{}", proof_inputs_json)?;

            // Step 2: Use the proof inputs to generate the proof
            let proof_data = plonk_bn254(proof_inputs, id);

            // Step 3: Send proof result to backend
            send_proof_result(&client, url, proof_data, 1).await?;

            println!("Proof result sent successfully");
            id += 1;
        } else {
            println!("No proof task available, retrying...");
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}

fn plonk_bn254(proof_inputs: ProofInputs, number: u32) -> ProofData {
    let mut stdin = SP1Stdin::new();

    // let proof_inputs: ProofInputs = load_proof_inputs_from_file("proof_inputs.json")
    //     .expect("Failed to load proof inputs from file");

    stdin.write(&proof_inputs);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);

    let proof = client.prove(&pk, stdin).plonk().run().unwrap();

    println!("generated proof");

    // Get the public values as bytes.
    let public_values = proof.public_values.raw();
    // println!("public values: {:?}", public_values);

    // Get the proof as bytes.
    let solidity_proof = proof.raw();
    // println!("solidity_proof: {:?}", solidity_proof);

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");

    // println!("proof_bytes hex string: 0x{}", hex::encode(proof.bytes()));
    create_plonk_fixture(&proof, &vk);
    ProofData {
        number,
        proof: format!("0x{}", hex::encode(proof.bytes())),
        public_values,
    }
}

/// A fixture that can be used to test the verification of SP1 zkVM proofs inside Solidity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1ProofFixture {
    vkey: String,
    public_values: String,
    proof: String,
}
/// Create a fixture for the given proof.
fn create_plonk_fixture(proof: &SP1ProofWithPublicValues, vk: &SP1VerifyingKey) {
    // Deserialize the public values.

    let output_bytes = proof.public_values.as_slice();
    // let ProofOutputs {
    //     user_ops,
    //     new_smt_root,
    //     d_tickets,
    //     w_tickets,
    // } = ProofOutputs::abi_decode(output_bytes, false).unwrap();
    // println!(
    //     "abi decoded user address: {:?}",
    //     user_addrs.to_checksum(None)
    // );
    // println!("abi decoded new_smt_root: {:?}", hex::encode(new_smt_root));
    // let user_addr_bytes = user_addrs.to_vec();

    // Create the testing fixture so we can test things end-to-end.
    let fixture = SP1ProofFixture {
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
