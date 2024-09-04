use omni_account_lib::types::ProofInputs;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;

#[derive(Serialize, Deserialize)]
struct ProofInputRequest {
    jsonrpc: String,
    method: String,
    params: Vec<serde_json::Value>,
    id: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProofInputResponse {
    jsonrpc: String,
    result: Option<ProofInputs>,
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
) -> Result<Option<ProofInputs>, Box<dyn Error>> {
    let request_body = ProofInputRequest {
        jsonrpc: "2.0".to_string(),
        method: "eth_getBatchProof".to_string(),
        params: vec![],
        id,
    };

    let response = client
        .post(url)
        .json(&request_body)
        .send()
        .await?
        .json::<ProofInputResponse>()
        .await?; // explicitly define the type for clarity

    Ok(response.result)
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
        if let Some(proof_inputs) = fetch_proof_task(&client, url, id).await? {
            println!("Proof inputs: {:?}", proof_inputs);

            // Step 2: Use the proof inputs to generate the proof
            // TODO: Here we would run ZKP proof generation logic
            // For now, we use a mock ProofData
            let proof_data = ProofData {
                number: 1,
                proof: "0x1222".to_string(),
                public_values: "0xdc".to_string(),
            };

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
