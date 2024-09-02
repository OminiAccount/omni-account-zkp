//! A simple script to generate and verify the proof of a given program.

use std::{fs::File, io::Write};

use alloy_primitives::{U256, U64};
use sp1_sdk::{ProverClient, SP1Stdin};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

use omni_account_lib::{
    conversions::{addr_hex_to_bytes, hex_to_alloy_address},
    types::{
        DomainInfo, ProofInputs, ProofOutputs, Ticket, TicketInput, UserOpInput, UserOperation,
    },
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

    let mut smt = prepare_mock_user_smt();
    let old_smt_root = smt.get_root();
    println!("Initial smt root in script: {}", old_smt_root);
    let (updated_smt, d_ticket_inputs) = create_mock_tickets_inputs(
        vec![sender, sender],
        vec![U256::from(3), U256::from(2)],
        smt,
        true,
    );
    smt = updated_smt;
    let (updated_smt, w_ticket_inputs) = create_mock_tickets_inputs(
        vec![sender, sender],
        vec![U256::from(2), U256::from(1)],
        smt,
        false,
    );
    smt = updated_smt;
    let userop_inputs =
        create_mock_userop_inputs(sender, private_key_hex, chain_id, 5, domain_info, smt);

    let proof_inputs = ProofInputs {
        userop_inputs,
        old_smt_root,
        d_ticket_inputs,
        w_ticket_inputs,
    };

    save_proof_inputs_to_file(&proof_inputs, "proof_inputs.json")
        .expect("Failed to save proof inputs to file");
    // stdin.write(&proof_inputs);

    // let client = ProverClient::new();
    // let (pk, vk) = client.setup(ELF);
    // let proof = client
    //     .prove(&pk, stdin)
    //     .run()
    //     .expect("failed to generate proof");

    // client.verify(&proof, &vk).expect("failed to verify proof");
    // println!("Successfully verified proof!");

    // let public_values = proof.public_values.raw();
    // println!("Public Values: {:?}", public_values);

    // let output_bytes = proof.public_values.as_slice();
    // let ProofOutputs {
    //     user_addrs,
    //     new_smt_root,
    //     d_ticket_hashes,
    //     w_ticket_hashes,
    // } = ProofOutputs::abi_decode(output_bytes, false).unwrap();
    // println!("abi decoded Public Values: {:?}", user_addrs);
    // println!("abi decoded new_smt_root: {:?}", new_smt_root);
    // println!("abi decoded d_ticket_hashes: {:?}", d_ticket_hashes);
    // println!("abi decoded w_ticket_hashes: {:?}", w_ticket_hashes);
}

fn create_mock_tickets_inputs(
    user: Vec<&str>,
    amounts: Vec<U256>,
    mut smt: ZeroMerkleTree,
    is_deposit: bool,
) -> (ZeroMerkleTree, Vec<TicketInput>) {
    let mut ticket_inputs = Vec::new();
    for (amount, user) in amounts.into_iter().zip(user.into_iter()) {
        let user_addr = hex_to_alloy_address(user);
        let ticket = Ticket {
            user: user_addr,
            amount,
            timestamp: U256::from(2),
        };
        let balance_key = compute_balance_key(user_addr.as_ref());
        let balance_index = key_to_index(balance_key);

        let old_balance = smt.get_leaf(balance_index).value;
        let new_balance = if is_deposit {
            U256::from_str_radix(&old_balance, 16)
                .unwrap()
                .checked_add(amount)
                .expect("Add overflow in script!")
        } else {
            U256::from_str_radix(&old_balance, 16)
                .unwrap()
                .checked_sub(amount)
                .expect("Sub overflow in script!")
        };

        let delta_proof = smt.set_leaf(balance_index, format!("{:0>64x}", new_balance));

        println!(
            "user: {}, old balance before ticket: {}",
            user,
            U256::from_str_radix(&old_balance, 16).unwrap()
        );
        println!("user: {}, new balance before ticket: {}", user, new_balance);
        let ticket_input = TicketInput {
            ticket,
            delta_proof,
        };
        ticket_inputs.push(ticket_input);
    }
    (smt, ticket_inputs)
}

fn create_mock_userop_inputs(
    sender: &str,
    private_key_hex: &str,
    chain_id: u64,
    user_op_count: usize,
    domain_info: DomainInfo,
    mut smt: ZeroMerkleTree,
) -> Vec<UserOpInput> {
    let mut userop_inputs = Vec::new();

    for i in 0..user_op_count {
        let (user_op, sig, reconvery_id, verifying_key) = create_mock_signed_user_operation(
            sender.to_string(),
            private_key_hex,
            chain_id,
            U256::from(i + 8),
        );
        // sig_bytes is 64 bytes
        let sig_bytes = sig.to_bytes().to_vec();

        let recovery_id_byte = reconvery_id.to_byte();
        // ecdsa gives us 0 or 1. Convert it into eth recovery id since the program handle eth rid
        let eth_reconvery_id = recovery_id_byte + 27;

        let (updated_smt, new_bal_set_proof, new_nonce_set_proof) =
            mock_user_op_smt(smt, user_op.clone());

        smt = updated_smt;

        let userop_input = UserOpInput {
            user_operation: user_op,
            sig_bytes,
            eth_reconvery_id,
            domain_info: domain_info.clone(),
            balance_delta_proof: new_bal_set_proof.clone(),
            nonce_delta_proof: new_nonce_set_proof.clone(),
        };
        userop_inputs.push(userop_input);
    }
    userop_inputs
}

fn prepare_mock_smt() -> (MerkleNodeValue, MerkleProof, DeltaMerkleProof) {
    //current index is u32, 50 height is sufficient
    let mut tree = ZeroMerkleTree::new(50);
    // TODO: should not use usize here, 999_999_999_999 cannot be set in the zkvm usize
    let delta_a = tree.set_leaf(
        U256::from(999_999),
        "0000000000000000000000000000000000000000000000000000000000000008".to_string(),
    );

    let proof_a = tree.get_leaf(U256::from(999_999));

    let delta_b = tree.set_leaf(
        U256::from(1337),
        "0000000000000000000000000000000000000000000000000000000000000007".to_string(),
    );

    let proof_b = tree.get_leaf(U256::from(1337));

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
    let mut tree = ZeroMerkleTree::new(256);

    let sender_addr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    let balance_key = compute_balance_key(&addr_hex_to_bytes(sender_addr));

    // init 1 ETH balance for mock user
    let _ = tree.set_leaf(
        key_to_index(balance_key),
        "0000000000000000000000000000000000000000000000000de0b6b3a7640000".to_string(),
    );
    let chain_id = U64::from(42161);
    let nonce_key = compute_nonce_key(&addr_hex_to_bytes(sender_addr), chain_id);

    let _ = tree.set_leaf(
        key_to_index(nonce_key),
        "0000000000000000000000000000000000000000000000000000000000000007".to_string(),
    );

    tree
}

// TODO: Update U256 op to check_op here
fn mock_user_op_smt(
    mut tree: ZeroMerkleTree,
    user_operation: UserOperation,
) -> (ZeroMerkleTree, DeltaMerkleProof, DeltaMerkleProof) {
    let sender_addr = user_operation.sender;
    let balance_key = compute_balance_key(sender_addr.as_ref());
    let balance_index = key_to_index(balance_key);
    let balance_merkle_proof = tree.get_leaf(balance_index);
    let balance = balance_merkle_proof.clone().value;
    println!("old balance before userOp in script: {}", balance);
    let chain_id = user_operation.chainId;
    let nonce_key = compute_nonce_key(sender_addr.as_ref(), U64::from(chain_id));
    let nonce_index = key_to_index(nonce_key);
    let nonce_merkle_proof = tree.get_leaf(nonce_index);
    let nonce = nonce_merkle_proof.clone().value;
    println!("old nonce before userOp in script: {}", nonce);

    // here, we compute the balance and nonce outside the zk program
    // the balance&nonce computation here must align with that in the program
    // nonce could be computed by userOp or by smt tree, we use only smt tree here, and use both userOp and tree in zk program
    let total_gas = user_operation.callGasLimit
        + user_operation.verificationGasLimit
        + user_operation.preVerificationGas;
    let total_gas_coeff = user_operation.maxFeePerGas + user_operation.maxPriorityFeePerGas;
    let new_balance = U256::from_str_radix(&balance, 16).unwrap() - total_gas * total_gas_coeff;
    let new_nonce = U64::from_str_radix(&nonce, 16).unwrap() + U64::from(1);

    println!("new sender balance after userOp in script: {}", new_balance);
    println!("new sender nonce after userOp in script: {}", new_nonce);
    let new_bal_set_proof = tree.set_leaf(balance_index, format!("{:0>64x}", new_balance));

    let new_nonce_set_proof = tree.set_leaf(nonce_index, format!("{:0>64x}", new_nonce));
    println!(
        "formatted new sender balance in script: {:0>64x}",
        new_balance
    );
    println!("formatted new sender nonce in script: {:0>64x}", new_nonce);
    println!("new smt root in script: {}", tree.get_root());
    (tree, new_bal_set_proof, new_nonce_set_proof)
}

fn save_proof_inputs_to_file(proof_inputs: &ProofInputs, file_path: &str) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(proof_inputs)?;
    let mut file = File::create(file_path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}
