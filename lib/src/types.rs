use alloy_sol_types::{sol, SolValue};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha3::Keccak256;

use crate::zero_smt::smt::{DeltaMerkleProof, MerkleNodeValue};

#[derive(Serialize, Deserialize, Debug)]
pub struct ProverWitness {
    pub user_signed_msgs: Vec<Vec<u8>>, // decode Vec<u8> to get one signed msg
    pub batch_num: u32,
    // pub d_tickets: Vec<DepositTicket>,
    // pub w_tickets: Vec<WithdrawTicket>,
    // pub old_smt_root: Vec<u8>, // Vec<u8> for bytes32
    // pub smt_merkle_proofs: Vec<Vec<u8>>, // Each merkle proof is Vec<Bytes32>
}

sol! {
    #[derive(Debug, Serialize, Deserialize)]
    struct UserOperation {
        address sender;
        uint256 nonce;
        uint64 chainId;
        bytes initCode;
        bytes callData;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes paymasterAndData;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfo {
    pub domain_chain_id: u64,
    pub domain_contract_addr_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofInputs {
    pub userop_inputs: Vec<UserOpInput>,
    pub d_ticket_inputs: Vec<TicketInput>,
    pub w_ticket_inputs: Vec<TicketInput>,
    pub old_smt_root: MerkleNodeValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOpInput {
    pub user_operation: UserOperation,
    pub sig_bytes: Vec<u8>,
    pub eth_reconvery_id: u8,
    pub domain_info: DomainInfo,
    pub balance_delta_proof: DeltaMerkleProof,
    pub nonce_delta_proof: DeltaMerkleProof,
}

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct ProofOutputs {
        address[] user_addrs;
        bytes32 new_smt_root;
        bytes32[] d_ticket_hashes;
        bytes32[] w_ticket_hashes;
    }
}

sol! {
    #[derive(Debug, Serialize, Deserialize)]
    struct Ticket {
        address user;
        uint256 amount;
        uint256 timestamp;
    }
}
impl Ticket {
    pub fn hash(&self) -> [u8; 32] {
        let encoded = self.abi_encode_packed();
        Keccak256::digest(encoded).into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketInput {
    pub ticket: Ticket,
    pub delta_proof: DeltaMerkleProof,
}
