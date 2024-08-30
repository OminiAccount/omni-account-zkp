use alloy_primitives::U256;
use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};

use crate::conversions::hex_to_alloy_address;

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
    pub user_operation: UserOperation,
    pub sig_bytes: Vec<u8>,
    pub eth_reconvery_id: u8,
    pub domain_info: DomainInfo,
}

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct ProofOutputs {
        address user_addr;
        bytes32 new_smt_root;
    }
}
