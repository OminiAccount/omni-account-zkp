use alloy::primitives::U256;
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
    struct UserOperation {
        address sender;
        uint256 nonce;
        uint256 chainId;
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
pub struct UserOperationRust {
    pub sender: String,
    pub nonce: u64,
    pub chain_id: u64,
    pub init_code: Vec<u8>,
    pub call_data: Vec<u8>,
    pub call_gas_limit: u128,
    pub verification_gas_limit: u128,
    pub pre_verification_gas: u128,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub paymaster_and_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfo {
    pub domain_chain_id: u64,
    pub domain_contract_addr_bytes: Vec<u8>,
}

impl UserOperationRust {
    pub fn to_user_operation(&self) -> UserOperation {
        let sender_address = hex_to_alloy_address(&self.sender);
        UserOperation {
            sender: sender_address,
            nonce: U256::from(self.nonce),
            chainId: U256::from(self.nonce),
            initCode: self.init_code.clone().into(),
            callData: self.call_data.clone().into(),
            callGasLimit: U256::from(self.call_gas_limit),
            verificationGasLimit: U256::from(self.verification_gas_limit),
            preVerificationGas: U256::from(self.pre_verification_gas),
            maxFeePerGas: U256::from(self.max_fee_per_gas),
            maxPriorityFeePerGas: U256::from(self.max_priority_fee_per_gas),
            paymasterAndData: self.paymaster_and_data.clone().into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofInputs {
    pub user_operation: UserOperationRust,
    pub sig_bytes: Vec<u8>,
    pub eth_reconvery_id: u8,
    pub domain_info: DomainInfo,
}

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct ProofOutputs {
        address user_addr;
    }
}
