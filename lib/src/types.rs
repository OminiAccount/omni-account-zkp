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

impl UserOperation {
    pub fn new(
        sender: String,
        nonce: u64,
        chain_id: u64,
        init_code: Vec<u8>,
        call_data: Vec<u8>,
        call_gas_limit: u128,
        verification_gas_limit: u128,
        pre_verification_gas: u128,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        paymaster_and_data: Vec<u8>,
    ) -> Self {
        let sender_address = hex_to_alloy_address(&sender);
        Self {
            sender: sender_address,
            nonce: U256::from(nonce),
            chainId: U256::from(chain_id),
            initCode: init_code.into(),
            callData: call_data.into(),
            callGasLimit: U256::from(call_gas_limit),
            verificationGasLimit: U256::from(verification_gas_limit),
            preVerificationGas: U256::from(pre_verification_gas),
            maxFeePerGas: U256::from(max_fee_per_gas),
            maxPriorityFeePerGas: U256::from(max_priority_fee_per_gas),
            paymasterAndData: paymaster_and_data.into(),
        }
    }
}
