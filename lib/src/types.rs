use alloy_primitives::{FixedBytes, U256};
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

// accountGasLimits is the packed combination of callGasLimit and verificationGasLimit
// gasFees is the packed combination of maxPriorityFeePerGas and maxFeePerGas
sol! {
    #[derive(Debug, Serialize, Deserialize)]
    struct PackedUserOperation {
        address sender;
        uint256 nonce;
        uint64 chainId;
        bytes initCode;
        bytes callData;
        bytes32 accountGasLimits;
        uint256 preVerificationGas;
        bytes32 gasFees;
        bytes paymasterAndData;
    }
}

fn pack_uints(high128: U256, low128: U256) -> FixedBytes<32> {
    let high_bytes = &high128.to_be_bytes::<32>()[16..];
    let low_bytes = &low128.to_be_bytes::<32>()[16..];
    let mut packed = [0u8; 32];
    packed[..16].copy_from_slice(high_bytes);
    packed[16..].copy_from_slice(low_bytes);

    FixedBytes::<32>::from(packed)
}

impl From<UserOperation> for PackedUserOperation {
    fn from(user_op: UserOperation) -> Self {
        let account_gas_limits = pack_uints(user_op.verificationGasLimit, user_op.callGasLimit);
        let gas_fees = pack_uints(user_op.maxFeePerGas, user_op.maxPriorityFeePerGas);

        PackedUserOperation {
            sender: user_op.sender,
            nonce: user_op.nonce,
            chainId: user_op.chainId,
            initCode: user_op.initCode,
            callData: user_op.callData,
            accountGasLimits: account_gas_limits,
            preVerificationGas: user_op.preVerificationGas,
            gasFees: gas_fees,
            paymasterAndData: user_op.paymasterAndData,
        }
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
        PackedUserOperation[] user_ops;
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

#[cfg(test)]
mod tests {
    use crate::conversions::hex_to_alloy_address;

    use super::*;
    use alloy::hex::FromHex;
    use alloy_primitives::{Bytes, U256};

    #[test]
    fn test_packed_user_operation_from_user_operation() {
        let eth_address = hex_to_alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let user_op = UserOperation {
            sender: eth_address,
            nonce: U256::from(1),
            chainId: 42161u64,
            initCode: Bytes::from_hex("0x").unwrap(),
            callData: Bytes::from_hex("0x").unwrap(),
            callGasLimit: U256::from_str_radix("20000", 10).unwrap(),
            verificationGasLimit: U256::from_str_radix("20000", 10).unwrap(),
            preVerificationGas: U256::from_str_radix("10000", 10).unwrap(),
            maxFeePerGas: U256::from_str_radix("20000000000", 10).unwrap(),
            maxPriorityFeePerGas: U256::from_str_radix("0", 10).unwrap(),
            paymasterAndData: Bytes::from_hex("0x").unwrap(),
        };

        let packed_user_op: PackedUserOperation = user_op.clone().into();

        println!("user_op: {:?}", user_op);

        println!("packed_user_op: {:?}", packed_user_op);
    }
}
