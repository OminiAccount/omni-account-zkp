use alloy::hex;
use alloy_primitives::{Address, FixedBytes, U256};
use alloy_sol_types::{sol, SolValue};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha3::Keccak256;

use crate::{
    conversions::addr_hex_to_bytes,
    types::{ProofInputs, Ticket, TicketInput, UserOpInput, UserOperation},
    zero_smt::smt::{DeltaMerkleProof, MerkleNodeValue},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOperationIntermediate {
    pub sender: String,
    pub nonce: String,
    pub chainId: String,
    pub initCode: String,
    pub callData: String,
    pub callGasLimit: String,
    pub verificationGasLimit: String,
    pub preVerificationGasLimit: String,
    pub maxFeePerGas: String,
    pub maxPriorityFeePerGas: String,
    pub paymasterAndData: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfoIntermediate {
    pub Name: String,
    pub Version: String,
    pub ChainId: u64,
    pub VerifyingContract: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofInputsIntermediate {
    pub number: u128,
    pub userop_inputs: Vec<UserOpInputIntermediate>,
    pub d_ticket_inputs: Vec<TicketInputIntermediate>,
    pub w_ticket_inputs: Vec<TicketInputIntermediate>,
    pub old_smt_root: MerkleNodeValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOpInputIntermediate {
    pub user_operation: UserOperationIntermediate,
    pub sig_bytes: String,
    pub eth_reconvery_id: u8,
    // pub domain_info: DomainInfoIntermediate,
    pub balance_delta_proof: DeltaMerkleProofIntermediate,
    pub nonce_delta_proof: DeltaMerkleProofIntermediate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaMerkleProofIntermediate {
    pub index: String,
    pub siblings: Vec<MerkleNodeValue>,
    pub old_root: MerkleNodeValue,
    pub old_value: MerkleNodeValue,
    pub new_root: MerkleNodeValue,
    pub new_value: MerkleNodeValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketInputIntermediate {
    pub ticket: TicketIntermediate,
    pub delta_proof: DeltaMerkleProofIntermediate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketIntermediate {
    pub user: String,
    pub amount: String,
    pub timestamp: String,
}

impl UserOperationIntermediate {
    pub fn to_actual(self) -> UserOperation {
        UserOperation {
            sender: addr_hex_to_bytes(&self.sender).into(),
            nonce: U256::from_str_radix(&self.nonce[2..], 16).unwrap(),
            chainId: u64::from_str_radix(&self.chainId[2..], 16).unwrap(),
            initCode: hex::decode(self.initCode).unwrap().into(),
            callData: hex::decode(self.callData).unwrap().into(),
            callGasLimit: U256::from_str_radix(&self.callGasLimit[2..], 16).unwrap(),
            verificationGasLimit: U256::from_str_radix(&self.verificationGasLimit[2..], 16)
                .unwrap(),
            preVerificationGas: U256::from_str_radix(&self.preVerificationGasLimit[2..], 16)
                .unwrap(),
            maxFeePerGas: U256::from_str_radix(&self.maxFeePerGas[2..], 16).unwrap(),
            maxPriorityFeePerGas: U256::from_str_radix(&self.maxPriorityFeePerGas[2..], 16)
                .unwrap(),
            paymasterAndData: hex::decode(self.paymasterAndData).unwrap().into(),
        }
    }
}

impl DeltaMerkleProofIntermediate {
    pub fn to_actual(self) -> DeltaMerkleProof {
        DeltaMerkleProof {
            index: U256::from_str_radix(&self.index, 16).unwrap(),
            siblings: self.siblings,
            old_root: self.old_root,
            old_value: self.old_value,
            new_root: self.new_root,
            new_value: self.new_value,
        }
    }
}

// impl DomainInfoIntermediate {
//     pub fn to_actual(self) -> DomainInfo {
//         // We hardcode Name and Version in our circuit
//         DomainInfo {
//             domain_chain_id: self.ChainId,
//             domain_contract_addr_bytes: hex::decode(self.VerifyingContract).unwrap(),
//         }
//     }
// }

impl TicketIntermediate {
    pub fn to_actual(self) -> Ticket {
        // We hardcode Name and Version in our circuit
        let user_bytes: [u8; 20] = hex::decode(self.user).unwrap().try_into().unwrap();
        Ticket {
            user: user_bytes.into(),
            amount: U256::from_str_radix(&self.amount[2..], 16).unwrap(),
            timestamp: U256::from_str_radix(&self.timestamp[2..], 16).unwrap(),
        }
    }
}

impl UserOpInputIntermediate {
    pub fn to_actual(self) -> UserOpInput {
        UserOpInput {
            user_operation: self.user_operation.to_actual(),
            sig_bytes: hex::decode(self.sig_bytes).unwrap(),
            eth_reconvery_id: self.eth_reconvery_id,
            // domain_info: self.domain_info.to_actual(),
            balance_delta_proof: self.balance_delta_proof.to_actual(),
            nonce_delta_proof: self.nonce_delta_proof.to_actual(),
        }
    }
}

impl TicketInputIntermediate {
    pub fn to_actual(self) -> TicketInput {
        TicketInput {
            ticket: self.ticket.to_actual(),
            delta_proof: self.delta_proof.to_actual(),
        }
    }
}

impl ProofInputsIntermediate {
    pub fn to_actual(self) -> ProofInputs {
        let userop_inputs = self
            .userop_inputs
            .into_iter()
            .map(|userop_input| userop_input.to_actual())
            .collect();
        let d_ticket_inputs = self
            .d_ticket_inputs
            .into_iter()
            .map(|d_ticket_input| d_ticket_input.to_actual())
            .collect();
        let w_ticket_inputs = self
            .w_ticket_inputs
            .into_iter()
            .map(|w_ticket_input| w_ticket_input.to_actual())
            .collect();
        ProofInputs {
            userop_inputs,
            d_ticket_inputs,
            w_ticket_inputs,
            old_smt_root: self.old_smt_root[2..].to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_operation_conversion() {
        let user_operation_intermediate = UserOperationIntermediate {
            sender: "0x93d53d2d8f0d623c5cbe46daa818177a450bd9f7".to_string(),
            nonce: "0x1".to_string(),
            chainId: "0xaa36a7".to_string(),
            initCode: "0x".to_string(),
            callData: "0xb61d27f600000000000000000000000027916984c665f15041929b68451303136fa16653000000000000000000000000000000000000000000000000002386f26fc1000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000".to_string(),
            callGasLimit: "0x30d40".to_string(),
            verificationGasLimit: "0x41eb0".to_string(),
            preVerificationGasLimit: "0x29810".to_string(),
            maxFeePerGas: "0x6fc23ac00".to_string(),
            maxPriorityFeePerGas: "0x77359400".to_string(),
            paymasterAndData: "0x".to_string(),
        };

        let user_operation = user_operation_intermediate.to_actual();

        assert_eq!(
            user_operation.sender,
            addr_hex_to_bytes("0x93d53d2d8f0d623c5cbe46daa818177a450bd9f7")
        );
        assert_eq!(user_operation.nonce, U256::from(1)); // 0x1 -> 1
        assert_eq!(user_operation.chainId, 11155111);
        assert_eq!(user_operation.initCode.len(), 0); // 0x -> vec![]
        println!("calldata: {}", user_operation.callData);
        // assert_eq!(user_operation.callData.len(), 196);
        assert_eq!(user_operation.callGasLimit, U256::from(200000)); // 0x30d40 -> 200000
        assert_eq!(user_operation.verificationGasLimit, U256::from(270000)); // 0x41eb0 -> 270000
        assert_eq!(user_operation.preVerificationGas, U256::from(170000)); // 0x29810 -> 170000
        assert_eq!(
            user_operation.maxFeePerGas,
            U256::from_str_radix("30000000000", 10).unwrap()
        ); // 0x6fc23ac00 -> 30000000000
        assert_eq!(
            user_operation.maxPriorityFeePerGas,
            U256::from_str_radix("2000000000", 10).unwrap()
        ); // 0x77359400 -> 2000000000
        assert_eq!(user_operation.paymasterAndData.len(), 0); // 0x -> vec![]
    }
}
