use blake2b_rs::{Blake2b, Blake2bBuilder};
use sparse_merkle_tree::{
    blake2b::Blake2bHasher, default_store::DefaultStore, error::Error, traits::Value, MerkleProof,
    SparseMerkleTree, H256,
};

use crate::conversions::{addr_hex_to_bytes, hex_to_alloy_address};

#[derive(Clone)]
pub enum AccountData {
    Balance(u128),
    Nonce(u64),
}

impl Value for AccountData {
    fn to_h256(&self) -> H256 {
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();

        match self {
            AccountData::Balance(balance) => {
                hasher.update(&balance.to_le_bytes());
            }
            AccountData::Nonce(nonce) => {
                hasher.update(&nonce.to_le_bytes());
            }
        }

        hasher.finalize(&mut buf);
        buf.into()
    }

    fn zero() -> Self {
        AccountData::Balance(0)
    }
}

impl Default for AccountData {
    fn default() -> Self {
        AccountData::Balance(0)
    }
}

type SMT = SparseMerkleTree<Blake2bHasher, AccountData, DefaultStore<AccountData>>;

fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32).personal(b"SMT").build()
}

fn generate_balance_key(user_address: &[u8; 20]) -> H256 {
    let mut key = [0u8; 32];
    key[..20].copy_from_slice(user_address);
    key.into()
}

fn generate_nonce_key(user_address: &[u8; 20], chain_id: u64) -> H256 {
    let mut key = [0u8; 32];
    key[..20].copy_from_slice(user_address);
    key[20..28].copy_from_slice(&chain_id.to_le_bytes());
    key.into()
}

// fn mock_construct_smt() -> H256 {
//     let mut tree = SMT::default();

//     let user_addr_hex = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

//     let user_address = addr_hex_to_bytes(user_addr_hex);

//     let balance = AccountData::Balance(10000000000);
//     let nonce = AccountData::Nonce(1);
//     let chain_id = 1_u64;

//     let balance_key = generate_balance_key(&user_address);
//     tree.update(balance_key, balance).expect("update balance");

//     let nonce_key = generate_nonce_key(&user_address, chain_id);
//     tree.update(nonce_key, nonce).expect("update nonce");

//     *tree.root()
// }

fn mock_construct_smt() -> (SMT, H256, H256, H256, u64) {
    let mut tree = SMT::default();

    let user_addr_hex = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    let user_address = addr_hex_to_bytes(user_addr_hex);

    let balance = AccountData::Balance(10000000000);
    let nonce = AccountData::Nonce(1);
    let chain_id = 1_u64;

    let balance_key = generate_balance_key(&user_address);
    tree.update(balance_key, balance).expect("update balance");

    let nonce_key = generate_nonce_key(&user_address, chain_id);
    tree.update(nonce_key, nonce).expect("update nonce");

    let root = *tree.root();
    (tree, root, balance_key, nonce_key, chain_id)
}

// fn verify_and_update(
//     old_smt_root: H256,
//     key: Vec<(H256, H256)>,
//     new_value: AccountData,
//     proof: MerkleProof,
// ) -> Result<H256, Error> {
//     let old_value = proof.verify(&old_smt_root, key).unwrap();

//     println!("Verified Old value: {:?}", old_value);

//     let new_root = proof.update(old_smt_root, key, new_value)?;

//     Ok(new_root)
// }

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn test_mock_smt_construct() {
    //     let smt_root = mock_construct_smt();
    //     println!("SMT root is {:?} ", smt_root);
    // }

    #[test]
    fn test_compiled_proof() {
        let (tree, root, balance_key, nonce_key, _chain_id) = mock_construct_smt();

        let proof = tree
            .merkle_proof(vec![balance_key, nonce_key])
            .expect("Failed to generate proof");

        let compiled_proof = proof
            .compile(vec![balance_key, nonce_key])
            .expect("Failed to compile proof");

        let sub_proof = compiled_proof
            .extract_proof::<Blake2bHasher>(vec![
                (balance_key, H256::zero(), true),
                (nonce_key, H256::zero(), false),
            ])
            .expect("Failed to extract sub proof");

        let is_valid = sub_proof
            .verify::<Blake2bHasher>(
                &root,
                vec![(balance_key, AccountData::Balance(10000000000).to_h256())],
            )
            .expect("Failed to verify sub proof");

        assert!(is_valid, "The sub proof for balance_key should be valid");

        let is_full_valid = compiled_proof
            .verify::<Blake2bHasher>(
                &root,
                vec![
                    (balance_key, AccountData::Balance(10000000000).to_h256()),
                    (nonce_key, AccountData::Nonce(1).to_h256()),
                ],
            )
            .expect("Failed to verify full proof");

        assert!(
            is_full_valid,
            "The full proof for both keys should be valid"
        );
    }
}
