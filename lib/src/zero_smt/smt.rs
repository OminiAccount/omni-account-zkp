use alloy::hex;
use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// We follow sparse merkle tree implementation here:
// https://medium.com/@carterfeldman/a-hackers-guide-to-layer-2-zero-merkle-trees-from-scratch-d612ea846016

// hex string for every smt node, length 64
// TODO: consider using Bytes32 later
pub type MerkleNodeValue = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub root: MerkleNodeValue,
    pub siblings: Vec<MerkleNodeValue>,
    pub index: usize,
    pub value: MerkleNodeValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaMerkleProof {
    pub index: usize,
    pub siblings: Vec<MerkleNodeValue>,
    pub old_root: MerkleNodeValue,
    pub old_value: MerkleNodeValue,
    pub new_root: MerkleNodeValue,
    pub new_value: MerkleNodeValue,
}

fn hash(left_node: &MerkleNodeValue, right_node: &MerkleNodeValue) -> MerkleNodeValue {
    let mut hasher = Sha256::new();
    hasher.update(hex::decode(left_node).unwrap());
    hasher.update(hex::decode(right_node).unwrap());
    hex::encode(hasher.finalize())
}

// at z0, we store the raw data 0..0, which is a hex string for u256
// z1 = hash(z0, z0); z2 = hash(z1, z1) ... z(height) = z(root)
// zi = TreeHeight - level
// level = height, z0; level = 0, root
fn compute_zero_hashes(height: usize) -> Vec<MerkleNodeValue> {
    // z0
    let mut current_zero_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let mut zero_hashes = vec![current_zero_hash.clone()];
    // z1 .. z_height
    for _ in 1..=height {
        current_zero_hash = hash(&current_zero_hash, &current_zero_hash);
        zero_hashes.push(current_zero_hash.clone());
    }
    // length = 1 + height
    zero_hashes
}

// Database of SMT, store all the non-zero nodes and zi nodes
// we just use level_index as the searching key in the database
struct NodeStore {
    nodes: HashMap<String, MerkleNodeValue>,
    height: usize,
    zero_hashes: Vec<MerkleNodeValue>,
}

impl NodeStore {
    fn new(height: usize) -> Self {
        Self {
            nodes: HashMap::new(),
            height,
            zero_hashes: compute_zero_hashes(height),
        }
    }

    fn contains(&self, level: usize, index: usize) -> bool {
        self.nodes.contains_key(&format!("{}_{}", level, index))
    }

    fn set(&mut self, level: usize, index: usize, value: MerkleNodeValue) {
        self.nodes.insert(format!("{}_{}", level, index), value);
    }

    fn get(&self, level: usize, index: usize) -> MerkleNodeValue {
        if self.contains(level, index) {
            self.nodes
                .get(&format!("{}_{}", level, index))
                .unwrap()
                .clone()
        } else {
            self.zero_hashes[self.height - level].clone()
        }
    }
}

pub struct ZeroMerkleTree {
    height: usize,
    node_store: NodeStore,
}

impl ZeroMerkleTree {
    pub fn new(height: usize) -> Self {
        Self {
            height,
            node_store: NodeStore::new(height),
        }
    }

    // TODO: index should be U256
    pub fn set_leaf(&mut self, index: usize, value: MerkleNodeValue) -> DeltaMerkleProof {
        let old_root = self.node_store.get(0, 0);
        let old_value = self.node_store.get(self.height, index);

        let mut siblings = vec![];

        let mut current_index = index;
        let mut current_value = value.clone();

        for level in (1..=self.height).rev() {
            self.node_store
                .set(level, current_index, current_value.clone());

            if current_index % 2 == 0 {
                let right_sibling = self.node_store.get(level, current_index + 1);
                current_value = hash(&current_value, &right_sibling);
                siblings.push(right_sibling);
            } else {
                let left_sibling = self.node_store.get(level, current_index - 1);
                current_value = hash(&left_sibling, &current_value);
                siblings.push(left_sibling);
            }

            current_index /= 2;
        }

        self.node_store.set(0, 0, current_value.clone());

        DeltaMerkleProof {
            index,
            siblings,
            old_root,
            old_value,
            new_value: value,
            new_root: current_value,
        }
    }

    pub fn get_leaf(&self, index: usize) -> MerkleProof {
        let mut siblings = vec![];

        let value = self.node_store.get(self.height, index);

        let mut current_index = index;
        let mut current_value = value.clone();

        for level in (1..=self.height).rev() {
            if current_index % 2 == 0 {
                let right_sibling = self.node_store.get(level, current_index + 1);
                current_value = hash(&current_value, &right_sibling);
                siblings.push(right_sibling);
            } else {
                let left_sibling = self.node_store.get(level, current_index - 1);
                current_value = hash(&left_sibling, &current_value);
                siblings.push(left_sibling);
            }

            current_index /= 2;
        }

        let root = current_value;

        MerkleProof {
            root,
            siblings,
            index,
            value,
        }
    }

    pub fn get_root(&self) -> MerkleNodeValue {
        self.node_store.get(0, 0)
    }
}

pub fn compute_merkle_root_from_proof(
    siblings: Vec<MerkleNodeValue>,
    index: usize,
    value: MerkleNodeValue,
) -> MerkleNodeValue {
    let mut merkle_path_node_value = value;
    let mut merkle_path_node_index = index;

    for sibling in siblings {
        if merkle_path_node_index % 2 == 0 {
            merkle_path_node_value = hash(&merkle_path_node_value, &sibling);
        } else {
            merkle_path_node_value = hash(&sibling, &merkle_path_node_value);
        }

        merkle_path_node_index /= 2;
    }
    merkle_path_node_value
}

pub fn verify_merkle_proof(proof: MerkleProof) -> bool {
    proof.root == compute_merkle_root_from_proof(proof.siblings, proof.index, proof.value)
}

// Note that the old merkle proof share the same siblings with the new one
// That's why we can ganrantee the status transition is correct
pub fn verify_delta_merkle_proof(delta_merkle_proof: DeltaMerkleProof) -> bool {
    let old_proof = MerkleProof {
        siblings: delta_merkle_proof.siblings.clone(),
        index: delta_merkle_proof.index,
        root: delta_merkle_proof.old_root,
        value: delta_merkle_proof.old_value,
    };

    let new_proof = MerkleProof {
        siblings: delta_merkle_proof.siblings.clone(),
        index: delta_merkle_proof.index,
        root: delta_merkle_proof.new_root,
        value: delta_merkle_proof.new_value,
    };

    verify_merkle_proof(old_proof) && verify_merkle_proof(new_proof)
}

#[cfg(test)]
mod tests {

    use serde_json::to_string_pretty;

    use super::*;

    #[test]
    fn example1() {
        let zero_hashes = compute_zero_hashes(32);
        let formatted_output = to_string_pretty(&zero_hashes).unwrap();
        println!(
            "[example1] the first 32 zero hashes are: {}",
            formatted_output
        );
    }

    // example2 root should be 7e286a6721a66675ea033a4dcdec5abbdc7d3c81580e2d6ded7433ed113b7737
    #[test]
    fn example2() {
        let leaves_to_set = [
            "0000000000000000000000000000000000000000000000000000000000000001", // 1
            "0000000000000000000000000000000000000000000000000000000000000003", // 3
            "0000000000000000000000000000000000000000000000000000000000000003", // 3
            "0000000000000000000000000000000000000000000000000000000000000007", // 7
            "0000000000000000000000000000000000000000000000000000000000000004", // 4
            "0000000000000000000000000000000000000000000000000000000000000002", // 2
            "0000000000000000000000000000000000000000000000000000000000000000", // 0
            "0000000000000000000000000000000000000000000000000000000000000006", // 6
        ];
        let mut tree = ZeroMerkleTree::new(3);
        for (index, leaf) in leaves_to_set.iter().enumerate() {
            tree.set_leaf(index, leaf.to_string());
        }
        println!("[example2] the root is: {}", tree.get_root());
    }

    // Note: at index 6, we insert 0. This will not change the smt root.
    // test delta proof verification and ensure the continuity of the state transition
    #[test]
    fn example3() {
        let leaves_to_set = [
            "0000000000000000000000000000000000000000000000000000000000000001", // 1
            "0000000000000000000000000000000000000000000000000000000000000003", // 3
            "0000000000000000000000000000000000000000000000000000000000000003", // 3
            "0000000000000000000000000000000000000000000000000000000000000007", // 7
            "0000000000000000000000000000000000000000000000000000000000000004", // 4
            "0000000000000000000000000000000000000000000000000000000000000002", // 2
            "0000000000000000000000000000000000000000000000000000000000000000", // 0
            "0000000000000000000000000000000000000000000000000000000000000006", // 6
        ];

        let mut tree = ZeroMerkleTree::new(3);

        let delta_merkle_proofs: Vec<DeltaMerkleProof> = leaves_to_set
            .iter()
            .enumerate()
            .map(|(index, leaf)| tree.set_leaf(index, leaf.to_string()))
            .collect();

        for (i, delta_proof) in delta_merkle_proofs.iter().enumerate() {
            if !verify_delta_merkle_proof(delta_proof.clone()) {
                eprintln!(
                    "[example5] ERROR: delta merkle proof for index {} is INVALID",
                    delta_proof.index
                );
                panic!("invalid delta merkle proof");
            } else if i > 0 && delta_proof.old_root != delta_merkle_proofs[i - 1].new_root {
                eprintln!(
                    "[example5] ERROR: delta merkle proof for index {} has a different old root than the previous delta merkle proof's new root",
                    delta_proof.index
                );
                panic!("delta merkle proof root sequence mismatch");
            } else {
                println!(
                    "[example5] delta merkle proof for index {} is valid",
                    delta_proof.index
                );
            }
        }

        for (i, leaf) in leaves_to_set.iter().enumerate() {
            let proof = tree.get_leaf(i);
            if !verify_merkle_proof(proof.clone()) {
                eprintln!(
                    "[example5] ERROR: merkle proof for index {} is INVALID",
                    proof.index
                );
                panic!("invalid merkle proof");
            } else if proof.value != *leaf {
                eprintln!(
                    "[example5] ERROR: merkle proof for index {} has the wrong value",
                    proof.index
                );
                panic!("merkle proof value mismatch");
            } else {
                println!("[example5] merkle proof for index {} is valid", proof.index);
            }
            println!(
                "merkle proof for index {}: {}",
                proof.index,
                serde_json::to_string_pretty(&proof).unwrap()
            );
        }
    }

    // arbitrary insert at two point
    #[test]
    fn example4() {
        let mut tree = ZeroMerkleTree::new(50);
        let delta_a = tree.set_leaf(
            999_999_999_999,
            "0000000000000000000000000000000000000000000000000000000000000008".to_string(),
        );
        let delta_b = tree.set_leaf(
            1337,
            "0000000000000000000000000000000000000000000000000000000000000007".to_string(),
        );

        let proof_a = tree.get_leaf(999_999_999_999);
        let proof_b = tree.get_leaf(1337);

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
    }
}
