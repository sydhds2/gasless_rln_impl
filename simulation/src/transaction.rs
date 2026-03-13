use ark_bn254::Bn254;
use ark_groth16::Proof;
use rln::protocol::RLNProofValues;
use rln_proof::RlnProof;

pub const DEFAULT_CHAIN_ID: u64 = 1;

#[derive(Debug, Clone)]
#[derive(Eq, Hash, PartialEq)]
pub struct Address(pub String);

#[derive(Debug, Clone)]
pub(crate) struct Transaction {
    pub sender: Address,
    pub chain_id: u64, // usually U256
    pub transaction_hash: Vec<u8>,
    pub rln_proof: RlnProof,
}
