use std::collections::{HashMap, HashSet};
use anyhow::anyhow;
use ark_bn254::{Bn254, Fr};
use ark_ff::Zero;
use ark_groth16::Proof;
use rln::poseidon_tree::{MerkleProof, PoseidonTree};
use rln::utils::IdSecret;
use rln::hashers::poseidon_hash;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::{debug, error, info};
use zerokit_utils::{ZerokitMerkleTree};
use rln_proof::RlnProof;
use crate::event::SimulationEvent;
use crate::transaction::Address;

#[derive(Debug)]
pub(crate) struct SlashingData {
    pub(crate) proof_1: RlnProof,
    pub(crate) proof_2: RlnProof,
    pub(crate) sender: Address,
}
#[derive(Debug)]
pub enum RlnScCommand {
    Slash(Address, IdSecret),
}

pub struct RlnScServiceConfig {
    pub rln_limit: u64,
    pub min_token_amount_for_registration: u64,
}

// A Smart contract that can register user
pub struct RLnScService {
    config: RlnScServiceConfig,
    tree: PoseidonTree,
    members: HashMap<Address, (Fr, usize)>,
    token_balances: HashMap<Address, u64>,
    user_count: usize,
    command_channel: UnboundedReceiver<RlnScCommand>,
    event_channel: UnboundedSender<SimulationEvent>,
}

impl RLnScService {

    pub fn new(config: RlnScServiceConfig, tree_depth: usize, channel: UnboundedReceiver<RlnScCommand>, event_channel: UnboundedSender<SimulationEvent>) -> Self {
        Self {
            config,
            tree: PoseidonTree::default(tree_depth).unwrap(), // assume will never unwrap here
            members: HashMap::new(),
            token_balances: Default::default(),
            user_count: 0,
            command_channel: channel,
            event_channel,
        }
    }

    pub fn mint(&mut self, address: Address, amount: u64) {
        self.token_balances.entry(address)
            .and_modify(|balance| *balance = (*balance).saturating_add(amount))
            .or_insert(amount);
    }

    pub fn register_user(&mut self, address: Address, id_co: Fr) -> anyhow::Result<usize> {

        let token_balance = self.token_balances.get(&address).unwrap_or(&0);
        if *token_balance < self.config.min_token_amount_for_registration {
            error!("Cannot register user - not enough token (need {}, has: {})", self.config.min_token_amount_for_registration, token_balance);
            return Err(anyhow!("Not enough tokens to register user"));
        }

        self.tree.set(self.user_count, Fr::from(self.config.rln_limit))?;
        let result = self.user_count;
        self.members.insert(address, (id_co, result));
        self.user_count += 1;
        Ok(result)
    }

    pub fn get_merkle_proof(&self, user_index_in_merkle_tree: usize) -> anyhow::Result<MerkleProof> {
        self.tree.proof(user_index_in_merkle_tree).map_err(anyhow::Error::from)
    }

    pub async fn serve(&mut self) -> anyhow::Result<()> {

        loop {
            let cmd = self.command_channel.recv().await;
            if cmd.is_none() {
                break;
            }
            let cmd = cmd.unwrap();

            debug!("cmd: {:?}", cmd);

            match cmd {
                RlnScCommand::Slash(sender, id_secret) => {

                    let recovered_id_co = poseidon_hash(&[*id_secret]);
                    let e = self.members.get_mut(&sender);
                    match e {
                        Some((id_co, index_in_mt)) => {
                            if *id_co == recovered_id_co {
                                info!("Found user {:?} and matching id commitment", sender);

                                // Cannot register again
                                self.token_balances.remove(&sender);
                                // Merkle tree reset
                                self.tree.set(*index_in_mt, Fr::zero())?;
                                self.event_channel.send(SimulationEvent::Slashed(sender))?;
                            }
                        },
                        None => {
                            error!("User {:?} not found in members", sender);
                        }
                    }
                }
            }
        }

        Ok(())
    }

}



