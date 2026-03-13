use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Context;
use ark_bn254::Bn254;
use ark_groth16::Proof;
use ark_serialize::CanonicalDeserialize;
use rln::protocol::{compute_id_secret, deserialize_proof_values};
use rln::utils::IdSecret;
// 3rd party
use tokio::sync::broadcast::Receiver;
use tokio::sync::RwLock;
use tokio::task::spawn_blocking;
use tracing::{debug, error, info};
use rln_proof::RlnProof;
use crate::rln_sc_service::{RlnScCommand, SlashingData};
// internal
use crate::transaction::{Address, Transaction};

pub struct SlasherServiceConfig {
    pub rln_limit: u64,
}

pub struct SlasherService {
    config: SlasherServiceConfig,
    receiver: Receiver<Transaction>,
    db: Arc<RwLock<Db>>,
    current_epoch: Option<u64>,
    rln_sc_channel: tokio::sync::mpsc::UnboundedSender<RlnScCommand>,
}

impl SlasherService {

    pub(crate) fn new(config: SlasherServiceConfig, receiver: Receiver<Transaction>, rln_sc_channel: tokio::sync::mpsc::UnboundedSender<RlnScCommand>) -> Self {
        Self {
            config,
            receiver,
            db: Default::default(),
            current_epoch: None,
            rln_sc_channel,
        }
    }

    pub(crate) async fn serve(&mut self) -> anyhow::Result<()> {

        info!("Starting slasher service...");
        loop {
            let tx = self.receiver.recv().await?;
            debug!("Received tx: {:?}", tx);

            self.process_transaction(tx).await?
        }

        Ok(())
    }

    async fn process_transaction(&mut self, tx: Transaction) -> anyhow::Result<()> {

        let sender_addr = tx.sender;
        let proof = tx.rln_proof;
        let tx_epoch = 0;

        let mut guard = self.db.write().await;

        /*
        self.current_epoch = match self.current_epoch {
            Some(current_epoch) => {
                if current_epoch < proof.epoch {
                    guard.0.clear();
                    debug!("New epoch: {}, resetting db...", proof.epoch);
                    Some(proof.epoch)
                } else if current_epoch == proof.epoch {
                    Some(current_epoch)
                } else {
                    // Decreasing epoch WTF? - aborting...
                    error!(
                        "Slasher current epoch is {} but received new epoch: {}, aborting...",
                        current_epoch, proof.epoch
                    );
                    return Err(ProofProcessError::DecreasingEpoch);
                }
            }
            None => Some(proof.epoch),
        };
        */

        let db_entry = guard.insert_proof(&sender_addr, &proof);

        if db_entry.seen_proof_count >= self.config.rln_limit {
            info!("Detected too many messages for address: {:?}", sender_addr);

            let slashing_data = SlashingData {
                proof_1: db_entry.proof_1.unwrap(),
                proof_2: db_entry.proof_2.unwrap(),
                sender: sender_addr.clone(),
            };

            let rln_sc_channel = self.rln_sc_channel.clone();
            tokio::task::spawn(async move {
                // Don't block tokio runtime
                let id_secret = spawn_blocking(|| recover(slashing_data)).await.expect("spawn");
                if let Err(e) = id_secret {
                    error!("Cannot recover id secret for slashing_data...");
                    return;
                }
                let id_secret = id_secret.unwrap(); // unwrap safe - just checked

                if let Err(e) = rln_sc_channel.send(RlnScCommand::Slash(sender_addr, id_secret)) {
                    error!("Cannot send to rln_sc_channel, {:?}", e);
                }
            });


        }

        drop(guard);
        Ok(())
    }
}


#[derive(Default)]
struct Db(HashMap<Address, DbEntry>);

impl Db {
    fn insert_proof(&mut self, addr: &Address, proof: &RlnProof) -> DbEntry {
        let e = self
            .0
            .entry(addr.clone())
            .and_modify(|db_e| {
                // Note: rln-prover manually tweaks the RLN message id if there is a spam
                //       this allows the slasher to keep only the two last proofs received
                db_e.set_proof(proof);
            })
            .or_insert_with(|| {
                let mut db_e = DbEntry::default();
                db_e.set_proof(proof);
                db_e
            });

        e.clone()
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct DbEntry {
    proof_1: Option<RlnProof>,
    proof_2: Option<RlnProof>,
    seen_proof_count: u64,
}

impl DbEntry {
    fn set_proof(&mut self, proof: &RlnProof) {
        let proof = proof.clone();
        if self.proof_1.is_none() {
            self.proof_1 = Some(proof);
        } else if self.proof_2.is_none() {
            self.proof_2 = Some(proof);
        } else {
            // Both proof_1 & proof_2 has been set - keep oldest (proof_2) and store new proof
            self.proof_1 = self.proof_2.clone();
            self.proof_2 = Some(proof);
        }

        self.seen_proof_count += 1;
    }
}

fn recover(slashing_data: SlashingData) -> anyhow::Result<IdSecret> {
    let proof_1 = slashing_data.proof_1;
    let proof_2 = slashing_data.proof_2;

    let recovered_identity_secret_hash = compute_id_secret(
        (proof_1.proof_values.x, proof_1.proof_values.y),
        (proof_2.proof_values.x, proof_2.proof_values.y),
    )
        .context("Fail to recover identity secret hash")?;

    Ok(recovered_identity_secret_hash)
}
