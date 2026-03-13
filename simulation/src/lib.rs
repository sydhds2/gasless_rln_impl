mod transaction;

// services
// mod epoch_service;
mod sequencer_service;
// mod user_service;
mod error;
mod slasher_service;
mod rln_sc_service;
mod event;

use tokio::task::JoinSet;
use tracing::error;
// tests
// use crate::user_service::{UserService, UserServiceConfig};
use crate::sequencer_service::SequencerService;
use crate::slasher_service::{SlasherService, SlasherServiceConfig};

const DEFAULT_MERKLE_TREE_DEPTH: usize = 20;
const DEFAULT_RLN_SPAM_LIMIT: u64 = 10_000;

/*
pub async fn run_simulation() -> anyhow::Result<()> {

    // Simulate a network link from UserService -> SequencerService & SlasherService
    let user_to_sequencer_slasher_channel = tokio::sync::broadcast::channel(100);

    let cfg = UserServiceConfig {
        rln_limit: DEFAULT_RLN_SPAM_LIMIT,
    };
    let mut user_service = UserService::new(cfg, DEFAULT_MERKLE_TREE_DEPTH, user_to_sequencer_slasher_channel.0.clone());
    let mut sequencer_service = SequencerService::new(user_to_sequencer_slasher_channel.0.subscribe());
    let cfg = SlasherServiceConfig {
        rln_limit: DEFAULT_RLN_SPAM_LIMIT,
    };
    let mut slasher_service = SlasherService::new(cfg, user_to_sequencer_slasher_channel.0.subscribe());

    let mut set = JoinSet::new();

    set.spawn(async move {
        sequencer_service.serve().await
    });
    /*
    set.spawn(async move {
        user_service.serve().await
    });
    */
    set.spawn(async move {
        slasher_service.serve().await
    });

    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                error!("Task error: {:#}", e);
                break;
            }
            Err(e) => {
                error!("Join error: {}", e);
                break;
            }
        }
    }

    Ok(())
}
*/

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use ark_bn254::Fr;
    use rln::hashers::hash_to_field_le;
    use rln::poseidon_tree::MerkleProof;
    use rln::protocol::keygen;
    use tracing::{debug, info};
    use tracing_subscriber::EnvFilter;
    use zerokit_utils::ZerokitMerkleProof;
    use rln_proof::{compute_rln_proof_and_values, RlnData, RlnIdentifier, RlnUserIdentity};
    use crate::event::SimulationEvent;
    use crate::rln_sc_service::{RLnScService, RlnScServiceConfig};
    use crate::transaction::{Address, Transaction, DEFAULT_CHAIN_ID};
    use super::*;

    #[tokio::test]
    async fn test_add_to_mempool() -> anyhow::Result<()> {

        // Test with 1 user creating multiple transaction to a point that a block is produced
        setup_test_tracing();

        // Test with 1 user creating multiple transaction to a point that he spam and get slashed

        // Simulate a network link to RLN Smart contract
        let rln_sc_command_channel = tokio::sync::mpsc::unbounded_channel();
        let mut event_channel = tokio::sync::mpsc::unbounded_channel();

        let rln_limit = 10;
        let min_token_amount_for_registration = 10;
        let epoch = Fr::from(0);

        // Rln SC
        let cfg = RlnScServiceConfig { rln_limit, min_token_amount_for_registration };
        let mut rln_sc_service = RLnScService::new(cfg, DEFAULT_MERKLE_TREE_DEPTH, rln_sc_command_channel.1, event_channel.0.clone());

        // User 1 + create tx
        let user_1 = Address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string());
        let user_1_rln_identity = {
            let (id_secret, id_co) = keygen();
            debug!("user_1 id_co: {}", id_co);
            debug!("user_1 id_secret: {:?}", id_secret);
            RlnUserIdentity {
                commitment: id_co,
                secret_hash: id_secret,
                user_limit: Fr::from(rln_limit),
            }
        };
        let tx_1_hash = b"AAA".to_vec();
        let tx_2_hash = b"12345".to_vec();

        rln_sc_service.mint(user_1.clone(), min_token_amount_for_registration * 5);
        let user_1_idx = rln_sc_service.register_user(user_1.clone(), user_1_rln_identity.commitment)?;


        let (tx_1, tx_2) = {
            let mt_proof = rln_sc_service.get_merkle_proof(user_1_idx)?;
            info!("Creating tx_1...");
            let tx_1 = create_transaction(user_1.clone(), tx_1_hash, Fr::from(0), &user_1_rln_identity, epoch, mt_proof.clone())?;
            info!("Creating tx_2...");
            let tx_2 = create_transaction(user_1.clone(), tx_2_hash, Fr::from(1), &user_1_rln_identity, epoch, mt_proof)?;
            (tx_1, tx_2)
        };

        // User 2 + create tx
        let user_2 = Address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string());
        let user_2_rln_identity = {
            let (id_secret, id_co) = keygen();
            debug!("user_2 id_co: {}", id_co);
            debug!("user_2 id_secret: {:?}", id_secret);
            RlnUserIdentity {
                commitment: id_co,
                secret_hash: id_secret,
                user_limit: Fr::from(rln_limit),
            }
        };
        let u2_tx_1_hash = b"aaa".to_vec();
        let u2_tx_2_hash = b"54321".to_vec();

        rln_sc_service.mint(user_2.clone(), min_token_amount_for_registration * 5);
        let user_2_idx = rln_sc_service.register_user(user_2.clone(), user_2_rln_identity.commitment)?;

        let (u2_tx_1, u2_tx_2) = {
            let mt_proof = rln_sc_service.get_merkle_proof(user_1_idx)?;
            info!("Creating tx_1...");
            let tx_1 = create_transaction(user_1.clone(), u2_tx_1_hash, Fr::from(0), &user_2_rln_identity, epoch, mt_proof.clone())?;
            info!("Creating tx_2...");
            let tx_2 = create_transaction(user_1.clone(), u2_tx_2_hash, Fr::from(1), &user_2_rln_identity, epoch, mt_proof)?;
            (tx_1, tx_2)
        };

        // Simulate a network link from User -> SequencerService & SlasherService
        let user_to_sequencer_slasher_channel = tokio::sync::broadcast::channel(100);

        let mut sequencer_service = SequencerService::new(user_to_sequencer_slasher_channel.0.subscribe(), event_channel.0.clone());
        let cfg = SlasherServiceConfig {
            rln_limit,
        };
        let mut slasher_service = SlasherService::new(cfg, user_to_sequencer_slasher_channel.0.subscribe(), rln_sc_command_channel.0);

        let mut set = JoinSet::new();

        set.spawn(async move {
            sequencer_service.serve().await
        });
        set.spawn(async move {
            slasher_service.serve().await
        });
        set.spawn(async move {
            rln_sc_service.serve().await
        });

        info!("Starting simulation...");
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        info!("Sending transactions...");
        user_to_sequencer_slasher_channel.0.send(tx_1)?;
        user_to_sequencer_slasher_channel.0.send(tx_2)?;
        user_to_sequencer_slasher_channel.0.send(u2_tx_1)?;
        user_to_sequencer_slasher_channel.0.send(u2_tx_2)?;

        info!("Waiting for events (or timeout)...");

        let events = collect_events(event_channel.1, 4, tokio::time::Duration::from_secs(10)).await;
        println!("events: {:?}", events);
        assert_eq!(events.len(), 4);

        Ok(())
    }

    #[tokio::test]
    async fn test_slashing() -> anyhow::Result<()> {

        setup_test_tracing();

        // Test with 1 user creating multiple transaction to a point that he spam and get slashed

        // Simulate a network link to RLN Smart contract
        let rln_sc_command_channel = tokio::sync::mpsc::unbounded_channel();
        let mut event_channel = tokio::sync::mpsc::unbounded_channel();

        let rln_limit = 2;
        let min_token_amount_for_registration = 10;

        let user_1 = Address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string());
        let user_1_rln_identity = {
            let (id_secret, id_co) = keygen();
            debug!("user_1 id_co: {}", id_co);
            debug!("user_1 id_secret: {:?}", id_secret);
            RlnUserIdentity {
                commitment: id_co,
                secret_hash: id_secret,
                user_limit: Fr::from(rln_limit),
            }
        };
        let tx_1_hash = b"AAA".to_vec();
        let tx_2_hash = b"12345".to_vec();

        let cfg = RlnScServiceConfig { rln_limit, min_token_amount_for_registration };
        let mut rln_sc_service = RLnScService::new(cfg, DEFAULT_MERKLE_TREE_DEPTH, rln_sc_command_channel.1, event_channel.0.clone());
        rln_sc_service.mint(user_1.clone(), min_token_amount_for_registration * 5);
        let user_1_idx = rln_sc_service.register_user(user_1.clone(), user_1_rln_identity.commitment)?;

        let epoch = Fr::from(0);

        let (tx_1, tx_2) = {
            let mt_proof = rln_sc_service.get_merkle_proof(user_1_idx)?;
            info!("Creating tx_1...");
            let tx_1 = create_transaction(user_1.clone(), tx_1_hash, Fr::from(0), &user_1_rln_identity, epoch, mt_proof.clone())?;
            info!("Creating tx_2...");
            let tx_2 = create_transaction(user_1.clone(), tx_2_hash, Fr::from(0), &user_1_rln_identity, epoch, mt_proof)?;
            (tx_1, tx_2)
        };

        // Simulate a network link from User -> SequencerService & SlasherService
        let user_to_sequencer_slasher_channel = tokio::sync::broadcast::channel(100);

        let mut sequencer_service = SequencerService::new(user_to_sequencer_slasher_channel.0.subscribe(), event_channel.0.clone());
        let cfg = SlasherServiceConfig {
            rln_limit,
        };
        let mut slasher_service = SlasherService::new(cfg, user_to_sequencer_slasher_channel.0.subscribe(), rln_sc_command_channel.0);

        let mut set = JoinSet::new();

        set.spawn(async move {
            sequencer_service.serve().await
        });
        set.spawn(async move {
            slasher_service.serve().await
        });
        set.spawn(async move {
            rln_sc_service.serve().await
        });

        info!("Starting simulation...");
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        info!("Sending transactions...");
        user_to_sequencer_slasher_channel.0.send(tx_1)?;
        user_to_sequencer_slasher_channel.0.send(tx_2)?;

        info!("Waiting for events (or timeout)...");

        let mut events = collect_events(event_channel.1, 3, tokio::time::Duration::from_secs(10)).await;

        // println!("events: {:?}", events);
        let event_2 = &events[2];
        match event_2 {
            SimulationEvent::Slashed(address) => { assert_eq!(*address, user_1); },
            _ => panic!("Unexpected simulation event received: {:?}", event_2),
        }


        /*
        let event = tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            event_channel.1.recv()
        ).await?;

        let event = event.ok_or(anyhow!("Cannot receive simulation event"))?;

        match event {
            SimulationEvent::Slashed(address) => { assert_eq!(address, user_1); },
            _ => panic!("Unexpected simulation event received: {event:?}"),
        }
        */

        Ok(())
    }

    fn create_transaction(sender: Address, tx_hash: Vec<u8>, message_id: Fr, rln_user_id: &RlnUserIdentity, epoch: Fr, merkle_proof: MerkleProof) -> anyhow::Result<Transaction> {

        let rln_identifier = RlnIdentifier::new("test-rln-identifier".as_bytes());

        let rln_data = RlnData {
            message_id,
            data: hash_to_field_le(tx_hash.as_slice()),
        };

        let rln_proof = compute_rln_proof_and_values(
            rln_user_id,
            &rln_identifier,
            rln_data,
            epoch,
            merkle_proof.get_path_elements(),
            merkle_proof.get_path_index(),
        ).map_err(anyhow::Error::from)?;

        let tx = Transaction {
            sender,
            chain_id: DEFAULT_CHAIN_ID,
            transaction_hash: tx_hash,
            rln_proof,
        };
        Ok(tx)
    }

    fn setup_test_tracing() {
        // Note: tracing-test crate is another dev dependency and only listen to main thread
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(EnvFilter::from_default_env())
            // ignore error if another // unit test already init. it
            .try_init();
    }

    pub async fn collect_events(
        mut rx: tokio::sync::mpsc::UnboundedReceiver<SimulationEvent>,
        max_events: usize,
        timeout_duration: tokio::time::Duration,
    ) -> Vec<SimulationEvent> {

        let mut events = Vec::with_capacity(max_events);
        let timeout = tokio::time::sleep(timeout_duration);
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                _ = &mut timeout => {
                    // The timer finishes
                    break;
                }

                msg = rx.recv() => {
                    match msg {
                        Some(event) => {
                            events.push(event);
                            if events.len() >= max_events {
                                break; // Target count reached
                            }
                        }
                        None => {
                            break; // All senders dropped, channel closed
                        }
                    }
                }
            }
        }

        events
    }

}