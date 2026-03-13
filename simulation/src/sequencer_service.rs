use ark_bn254::{Bn254, Fr};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use rln::circuit::zkey_from_folder;
use rln::protocol::verify_proof;
use tokio::sync::broadcast::Receiver;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, info};
use crate::event::SimulationEvent;
use crate::transaction::Transaction;

pub struct SequencerService {
    receiver: Receiver<Transaction>,
    tx_mempool: Vec<Transaction>,
    proving_key: (ProvingKey<Bn254>, ConstraintMatrices<Fr>),
    event_channel: UnboundedSender<SimulationEvent>,
}

impl SequencerService {

    pub(crate) fn new(receiver: Receiver<Transaction>, event_channel: UnboundedSender<SimulationEvent>) -> Self {

        let (pk, matrices) = zkey_from_folder();

        Self {
            receiver,
            tx_mempool: Vec::new(),
            proving_key: (pk.clone(), matrices.clone()),
            event_channel,
        }
    }

    pub(crate) async fn serve(&mut self) -> anyhow::Result<()> {

        info!("Starting sequencer service...");

        loop {
            let tx = self.receiver.recv().await?;
            debug!("Received tx: {:?}", tx);

            if Self::verify_transaction( &self.proving_key.0.vk, tx.clone()) {
                info!("Verifying transaction OK, adding it to mempool...");
                self.event_channel.send(SimulationEvent::SequencerAddToMempool(tx.clone()));
                self.tx_mempool.push(tx);
            } else {
                info!("Verifying transaction KO, skipping it...");
                self.event_channel.send(SimulationEvent::SequencerVerifyError(tx.clone()));
            }
        }

        Ok(())
    }

    fn verify_transaction( vk: &VerifyingKey<Bn254>, tx: Transaction) -> bool {
        /*
        if let Err(e) = verify_proof(vk, &tx.rln_proof.proof, &tx.rln_proof.proof_values) {
            false
        } else {
            true
        }
        */

        match verify_proof(vk, &tx.rln_proof.proof, &tx.rln_proof.proof_values) {
            Ok(r) => r,
            Err(_) => false,
        }
    }


}