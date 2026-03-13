use crate::transaction::{Address, Transaction};

#[derive(Debug)]
pub enum SimulationEvent {
    SequencerAddToMempool(Transaction),
    SequencerVerifyError(Transaction),
    Slashed(Address),
}