use crate::ethereum_types::U256;

use crate::base_structures::decommit_query::DecommitQueryWitness;
use crate::base_structures::vm_state::saved_context::ExecutionContextRecordWitness;
use boojum::field::SmallField;

use super::*;

#[derive(Derivative)]
#[derivative(Clone, Debug, Default)]
pub struct MemoryWitness {
    pub value: U256,
    pub is_ptr: bool,
}

use std::sync::{Arc, RwLock};

pub struct SynchronizedWitnessOracle<F: SmallField, W: WitnessOracle<F>> {
    pub inner: Arc<RwLock<W>>,
    pub _marker: std::marker::PhantomData<F>,
}

impl<F: SmallField, W: WitnessOracle<F>> Clone for SynchronizedWitnessOracle<F, W> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F: SmallField, W: WitnessOracle<F>> SynchronizedWitnessOracle<F, W> {
    pub fn new(raw_oracle: W) -> Self {
        Self {
            inner: Arc::new(RwLock::new(raw_oracle)),
            _marker: std::marker::PhantomData,
        }
    }
}

use crate::base_structures::log_query::LogQueryWitness;

use crate::base_structures::memory_query::MemoryQueryWitness;

pub trait WitnessOracle<F: SmallField>:
    'static + Send + Sync + Default + Clone + serde::Serialize + serde::de::DeserializeOwned
{
    fn get_memory_witness_for_read(
        &mut self,
        timestamp: u32,
        memory_page: u32,
        index: u32,
        execute: bool,
    ) -> MemoryWitness;
    fn push_memory_witness(&mut self, memory_query: &MemoryQueryWitness<F>, execute: bool);
    fn get_storage_read_witness(
        &mut self,
        key: &LogQueryWitness<F>,
        needs_witness: bool,
        execute: bool,
    ) -> U256;
    fn get_refunds(&mut self, query: &LogQueryWitness<F>, is_write: bool, execute: bool) -> u32;
    fn push_storage_witness(&mut self, key: &LogQueryWitness<F>, execute: bool);
    fn get_rollback_queue_witness(&mut self, key: &LogQueryWitness<F>, execute: bool) -> [F; 4];
    fn get_rollback_queue_tail_witness_for_call(&mut self, timestamp: u32, execute: bool)
        -> [F; 4];
    fn report_new_callstack_frame(
        &mut self,
        new_record: &ExecutionContextRecordWitness<F>,
        new_depth: u32,
        is_call: bool,
        execute: bool,
    );
    fn push_callstack_witness(
        &mut self,
        current_record: &ExecutionContextRecordWitness<F>,
        current_depth: u32,
        execute: bool,
    );
    fn get_callstack_witness(
        &mut self,
        execute: bool,
        depth: u32,
    ) -> (ExecutionContextRecordWitness<F>, [F; 12]);
    fn get_decommittment_request_suggested_page(
        &mut self,
        request: &DecommitQueryWitness<F>,
        execute: bool,
    ) -> u32;
    fn at_completion(self) {}
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct DummyOracle<F: SmallField> {
    pub _marker: std::marker::PhantomData<F>,
}

impl<F: SmallField> WitnessOracle<F> for DummyOracle<F> {
    fn get_memory_witness_for_read(
        &mut self,
        _timestamp: u32,
        _memory_page: u32,
        _index: u32,
        _execute: bool,
    ) -> MemoryWitness {
        todo!()
    }
    fn push_memory_witness(&mut self, _memory_query: &MemoryQueryWitness<F>, _execute: bool) {
        todo!()
    }
    fn get_storage_read_witness(
        &mut self,
        _key: &LogQueryWitness<F>,
        _needs_witness: bool,
        _execute: bool,
    ) -> U256 {
        todo!()
    }
    fn get_refunds(&mut self, _query: &LogQueryWitness<F>, _is_write: bool, _execute: bool) -> u32 {
        todo!()
    }
    fn push_storage_witness(&mut self, _key: &LogQueryWitness<F>, _execute: bool) {
        todo!()
    }
    fn get_rollback_queue_witness(&mut self, _key: &LogQueryWitness<F>, _execute: bool) -> [F; 4] {
        todo!()
    }
    fn get_rollback_queue_tail_witness_for_call(
        &mut self,
        _timestamp: u32,
        _execute: bool,
    ) -> [F; 4] {
        todo!()
    }
    fn report_new_callstack_frame(
        &mut self,
        _current_record: &ExecutionContextRecordWitness<F>,
        _new_depth: u32,
        _is_call: bool,
        _execute: bool,
    ) {
        todo!()
    }
    fn push_callstack_witness(
        &mut self,
        _current_record: &ExecutionContextRecordWitness<F>,
        _current_depth: u32,
        _execute: bool,
    ) {
        todo!()
    }
    fn get_callstack_witness(
        &mut self,
        _execute: bool,
        _depth: u32,
    ) -> (ExecutionContextRecordWitness<F>, [F; 12]) {
        todo!()
    }
    fn get_decommittment_request_suggested_page(
        &mut self,
        _request: &DecommitQueryWitness<F>,
        _execute: bool,
    ) -> u32 {
        todo!()
    }
    fn at_completion(self) {}
}
