use crate::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;

use crate::fsm_input_output::commit_variable_length_encodable_item;

use crate::base_structures::vm_state::*;
use crate::fsm_input_output::*;
use crate::linear_hasher::input::LinearHasherInputData;
use boojum::gadgets::u32::UInt32;

use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::field::SmallField;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;
use boojum::gadgets::{boolean::Boolean, num::Num, queue::*, traits::selectable::Selectable};

use crate::base_structures::precompile_input_outputs::*;
use crate::log_sorter::input::*;
use crate::storage_application::input::*;
use boojum::gadgets::u8::UInt8;

use super::*;

pub const NUM_CIRCUIT_TYPES_TO_SCHEDULE: usize = crate::recursion::NUM_BASE_LAYER_CIRCUITS;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum BaseLayerCircuitType {
    None = 0,
    VM = 1,
    DecommitmentsFilter = 2,
    Decommiter = 3,
    LogDemultiplexer = 4,
    KeccakPrecompile = 5,
    Sha256Precompile = 6,
    EcrecoverPrecompile = 7,
    RamValidation = 8,
    StorageFilter = 9,
    StorageApplicator = 10,
    EventsRevertsFilter = 11,
    L1MessagesRevertsFilter = 12,
    L1MessagesHasher = 13,
}

impl BaseLayerCircuitType {
    pub fn from_numeric_value(value: u8) -> Self {
        match value {
            a if a == Self::VM as u8 => Self::VM,
            a if a == Self::DecommitmentsFilter as u8 => Self::DecommitmentsFilter,
            a if a == Self::Decommiter as u8 => Self::Decommiter,
            a if a == Self::LogDemultiplexer as u8 => Self::LogDemultiplexer,
            a if a == Self::KeccakPrecompile as u8 => Self::KeccakPrecompile,
            a if a == Self::Sha256Precompile as u8 => Self::Sha256Precompile,
            a if a == Self::EcrecoverPrecompile as u8 => Self::EcrecoverPrecompile,
            a if a == Self::RamValidation as u8 => Self::RamValidation,
            a if a == Self::StorageFilter as u8 => Self::StorageFilter,
            a if a == Self::StorageApplicator as u8 => Self::StorageApplicator,
            a if a == Self::EventsRevertsFilter as u8 => Self::EventsRevertsFilter,
            a if a == Self::L1MessagesRevertsFilter as u8 => Self::L1MessagesRevertsFilter,
            a if a == Self::L1MessagesHasher as u8 => Self::L1MessagesHasher,
            _ => {
                panic!("unknown circuit type {}", value)
            }
        }
    }
}

#[track_caller]
pub(crate) fn compute_precompile_commitment<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    precompile_queue_state: &QueueState<F, QUEUE_STATE_WIDTH>,
    mem_queue_state_before: &QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    mem_queue_state_after: &QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    round_function: &R,
) -> (
    [Num<F>; CLOSED_FORM_COMMITTMENT_LENGTH],
    [Num<F>; CLOSED_FORM_COMMITTMENT_LENGTH],
) {
    let input_data = PrecompileFunctionInputData {
        initial_log_queue_state: precompile_queue_state.clone(),
        initial_memory_queue_state: mem_queue_state_before.clone(),
    };
    let input_data_commitment =
        commit_variable_length_encodable_item(cs, &input_data, round_function);

    let output_data = PrecompileFunctionOutputData {
        final_memory_state: mem_queue_state_after.clone(),
    };
    let output_data_commitment =
        commit_variable_length_encodable_item(cs, &output_data, round_function);

    (input_data_commitment, output_data_commitment)
}

#[track_caller]
pub(crate) fn compute_storage_sorter_circuit_commitment<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    shard_id: UInt8<F>,
    queue_state_before: &QueueState<F, QUEUE_STATE_WIDTH>,
    intermediate_queue_state: &QueueTailState<F, QUEUE_STATE_WIDTH>,
    queue_state_after: &QueueState<F, QUEUE_STATE_WIDTH>,
    round_function: &R,
) -> (
    [Num<F>; CLOSED_FORM_COMMITTMENT_LENGTH],
    [Num<F>; CLOSED_FORM_COMMITTMENT_LENGTH],
) {
    // We use here the naming events_deduplicator but the function is applicable for
    // storage deduplicator is well - may be we should make this fact more observable
    let mut full_state = QueueState::empty(cs);
    full_state.tail = *intermediate_queue_state;
    let input_data = StorageDeduplicatorInputData {
        shard_id_to_process: shard_id,
        unsorted_log_queue_state: queue_state_before.clone(),
        intermediate_sorted_queue_state: full_state,
    };
    let input_data_commitment =
        commit_variable_length_encodable_item(cs, &input_data, round_function);

    let output_data = StorageDeduplicatorOutputData {
        final_sorted_queue_state: queue_state_after.clone(),
    };
    let output_data_commitment =
        commit_variable_length_encodable_item(cs, &output_data, round_function);

    (input_data_commitment, output_data_commitment)
}

#[track_caller]
pub(crate) fn compute_filter_circuit_commitment<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    queue_state_before: &QueueState<F, QUEUE_STATE_WIDTH>,
    intermediate_queue_state: &QueueTailState<F, QUEUE_STATE_WIDTH>,
    queue_state_after: &QueueState<F, QUEUE_STATE_WIDTH>,
    round_function: &R,
) -> (
    [Num<F>; CLOSED_FORM_COMMITTMENT_LENGTH],
    [Num<F>; CLOSED_FORM_COMMITTMENT_LENGTH],
) {
    // We use here the naming events_deduplicator but the function is applicable for
    // storage deduplicator is well - may be we should make this fact more observable
    let mut full_state = QueueState::empty(cs);
    full_state.tail = *intermediate_queue_state;
    let input_data = EventsDeduplicatorInputData {
        initial_log_queue_state: queue_state_before.clone(),
        intermediate_sorted_queue_state: full_state,
    };
    let input_data_commitment =
        commit_variable_length_encodable_item(cs, &input_data, round_function);

    let output_data = EventsDeduplicatorOutputData {
        final_queue_state: queue_state_after.clone(),
    };
    let output_data_commitment =
        commit_variable_length_encodable_item(cs, &output_data, round_function);

    (input_data_commitment, output_data_commitment)
}

#[track_caller]
pub(crate) fn compute_storage_applicator_circuit_commitment<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    storage_queue_state: &QueueState<F, QUEUE_STATE_WIDTH>,
    initial_root: &[UInt8<F>; 32],
    initial_enumeration_counter: &[UInt32<F>; 2],
    final_root: &[UInt8<F>; 32],
    final_enumeration_counter: &[UInt32<F>; 2],
    rollup_state_diff_for_compression: &[UInt8<F>; 32],
    shard_id: u8,
    round_function: &R,
) -> (
    [Num<F>; CLOSED_FORM_COMMITTMENT_LENGTH],
    [Num<F>; CLOSED_FORM_COMMITTMENT_LENGTH],
) {
    let shard_id = UInt8::allocated_constant(cs, shard_id);

    let input_data = StorageApplicationInputData {
        initial_next_enumeration_counter: *initial_enumeration_counter,
        shard: shard_id,
        initial_root_hash: *initial_root,
        storage_application_log_state: storage_queue_state.clone(),
    };
    let input_data_commitment =
        commit_variable_length_encodable_item(cs, &input_data, round_function);

    let output_data = StorageApplicationOutputData {
        new_root_hash: *final_root,
        new_next_enumeration_counter: *final_enumeration_counter,
        state_diffs_keccak256_hash: *rollup_state_diff_for_compression,
    };
    let output_data_commitment =
        commit_variable_length_encodable_item(cs, &output_data, round_function);

    (input_data_commitment, output_data_commitment)
}

#[track_caller]
pub(crate) fn compute_hasher_circuit_commitment<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    input_queue_state: &QueueState<F, QUEUE_STATE_WIDTH>,
    pubdata_hash: &[UInt8<F>; 32],
    round_function: &R,
) -> (
    [Num<F>; CLOSED_FORM_COMMITTMENT_LENGTH],
    [Num<F>; CLOSED_FORM_COMMITTMENT_LENGTH],
) {
    let input_data = LinearHasherInputData {
        queue_state: input_queue_state.clone(),
    };
    let input_data_commitment =
        commit_variable_length_encodable_item(cs, &input_data, round_function);

    let output_data = LinearHasherOutputData {
        keccak256_hash: *pubdata_hash,
    };
    let output_data_commitment =
        commit_variable_length_encodable_item(cs, &output_data, round_function);

    (input_data_commitment, output_data_commitment)
}

#[track_caller]
pub(crate) fn conditionally_enforce_circuit_commitment<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    should_validate: Boolean<F>,
    actual_commitment: &[Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH],
    sample_commitment: &[Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH],
) {
    for (a, b) in actual_commitment.iter().zip(sample_commitment.iter()) {
        Num::conditionally_enforce_equal(cs, should_validate, a, b);
    }
}

#[track_caller]
pub(crate) fn conditionally_select_queue_tail<
    F: SmallField,
    CS: ConstraintSystem<F>,
    const N: usize,
>(
    cs: &mut CS,
    flag: Boolean<F>,
    a: &QueueTailState<F, N>,
    b: &QueueTailState<F, N>,
) -> QueueTailState<F, N> {
    let tail = Num::parallel_select(cs, flag, &a.tail, &b.tail);
    let length = UInt32::conditionally_select(cs, flag, &a.length, &b.length);

    QueueTailState { tail, length }
}

pub(crate) fn finalize_queue_state<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4>,
    const N: usize,
    const M: usize,
>(
    cs: &mut CS,
    state: &QueueTailState<F, N>,
    _round_function: &R,
) -> [Num<F>; M] {
    let mut to_absorb = vec![];
    to_absorb.extend(state.tail);
    let one_num = Num::allocated_constant(cs, F::ONE);
    let zero_num = Num::zero(cs);
    // we do rescue prime padding and absorb
    to_absorb.push(one_num);
    let mut multiple = to_absorb.len() / 8;
    if to_absorb.len() % 8 != 0 {
        multiple += 1;
    }
    to_absorb.resize(multiple * 8, zero_num);
    let mut state = [zero_num; 12];
    for chunk in to_absorb.array_chunks::<8>() {
        let els_to_keep = R::split_capacity_elements(&state.map(|el| el.get_variable()))
            .map(|el| Num::from_variable(el));
        state = R::absorb_with_replacement_over_nums(cs, *chunk, els_to_keep);
        state = R::compute_round_function_over_nums(cs, state);
    }

    R::state_into_commitment::<M>(&state.map(|el| el.get_variable()))
        .map(|el| Num::from_variable(el))
}
