use crate::base_structures::recursion_query::RecursionQuery;
use crate::fsm_input_output::commit_variable_length_encodable_item;
use boojum::cs::implementations::proof::Proof;
use boojum::cs::implementations::prover::ProofConfig;

use crate::base_structures::recursion_query::RecursionQueue;
use boojum::gadgets::recursion::allocated_proof::AllocatedProof;
use boojum::gadgets::recursion::allocated_vk::AllocatedVerificationKey;
use boojum::gadgets::recursion::recursive_transcript::RecursiveTranscript;
use boojum::gadgets::recursion::recursive_tree_hasher::RecursiveTreeHasher;
use boojum::gadgets::traits::witnessable::WitnessHookable;

use std::collections::VecDeque;

use crate::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::cs::{gates::*, traits::cs::ConstraintSystem};
use boojum::field::SmallField;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;
use boojum::gadgets::{
    boolean::Boolean,
    num::Num,
    queue::*,
    traits::{allocatable::CSAllocatable, allocatable::CSAllocatableExt, selectable::Selectable},
};

use boojum::config::*;
use boojum::gadgets::u32::UInt32;

use super::*;

pub mod input;

use self::input::*;

use boojum::cs::implementations::verifier::VerificationKeyCircuitGeometry;
use boojum::cs::oracle::TreeHasher;
use boojum::field::FieldExtension;
use boojum::gadgets::recursion::circuit_pow::RecursivePoWRunner;
use boojum::gadgets::recursion::recursive_transcript::CircuitTranscript;
use boojum::gadgets::recursion::recursive_tree_hasher::CircuitTreeHasher;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug(bound = ""))]
#[serde(bound = "H::Output: serde::Serialize + serde::de::DeserializeOwned")]
pub struct NodeLayerRecursionConfig<
    F: SmallField,
    H: TreeHasher<F>,
    EXT: FieldExtension<2, BaseField = F>,
> {
    pub proof_config: ProofConfig,
    pub vk_fixed_parameters: VerificationKeyCircuitGeometry,
    pub leaf_layer_capacity: usize,
    pub node_layer_capacity: usize,
    pub _marker: std::marker::PhantomData<(F, H, EXT)>,
}

use boojum::cs::traits::circuit::*;

// NOTE: does NOT allocate public inputs! we will deal with locations of public inputs being the same at the "outer" stage
pub fn node_layer_recursion_entry_point<
    F: SmallField,
    CS: ConstraintSystem<F> + 'static,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
    H: RecursiveTreeHasher<F, Num<F>>,
    EXT: FieldExtension<2, BaseField = F>,
    TR: RecursiveTranscript<
        F,
        CompatibleCap = <H::NonCircuitSimulator as TreeHasher<F>>::Output,
        CircuitReflection = CTR,
    >,
    CTR: CircuitTranscript<
        F,
        CircuitCompatibleCap = <H as CircuitTreeHasher<F, Num<F>>>::CircuitOutput,
        TransciptParameters = TR::TransciptParameters,
    >,
    POW: RecursivePoWRunner<F>,
>(
    cs: &mut CS,
    witness: RecursionNodeInstanceWitness<F, H, EXT>,
    round_function: &R,
    config: NodeLayerRecursionConfig<F, H::NonCircuitSimulator, EXT>,
    verifier_builder: Box<dyn ErasedBuilderForRecursiveVerifier<F, EXT, CS>>,
    transcript_params: TR::TransciptParameters,
) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH]
where
    [(); <RecursionQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    let RecursionNodeInstanceWitness {
        input,
        vk_witness,
        split_points,
        proof_witnesses,
    } = witness;

    let input = RecursionNodeInput::allocate(cs, input);
    let RecursionNodeInput {
        branch_circuit_type,
        leaf_layer_parameters,
        node_layer_vk_commitment,
        queue_state,
    } = input;

    assert_eq!(config.vk_fixed_parameters, vk_witness.fixed_parameters,);

    let vk = AllocatedVerificationKey::<F, H>::allocate(cs, vk_witness);
    assert_eq!(
        vk.setup_merkle_tree_cap.len(),
        config.vk_fixed_parameters.cap_size
    );
    let vk_commitment_computed: [_; VK_COMMITMENT_LENGTH] =
        commit_variable_length_encodable_item(cs, &vk, round_function);

    // select over which branch we work
    use crate::recursion::leaf_layer::input::RecursionLeafParameters;
    use boojum::gadgets::traits::allocatable::CSPlaceholder;
    let mut leaf_params = RecursionLeafParameters::placeholder(cs);

    for el in leaf_layer_parameters.iter() {
        let this_type = Num::equals(cs, &branch_circuit_type, &el.circuit_type);
        leaf_params =
            RecursionLeafParameters::conditionally_select(cs, this_type, el, &leaf_params);
    }

    // now we need to try to split the circuit

    let NodeLayerRecursionConfig {
        proof_config,
        vk_fixed_parameters,
        leaf_layer_capacity,
        node_layer_capacity,
        ..
    } = config;

    let max_length_if_leafs = leaf_layer_capacity * node_layer_capacity;
    let max_length_if_leafs = UInt32::allocated_constant(cs, max_length_if_leafs as u32);
    // if queue length is <= max_length_if_leafs then next layer we aggregate leafs, or aggregate nodes otherwise
    let (_, uf) = max_length_if_leafs.overflowing_sub(cs, queue_state.tail.length);
    let next_layer_aggregates_nodes = uf;
    let next_layer_aggregates_leafs = next_layer_aggregates_nodes.negated(cs);

    let mut vk_commitment = leaf_params.leaf_layer_vk_commitment;

    vk_commitment = <[Num<F>; VK_COMMITMENT_LENGTH]>::conditionally_select(
        cs,
        next_layer_aggregates_nodes,
        &node_layer_vk_commitment,
        &vk_commitment,
    );

    // small trick to simplify setup. If we have nothing to verify, we do not care about VK
    // being one that we want
    let is_meaningful = RecursionQueue::<F, R>::from_state(cs, queue_state)
        .is_empty(cs)
        .negated(cs);

    for (a, b) in vk_commitment.iter().zip(vk_commitment_computed.iter()) {
        Num::conditionally_enforce_equal(cs, is_meaningful, a, b);
    }

    // split the original queue into "node_layer_capacity" elements, regardless if next layer
    // down will aggregate leafs or nodes

    let mut proof_witnesses = proof_witnesses;

    // use this and deal with borrow checker

    let r = cs as *mut CS;

    assert_eq!(vk_fixed_parameters.parameters, verifier_builder.geometry());

    let verifier = verifier_builder.create_recursive_verifier(cs);

    drop(cs);

    let cs = unsafe { &mut *r };

    let subqueues = split_queue_state_into_n(cs, queue_state, node_layer_capacity, split_points);

    let leaf_layer_capacity = UInt32::allocated_constant(cs, leaf_layer_capacity as u32);
    for el in subqueues.iter() {
        // if we aggregate leafs, then we ensure length to be small enough.
        // It's not mandatory, but nevertheless

        // check len <= leaf capacity

        let (_, uf) = leaf_layer_capacity.overflowing_sub(cs, el.tail.length);
        uf.conditionally_enforce_false(cs, next_layer_aggregates_leafs);
    }

    assert_eq!(subqueues.len(), node_layer_capacity);

    for subqueue in subqueues.into_iter() {
        let proof_witness = proof_witnesses.pop_front();

        let proof = AllocatedProof::allocate_from_witness(
            cs,
            proof_witness,
            &verifier,
            &vk_fixed_parameters,
            &proof_config,
        );

        let chunk_is_empty = subqueue.tail.length.is_zero(cs);
        let chunk_is_meaningful = chunk_is_empty.negated(cs);

        // verify the proof
        let (is_valid, public_inputs) = verifier.verify::<H, TR, CTR, POW>(
            cs,
            transcript_params.clone(),
            &proof,
            &vk_fixed_parameters,
            &proof_config,
            &vk,
        );

        is_valid.conditionally_enforce_true(cs, chunk_is_meaningful);

        // if it's a meaningful proof we should also check that it indeed proofs a subqueue

        let next_layer_input_if_node = RecursionNodeInput {
            branch_circuit_type: branch_circuit_type,
            leaf_layer_parameters: leaf_layer_parameters,
            node_layer_vk_commitment: node_layer_vk_commitment,
            queue_state: subqueue,
        };
        let input_commitment_if_node: [_; INPUT_OUTPUT_COMMITMENT_LENGTH] =
            commit_variable_length_encodable_item(cs, &next_layer_input_if_node, round_function);

        use crate::recursion::leaf_layer::input::RecursionLeafInput;
        let next_layer_input_if_leaf = RecursionLeafInput {
            params: leaf_params,
            queue_state: subqueue,
        };
        let input_commitment_if_leaf: [_; INPUT_OUTPUT_COMMITMENT_LENGTH] =
            commit_variable_length_encodable_item(cs, &next_layer_input_if_leaf, round_function);

        let input_commitment = <[Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH]>::conditionally_select(
            cs,
            next_layer_aggregates_nodes,
            &input_commitment_if_node,
            &input_commitment_if_leaf,
        );

        assert_eq!(public_inputs.len(), INPUT_OUTPUT_COMMITMENT_LENGTH);
        for (a, b) in input_commitment.iter().zip(public_inputs.into_iter()) {
            Num::conditionally_enforce_equal(cs, chunk_is_meaningful, a, &b);
        }
    }

    let input_commitment: [_; INPUT_OUTPUT_COMMITMENT_LENGTH] =
        commit_variable_length_encodable_item(cs, &input, round_function);
    // for el in input_commitment.iter() {
    //     let gate = PublicInputGate::new(el.get_variable());
    //     gate.add_to_cs(cs);
    // }

    input_commitment
}

pub(crate) fn split_queue_state_into_n<F: SmallField, CS: ConstraintSystem<F>, const N: usize>(
    cs: &mut CS,
    queue_state: QueueState<F, N>,
    split_into: usize,
    mut split_point_witnesses: VecDeque<QueueTailStateWitness<F, N>>,
) -> Vec<QueueState<F, N>> {
    assert!(split_into <= u32::MAX as usize);
    assert!(split_into >= 2);
    if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
        assert_eq!(split_point_witnesses.len() + 1, split_into);
    }

    // our logic is that external caller provides splitting witness, and
    // we just need to ensure that total length matches, and glue intermediate points.

    // We also ensure consistency of split points

    let mut total_len = UInt32::zero(cs);

    let mut current_head = queue_state.head;
    let mut result = Vec::with_capacity(split_into);

    for _ in 0..(split_into - 1) {
        let witness = split_point_witnesses
            .pop_front()
            .unwrap_or(QueueTailState::placeholder_witness());
        let current_tail = QueueTailState::allocate(cs, witness);
        let first = QueueState {
            head: current_head,
            tail: current_tail,
        };

        current_head = current_tail.tail;
        // add length
        total_len = total_len.add_no_overflow(cs, current_tail.length);
        // ensure consistency
        first.enforce_consistency(cs);

        result.push(first);
    }
    // push the last one
    let last_len = queue_state.tail.length.sub_no_overflow(cs, total_len);
    let last = QueueState {
        head: current_head,
        tail: QueueTailState {
            tail: queue_state.tail.tail,
            length: last_len,
        },
    };
    last.enforce_consistency(cs);
    result.push(last);

    assert_eq!(result.len(), split_into);

    result
}
