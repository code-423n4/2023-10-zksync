use super::*;

use boojum::cs::{traits::cs::ConstraintSystem, Variable};
use boojum::field::SmallField;

use boojum::gadgets::u256::UInt256;
use boojum::gadgets::u32::UInt32;
use boojum::gadgets::u8::UInt8;
use boojum::gadgets::{
    boolean::Boolean,
    traits::{
        allocatable::*, encodable::CircuitVarLengthEncodable, selectable::Selectable,
        witnessable::WitnessHookable,
    },
};
use cs_derive::*;

use boojum::serde_utils::BigArraySerde;

use boojum::gadgets::keccak256;

pub const NUM_SHARDS: usize = 2;

// Data that represents a pure state
#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
pub struct PerShardState<F: SmallField> {
    pub enumeration_counter: [UInt32<F>; 2],
    pub state_root: [UInt8<F>; 32],
}

// Data that is something like STF(BlockPassthroughData, BlockMetaParameters) -> (BlockPassthroughData, BlockAuxilaryOutput)
#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
pub struct BlockPassthroughData<F: SmallField> {
    pub per_shard_states: [PerShardState<F>; NUM_SHARDS],
}

// Defining some system parameters that are configurable
#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
pub struct BlockMetaParameters<F: SmallField> {
    pub zkporter_is_available: Boolean<F>,
    pub bootloader_code_hash: UInt256<F>,
    pub default_aa_code_hash: UInt256<F>,
}

// This is the information that represents artifacts only meaningful for this block, that will not be used for any
// next block
#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
pub struct BlockAuxilaryOutput<F: SmallField> {
    pub l1_messages_linear_hash: [UInt8<F>; 32],
    pub rollup_state_diff_for_compression: [UInt8<F>; 32],
    pub bootloader_heap_initial_content: [UInt8<F>; 32],
    pub events_queue_state: [UInt8<F>; 32],
}

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
pub struct BlockHeader<F: SmallField> {
    pub previous_block_content_hash: [UInt8<F>; 32],
    pub new_block_content_hash: [UInt8<F>; 32],
}

// only contains information about this block (or any one block in general),
// without anything about the previous one
#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
pub struct BlockContentHeader<F: SmallField> {
    pub block_data: BlockPassthroughData<F>,
    pub block_meta: BlockMetaParameters<F>,
    pub auxilary_output: BlockAuxilaryOutput<F>,
}

impl<F: SmallField> PerShardState<F> {
    pub fn into_flattened_bytes<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Vec<UInt8<F>> {
        // everything is BE
        let mut result = vec![];
        for el in self.enumeration_counter.iter().rev() {
            let be_bytes = el.to_be_bytes(cs);
            result.extend(be_bytes);
        }
        result.extend_from_slice(&self.state_root);

        result
    }
}

impl<F: SmallField> BlockPassthroughData<F> {
    pub fn into_flattened_bytes<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Vec<UInt8<F>> {
        // everything is BE
        let mut result = vec![];
        for el in self.per_shard_states.iter() {
            let be_bytes = el.into_flattened_bytes(cs);
            result.extend(be_bytes);
        }

        result
    }
}

impl<F: SmallField> BlockMetaParameters<F> {
    pub fn into_flattened_bytes<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Vec<UInt8<F>> {
        // everything is BE
        let mut result = vec![];
        let zk_porter_byte =
            unsafe { UInt8::from_variable_unchecked(self.zkporter_is_available.get_variable()) };
        result.push(zk_porter_byte);

        result.extend_from_slice(&self.bootloader_code_hash.to_be_bytes(cs));
        result.extend_from_slice(&self.default_aa_code_hash.to_be_bytes(cs));

        result
    }
}

impl<F: SmallField> BlockAuxilaryOutput<F> {
    pub fn into_flattened_bytes<CS: ConstraintSystem<F>>(&self, _cs: &mut CS) -> Vec<UInt8<F>> {
        // everything is BE
        let mut result = vec![];
        result.extend_from_slice(&self.l1_messages_linear_hash);
        result.extend_from_slice(&self.rollup_state_diff_for_compression);
        result.extend_from_slice(&self.bootloader_heap_initial_content);
        result.extend_from_slice(&self.events_queue_state);

        result
    }
}

impl<F: SmallField> BlockContentHeader<F> {
    pub fn into_formal_block_hash<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> (
        [UInt8<F>; 32],
        ([UInt8<F>; 32], [UInt8<F>; 32], [UInt8<F>; 32]),
    ) {
        // everything is BE
        let block_data = self.block_data.into_flattened_bytes(cs);
        let block_meta = self.block_meta.into_flattened_bytes(cs);
        let auxilary_output = self.auxilary_output.into_flattened_bytes(cs);

        let block_data_hash = keccak256::keccak256(cs, &block_data);

        let block_meta_hash = keccak256::keccak256(cs, &block_meta);

        let auxilary_output_hash = keccak256::keccak256(cs, &auxilary_output);

        let block_hash = Self::formal_block_hash_from_partial_hashes(
            cs,
            block_data_hash,
            block_meta_hash,
            auxilary_output_hash,
        );

        (
            block_hash,
            (block_data_hash, block_meta_hash, auxilary_output_hash),
        )
    }

    pub fn formal_block_hash_from_partial_hashes<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        block_data_hash: [UInt8<F>; 32],
        block_meta_hash: [UInt8<F>; 32],
        auxilary_output_hash: [UInt8<F>; 32],
    ) -> [UInt8<F>; 32] {
        let mut concatenated = vec![];
        concatenated.extend(block_data_hash);
        concatenated.extend(block_meta_hash);
        concatenated.extend(auxilary_output_hash);

        let block_header_hash = keccak256::keccak256(cs, &concatenated);

        block_header_hash
    }
}
