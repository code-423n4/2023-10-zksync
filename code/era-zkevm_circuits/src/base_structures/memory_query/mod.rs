use super::*;

use boojum::field::SmallField;

use boojum::gadgets::queue::full_state_queue::FullStateCircuitQueue;
use boojum::gadgets::u256::UInt256;

use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::u32::UInt32;

use crate::ethereum_types::U256;
use boojum::config::*;
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::cs::traits::cs::DstBuffer;
use boojum::cs::Place;
use boojum::cs::Variable;
use boojum::gadgets::num::Num;
use boojum::gadgets::traits::allocatable::{CSAllocatable, CSAllocatableExt};
use boojum::gadgets::traits::castable::WitnessCastable;
use boojum::gadgets::traits::encodable::{CircuitEncodable, CircuitEncodableExt};
use boojum::gadgets::traits::selectable::Selectable;

use boojum::gadgets::traits::witnessable::WitnessHookable;
use cs_derive::*;

pub const MEMORY_QUERY_PACKED_WIDTH: usize = 8;

#[derive(Derivative, CSSelectable, CSAllocatable, WitnessHookable)]
#[derivative(Clone, Copy, Debug, Hash)]
pub struct MemoryQuery<F: SmallField> {
    pub timestamp: UInt32<F>,
    pub memory_page: UInt32<F>,
    pub index: UInt32<F>,
    pub rw_flag: Boolean<F>,
    pub is_ptr: Boolean<F>,
    pub value: UInt256<F>,
}

impl<F: SmallField> CircuitEncodableExt<F, MEMORY_QUERY_PACKED_WIDTH> for MemoryQuery<F> {}

// in practice we use memory queue, so we need to have a nice way to pack memory query into
// 8 field elements. In addition we can exploit the fact that when we will process the elements
// we will only need to exploit timestamp, page, index, value and r/w flag in their types, but
// actual value can be packed more tightly into full field elements as it will only be compared,
// without access to it's bitwidth

pub const MEMORY_QUERY_UNROLLED_WIDTH: usize = 13;

impl<F: SmallField> CSAllocatableExt<F> for MemoryQuery<F> {
    const INTERNAL_STRUCT_LEN: usize = MEMORY_QUERY_UNROLLED_WIDTH;

    fn flatten_as_variables(&self) -> [Variable; Self::INTERNAL_STRUCT_LEN] {
        [
            self.timestamp.get_variable(),
            self.memory_page.get_variable(),
            self.index.get_variable(),
            self.rw_flag.get_variable(),
            self.is_ptr.get_variable(),
            self.value.inner[0].get_variable(),
            self.value.inner[1].get_variable(),
            self.value.inner[2].get_variable(),
            self.value.inner[3].get_variable(),
            self.value.inner[4].get_variable(),
            self.value.inner[5].get_variable(),
            self.value.inner[6].get_variable(),
            self.value.inner[7].get_variable(),
        ]
    }

    fn set_internal_variables_values(witness: Self::Witness, dst: &mut DstBuffer<'_, '_, F>) {
        // NOTE: must be same sequence as in `flatten_as_variables`
        UInt32::set_internal_variables_values(witness.timestamp, dst);
        UInt32::set_internal_variables_values(witness.memory_page, dst);
        UInt32::set_internal_variables_values(witness.index, dst);
        Boolean::set_internal_variables_values(witness.rw_flag, dst);
        Boolean::set_internal_variables_values(witness.is_ptr, dst);
        UInt256::set_internal_variables_values(witness.value, dst);
    }

    fn witness_from_set_of_values(values: [F; Self::INTERNAL_STRUCT_LEN]) -> Self::Witness {
        let timestamp: u32 = WitnessCastable::cast_from_source(values[0]);
        let memory_page: u32 = WitnessCastable::cast_from_source(values[1]);
        let index: u32 = WitnessCastable::cast_from_source(values[2]);
        let rw_flag: bool = WitnessCastable::cast_from_source(values[3]);
        let is_ptr: bool = WitnessCastable::cast_from_source(values[4]);

        let value: U256 = WitnessCastable::cast_from_source([
            values[5], values[6], values[7], values[8], values[9], values[10], values[11],
            values[12],
        ]);

        Self::Witness {
            timestamp,
            memory_page,
            index,
            rw_flag,
            is_ptr,
            value,
        }
    }
}

impl<F: SmallField> CircuitEncodable<F, MEMORY_QUERY_PACKED_WIDTH> for MemoryQuery<F> {
    fn encode<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
    ) -> [Variable; MEMORY_QUERY_PACKED_WIDTH] {
        // we assume the fact that capacity of F is quite close to 64 bits
        debug_assert!(F::CAPACITY_BITS >= 56);

        // strategy: we use 3 field elements to pack timestamp, decomposition of page, index and r/w flag,
        // and 5 more elements to tightly pack 8xu32 of values

        let v0 = self.timestamp.get_variable();
        let v1 = self.memory_page.get_variable();
        let v2 = Num::linear_combination(
            cs,
            &[
                (self.index.get_variable(), F::ONE),
                (
                    self.rw_flag.get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    self.is_ptr.get_variable(),
                    F::from_u64_unchecked(1u64 << 33),
                ),
            ],
        )
        .get_variable();

        // value. Those in most of the cases will be nops
        let decomposition_5 = self.value.inner[5].decompose_into_bytes(cs);
        let decomposition_6 = self.value.inner[6].decompose_into_bytes(cs);
        let decomposition_7 = self.value.inner[7].decompose_into_bytes(cs);

        let v3 = Num::linear_combination(
            cs,
            &[
                (self.value.inner[0].get_variable(), F::ONE),
                (
                    decomposition_5[0].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    decomposition_5[1].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    decomposition_5[2].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v4 = Num::linear_combination(
            cs,
            &[
                (self.value.inner[1].get_variable(), F::ONE),
                (
                    decomposition_5[3].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    decomposition_6[0].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    decomposition_6[1].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v5 = Num::linear_combination(
            cs,
            &[
                (self.value.inner[2].get_variable(), F::ONE),
                (
                    decomposition_6[2].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    decomposition_6[3].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    decomposition_7[0].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v6 = Num::linear_combination(
            cs,
            &[
                (self.value.inner[3].get_variable(), F::ONE),
                (
                    decomposition_7[1].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    decomposition_7[2].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    decomposition_7[3].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v7 = self.value.inner[4].get_variable();

        [v0, v1, v2, v3, v4, v5, v6, v7]
    }
}

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug, Hash)]
pub struct MemoryValue<F: SmallField> {
    pub is_ptr: Boolean<F>,
    pub value: UInt256<F>,
}

use crate::main_vm::witness_oracle::MemoryWitness;
use boojum::gadgets::u256::decompose_u256_as_u32x8;

impl<F: SmallField> MemoryValue<F> {
    pub fn allocate_from_closure_and_dependencies<
        CS: ConstraintSystem<F>,
        FN: FnOnce(&[F]) -> MemoryWitness + 'static + Send + Sync,
    >(
        cs: &mut CS,
        witness_closure: FN,
        dependencies: &[Place],
    ) -> Self {
        let outputs = cs.alloc_multiple_variables_without_values::<9>();

        if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
            let value_fn = move |inputs: &[F], output_buffer: &mut DstBuffer<'_, '_, F>| {
                debug_assert!(F::CAPACITY_BITS >= 32);
                let witness = (witness_closure)(inputs);
                let chunks = decompose_u256_as_u32x8(witness.value);
                output_buffer.extend(chunks.map(|el| F::from_u64_unchecked(el as u64)));
                output_buffer.push(F::from_u64_unchecked(witness.is_ptr as u64));
            };

            cs.set_values_with_dependencies_vararg(
                &dependencies,
                &Place::from_variables(outputs),
                value_fn,
            );
        }

        let [l0, l1, l2, l3, l4, l5, l6, l7, b] = outputs;

        let chunks =
            [l0, l1, l2, l3, l4, l5, l6, l7].map(|el| UInt32::from_variable_checked(cs, el));
        let is_ptr = Boolean::from_variable_checked(cs, b);

        Self {
            is_ptr,
            value: UInt256 { inner: chunks },
        }
    }

    pub fn allocate_from_closure_and_dependencies_non_pointer<
        CS: ConstraintSystem<F>,
        FN: FnOnce(&[F]) -> MemoryWitness + 'static + Send + Sync,
    >(
        cs: &mut CS,
        witness_closure: FN,
        dependencies: &[Place],
    ) -> Self {
        let outputs = cs.alloc_multiple_variables_without_values::<8>();

        if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
            let value_fn = move |inputs: &[F], output_buffer: &mut DstBuffer<'_, '_, F>| {
                debug_assert!(F::CAPACITY_BITS >= 32);
                let witness = (witness_closure)(inputs);
                let chunks = decompose_u256_as_u32x8(witness.value);
                output_buffer.extend(chunks.map(|el| F::from_u64_unchecked(el as u64)));
            };

            cs.set_values_with_dependencies_vararg(
                &dependencies,
                &Place::from_variables(outputs),
                value_fn,
            );
        }

        let chunks = outputs.map(|el| UInt32::from_variable_checked(cs, el));
        let is_ptr = Boolean::allocated_constant(cs, false);

        Self {
            is_ptr,
            value: UInt256 { inner: chunks },
        }
    }
}

use boojum::gadgets::queue::full_state_queue::FullStateCircuitQueueWitness;

pub type MemoryQueryQueue<F, const AW: usize, const SW: usize, const CW: usize, R> =
    FullStateCircuitQueue<F, MemoryQuery<F>, AW, SW, CW, MEMORY_QUERY_PACKED_WIDTH, R>;
pub type MemoryQueue<F, R> = MemoryQueryQueue<F, 8, 12, 4, R>;

pub type MemoryQueryQueueWitness<F, const SW: usize> =
    FullStateCircuitQueueWitness<F, MemoryQuery<F>, SW, MEMORY_QUERY_PACKED_WIDTH>;
