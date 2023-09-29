use boojum::cs::gates::ConstantAllocatableCS;
use cs_derive::*;

use crate::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;

use super::*;
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::cs::traits::cs::DstBuffer;
use boojum::cs::Variable;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::num::Num;
use boojum::gadgets::traits::allocatable::CSPlaceholder;
use boojum::gadgets::traits::allocatable::{CSAllocatable, CSAllocatableExt};
use boojum::gadgets::traits::encodable::CircuitVarLengthEncodable;
use boojum::gadgets::traits::encodable::{CircuitEncodable, CircuitEncodableExt};
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::traits::witnessable::WitnessHookable;
use boojum::serde_utils::BigArraySerde;

#[derive(Derivative, CSAllocatable, CSSelectable, WitnessHookable, CSVarLengthEncodable)]
#[derivative(Clone, Copy, Debug)]
pub struct RecursionQuery<F: SmallField> {
    pub circuit_type: Num<F>,
    pub input_commitment: [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH],
}

pub const RECURSION_QUERY_PACKED_WIDTH: usize = 8;

impl<F: SmallField> CircuitEncodable<F, RECURSION_QUERY_PACKED_WIDTH> for RecursionQuery<F> {
    fn encode<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
    ) -> [Variable; RECURSION_QUERY_PACKED_WIDTH] {
        let zero = cs.allocate_constant(F::ZERO);
        let [t0, t1, t2, t3] = self.input_commitment.map(|el| el.get_variable());
        [
            self.circuit_type.get_variable(),
            t0,
            t1,
            t2,
            t3,
            zero,
            zero,
            zero,
        ]
    }
}

impl<F: SmallField> CSAllocatableExt<F> for RecursionQuery<F> {
    const INTERNAL_STRUCT_LEN: usize = 5;

    fn witness_from_set_of_values(values: [F; Self::INTERNAL_STRUCT_LEN]) -> Self::Witness {
        let circuit_type = values[0];

        let t0 = values[1];
        let t1 = values[2];
        let t2 = values[3];
        let t3 = values[4];

        Self::Witness {
            circuit_type,
            input_commitment: [t0, t1, t2, t3],
        }
    }

    fn flatten_as_variables(&self) -> [Variable; Self::INTERNAL_STRUCT_LEN]
    where
        [(); Self::INTERNAL_STRUCT_LEN]:,
    {
        [
            self.circuit_type.get_variable(),
            self.input_commitment[0].get_variable(),
            self.input_commitment[1].get_variable(),
            self.input_commitment[2].get_variable(),
            self.input_commitment[3].get_variable(),
        ]
    }
    fn set_internal_variables_values(witness: Self::Witness, dst: &mut DstBuffer<'_, '_, F>) {
        Num::set_internal_variables_values(witness.circuit_type, dst);
        for src in witness.input_commitment.into_iter() {
            Num::set_internal_variables_values(src, dst);
        }
    }
}

impl<F: SmallField> CircuitEncodableExt<F, RECURSION_QUERY_PACKED_WIDTH> for RecursionQuery<F> {}

impl<F: SmallField> CSPlaceholder<F> for RecursionQuery<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let zero_num = Num::zero(cs);

        Self {
            circuit_type: zero_num,
            input_commitment: [zero_num; INPUT_OUTPUT_COMMITMENT_LENGTH],
        }
    }
}

use boojum::gadgets::queue::full_state_queue::{
    FullStateCircuitQueue, FullStateCircuitQueueWitness,
};

pub type RecursionQueryQueue<F, const AW: usize, const SW: usize, const CW: usize, R> =
    FullStateCircuitQueue<F, RecursionQuery<F>, AW, SW, CW, RECURSION_QUERY_PACKED_WIDTH, R>;

pub type RecursionQueue<F, R> = RecursionQueryQueue<F, 8, 12, 4, R>;

pub type RecursionQueueWitness<F, const SW: usize> =
    FullStateCircuitQueueWitness<F, RecursionQuery<F>, SW, RECURSION_QUERY_PACKED_WIDTH>;
