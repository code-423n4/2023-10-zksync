use super::*;
use boojum::gadgets::traits::auxiliary::PrettyComparison;
use cs_derive::*;

use boojum::cs::gates::ConstantAllocatableCS;
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::cs::Variable;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::num::Num;
use boojum::gadgets::traits::allocatable::CSAllocatable;
use boojum::gadgets::traits::allocatable::CSPlaceholder;
use boojum::gadgets::traits::encodable::CircuitVarLengthEncodable;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::traits::witnessable::WitnessHookable;
use boojum::gadgets::u32::UInt32;
use boojum::serde_utils::BigArraySerde;

pub mod circuit_inputs;

#[derive(Derivative, CSAllocatable, WitnessHookable)]
#[WitnessHookBound(
    "
where
    <T as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
    <IN as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
    <OUT as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
"
)]
#[derivative(Clone, Debug)]
pub struct ClosedFormInput<
    F: SmallField,
    T: Clone + std::fmt::Debug + CSAllocatable<F> + CircuitVarLengthEncodable<F> + WitnessHookable<F>,
    IN: Clone + std::fmt::Debug + CSAllocatable<F> + CircuitVarLengthEncodable<F> + WitnessHookable<F>,
    OUT: Clone + std::fmt::Debug + CSAllocatable<F> + CircuitVarLengthEncodable<F> + WitnessHookable<F>,
> where
    <T as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
    <IN as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
    <OUT as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
{
    pub start_flag: Boolean<F>,
    pub completion_flag: Boolean<F>,
    pub observable_input: IN,
    pub observable_output: OUT,
    pub hidden_fsm_input: T,
    pub hidden_fsm_output: T,
}

impl<
        F: SmallField,
        T: Clone
            + std::fmt::Debug
            + CSAllocatable<F>
            + CircuitVarLengthEncodable<F>
            + WitnessHookable<F>,
        IN: Clone
            + std::fmt::Debug
            + CSAllocatable<F>
            + CircuitVarLengthEncodable<F>
            + WitnessHookable<F>,
        OUT: Clone
            + std::fmt::Debug
            + CSAllocatable<F>
            + CircuitVarLengthEncodable<F>
            + WitnessHookable<F>,
    > ClosedFormInput<F, T, IN, OUT>
where
    <T as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
    <IN as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
    <OUT as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
{
    pub fn alloc_ignoring_outputs<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        witness: ClosedFormInputWitness<F, T, IN, OUT>,
    ) -> Self
    where
        T: CSPlaceholder<F>,
        OUT: CSPlaceholder<F>,
    {
        let start_flag = Boolean::allocate(cs, witness.start_flag);
        let observable_input = IN::allocate(cs, witness.observable_input.clone());
        let hidden_fsm_input = T::allocate(cs, witness.hidden_fsm_input.clone());
        let boolean_false = Boolean::allocated_constant(cs, false);

        let observable_output = OUT::placeholder(cs);
        let hidden_fsm_output = T::placeholder(cs);

        let new = Self {
            start_flag,
            completion_flag: boolean_false,
            observable_input,
            observable_output,
            hidden_fsm_input,
            hidden_fsm_output,
        };

        new
    }

    #[track_caller]
    pub fn hook_compare_witness<CS: ConstraintSystem<F>>(
        &self,
        cs: &CS,
        expected: &<ClosedFormInput<F, T, IN, OUT> as CSAllocatable<F>>::Witness,
    ) where
        T: PrettyComparison<F>,
        OUT: PrettyComparison<F>,
    {
        if let Some(circuit_result) = (self.witness_hook(&*cs))() {
            let comparison_lines = <T as PrettyComparison<F>>::find_diffs(
                &circuit_result.hidden_fsm_output,
                &expected.hidden_fsm_output,
            );
            if comparison_lines.is_empty() == false {
                panic!(
                    "Difference in FSM. Left is circuit, right is expected:\n{}",
                    comparison_lines.join("\n")
                );
            }
            let comparison_lines = <OUT as PrettyComparison<F>>::find_diffs(
                &circuit_result.observable_output,
                &expected.observable_output,
            );
            if comparison_lines.is_empty() == false {
                panic!(
                    "Difference in observable output. Left is circuit, right is expected:\n{}",
                    comparison_lines.join("\n")
                );
            }
            assert_eq!(&circuit_result, expected);
        }
    }
}

pub const CLOSED_FORM_COMMITTMENT_LENGTH: usize = 4;

impl<
        F: SmallField,
        T: Clone
            + std::fmt::Debug
            + CSAllocatable<F>
            + CircuitVarLengthEncodable<F>
            + WitnessHookable<F>,
        IN: Clone
            + std::fmt::Debug
            + CSAllocatable<F>
            + CircuitVarLengthEncodable<F>
            + WitnessHookable<F>,
        OUT: Clone
            + std::fmt::Debug
            + CSAllocatable<F>
            + CircuitVarLengthEncodable<F>
            + WitnessHookable<F>,
    > std::default::Default for ClosedFormInputWitness<F, T, IN, OUT>
where
    <T as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
    <IN as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
    <OUT as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
{
    fn default() -> Self {
        ClosedFormInput::<F, T, IN, OUT>::placeholder_witness()
    }
}

#[derive(Derivative, CSAllocatable, CSSelectable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Debug)]
pub struct ClosedFormInputCompactForm<F: SmallField> {
    pub start_flag: Boolean<F>,
    pub completion_flag: Boolean<F>,
    pub observable_input_committment: [Num<F>; CLOSED_FORM_COMMITTMENT_LENGTH],
    pub observable_output_committment: [Num<F>; CLOSED_FORM_COMMITTMENT_LENGTH],
    pub hidden_fsm_input_committment: [Num<F>; CLOSED_FORM_COMMITTMENT_LENGTH],
    pub hidden_fsm_output_committment: [Num<F>; CLOSED_FORM_COMMITTMENT_LENGTH],
}

impl<F: SmallField> ClosedFormInputCompactForm<F> {
    pub fn from_full_form<
        CS: ConstraintSystem<F>,
        T: Clone
            + std::fmt::Debug
            + CSAllocatable<F>
            + CircuitVarLengthEncodable<F>
            + WitnessHookable<F>,
        IN: Clone
            + std::fmt::Debug
            + CSAllocatable<F>
            + CircuitVarLengthEncodable<F>
            + WitnessHookable<F>,
        OUT: Clone
            + std::fmt::Debug
            + CSAllocatable<F>
            + CircuitVarLengthEncodable<F>
            + WitnessHookable<F>,
        R: CircuitRoundFunction<F, 8, 12, 4>,
    >(
        cs: &mut CS,
        full_form: &ClosedFormInput<F, T, IN, OUT>,
        round_function: &R,
    ) -> Self
    where
        <T as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
        <IN as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
        <OUT as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
    {
        let observable_input_committment =
            commit_variable_length_encodable_item(cs, &full_form.observable_input, round_function);
        let observable_output_committment =
            commit_variable_length_encodable_item(cs, &full_form.observable_output, round_function);

        let hidden_fsm_input_committment =
            commit_variable_length_encodable_item(cs, &full_form.hidden_fsm_input, round_function);
        let hidden_fsm_output_committment =
            commit_variable_length_encodable_item(cs, &full_form.hidden_fsm_output, round_function);

        // mask FSM part. Observable part is NEVER masked

        let zero_num = Num::zero(cs);
        let empty_committment = [zero_num; CLOSED_FORM_COMMITTMENT_LENGTH];

        let hidden_fsm_input_committment = Num::parallel_select(
            cs,
            full_form.start_flag,
            &empty_committment,
            &hidden_fsm_input_committment,
        );

        // mask output. Observable output is zero is not the last indeed
        let observable_output_committment = Num::parallel_select(
            cs,
            full_form.completion_flag,
            &observable_output_committment,
            &empty_committment,
        );

        // and vice versa for FSM
        let hidden_fsm_output_committment = Num::parallel_select(
            cs,
            full_form.completion_flag,
            &empty_committment,
            &hidden_fsm_output_committment,
        );

        let new = Self {
            start_flag: full_form.start_flag,
            completion_flag: full_form.completion_flag,
            observable_input_committment,
            observable_output_committment,
            hidden_fsm_input_committment,
            hidden_fsm_output_committment,
        };

        new
    }
}

pub fn commit_variable_length_encodable_item<
    F: SmallField,
    CS: ConstraintSystem<F>,
    T: CircuitVarLengthEncodable<F>,
    const AW: usize,
    const SW: usize,
    const CW: usize,
    const N: usize,
    R: CircuitRoundFunction<F, AW, SW, CW>,
>(
    cs: &mut CS,
    item: &T,
    _round_function: &R,
) -> [Num<F>; N] {
    let expected_length = item.encoding_length();

    let mut buffer = Vec::with_capacity(expected_length);
    item.encode_to_buffer(cs, &mut buffer);

    assert_eq!(buffer.len(), expected_length);

    commit_encoding::<F, CS, AW, SW, CW, N, R>(cs, &buffer, _round_function)
}

pub fn commit_encoding<
    F: SmallField,
    CS: ConstraintSystem<F>,
    const AW: usize,
    const SW: usize,
    const CW: usize,
    const N: usize,
    R: CircuitRoundFunction<F, AW, SW, CW>,
>(
    cs: &mut CS,
    input: &[Variable],
    _round_function: &R,
) -> [Num<F>; N] {
    // we use length specialization here
    let expected_length = input.len();

    let mut state = R::create_empty_state(cs);
    let length = UInt32::allocated_constant(cs, expected_length as u32);
    R::apply_length_specialization(cs, &mut state, length.get_variable());

    // pad with zeroes

    let mut buffer_length = expected_length / AW;
    if expected_length % AW != 0 {
        buffer_length += 1;
    }

    buffer_length *= AW;

    let mut buffer = Vec::with_capacity(buffer_length);
    buffer.extend_from_slice(input);

    let zero_var = cs.allocate_constant(F::ZERO);
    buffer.resize(buffer_length, zero_var);

    for chunk in buffer.array_chunks::<AW>() {
        let capacity_els = R::split_capacity_elements(&state);

        state = R::absorb_with_replacement(cs, *chunk, capacity_els);
        state = R::compute_round_function(cs, state);
    }

    let output = R::state_into_commitment::<N>(&state);

    output.map(|el| Num::from_variable(el))
}
