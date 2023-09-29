use super::*;
use boojum::cs::gates::{ConstantAllocatableCS, ReductionByPowersGate, ReductionGate};
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::cs::{Place, Variable};
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::impls::limbs_decompose::reduce_terms;
use boojum::gadgets::num::Num;
use boojum::gadgets::traits::allocatable::CSAllocatable;
use boojum::gadgets::traits::castable::WitnessCastable;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::u32::UInt32;
use boojum::gadgets::u8::UInt8;
use boojum::serde_utils::BigArraySerde;
use boojum::{field::SmallField, gadgets::u16::UInt16};
use cs_derive::*;

use zkevm_opcode_defs::{
    OPCODE_INPUT_VARIANT_FLAGS, OPCODE_OUTPUT_VARIANT_FLAGS, OPCODE_TYPE_BITS, REGISTERS_COUNT,
};

pub const NUM_SRC_REGISTERS: usize = 2;
pub const NUM_DST_REGISTERS: usize = 2;
pub const REGISTER_ENCODING_BITS: usize = 4;

use super::opcode_bitmask::OpcodeBitmask;
use super::opcode_bitmask::TOTAL_OPCODE_MEANINGFULL_DESCRIPTION_BITS;

#[derive(Derivative, CSAllocatable, WitnessHookable)]
#[derivative(Debug)]
pub struct OpcodePropertiesDecoding<F: SmallField> {
    pub properties_bits: OpcodeBitmask<F>,
    pub src_regs_selectors: [[Boolean<F>; REGISTERS_COUNT]; NUM_SRC_REGISTERS],
    pub dst_regs_selectors: [[Boolean<F>; REGISTERS_COUNT]; NUM_DST_REGISTERS],
    pub imm0: UInt16<F>,
    pub imm1: UInt16<F>,
}

/// we assume that
/// - we did read the opcode either from memory, or have skipped opcode, or something else
/// - if we should have skipped cycle then we did it already
/// Now we need to decide either to mask into exception or into NOP, or execute
pub fn perform_initial_decoding<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    raw_opcode: [UInt32<F>; 2],
    encoded_flags: Num<F>,
    is_kernel_mode: Boolean<F>,
    is_static_context: Boolean<F>,
    callstack_is_full: Boolean<F>,
    ergs_left: UInt32<F>,
    did_skip_cycle: Boolean<F>,
) -> (OpcodePropertiesDecoding<F>, UInt32<F>) {
    // decode and resolve condition immediatelly
    // If we will later on mask into PANIC then we will just ignore resolved condition
    let initial_decoding =
        partially_decode_from_integer_and_resolve_condition(cs, raw_opcode, encoded_flags);

    let (opcode_boolean_spread_data, aux_bools) =
        split_out_aux_bits(cs, initial_decoding.opcode_boolean_spread_data);
    let condition_if_not_masked_later = initial_decoding.condition;

    // resolve fast exceptions
    // - out of ergs
    // - kernel mode
    // - writes in static context
    // - callstack is full

    // set ergs cost to 0 if we are skipping cycle
    let masked_ergs_cost = initial_decoding.ergs_cost.mask_negated(cs, did_skip_cycle);

    if crate::config::CIRCUIT_VERSOBE {
        println!(
            "Have {} ergs left, opcode cost is {}",
            ergs_left.witness_hook(&*cs)().unwrap(),
            masked_ergs_cost.witness_hook(&*cs)().unwrap(),
        );
    }

    let (ergs_left, out_of_ergs_exception) = ergs_left.overflowing_sub(cs, masked_ergs_cost);
    let ergs_left = ergs_left.mask_negated(cs, out_of_ergs_exception); // it's 0 if we underflow

    let requires_kernel_mode = aux_bools[zkevm_opcode_defs::KERNER_MODE_FLAG_IDX];
    let can_be_used_in_static_context =
        aux_bools[zkevm_opcode_defs::CAN_BE_USED_IN_STATIC_CONTEXT_FLAG_IDX];
    let explicit_panic = aux_bools[zkevm_opcode_defs::EXPLICIT_PANIC_FLAG_IDX];

    let normal_mode = is_kernel_mode.negated(cs);
    let kernel_mode_exception = Boolean::multi_and(cs, &[requires_kernel_mode, normal_mode]);
    let opcode_can_not_be_used_in_static_context = can_be_used_in_static_context.negated(cs);
    let write_in_static_exception = Boolean::multi_and(
        cs,
        &[is_static_context, opcode_can_not_be_used_in_static_context],
    );

    let any_exception = Boolean::multi_or(
        cs,
        &[
            explicit_panic,
            out_of_ergs_exception,
            kernel_mode_exception,
            write_in_static_exception,
            callstack_is_full,
        ],
    );

    // if we do have an exception then we have mask properties into PANIC
    let mask_into_panic = any_exception;
    if crate::config::CIRCUIT_VERSOBE {
        if mask_into_panic.witness_hook(&*cs)().unwrap() {
            println!("Masking into PANIC in decoding phase");
            dbg!([
                explicit_panic,
                out_of_ergs_exception,
                kernel_mode_exception,
                write_in_static_exception,
                callstack_is_full,
            ]
            .witness_hook(&*cs)()
            .unwrap());
        }
    }
    let panic_encoding = *zkevm_opcode_defs::PANIC_BITSPREAD_U64;

    // mask out aux bits (those are 0, but do it just in case)
    let panic_encoding = panic_encoding & OPCODE_PROPS_BITMASK_FOR_BITSPREAD_ENCODING;

    let panic_encoding = F::from_u64(panic_encoding).expect("fits into field");
    let panic_encoding = Num::allocated_constant(cs, panic_encoding);
    let opcode_boolean_spread_data = Num::conditionally_select(
        cs,
        mask_into_panic,
        &panic_encoding,
        &opcode_boolean_spread_data,
    );

    let no_panic = mask_into_panic.negated(cs);
    let condition_is_not_fulfilled = condition_if_not_masked_later.negated(cs);

    // then if we didn't mask into panic and condition was false then mask into NOP
    let mask_into_nop = Boolean::multi_and(cs, &[no_panic, condition_is_not_fulfilled]);
    if crate::config::CIRCUIT_VERSOBE {
        if mask_into_nop.witness_hook(&*cs)().unwrap() {
            println!("Masking into NOP in decoding phase");
        }
    }

    let nop_encoding = *zkevm_opcode_defs::NOP_BITSPREAD_U64;
    // mask out aux bits (those are 0, but do it just in case)
    let nop_encoding = nop_encoding & OPCODE_PROPS_BITMASK_FOR_BITSPREAD_ENCODING;
    let nop_encoding = F::from_u64(nop_encoding).expect("fits into field");
    let nop_encoding = Num::allocated_constant(cs, nop_encoding);

    let opcode_boolean_spread_data = Num::conditionally_select(
        cs,
        mask_into_nop,
        &nop_encoding,
        &opcode_boolean_spread_data,
    );

    let mask_any = Boolean::multi_or(cs, &[mask_into_nop, mask_into_panic]);

    // Ok, now just decompose spreads into bitmasks, and spread and decompose register indexes

    let all_opcodes_props_bits =
        opcode_boolean_spread_data
            .spread_into_bits::<_, TOTAL_OPCODE_MEANINGFULL_DESCRIPTION_BITS>(cs);

    let src_regs_encoding = initial_decoding
        .src_regs_encoding
        .mask_negated(cs, mask_any);
    let dst_regs_encoding = initial_decoding
        .dst_regs_encoding
        .mask_negated(cs, mask_any);

    // split encodings into 4 bit chunks unchecked

    let [src0_encoding, src1_encoding] = split_register_encoding_byte(cs, src_regs_encoding);
    let [dst0_encoding, dst1_encoding] = split_register_encoding_byte(cs, dst_regs_encoding);

    if crate::config::CIRCUIT_VERSOBE {
        dbg!(&src0_encoding.witness_hook(&*cs)().unwrap());
        dbg!(&src1_encoding.witness_hook(&*cs)().unwrap());

        dbg!(&dst0_encoding.witness_hook(&*cs)().unwrap());
        dbg!(&dst1_encoding.witness_hook(&*cs)().unwrap());
    }

    // and enforce their bit length by table access, and simultaneously get
    // bitmasks for selection

    // for every register we first need to spread integer index -> bitmask as integer, and then transform integer bitmask into individual bits

    let src0_mask = reg_idx_into_bitspread(cs, src0_encoding);
    let src0_bitspread = src0_mask.spread_into_bits::<_, REGISTERS_COUNT>(cs);

    let src1_mask = reg_idx_into_bitspread(cs, src1_encoding);
    let src1_bitspread = src1_mask.spread_into_bits::<_, REGISTERS_COUNT>(cs);

    let dst0_mask = reg_idx_into_bitspread(cs, dst0_encoding);
    let dst0_bitspread = dst0_mask.spread_into_bits::<_, REGISTERS_COUNT>(cs);

    let dst1_mask = reg_idx_into_bitspread(cs, dst1_encoding);
    let dst1_bitspread = dst1_mask.spread_into_bits::<_, REGISTERS_COUNT>(cs);

    let imm0 = initial_decoding.imm0;
    let imm1 = initial_decoding.imm1;

    // place everything into struct

    let opcode_props = OpcodeBitmask::from_full_mask(all_opcodes_props_bits);

    let new = OpcodePropertiesDecoding {
        properties_bits: opcode_props,
        src_regs_selectors: [src0_bitspread, src1_bitspread],
        dst_regs_selectors: [dst0_bitspread, dst1_bitspread],
        imm0,
        imm1,
    };

    (new, ergs_left)
}

// for integer N returns a field element with value 0 if N is zero, and 1 << (N-1) otherwise
pub fn reg_idx_into_bitspread<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    integer: Num<F>,
) -> Num<F> {
    use crate::tables::integer_to_boolean_mask::RegisterIndexToBitmaskTable;

    let table_id = cs
        .get_table_id_for_marker::<RegisterIndexToBitmaskTable>()
        .expect("table must be added before");

    let vals = cs.perform_lookup::<1, 2>(table_id, &[integer.get_variable()]);
    let bitspread = vals[0];

    Num::from_variable(bitspread)
}

use zkevm_opcode_defs::{
    CONDITIONAL_BITS_SHIFT, OPCODES_TABLE_WIDTH, VARIANT_AND_CONDITION_ENCODING_BITS,
};

use crate::bit_width_to_bitmask;

pub const VARIANT_AND_CONDITION_ENCODING_MASK: u64 =
    bit_width_to_bitmask(VARIANT_AND_CONDITION_ENCODING_BITS);
pub const VARIANT_ENCODING_MASK: u64 = bit_width_to_bitmask(OPCODES_TABLE_WIDTH);
pub const OPCODE_PROPS_BITMASK_FOR_BITSPREAD_ENCODING: u64 =
    bit_width_to_bitmask(TOTAL_OPCODE_DESCRIPTION_BITS_FLATTENED);

use zkevm_opcode_defs::TOTAL_AUX_BITS;

use super::opcode_bitmask::{
    OPCODE_FLAGS_BITS, OPCODE_VARIANT_BITS, TOTAL_OPCODE_DESCRIPTION_AND_AUX_BITS,
    TOTAL_OPCODE_DESCRIPTION_BITS_FLATTENED,
};

const CONDITION_ENCODING_BITS: usize = 3;

const UNUSED_GAP: usize =
    VARIANT_AND_CONDITION_ENCODING_BITS - OPCODES_TABLE_WIDTH - CONDITION_ENCODING_BITS;

pub const NUM_BITS_BEFORE_AUX_INFORMATION: usize = OPCODE_TYPE_BITS
    + OPCODE_VARIANT_BITS
    + OPCODE_FLAGS_BITS
    + OPCODE_INPUT_VARIANT_FLAGS
    + OPCODE_OUTPUT_VARIANT_FLAGS;

use crate::base_structures::vm_state::ArithmeticFlagsPort;

pub(crate) fn encode_flags<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    flags: &ArithmeticFlagsPort<F>,
) -> Num<F> {
    if cs.gate_is_allowed::<ReductionByPowersGate<F, 4>>() {
        let zero = Num::allocated_constant(cs, F::ZERO);
        let inputs = [
            flags.overflow_or_less_than.get_variable(),
            flags.equal.get_variable(),
            flags.greater_than.get_variable(),
            zero.get_variable(),
        ];
        let result = reduce_terms(cs, F::TWO, inputs);

        Num::from_variable(result)
    } else if cs.gate_is_allowed::<ReductionGate<F, 4>>() {
        let zero = Num::allocated_constant(cs, F::ZERO);
        let inputs = [
            flags.overflow_or_less_than.get_variable(),
            flags.equal.get_variable(),
            flags.greater_than.get_variable(),
            zero.get_variable(),
        ];
        let contants = [F::ONE, F::TWO, F::from_u64_unchecked(4), F::ZERO];
        let result = ReductionGate::<F, 4>::reduce_terms(cs, contants, inputs);

        Num::from_variable(result)
    } else {
        unimplemented!()
    }
}

pub struct OpcodePreliminaryDecoding<F: SmallField> {
    pub condition: Boolean<F>,
    pub opcode_boolean_spread_data: Num<F>, // this has both flags that describe the opcode itself, and aux flags for EH
    pub src_regs_encoding: UInt8<F>,
    pub dst_regs_encoding: UInt8<F>,
    pub imm0: UInt16<F>,
    pub imm1: UInt16<F>,
    pub ergs_cost: UInt32<F>,
}

pub fn split_out_aux_bits<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    opcode_boolean_spread_data: Num<F>,
) -> (Num<F>, [Boolean<F>; TOTAL_AUX_BITS]) {
    assert!(TOTAL_OPCODE_DESCRIPTION_AND_AUX_BITS <= 64);
    assert!(TOTAL_OPCODE_DESCRIPTION_AND_AUX_BITS <= F::CAPACITY_BITS);

    let main_props_var = cs.alloc_variable_without_value();
    let extra_props_vars = cs.alloc_multiple_variables_without_values::<TOTAL_AUX_BITS>();

    if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
        let mut all_outputs = [Variable::placeholder(); TOTAL_AUX_BITS + 1];
        all_outputs[0] = main_props_var;
        all_outputs[1..].copy_from_slice(&extra_props_vars);

        let value_fn = move |inputs: [F; 1]| {
            let witness = inputs[0].as_u64_reduced();
            let mut result = [F::ZERO; TOTAL_AUX_BITS + 1];

            let props = witness & OPCODE_PROPS_BITMASK_FOR_BITSPREAD_ENCODING; // bits without AUX flag

            result[0] = F::from_u64(props).expect("must fit into field");

            assert!(OPCODE_PROPS_BITMASK_FOR_BITSPREAD_ENCODING < u64::MAX);
            let aux_bits_as_u64 = witness >> TOTAL_OPCODE_DESCRIPTION_BITS_FLATTENED;
            let mut aux_bits_as_u64 = aux_bits_as_u64 as u64;
            for idx in 0..TOTAL_AUX_BITS {
                let bit = (aux_bits_as_u64 & 1u64) == 1;
                result[idx + 1] = if bit { F::ONE } else { F::ZERO };

                aux_bits_as_u64 >>= 1;
            }
            debug_assert!(aux_bits_as_u64 == 0);

            result
        };

        let dependencies = [opcode_boolean_spread_data.get_variable().into()];

        cs.set_values_with_dependencies(
            &dependencies,
            &Place::from_variables(all_outputs),
            value_fn,
        );
    }

    let main_props = Num::from_variable(main_props_var);
    let extra_props_bits = extra_props_vars.map(|el| Boolean::from_variable_checked(cs, el));

    // we should enforce bit length because we just did the splitting
    let _ = main_props.constraint_bit_length_as_bytes(cs, TOTAL_OPCODE_DESCRIPTION_BITS_FLATTENED);

    // now just make a combination to prove equality

    let to_enforce = [
        (main_props_var, F::ONE),
        (
            extra_props_vars[0],
            F::from_u64_unchecked(1u64 << (TOTAL_OPCODE_DESCRIPTION_BITS_FLATTENED)),
        ),
        (
            extra_props_vars[1],
            F::from_u64_unchecked(1u64 << (TOTAL_OPCODE_DESCRIPTION_BITS_FLATTENED + 1)),
        ),
        (
            extra_props_vars[2],
            F::from_u64_unchecked(1u64 << (TOTAL_OPCODE_DESCRIPTION_BITS_FLATTENED + 2)),
        ),
        (opcode_boolean_spread_data.get_variable(), F::MINUS_ONE),
    ];

    Num::enforce_zero_for_linear_combination(cs, &to_enforce);

    (main_props, extra_props_bits)
}

/// Decodes only necessary parts of the opcode to resolve condition
/// for masking into NOP if opcode does nothing.
/// We also output imm0/imm1 parts that will NOT be ever masked,
/// and register index encoding parts too that would be masked into 0.
/// Please remember that we mask only bitspread part after condition is resolved, and we do not need
/// to recompute the cost(!)
pub fn partially_decode_from_integer_and_resolve_condition<
    F: SmallField,
    CS: ConstraintSystem<F>,
>(
    cs: &mut CS,
    opcode_properties_words: [UInt32<F>; 2],
    encoded_flags: Num<F>,
) -> OpcodePreliminaryDecoding<F> {
    // we need into total 4 elements:
    // - 11 bits that encode opcode + variant + addressing mode + etc
    // - 2x1 unused bits
    // - conditional 3bit integer (constrainted later by lookup table)

    let word_0_bytes = opcode_properties_words[0].decompose_into_bytes(cs);

    let opcode_variant_and_conditional_word =
        UInt16::from_le_bytes(cs, [word_0_bytes[0], word_0_bytes[1]]);

    let variant_var = cs.alloc_variable_without_value();
    let unused_bits_vars = cs.alloc_multiple_variables_without_values::<2>();
    let conditionals_var = cs.alloc_variable_without_value();

    // booleanity constraints
    let _unused_bits = unused_bits_vars.map(|el| Boolean::from_variable_checked(cs, el));

    if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
        let all_outputs = [
            variant_var,
            unused_bits_vars[0],
            unused_bits_vars[1],
            conditionals_var,
        ];

        let value_fn = move |inputs: [F; 1]| {
            debug_assert_eq!(VARIANT_AND_CONDITION_ENCODING_BITS, 16);

            let variant_and_condition = <u16 as WitnessCastable<F, F>>::cast_from_source(inputs[0]);
            let variant_and_condition = variant_and_condition as u64;
            let variant_and_condition = variant_and_condition & VARIANT_AND_CONDITION_ENCODING_MASK;

            let variant = variant_and_condition & VARIANT_ENCODING_MASK;

            let unused_bits =
                (variant_and_condition >> OPCODES_TABLE_WIDTH) & bit_width_to_bitmask(UNUSED_GAP);
            let unused_bit_0 = unused_bits & 1 > 0;
            let unused_bit_1 = (unused_bits >> 1) & 1 > 0;
            let condition = variant_and_condition >> CONDITIONAL_BITS_SHIFT;

            if crate::config::CIRCUIT_VERSOBE {
                let opcode = zkevm_opcode_defs::OPCODES_TABLE[variant as usize];
                dbg!(opcode);
                let condition = zkevm_opcode_defs::condition::Condition::materialize_variant(
                    condition as usize,
                );
                dbg!(condition);
            }

            [
                F::from_u64_unchecked(variant),
                F::from_u64_unchecked(unused_bit_0 as u64),
                F::from_u64_unchecked(unused_bit_1 as u64),
                F::from_u64_unchecked(condition),
            ]
        };

        let dependencies = [opcode_variant_and_conditional_word.get_variable().into()];

        cs.set_values_with_dependencies(
            &dependencies,
            &Place::from_variables(all_outputs),
            value_fn,
        );
    }

    // enforce our claimed decomposition
    Num::enforce_zero_for_linear_combination(
        cs,
        &[
            (variant_var, F::ONE),
            (unused_bits_vars[0], F::SHIFTS[OPCODES_TABLE_WIDTH]),
            (unused_bits_vars[1], F::SHIFTS[OPCODES_TABLE_WIDTH + 1]),
            (conditionals_var, F::SHIFTS[OPCODES_TABLE_WIDTH + 2]),
            (
                opcode_variant_and_conditional_word.get_variable(),
                F::MINUS_ONE,
            ),
        ],
    );

    // range check parts by feeding into the tables

    use crate::tables::opcodes_decoding::VMOpcodeDecodingTable;
    let table_id = cs
        .get_table_id_for_marker::<VMOpcodeDecodingTable>()
        .expect("table must exist");

    // bit check variant and spread it
    let values = cs.perform_lookup::<1, 2>(table_id, &[variant_var]);
    // by our definition of the table we check the prices to fit into u32
    let opcode_cost = unsafe { UInt32::from_variable_unchecked(values[0]) };
    let opcode_properties = Num::from_variable(values[1]);

    // condition is checked to be 3 bits through resolution here
    use crate::tables::conditional::VMConditionalResolutionTable;
    let table_id = cs
        .get_table_id_for_marker::<VMConditionalResolutionTable>()
        .expect("table must exist");

    let values =
        cs.perform_lookup::<2, 1>(table_id, &[conditionals_var, encoded_flags.get_variable()]);
    let resolution = unsafe { Boolean::from_variable_unchecked(values[0]) };

    // decode the end
    let src_regs_encoding = word_0_bytes[2];
    let dst_regs_encoding = word_0_bytes[3];

    let word_1_bytes = opcode_properties_words[1].decompose_into_bytes(cs);

    let imm0 = UInt16::from_le_bytes(cs, [word_1_bytes[0], word_1_bytes[1]]);
    let imm1 = UInt16::from_le_bytes(cs, [word_1_bytes[2], word_1_bytes[3]]);

    let props = OpcodePreliminaryDecoding {
        condition: resolution,
        opcode_boolean_spread_data: opcode_properties,
        src_regs_encoding,
        dst_regs_encoding,
        imm0,
        imm1,
        ergs_cost: opcode_cost,
    };

    props
}

fn split_register_encoding_byte<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    encoding: UInt8<F>,
) -> [Num<F>; 2] {
    // we only need one FMA gate, so we write the routine manually

    let outputs = cs.alloc_multiple_variables_without_values::<2>();

    if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
        const MASK: u64 = (1u64 << REGISTER_ENCODING_BITS) - 1;
        let value_fn = move |inputs: [F; 1]| {
            let mut as_u64 = inputs[0].as_u64();
            let src0 = as_u64 & MASK;
            as_u64 >>= REGISTER_ENCODING_BITS;
            debug_assert!(as_u64 <= MASK);
            let src1 = as_u64;

            [F::from_u64_unchecked(src0), F::from_u64_unchecked(src1)]
        };

        let dependencies = Place::from_variables([encoding.get_variable()]);

        cs.set_values_with_dependencies(&dependencies, &Place::from_variables(outputs), value_fn);
    }

    if <CS::Config as CSConfig>::SetupConfig::KEEP_SETUP {
        use boojum::cs::gates::FmaGateInBaseFieldWithoutConstant;

        if cs.gate_is_allowed::<FmaGateInBaseFieldWithoutConstant<F>>() {
            let one = cs.allocate_constant(F::ONE);
            let mut gate = FmaGateInBaseFieldWithoutConstant::empty();
            gate.quadratic_part = (one, outputs[0]);
            gate.linear_part = outputs[1];
            use boojum::cs::gates::fma_gate_without_constant::FmaGateInBaseWithoutConstantParams;
            gate.params = FmaGateInBaseWithoutConstantParams {
                coeff_for_quadtaric_part: F::ONE,
                linear_term_coeff: F::from_u64_unchecked(1u64 << REGISTER_ENCODING_BITS),
            };
            gate.rhs_part = encoding.get_variable();

            gate.add_to_cs(cs);
        } else {
            unimplemented!()
        }
    }

    outputs.map(|el| Num::from_variable(el))
}
