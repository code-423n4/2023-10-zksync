use super::*;
use crate::base_structures::register::VMRegister;
use crate::base_structures::vm_state::ArithmeticFlagsPort;
use crate::tables::bitshift::*;
use arrayvec::ArrayVec;
use boojum::gadgets::u256::UInt256;

pub(crate) fn apply_shifts<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    _draft_vm_state: &VmLocalState<F>,
    common_opcode_state: &CommonOpcodeState<F>,
    _opcode_carry_parts: &AfterDecodingCarryParts<F>,
    diffs_accumulator: &mut StateDiffsAccumulator<F>,
) {
    const SHL_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Shift(zkevm_opcode_defs::definitions::shift::ShiftOpcode::Shl);
    const ROL_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Shift(zkevm_opcode_defs::definitions::shift::ShiftOpcode::Rol);
    const SHR_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Shift(zkevm_opcode_defs::definitions::shift::ShiftOpcode::Shr);
    const ROR_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Shift(zkevm_opcode_defs::definitions::shift::ShiftOpcode::Ror);

    let should_apply = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_opcode(SHL_OPCODE);

    if crate::config::CIRCUIT_VERSOBE {
        if (should_apply.witness_hook(&*cs))().unwrap_or(false) {
            println!("Applying SHIFT");
        }
    }

    let should_set_flags = common_opcode_state
        .decoded_opcode
        .properties_bits
        .flag_booleans[SET_FLAGS_FLAG_IDX];

    let is_rol = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(ROL_OPCODE);
    let is_ror = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(ROR_OPCODE);
    let is_shr = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(SHR_OPCODE);

    let is_cyclic = is_rol.or(cs, is_ror);
    let is_right = is_ror.or(cs, is_shr);

    let reg = &common_opcode_state.src0_view.u32x8_view;
    let shift = common_opcode_state.src1_view.u8x32_view[0];
    let shift = shift.into_num();

    // cyclic right rotation x is the same as left cyclic rotation 256 - x
    let change_rot = is_ror;
    let shift_is_zero = shift.is_zero(cs);
    let cnst = Num::allocated_constant(cs, F::from_u64_unchecked(256));
    // no underflow here
    let inverted_shift = cnst.sub(cs, &shift);

    let change_flag = {
        let x = shift_is_zero.negated(cs);
        change_rot.and(cs, x)
    };
    let full_shift = Num::conditionally_select(cs, change_flag, &inverted_shift, &shift);

    // and only NOW it's indeed 8-bit, even if we had a subtraction of 256 - 0 above
    let full_shift = unsafe { UInt8::from_variable_unchecked(full_shift.get_variable()) };

    let full_shift_limbs = get_shift_constant(cs, full_shift);

    let is_right_shift = {
        let x = is_cyclic.negated(cs);
        is_right.and(cs, x)
    };
    let (rshift_q, _rshift_r) = allocate_div_result_unchecked(cs, &reg, &full_shift_limbs);

    let apply_left_shift = {
        let x = is_right_shift.negated(cs);
        Boolean::multi_and(cs, &[should_apply, x])
    };
    let (lshift_low, lshift_high) = allocate_mul_result_unchecked(cs, &reg, &full_shift_limbs);

    // actual enforcement:
    // for left_shift: a = reg, b = full_shuft, remainder = 0, high = lshift_high, low = lshift_low
    // for right_shift : a = rshift_q, b = full_shift, remainder = rshift_r, high = 0, low = reg
    let uint256_zero = UInt256::zero(cs);

    let rem_to_enforce =
        UInt32::parallel_select(cs, apply_left_shift, &uint256_zero.inner, &_rshift_r);
    let a_to_enforce = UInt32::parallel_select(cs, apply_left_shift, reg, &rshift_q);
    let b_to_enforce = full_shift_limbs;
    let mul_low_to_enforce = UInt32::parallel_select(cs, apply_left_shift, &lshift_low, reg);
    let mul_high_to_enforce =
        UInt32::parallel_select(cs, apply_left_shift, &lshift_high, &uint256_zero.inner);

    let mul_relation = MulDivRelation {
        a: a_to_enforce,
        b: b_to_enforce,
        rem: rem_to_enforce,
        mul_low: mul_low_to_enforce,
        mul_high: mul_high_to_enforce,
    };

    let temp_result = UInt32::parallel_select(cs, is_right_shift, &rshift_q, &lshift_low);
    let overflow = lshift_high;
    let mut final_result = UInt256::zero(cs).inner;

    let zipped_iter = (temp_result.iter(), overflow.iter(), final_result.iter_mut());
    for (limb_in, of_in, limb_out) in itertools::multizip(zipped_iter) {
        // of * is_cyclic + limb_in
        let res = Num::fma(
            cs,
            &of_in.into_num(),
            &is_cyclic.into_num(),
            &F::ONE,
            &limb_in.into_num(),
            &F::ONE,
        );
        *limb_out = unsafe { UInt32::from_variable_unchecked(res.get_variable()) };
    }

    // Sets an eq flag if out1 is zero
    let res_is_zero = all_limbs_are_zero(cs, &final_result);
    let boolean_false = Boolean::allocated_constant(cs, false);
    let new_flag_port = ArithmeticFlagsPort {
        overflow_or_less_than: boolean_false,
        equal: res_is_zero,
        greater_than: boolean_false,
    };

    // flags for a case if we do not set flags
    let set_flags_and_execute = Boolean::multi_and(cs, &[should_apply, should_set_flags]);

    let dst0 = VMRegister {
        is_pointer: boolean_false,
        value: UInt256 {
            inner: final_result,
        },
    };

    let can_write_into_memory = SHL_OPCODE.can_write_dst0_into_memory(SUPPORTED_ISA_VERSION);

    diffs_accumulator
        .dst_0_values
        .push((can_write_into_memory, should_apply, dst0));
    diffs_accumulator
        .flags
        .push((set_flags_and_execute, new_flag_port));

    let mut mul_div_relations = ArrayVec::new();
    mul_div_relations.push(mul_relation);
    diffs_accumulator
        .mul_div_relations
        .push((should_apply, mul_div_relations));
}

pub(crate) fn get_shift_constant<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    shift: UInt8<F>,
) -> [UInt32<F>; 8] {
    let shift_table_id = cs
        .get_table_id_for_marker::<BitshiftTable>()
        .expect("table must exist");

    let mut full_shift_limbs = [UInt32::zero(cs); 8];
    for (idx, dst) in full_shift_limbs.chunks_mut(2).enumerate() {
        // shift + idx << 8
        let summand = Num::allocated_constant(cs, F::from_u64_unchecked((idx << 8) as u64));
        let key = shift.into_num().add(cs, &summand);
        let [a, b] = cs.perform_lookup::<1, 2>(shift_table_id, &[key.get_variable()]);
        unsafe {
            dst[0] = UInt32::from_variable_unchecked(a);
            dst[1] = UInt32::from_variable_unchecked(b);
        }
    }

    full_shift_limbs
}
