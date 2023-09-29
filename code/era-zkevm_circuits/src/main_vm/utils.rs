use boojum::field::SmallField;

use super::decoded_opcode::OpcodePropertiesDecoding;
use super::witness_oracle::SynchronizedWitnessOracle;
use super::*;
use crate::base_structures::memory_query::{MemoryQuery, MemoryValue};
use crate::base_structures::register::VMRegister;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::config::*;
use boojum::cs::gates::ConstantAllocatableCS;
use boojum::gadgets::traits::encodable::CircuitEncodable;
use boojum::gadgets::u256::UInt256;

pub fn mask_into_nop<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    should_mask: Boolean<F>,
    opcode: [UInt32<F>; 2],
) -> [UInt32<F>; 2] {
    use zkevm_opcode_defs::decoding::*;
    let nop_encoding = EncodingModeProduction::nop_encoding();
    let low = nop_encoding as u32;
    let low = UInt32::allocated_constant(cs, low);
    let high = (nop_encoding >> 32) as u32;
    let high = UInt32::allocated_constant(cs, high);

    <[UInt32<F>; 2]>::conditionally_select(cs, should_mask, &[low, high], &opcode)
}

pub fn mask_into_panic<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    should_mask: Boolean<F>,
    opcode: [UInt32<F>; 2],
) -> [UInt32<F>; 2] {
    use zkevm_opcode_defs::decoding::*;
    let nop_encoding = EncodingModeProduction::exception_revert_encoding();
    let low = nop_encoding as u32;
    let low = UInt32::allocated_constant(cs, low);
    let high = (nop_encoding >> 32) as u32;
    let high = UInt32::allocated_constant(cs, high);

    <[UInt32<F>; 2]>::conditionally_select(cs, should_mask, &[low, high], &opcode)
}

pub(crate) const SUB_PC_BITS: usize = 2;
pub(crate) const SUB_PC_MASK: u16 = (1u16 << SUB_PC_BITS) - 1;

pub(crate) fn split_pc<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    pc: UInt16<F>,
) -> (UInt16<F>, Num<F>) {
    let outputs = cs.alloc_multiple_variables_without_values::<2>();

    if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
        let value_fn = move |inputs: [F; 1]| {
            let mut as_u64 = inputs[0].as_u64();
            let sub_pc = as_u64 & (SUB_PC_MASK as u64);
            as_u64 >>= SUB_PC_BITS;
            let super_pc = as_u64;

            [
                F::from_u64_unchecked(sub_pc),
                F::from_u64_unchecked(super_pc),
            ]
        };

        let dependencies = Place::from_variables([pc.get_variable()]);

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
                linear_term_coeff: F::from_u64_unchecked(1u64 << SUB_PC_BITS),
            };
            gate.rhs_part = pc.get_variable();

            gate.add_to_cs(cs);
        } else {
            unimplemented!()
        }
    }

    let super_pc = UInt16::from_variable_checked(cs, outputs[1]);

    use crate::tables::integer_to_boolean_mask::VMSubPCToBitmaskTable;
    let table_id = cs
        .get_table_id_for_marker::<VMSubPCToBitmaskTable>()
        .expect("table must be added before");

    let vals = cs.perform_lookup::<1, 2>(table_id, &[outputs[0]]);
    let bitspread = vals[0];
    let bitspread = Num::from_variable(bitspread);

    (super_pc, bitspread)
}

#[inline]
pub(crate) fn should_read_memory<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    previous_code_page: UInt32<F>,
    current_code_page: UInt32<F>,
    super_pc: UInt16<F>,
    previous_super_pc: UInt16<F>,
) -> Boolean<F> {
    let code_pages_are_equal = UInt32::equals(cs, &previous_code_page, &current_code_page);
    let super_pc_are_equal = UInt16::equals(cs, &super_pc, &previous_super_pc);

    let can_skip = Boolean::multi_and(cs, &[code_pages_are_equal, super_pc_are_equal]);

    can_skip.negated(cs)
}

use crate::base_structures::vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH;
use crate::main_vm::pre_state::MemoryLocation;
use crate::main_vm::witness_oracle::WitnessOracle;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;

/// NOTE: final state is one if we INDEED READ, so extra care should be taken to select and preserve markers
/// if we ever need it or not
pub(crate) fn may_be_read_memory_for_code<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4>,
    W: WitnessOracle<F>,
>(
    cs: &mut CS,
    should_access: Boolean<F>,
    timestamp: UInt32<F>,
    location: MemoryLocation<F>,
    current_memory_sponge_state: [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
    current_memory_sponge_length: UInt32<F>,
    _round_function: &R,
    witness_oracle: &SynchronizedWitnessOracle<F, W>,
) -> (
    UInt256<F>,
    ([Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH], UInt32<F>),
) {
    if crate::config::CIRCUIT_VERSOBE {
        if should_access.witness_hook(&*cs)().unwrap() {
            println!("Will read 32-byte word for opcode");
            // dbg!(timestamp.witness_hook(&*cs)().unwrap());
            // dbg!(location.witness_hook(&*cs)().unwrap());
        }
    }

    let MemoryLocation { page, index } = location;

    let witness_oracle = witness_oracle.clone();
    let memory_value = MemoryValue::allocate_from_closure_and_dependencies_non_pointer(
        cs,
        move |inputs: &[F]| {
            debug_assert_eq!(inputs.len(), 4);
            let timestamp = inputs[0].as_u64() as u32;
            let memory_page = inputs[1].as_u64() as u32;
            let index = inputs[2].as_u64() as u32;
            debug_assert!(inputs[3].as_u64() == 0 || inputs[3].as_u64() == 1);
            let should_access = if inputs[3].as_u64() == 0 { false } else { true };

            let mut guard = witness_oracle.inner.write().expect("not poisoned");
            let witness =
                guard.get_memory_witness_for_read(timestamp, memory_page, index, should_access);
            drop(guard);

            witness
        },
        &[
            timestamp.get_variable().into(),
            page.get_variable().into(),
            index.get_variable().into(),
            should_access.get_variable().into(),
        ],
    );

    let boolean_false = Boolean::allocated_constant(cs, false);

    let query = MemoryQuery {
        timestamp,
        memory_page: page,
        index,
        is_ptr: memory_value.is_ptr,
        value: memory_value.value,
        rw_flag: boolean_false,
    };

    let packed_query = query.encode(cs);

    // this is absorb with replacement
    let initial_state = [
        packed_query[0],
        packed_query[1],
        packed_query[2],
        packed_query[3],
        packed_query[4],
        packed_query[5],
        packed_query[6],
        packed_query[7],
        current_memory_sponge_state[8].get_variable(),
        current_memory_sponge_state[9].get_variable(),
        current_memory_sponge_state[10].get_variable(),
        current_memory_sponge_state[11].get_variable(),
    ];

    let final_state_candidate = R::compute_round_function(cs, initial_state);
    let final_state_candidate = final_state_candidate.map(|el| Num::from_variable(el));

    // for all reasonable execution traces it's fine
    let new_len_candidate = unsafe { current_memory_sponge_length.increment_unchecked(cs) };

    let new_length = UInt32::conditionally_select(
        cs,
        should_access,
        &new_len_candidate,
        &current_memory_sponge_length,
    );

    let final_state = Num::parallel_select(
        cs,
        should_access,
        &final_state_candidate,
        &current_memory_sponge_state,
    );

    (memory_value.value, (final_state, new_length))
}

use zkevm_opcode_defs::ImmMemHandlerFlags;

pub fn resolve_memory_region_and_index_for_source<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    code_page: UInt32<F>,
    stack_page: UInt32<F>,
    register_low_value: UInt16<F>,
    opcode_props: &OpcodePropertiesDecoding<F>,
    current_sp: UInt16<F>,
) -> (MemoryLocation<F>, UInt16<F>, Boolean<F>) {
    // we assume that we did quickly select low part of the register before somehow, so we

    let use_code = opcode_props
        .properties_bits
        .boolean_for_src_mem_access(ImmMemHandlerFlags::UseCodePage);
    let use_stack_absolute = opcode_props
        .properties_bits
        .boolean_for_src_mem_access(ImmMemHandlerFlags::UseAbsoluteOnStack);
    let use_stack_relative = opcode_props
        .properties_bits
        .boolean_for_src_mem_access(ImmMemHandlerFlags::UseStackWithOffset);
    let use_stack_with_push_pop = opcode_props
        .properties_bits
        .boolean_for_src_mem_access(ImmMemHandlerFlags::UseStackWithPushPop);

    let absolute_mode = Boolean::multi_or(cs, &[use_code, use_stack_absolute]);
    let (index_for_absolute, _) = register_low_value.overflowing_add(cs, &opcode_props.imm0);
    let (index_for_relative, _) = current_sp.overflowing_sub(cs, &index_for_absolute);

    // if we use absolute addressing then we just access reg + imm mod 2^16
    // if we use relative addressing then we access sp +/- (reg + imm), and if we push/pop then we update sp to such value

    // here we only read

    // manually unrolled selection. We KNOW that either we will not care about this particular value,
    // or one of the bits here was set anyway

    let use_stack = Boolean::multi_or(
        cs,
        &[
            use_stack_absolute,
            use_stack_relative,
            use_stack_with_push_pop,
        ],
    );
    let did_read = Boolean::multi_or(cs, &[use_stack, use_code]);
    // we have a special rule for NOP opcode: if we NOP then even though we CAN formally address the memory we SHOULD NOT read
    let is_nop = opcode_props
        .properties_bits
        .boolean_for_opcode(zkevm_opcode_defs::Opcode::Nop(zkevm_opcode_defs::NopOpcode));

    let not_nop = is_nop.negated(cs);
    let did_read = Boolean::multi_and(cs, &[did_read, not_nop]);
    let page = UInt32::conditionally_select(cs, use_stack, &stack_page, &code_page);

    let index =
        UInt16::conditionally_select(cs, absolute_mode, &index_for_absolute, &index_for_relative);

    let new_sp = UInt16::conditionally_select(
        cs,
        use_stack_with_push_pop,
        &index_for_relative,
        &current_sp,
    );
    let location = MemoryLocation {
        page,
        index: unsafe { UInt32::from_variable_unchecked(index.get_variable()) },
    };

    (location, new_sp, did_read)
}

pub fn resolve_memory_region_and_index_for_dest<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    stack_page: UInt32<F>,
    register_low_value: UInt16<F>,
    opcode_props: &OpcodePropertiesDecoding<F>,
    current_sp: UInt16<F>,
) -> (MemoryLocation<F>, UInt16<F>, Boolean<F>) {
    // we assume that we did quickly select low part of the register before somehow, so we

    let use_stack_absolute = opcode_props
        .properties_bits
        .boolean_for_dst_mem_access(ImmMemHandlerFlags::UseAbsoluteOnStack);
    let use_stack_relative = opcode_props
        .properties_bits
        .boolean_for_dst_mem_access(ImmMemHandlerFlags::UseStackWithOffset);
    let use_stack_with_push_pop = opcode_props
        .properties_bits
        .boolean_for_dst_mem_access(ImmMemHandlerFlags::UseStackWithPushPop);

    let absolute_mode = use_stack_absolute;
    let (index_for_absolute, _) = register_low_value.overflowing_add(cs, &opcode_props.imm1);
    let (index_for_relative_with_push, _) = current_sp.overflowing_add(cs, &index_for_absolute);
    let (index_for_relative, _) = current_sp.overflowing_sub(cs, &index_for_absolute);

    // if we use absolute addressing then we just access reg + imm mod 2^16
    // if we use relative addressing then we access sp +/- (reg + imm), and if we push/pop then we update sp

    // here we only write

    // manually unrolled selection. We KNOW that either we will not care about this particular value,
    // or one of the bits here was set anyway

    let page = stack_page;
    let did_write = Boolean::multi_or(
        cs,
        &[
            use_stack_absolute,
            use_stack_relative,
            use_stack_with_push_pop,
        ],
    );
    // we have a special rule for NOP opcode: if we NOP then even though we CAN formally address the memory we SHOULD NOT write
    let is_nop = opcode_props
        .properties_bits
        .boolean_for_opcode(zkevm_opcode_defs::Opcode::Nop(zkevm_opcode_defs::NopOpcode));

    let not_nop = is_nop.negated(cs);
    let did_write = Boolean::multi_and(cs, &[did_write, not_nop]);

    let index_with_somewhat_relative_addressing = UInt16::conditionally_select(
        cs,
        use_stack_with_push_pop,
        &index_for_relative_with_push,
        &index_for_relative,
    );

    let index = UInt16::conditionally_select(
        cs,
        absolute_mode,
        &index_for_absolute,
        &index_with_somewhat_relative_addressing,
    );

    let new_sp = UInt16::conditionally_select(
        cs,
        use_stack_with_push_pop,
        &index_for_relative_with_push,
        &current_sp,
    );

    let location = MemoryLocation {
        page,
        index: unsafe { UInt32::from_variable_unchecked(index.get_variable()) },
    };

    (location, new_sp, did_write)
}

/// NOTE: final state is one if we INDEED READ, so extra care should be taken to select and preserve markers
/// if we ever need it or not
pub fn may_be_read_memory_for_source_operand<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
    W: WitnessOracle<F>,
>(
    cs: &mut CS,
    should_access: Boolean<F>,
    timestamp: UInt32<F>,
    location: MemoryLocation<F>,
    current_memory_sponge_state: [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
    current_memory_sponge_length: UInt32<F>,
    _round_function: &R,
    witness_oracle: &SynchronizedWitnessOracle<F, W>,
) -> (
    VMRegister<F>,
    (
        [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
        [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
        UInt32<F>,
        Boolean<F>,
    ),
) {
    if crate::config::CIRCUIT_VERSOBE {
        if should_access.witness_hook(&*cs)().unwrap() {
            println!("Will read SRC0 from memory");
            dbg!(timestamp.witness_hook(&*cs)().unwrap());
            dbg!(location.witness_hook(&*cs)().unwrap());
        }
    }

    let MemoryLocation { page, index } = location;

    let witness_oracle = witness_oracle.clone();
    let memory_value = MemoryValue::allocate_from_closure_and_dependencies(
        cs,
        move |inputs: &[F]| {
            debug_assert_eq!(inputs.len(), 4);
            let timestamp = inputs[0].as_u64() as u32;
            let memory_page = inputs[1].as_u64() as u32;
            let index = inputs[2].as_u64() as u32;
            debug_assert!(inputs[3].as_u64() == 0 || inputs[3].as_u64() == 1);
            let should_access = if inputs[3].as_u64() == 0 { false } else { true };

            let mut guard = witness_oracle.inner.write().expect("not poisoned");
            let witness =
                guard.get_memory_witness_for_read(timestamp, memory_page, index, should_access);
            drop(guard);

            witness
        },
        &[
            timestamp.get_variable().into(),
            page.get_variable().into(),
            index.get_variable().into(),
            should_access.get_variable().into(),
        ],
    );

    let boolean_false = Boolean::allocated_constant(cs, false);

    let query = MemoryQuery {
        timestamp,
        memory_page: page,
        index,
        is_ptr: memory_value.is_ptr,
        value: memory_value.value,
        rw_flag: boolean_false,
    };

    let packed_query = query.encode(cs);

    use boojum::gadgets::queue::full_state_queue::simulate_new_tail_for_full_state_queue;

    use crate::base_structures::memory_query::MEMORY_QUERY_PACKED_WIDTH;

    let simulated_values = simulate_new_tail_for_full_state_queue::<
        F,
        8,
        FULL_SPONGE_QUEUE_STATE_WIDTH,
        4,
        MEMORY_QUERY_PACKED_WIDTH,
        R,
        _,
    >(
        cs,
        packed_query,
        current_memory_sponge_state.map(|el| el.get_variable()),
        should_access,
    );

    let initial_state = [
        Num::from_variable(packed_query[0]),
        Num::from_variable(packed_query[1]),
        Num::from_variable(packed_query[2]),
        Num::from_variable(packed_query[3]),
        Num::from_variable(packed_query[4]),
        Num::from_variable(packed_query[5]),
        Num::from_variable(packed_query[6]),
        Num::from_variable(packed_query[7]),
        current_memory_sponge_state[8],
        current_memory_sponge_state[9],
        current_memory_sponge_state[10],
        current_memory_sponge_state[11],
    ];

    let simulated_final_state = simulated_values.map(|el| Num::from_variable(el));

    // for all reasonable execution traces it's fine
    let new_len_candidate = unsafe { current_memory_sponge_length.increment_unchecked(cs) };

    let new_length = UInt32::conditionally_select(
        cs,
        should_access,
        &new_len_candidate,
        &current_memory_sponge_length,
    );

    let final_state = Num::parallel_select(
        cs,
        should_access,
        &simulated_final_state,
        &current_memory_sponge_state,
    );

    let as_register = VMRegister {
        is_pointer: memory_value.is_ptr,
        value: memory_value.value,
    };

    (
        as_register,
        (initial_state, final_state, new_length, should_access),
    )
}
