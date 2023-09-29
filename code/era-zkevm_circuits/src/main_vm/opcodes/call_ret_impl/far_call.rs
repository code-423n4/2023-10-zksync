use zkevm_opcode_defs::system_params::STORAGE_AUX_BYTE;

use crate::base_structures::{
    log_query::{self, LogQuery},
    register::VMRegister,
    vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH,
};
use boojum::gadgets::{u160::UInt160, u256::UInt256};

use super::*;
use crate::base_structures::decommit_query::DecommitQuery;
use crate::base_structures::decommit_query::DecommitQueryWitness;
use crate::base_structures::vm_state::saved_context::ExecutionContextRecord;
use crate::base_structures::vm_state::saved_context::ExecutionContextRecordWitness;
use crate::base_structures::vm_state::GlobalContext;
use crate::base_structures::vm_state::QUEUE_STATE_WIDTH;
use crate::main_vm::opcodes::call_ret_impl::far_call::log_query::LogQueryWitness;
use crate::main_vm::state_diffs::MAX_SPONGES_PER_CYCLE;
use crate::main_vm::witness_oracle::SynchronizedWitnessOracle;
use crate::main_vm::witness_oracle::WitnessOracle;
use arrayvec::ArrayVec;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::cs::traits::cs::DstBuffer;
use boojum::gadgets::traits::allocatable::CSAllocatable;
use boojum::gadgets::traits::allocatable::CSAllocatableExt;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;

const FORCED_ERGS_FOR_MSG_VALUE_SIMUALTOR: bool = false;

pub(crate) struct FarCallData<F: SmallField> {
    pub(crate) apply_far_call: Boolean<F>,
    pub(crate) old_context: ExecutionContextRecord<F>,
    pub(crate) new_context: ExecutionContextRecord<F>,
    pub(crate) new_decommittment_queue_tail: [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
    pub(crate) new_decommittment_queue_len: UInt32<F>,
    pub(crate) new_forward_queue_tail: [Num<F>; QUEUE_STATE_WIDTH],
    pub(crate) new_forward_queue_len: UInt32<F>,
    pub(crate) pending_sponges: ArrayVec<
        (
            Boolean<F>,
            [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
            [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
        ),
        MAX_SPONGES_PER_CYCLE,
    >,
    pub(crate) specific_registers_updates: [Option<(Boolean<F>, VMRegister<F>)>; REGISTERS_COUNT],
    pub(crate) specific_registers_zeroing: [Option<Boolean<F>>; REGISTERS_COUNT],
    pub(crate) remove_ptr_on_specific_registers: [Option<Boolean<F>>; REGISTERS_COUNT],
    pub(crate) pending_exception: Boolean<F>,
    pub(crate) new_memory_pages_counter: UInt32<F>,
}

#[derive(Derivative, CSAllocatable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]

pub(crate) struct FarCallPartialABI<F: SmallField> {
    pub(crate) ergs_passed: UInt32<F>,
    pub(crate) shard_id: UInt8<F>,
    pub(crate) constructor_call: Boolean<F>,
    pub(crate) system_call: Boolean<F>,
}

use crate::main_vm::register_input_view::RegisterInputView;

impl<F: SmallField> FarCallPartialABI<F> {
    pub fn from_register_view<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        input: &RegisterInputView<F>,
    ) -> Self {
        // low part of highest 64 bits
        let ergs_passed = input.u32x8_view[6];

        // higher parts of highest 64 bits
        let shard_id = input.u8x32_view
            [zkevm_opcode_defs::definitions::abi::far_call::FAR_CALL_SHARD_ID_BYTE_IDX];
        let constructor_call = input.u8x32_view
            [zkevm_opcode_defs::definitions::abi::far_call::FAR_CALL_CONSTRUCTOR_CALL_BYTE_IDX]
            .is_zero(cs)
            .negated(cs);
        let system_call = input.u8x32_view
            [zkevm_opcode_defs::definitions::abi::far_call::FAR_CALL_SYSTEM_CALL_BYTE_IDX]
            .is_zero(cs)
            .negated(cs);

        let new = Self {
            ergs_passed,
            shard_id,
            constructor_call,
            system_call,
        };

        new
    }
}

#[derive(Derivative, CSAllocatable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]

pub(crate) struct CommonCallRetABI<F: SmallField> {
    pub(crate) fat_ptr: FatPtrInABI<F>,
    pub(crate) upper_bound: UInt32<F>,
    pub(crate) ptr_validation_data: PtrValidationData<F>,
}

#[derive(Derivative, CSAllocatable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]

pub(crate) struct CallRetForwardingMode<F: SmallField> {
    pub(crate) use_heap: Boolean<F>,
    pub(crate) use_aux_heap: Boolean<F>,
    pub(crate) forward_fat_pointer: Boolean<F>,
}

#[derive(Derivative, CSAllocatable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
pub(crate) struct FatPtrInABI<F: SmallField> {
    pub(crate) offset: UInt32<F>,
    pub(crate) page: UInt32<F>,
    pub(crate) start: UInt32<F>,
    pub(crate) length: UInt32<F>,
}

impl<F: SmallField> Selectable<F> for FatPtrInABI<F> {
    fn conditionally_select<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        flag: Boolean<F>,
        a: &Self,
        b: &Self,
    ) -> Self {
        // do via multiselect
        let a = [a.offset, a.page, a.start, a.length];
        let b = [b.offset, b.page, b.start, b.length];

        let result = UInt32::parallel_select(cs, flag, &a, &b);

        Self {
            offset: result[0],
            page: result[1],
            start: result[2],
            length: result[3],
        }
    }
}

#[derive(Derivative, CSAllocatable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
pub(crate) struct PtrValidationData<F: SmallField> {
    pub(crate) generally_invalid: Boolean<F>, // common invariants
    pub(crate) is_non_addressable: Boolean<F>,
}

impl<F: SmallField> FatPtrInABI<F> {
    pub(crate) fn parse_and_validate<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        input: &RegisterInputView<F>,
        as_fresh: Boolean<F>,
    ) -> (Self, UInt32<F>, PtrValidationData<F>) {
        // we can never address a range [2^32 - 32..2^32] this way, but we don't care because
        // it's impossible to pay for such memory growth
        let offset = input.u32x8_view[0];
        let page = input.u32x8_view[1];
        let start = input.u32x8_view[2];
        let length = input.u32x8_view[3];

        let offset_is_zero = offset.is_zero(cs);
        let offset_is_non_zero = offset_is_zero.negated(cs);

        let non_zero_offset_if_should_be_fresh =
            Boolean::multi_and(cs, &[offset_is_non_zero, as_fresh]);

        let (end_non_inclusive, slice_u32_range_overflow) = start.overflowing_add(cs, length);

        // offset <= length, that captures the empty slice (0, 0)
        let (_, is_invalid_as_slice) = length.overflowing_sub(cs, offset);

        let ptr_is_invalid = Boolean::multi_or(
            cs,
            &[
                non_zero_offset_if_should_be_fresh,
                slice_u32_range_overflow,
                is_invalid_as_slice,
            ],
        );

        let offset = offset.mask_negated(cs, ptr_is_invalid);
        let page = page.mask_negated(cs, ptr_is_invalid);
        let start = start.mask_negated(cs, ptr_is_invalid);
        let length = length.mask_negated(cs, ptr_is_invalid);

        let new = Self {
            offset,
            page,
            start,
            length,
        };

        let validation_data = PtrValidationData {
            generally_invalid: ptr_is_invalid,
            is_non_addressable: slice_u32_range_overflow,
        };

        (new, end_non_inclusive, validation_data)
    }

    pub(crate) fn mask_into_empty<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        set_empty: Boolean<F>,
    ) -> Self {
        let offset = self.offset.mask_negated(cs, set_empty);
        let page = self.page.mask_negated(cs, set_empty);
        let start = self.start.mask_negated(cs, set_empty);
        let length = self.length.mask_negated(cs, set_empty);

        let new = Self {
            offset,
            page,
            start,
            length,
        };

        new
    }

    // ONLY call after validations
    pub(crate) fn readjust<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Self {
        // if we have prevalidated everything, then we KNOW that "length + start" doesn't overflow and is within addressable bound,
        // and that offset < length, so overflows here can be ignored
        let new_start = self.start.add_no_overflow(cs, self.offset);
        let new_length = self.length.sub_no_overflow(cs, self.offset);

        let zero_u32 = UInt32::zero(cs);

        let new = Self {
            offset: zero_u32,
            page: self.page,
            start: new_start,
            length: new_length,
        };

        new
    }

    pub(crate) fn into_register<CS: ConstraintSystem<F>>(self, cs: &mut CS) -> VMRegister<F> {
        let zero_u32 = UInt32::zero(cs);
        let boolean_true = Boolean::allocated_constant(cs, true);

        let result = VMRegister {
            is_pointer: boolean_true,
            value: UInt256 {
                inner: [
                    self.offset,
                    self.page,
                    self.start,
                    self.length,
                    zero_u32,
                    zero_u32,
                    zero_u32,
                    zero_u32,
                ],
            },
        };

        result
    }
}

pub(crate) fn callstack_candidate_for_far_call<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
    W: WitnessOracle<F>,
>(
    cs: &mut CS,
    draft_vm_state: &VmLocalState<F>,
    common_opcode_state: &CommonOpcodeState<F>,
    opcode_carry_parts: &AfterDecodingCarryParts<F>,
    witness_oracle: &SynchronizedWitnessOracle<F, W>,
    global_context: &GlobalContext<F>,
    common_abi_parts: &CommonCallRetABI<F>,
    far_call_abi: &FarCallPartialABI<F>,
    forwarding_data: &CallRetForwardingMode<F>,
    round_function: &R,
) -> FarCallData<F>
where
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    // new callstack should be just the same a the old one, but we also need to update the pricing for pubdata in the rare case

    const FAR_CALL_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::FarCall(zkevm_opcode_defs::FarCallOpcode::Normal);

    let execute = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_opcode(FAR_CALL_OPCODE);

    if crate::config::CIRCUIT_VERSOBE {
        if (execute.witness_hook(&*cs))().unwrap_or(false) {
            println!("Applying FAR CALL");
        }
    }

    let _is_normal_call = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(zkevm_opcode_defs::Opcode::FarCall(
            zkevm_opcode_defs::FarCallOpcode::Normal,
        ));
    let is_delegated_call = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(zkevm_opcode_defs::Opcode::FarCall(
            zkevm_opcode_defs::FarCallOpcode::Delegate,
        ));
    let is_mimic_call = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(zkevm_opcode_defs::Opcode::FarCall(
            zkevm_opcode_defs::FarCallOpcode::Mimic,
        ));

    let is_kernel_mode = draft_vm_state
        .callstack
        .current_context
        .saved_context
        .is_kernel_mode;
    let mut current_callstack_entry = draft_vm_state.callstack.current_context.saved_context;
    // perform all known modifications, like PC/SP saving
    current_callstack_entry.pc = opcode_carry_parts.next_pc;

    // we need a completely fresh one
    let mut new_callstack_entry = ExecutionContextRecord::uninitialized(cs);
    // apply memory stipends right away
    new_callstack_entry.heap_upper_bound = UInt32::allocated_constant(
        cs,
        zkevm_opcode_defs::system_params::NEW_FRAME_MEMORY_STIPEND,
    );
    new_callstack_entry.aux_heap_upper_bound = UInt32::allocated_constant(
        cs,
        zkevm_opcode_defs::system_params::NEW_FRAME_MEMORY_STIPEND,
    );

    // now also create target for mimic
    let implicit_mimic_call_reg = draft_vm_state.registers
        [zkevm_opcode_defs::definitions::far_call::CALL_IMPLICIT_PARAMETER_REG_IDX as usize];

    // - get code destination address
    // - resolve caller/callee dependencies
    // - resolve calldata page
    // - resolve ergs

    let caller_address_for_mimic = UInt160 {
        inner: [
            implicit_mimic_call_reg.value.inner[0],
            implicit_mimic_call_reg.value.inner[1],
            implicit_mimic_call_reg.value.inner[2],
            implicit_mimic_call_reg.value.inner[3],
            implicit_mimic_call_reg.value.inner[4],
        ],
    };

    // in src0 lives the ABI
    // in src1 lives the destination

    // we also reuse pre-parsed ABI

    // src1 is target address
    let destination_address = UInt160 {
        inner: [
            common_opcode_state.src1_view.u32x8_view[0],
            common_opcode_state.src1_view.u32x8_view[1],
            common_opcode_state.src1_view.u32x8_view[2],
            common_opcode_state.src1_view.u32x8_view[3],
            common_opcode_state.src1_view.u32x8_view[4],
        ],
    };

    let is_static_call = common_opcode_state
        .decoded_opcode
        .properties_bits
        .flag_booleans[FAR_CALL_STATIC_FLAG_IDX];
    let is_call_shard = common_opcode_state
        .decoded_opcode
        .properties_bits
        .flag_booleans[FAR_CALL_SHARD_FLAG_IDX];

    let destination_shard = far_call_abi.shard_id;
    let caller_shard_id = current_callstack_entry.this_shard_id;
    let destination_shard =
        UInt8::conditionally_select(cs, is_call_shard, &destination_shard, &caller_shard_id);
    let target_is_zkporter = destination_shard.is_zero(cs).negated(cs);

    let target_is_kernel = {
        let destination_16_32 = UInt16::from_le_bytes(
            cs,
            [
                common_opcode_state.src1_view.u8x32_view[2],
                common_opcode_state.src1_view.u8x32_view[3],
            ],
        );

        let destination_16_32_is_zero = destination_16_32.is_zero(cs);
        let destination_32_64_is_zero = common_opcode_state.src1_view.u32x8_view[1].is_zero(cs);
        let destination_64_96_is_zero = common_opcode_state.src1_view.u32x8_view[2].is_zero(cs);
        let destination_96_128_is_zero = common_opcode_state.src1_view.u32x8_view[3].is_zero(cs);
        let destination_128_160_is_zero = common_opcode_state.src1_view.u32x8_view[4].is_zero(cs);

        let higher_bytes_are_zeroes = Boolean::multi_and(
            cs,
            &[
                destination_16_32_is_zero,
                destination_32_64_is_zero,
                destination_64_96_is_zero,
                destination_96_128_is_zero,
                destination_128_160_is_zero,
            ],
        );

        higher_bytes_are_zeroes
    };

    let mut far_call_abi = *far_call_abi;

    // mask flags in ABI if not applicable
    far_call_abi.constructor_call =
        Boolean::multi_and(cs, &[far_call_abi.constructor_call, is_kernel_mode]);
    far_call_abi.system_call =
        Boolean::multi_and(cs, &[far_call_abi.system_call, target_is_kernel]);

    if crate::config::CIRCUIT_VERSOBE {
        if execute.witness_hook(&*cs)().unwrap_or(false) {
            dbg!(forwarding_data.witness_hook(&*cs)().unwrap());
            dbg!(far_call_abi.witness_hook(&*cs)().unwrap());
        }
    }

    // the same as we use for LOG
    let timestamp_to_use_for_decommittment_request =
        common_opcode_state.timestamp_for_first_decommit_or_precompile_read;
    let default_target_memory_page = draft_vm_state.memory_page_counter;

    // increment next counter
    let new_base_page = draft_vm_state.memory_page_counter;
    let memory_pages_per_far_call = UInt32::allocated_constant(cs, NEW_MEMORY_PAGES_PER_FAR_CALL);
    let new_memory_pages_counter = draft_vm_state
        .memory_page_counter
        .add_no_overflow(cs, memory_pages_per_far_call);

    let new_memory_pages_counter = UInt32::conditionally_select(
        cs,
        execute,
        &new_memory_pages_counter,
        &draft_vm_state.memory_page_counter,
    );

    // now we have everything to perform code read and decommittment

    let mut all_pending_sponges = ArrayVec::new();

    let (bytecode_hash_is_trivial, bytecode_hash, (new_forward_queue_tail, new_forward_queue_len)) =
        may_be_read_code_hash(
            cs,
            &mut all_pending_sponges,
            &destination_address,
            &destination_shard,
            &target_is_zkporter,
            &global_context.zkporter_is_available,
            &execute,
            &global_context.default_aa_code_hash,
            &target_is_kernel,
            draft_vm_state
                .callstack
                .current_context
                .log_queue_forward_tail,
            draft_vm_state
                .callstack
                .current_context
                .log_queue_forward_part_length,
            timestamp_to_use_for_decommittment_request,
            draft_vm_state.tx_number_in_block,
            witness_oracle,
            round_function,
        );

    // now we should do validation BEFORE decommittment

    let zero_u32 = UInt32::zero(cs);

    let target_code_memory_page = UInt32::conditionally_select(
        cs,
        bytecode_hash_is_trivial,
        &zero_u32,
        &default_target_memory_page,
    );

    // first we validate if code hash is indeed in the format that we expect

    // If we do not do "constructor call" then 2nd byte should be 0,
    // otherwise it's 1

    let bytecode_hash_upper_decomposition = bytecode_hash.inner[7].decompose_into_bytes(cs);

    let version_byte = bytecode_hash_upper_decomposition[3];
    let code_hash_version_byte =
        UInt8::allocated_constant(cs, zkevm_opcode_defs::ContractCodeSha256::VERSION_BYTE);
    let versioned_byte_is_valid = UInt8::equals(cs, &version_byte, &code_hash_version_byte);
    let versioned_byte_is_invalid = versioned_byte_is_valid.negated(cs);

    let marker_byte = bytecode_hash_upper_decomposition[2];
    let is_normal_call_marker = marker_byte.is_zero(cs);
    let now_in_construction_marker_byte = UInt8::allocated_constant(
        cs,
        zkevm_opcode_defs::ContractCodeSha256::YET_CONSTRUCTED_MARKER,
    );
    let is_constructor_call_marker =
        UInt8::equals(cs, &marker_byte, &now_in_construction_marker_byte);
    let unknown_marker =
        Boolean::multi_or(cs, &[is_normal_call_marker, is_constructor_call_marker]).negated(cs);

    // NOTE: if bytecode hash is trivial then it's 0, so version byte is not valid!
    let code_format_exception = Boolean::multi_or(cs, &[versioned_byte_is_invalid, unknown_marker]);

    // we do not remask right away yet

    let normal_call_code = far_call_abi.constructor_call.negated(cs);

    let can_call_normally = Boolean::multi_and(cs, &[is_normal_call_marker, normal_call_code]);
    let can_call_constructor = Boolean::multi_and(
        cs,
        &[is_constructor_call_marker, far_call_abi.constructor_call],
    );
    let can_call_code = Boolean::multi_or(cs, &[can_call_normally, can_call_constructor]);

    let marker_byte_masked = UInt8::allocated_constant(
        cs,
        zkevm_opcode_defs::ContractCodeSha256::CODE_AT_REST_MARKER,
    );

    let bytecode_at_rest_top_word = UInt32::from_le_bytes(
        cs,
        [
            bytecode_hash_upper_decomposition[0],
            bytecode_hash_upper_decomposition[1],
            marker_byte_masked,
            code_hash_version_byte,
        ],
    );

    let mut bytecode_at_storage_format = bytecode_hash;
    bytecode_at_storage_format.inner[7] = bytecode_at_rest_top_word;

    let zero_u256 = UInt256::zero(cs);

    let masked_value_if_mask = UInt256::conditionally_select(
        cs,
        target_is_kernel,
        &zero_u256,
        &global_context.default_aa_code_hash,
    );

    let masked_bytecode_hash = UInt256::conditionally_select(
        cs,
        can_call_code,
        &bytecode_at_storage_format,
        &masked_value_if_mask,
    );

    // at the end of the day all our exceptions will lead to memory page being 0

    let masked_bytecode_hash_upper_decomposition =
        masked_bytecode_hash.inner[7].decompose_into_bytes(cs);

    let mut code_hash_length_in_words = UInt16::from_le_bytes(
        cs,
        [
            masked_bytecode_hash_upper_decomposition[0],
            masked_bytecode_hash_upper_decomposition[1],
        ],
    );
    code_hash_length_in_words = code_hash_length_in_words.mask_negated(cs, code_format_exception);

    // if we call now-in-construction system contract, then we formally mask into 0 (even though it's not needed),
    // and we should put an exception here

    let can_not_call_code = can_call_code.negated(cs);
    let call_now_in_construction_kernel =
        Boolean::multi_and(cs, &[can_not_call_code, target_is_kernel]);

    // exceptions, along with `bytecode_hash_is_trivial` indicate whether we will or will decommit code
    // into memory, or will just use UNMAPPED_PAGE
    let mut exceptions = ArrayVec::<Boolean<F>, 5>::new();
    exceptions.push(code_format_exception);
    exceptions.push(call_now_in_construction_kernel);

    // resolve passed ergs, passed calldata page, etc

    let forward_fat_pointer = forwarding_data.forward_fat_pointer;
    let src0_is_integer = common_opcode_state.src0_view.is_ptr.negated(cs);

    let fat_ptr_expected_exception =
        Boolean::multi_and(cs, &[forward_fat_pointer, src0_is_integer]);
    exceptions.push(fat_ptr_expected_exception);

    // add pointer validation cases
    exceptions.push(common_abi_parts.ptr_validation_data.generally_invalid);
    exceptions.push(common_abi_parts.ptr_validation_data.is_non_addressable);

    let do_not_forward_ptr = forward_fat_pointer.negated(cs);

    let exceptions_collapsed = Boolean::multi_or(cs, &exceptions);

    // if crate::config::CIRCUIT_VERSOBE {
    //     if execute.witness_hook(&*cs)().unwrap() {
    //         dbg!(code_format_exception.witness_hook(&*cs)().unwrap());
    //         dbg!(call_now_in_construction_kernel.witness_hook(&*cs)().unwrap());
    //         dbg!(fat_ptr_expected_exception.witness_hook(&*cs)().unwrap());
    //     }
    // }

    let fat_ptr = common_abi_parts.fat_ptr;
    // we readjust before heap resize

    let fat_ptr_adjusted_if_forward = fat_ptr.readjust(cs);

    let page = UInt32::conditionally_select(
        cs,
        forwarding_data.use_heap,
        &opcode_carry_parts.heap_page,
        &opcode_carry_parts.aux_heap_page,
    );

    let fat_ptr_for_heaps = FatPtrInABI {
        offset: zero_u32,
        page,
        start: fat_ptr.start,
        length: fat_ptr.length,
    };

    let final_fat_ptr = FatPtrInABI::conditionally_select(
        cs,
        forwarding_data.forward_fat_pointer,
        &fat_ptr_adjusted_if_forward,
        &fat_ptr_for_heaps,
    );

    // and mask in case of exceptions

    let final_fat_ptr = final_fat_ptr.mask_into_empty(cs, exceptions_collapsed);

    if crate::config::CIRCUIT_VERSOBE {
        if execute.witness_hook(&*cs)().unwrap_or(false) {
            dbg!(final_fat_ptr.witness_hook(&*cs)().unwrap());
        }
    }

    // now we can resize memory

    let upper_bound = common_abi_parts.upper_bound;
    // first mask to 0 if exceptions happened
    let upper_bound = upper_bound.mask_negated(cs, exceptions_collapsed);
    // then compute to penalize for out of memory access attemp
    let memory_region_is_not_addressable = common_abi_parts.ptr_validation_data.is_non_addressable;

    // and penalize if pointer is fresh and not addressable
    let penalize_heap_overflow =
        Boolean::multi_and(cs, &[memory_region_is_not_addressable, do_not_forward_ptr]);
    let u32_max = UInt32::allocated_constant(cs, u32::MAX);

    let upper_bound =
        UInt32::conditionally_select(cs, penalize_heap_overflow, &u32_max, &upper_bound);

    // potentially pay for memory growth for heap and aux heap

    let heap_max_accessed = upper_bound.mask(cs, forwarding_data.use_heap);
    let heap_bound = current_callstack_entry.heap_upper_bound;
    let (mut heap_growth, uf) = heap_max_accessed.overflowing_sub(cs, heap_bound);
    heap_growth = heap_growth.mask_negated(cs, uf); // if we access in bounds then it's 0
    let new_heap_upper_bound =
        UInt32::conditionally_select(cs, uf, &heap_bound, &heap_max_accessed);
    let grow_heap = Boolean::multi_and(cs, &[forwarding_data.use_heap, execute]);

    let aux_heap_max_accessed = upper_bound.mask(cs, forwarding_data.use_aux_heap);
    let aux_heap_bound = current_callstack_entry.aux_heap_upper_bound;
    let (mut aux_heap_growth, uf) = aux_heap_max_accessed.overflowing_sub(cs, aux_heap_bound);
    aux_heap_growth = aux_heap_growth.mask_negated(cs, uf); // if we access in bounds then it's 0
    let new_aux_heap_upper_bound =
        UInt32::conditionally_select(cs, uf, &aux_heap_bound, &aux_heap_max_accessed);
    let grow_aux_heap = Boolean::multi_and(cs, &[forwarding_data.use_aux_heap, execute]);

    let mut growth_cost = heap_growth.mask(cs, grow_heap);
    growth_cost = UInt32::conditionally_select(cs, grow_aux_heap, &aux_heap_growth, &growth_cost);

    // if crate::config::CIRCUIT_VERSOBE {
    //     if execute.witness_hook(&*cs)().unwrap() {
    //         dbg!(opcode_carry_parts.preliminary_ergs_left.witness_hook(&*cs)().unwrap());
    //         dbg!(growth_cost.witness_hook(&*cs)().unwrap());
    //     }
    // }

    let (ergs_left_after_growth, uf) = opcode_carry_parts
        .preliminary_ergs_left
        .overflowing_sub(cs, growth_cost);

    let mut exceptions = ArrayVec::<Boolean<F>, 5>::new();
    exceptions.push(exceptions_collapsed);

    let ergs_left_after_growth = ergs_left_after_growth.mask_negated(cs, uf); // if not enough - set to 0
    exceptions.push(uf);

    // if crate::config::CIRCUIT_VERSOBE {
    //     if execute.witness_hook(&*cs)().unwrap() {
    //         dbg!(ergs_left_after_growth.witness_hook(&*cs)().unwrap());
    //     }
    // }

    current_callstack_entry.heap_upper_bound = UInt32::conditionally_select(
        cs,
        grow_heap,
        &new_heap_upper_bound,
        &current_callstack_entry.heap_upper_bound,
    );

    current_callstack_entry.aux_heap_upper_bound = UInt32::conditionally_select(
        cs,
        grow_aux_heap,
        &new_aux_heap_upper_bound,
        &current_callstack_entry.aux_heap_upper_bound,
    );

    // now any extra cost
    let callee_stipend = if FORCED_ERGS_FOR_MSG_VALUE_SIMUALTOR == false {
        zero_u32
    } else {
        let is_msg_value_simulator_address_low =
            UInt32::allocated_constant(cs, zkevm_opcode_defs::ADDRESS_MSG_VALUE as u32);
        let target_low_is_msg_value_simulator = UInt32::equals(
            cs,
            &destination_address.inner[0],
            &is_msg_value_simulator_address_low,
        );
        // we know that that msg.value simulator is kernel, so we test equality of low address segment and test for kernel
        let target_is_msg_value =
            Boolean::multi_and(cs, &[target_is_kernel, target_low_is_msg_value_simulator]);
        let is_system_abi = far_call_abi.system_call;
        let require_extra = Boolean::multi_and(cs, &[target_is_msg_value, is_system_abi]);

        let additive_cost = UInt32::allocated_constant(
            cs,
            zkevm_opcode_defs::system_params::MSG_VALUE_SIMULATOR_ADDITIVE_COST,
        );
        let max_pubdata_bytes = UInt32::allocated_constant(
            cs,
            zkevm_opcode_defs::system_params::MSG_VALUE_SIMULATOR_PUBDATA_BYTES_TO_PREPAY,
        );

        let pubdata_cost =
            max_pubdata_bytes.non_widening_mul(cs, &draft_vm_state.ergs_per_pubdata_byte);
        let cost = pubdata_cost.add_no_overflow(cs, additive_cost);

        cost.mask(cs, require_extra)
    };

    let (ergs_left_after_extra_costs, uf) =
        ergs_left_after_growth.overflowing_sub(cs, callee_stipend);
    let ergs_left_after_extra_costs = ergs_left_after_extra_costs.mask_negated(cs, uf); // if not enough - set to 0
    let callee_stipend = callee_stipend.mask_negated(cs, uf); // also set to 0 if we were not able to take it
    exceptions.push(uf);

    // now we can indeed decommit

    let exception = Boolean::multi_or(cs, &exceptions);
    let valid_execution = exception.negated(cs);
    let should_decommit = Boolean::multi_and(cs, &[execute, valid_execution]);

    let target_code_memory_page = target_code_memory_page.mask(cs, should_decommit);

    // if crate::config::CIRCUIT_VERSOBE {
    //     if execute.witness_hook(&*cs)().unwrap() {
    //         dbg!(exception.witness_hook(&*cs)().unwrap());
    //         dbg!(ergs_left_after_extra_costs.witness_hook(&*cs)().unwrap());
    //     }
    // }

    let (
        not_enough_ergs_to_decommit,
        code_memory_page,
        (new_decommittment_queue_tail, new_decommittment_queue_len),
        ergs_remaining_after_decommit,
    ) = add_to_decommittment_queue(
        cs,
        &mut all_pending_sponges,
        &should_decommit,
        &ergs_left_after_extra_costs,
        &masked_bytecode_hash,
        &code_hash_length_in_words,
        &draft_vm_state.code_decommittment_queue_state,
        &draft_vm_state.code_decommittment_queue_length,
        &timestamp_to_use_for_decommittment_request,
        &target_code_memory_page,
        witness_oracle,
        round_function,
    );

    let exception = Boolean::multi_or(cs, &[exception, not_enough_ergs_to_decommit]);

    if crate::config::CIRCUIT_VERSOBE {
        if execute.witness_hook(&*cs)().unwrap_or(false) {
            dbg!(exception.witness_hook(&*cs)().unwrap());
        }
    }

    // on call-like path we continue the forward queue, but have to allocate the rollback queue state from witness
    let call_timestamp = draft_vm_state.timestamp;

    let oracle = witness_oracle.clone();

    let dependencies = [
        call_timestamp.get_variable().into(),
        execute.get_variable().into(),
    ];

    // we always access witness, as even for writes we have to get a claimed read value!
    let potential_rollback_queue_segment_tail =
        Num::allocate_multiple_from_closure_and_dependencies(
            cs,
            move |inputs: &[F]| {
                let call_timestamp = <u32 as WitnessCastable<F, F>>::cast_from_source(inputs[0]);
                let execute = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[1]);

                let mut guard = oracle.inner.write().expect("not poisoned");
                let witness =
                    guard.get_rollback_queue_tail_witness_for_call(call_timestamp, execute);
                drop(guard);

                witness
            },
            &dependencies,
        );

    new_callstack_entry.reverted_queue_tail = potential_rollback_queue_segment_tail;
    new_callstack_entry.reverted_queue_head = potential_rollback_queue_segment_tail;
    new_callstack_entry.reverted_queue_segment_len = zero_u32;

    let dst_pc = UInt16::zero(cs);
    let eh_pc = common_opcode_state.decoded_opcode.imm0;

    // if crate::config::CIRCUIT_VERSOBE {
    //     if execute.witness_hook(&*cs)().unwrap() {
    //         dbg!(ergs_remaining_after_decommit.witness_hook(&*cs)().unwrap());
    //     }
    // }

    // now we should resolve all passed ergs. That means
    // that we have to read it from ABI, and then use 63/64 rule
    let preliminary_ergs_left = ergs_remaining_after_decommit;

    let (ergs_div_by_64, _) = preliminary_ergs_left.div_by_constant(cs, 64);

    let constant_63 = UInt32::allocated_constant(cs, 63);
    // NOTE: max passable is 63 / 64 * preliminary_ergs_left, that is itself u32, so it's safe to just
    // mul as field elements
    let max_passable = Num::from_variable(ergs_div_by_64.get_variable())
        .mul(cs, &Num::from_variable(constant_63.get_variable()));
    let max_passable = unsafe { UInt32::from_variable_unchecked(max_passable.get_variable()) };

    // max passable is <= preliminary_ergs_left from computations above, so it's also safe
    let leftover = Num::from_variable(preliminary_ergs_left.get_variable())
        .sub(cs, &Num::from_variable(max_passable.get_variable()));
    let leftover = unsafe { UInt32::from_variable_unchecked(leftover.get_variable()) };
    let ergs_to_pass = far_call_abi.ergs_passed;

    let (remaining_from_max_passable, uf) = max_passable.overflowing_sub(cs, ergs_to_pass);
    // this one can overflow IF one above underflows, but we are not interested in it's overflow value
    let (leftover_and_remaining_if_no_uf, _of) =
        leftover.overflowing_add(cs, remaining_from_max_passable);

    let ergs_to_pass = UInt32::conditionally_select(cs, uf, &max_passable, &ergs_to_pass);

    let remaining_for_this_context =
        UInt32::conditionally_select(cs, uf, &leftover, &leftover_and_remaining_if_no_uf);

    let remaining_ergs_if_pass = remaining_for_this_context;
    let passed_ergs_if_pass = ergs_to_pass;
    let passed_ergs_if_pass = passed_ergs_if_pass.add_no_overflow(cs, callee_stipend);

    current_callstack_entry.ergs_remaining = remaining_ergs_if_pass;

    // resolve this/callee shard
    let new_this_shard_id =
        UInt8::conditionally_select(cs, is_delegated_call, &caller_shard_id, &destination_shard);

    // default is normal call
    let mut this_for_next = destination_address;
    let mut caller_for_next = current_callstack_entry.this;

    // change if delegate or mimic
    // - "this" only changed if delegate
    this_for_next = UInt160::conditionally_select(
        cs,
        is_delegated_call,
        &current_callstack_entry.this,
        &this_for_next,
    );
    // "caller" changes in both cases

    caller_for_next = UInt160::conditionally_select(
        cs,
        is_delegated_call,
        &current_callstack_entry.caller,
        &caller_for_next,
    );

    caller_for_next = UInt160::conditionally_select(
        cs,
        is_mimic_call,
        &caller_address_for_mimic,
        &caller_for_next,
    );

    // resolve static, etc
    let next_is_static = Boolean::multi_or(
        cs,
        &[is_static_call, current_callstack_entry.is_static_execution],
    );

    // actually parts to the new one
    new_callstack_entry.ergs_remaining = passed_ergs_if_pass;
    new_callstack_entry.pc = dst_pc;
    new_callstack_entry.exception_handler_loc = eh_pc;
    new_callstack_entry.is_static_execution = next_is_static;

    // we need to decide whether new frame is kernel or not for degelatecall
    let new_frame_is_kernel = Boolean::conditionally_select(
        cs,
        is_delegated_call,
        &current_callstack_entry.is_kernel_mode,
        &target_is_kernel,
    );
    new_callstack_entry.is_kernel_mode = new_frame_is_kernel;

    // code part
    new_callstack_entry.code_shard_id = destination_shard;
    new_callstack_entry.code_address = destination_address;
    // this part
    new_callstack_entry.this_shard_id = new_this_shard_id;
    new_callstack_entry.this = this_for_next;
    // caller part
    new_callstack_entry.caller = caller_for_next;
    new_callstack_entry.caller_shard_id = caller_shard_id;
    // code page
    new_callstack_entry.code_page = code_memory_page;
    // base page
    new_callstack_entry.base_page = new_base_page;
    // context u128
    // if we do delegatecall then we propagate current context value, otherwise
    // we capture the current one
    new_callstack_entry.context_u128_value_composite = UInt32::parallel_select(
        cs,
        is_delegated_call,
        &current_callstack_entry.context_u128_value_composite,
        &draft_vm_state.context_composite_u128,
    );
    // non-local call
    let boolean_false = Boolean::allocated_constant(cs, false);
    new_callstack_entry.is_local_call = boolean_false;

    let oracle = witness_oracle.clone();
    // we should assemble all the dependencies here, and we will use AllocateExt here
    let mut dependencies = Vec::with_capacity(
        <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 2,
    );
    dependencies.push(execute.get_variable().into());
    dependencies.push(
        draft_vm_state
            .callstack
            .context_stack_depth
            .get_variable()
            .into(),
    );
    dependencies.extend(Place::from_variables(
        current_callstack_entry.flatten_as_variables(),
    ));

    cs.set_values_with_dependencies_vararg(
        &dependencies,
        &[],
        move |inputs: &[F], _buffer: &mut DstBuffer<'_, '_, F>| {
            let execute = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[0]);
            let current_depth = <u32 as WitnessCastable<F, F>>::cast_from_source(inputs[1]);

            let mut query =
                [F::ZERO; <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN];
            query.copy_from_slice(&inputs[2..]);
            let query: ExecutionContextRecordWitness<F> =
                CSAllocatableExt::witness_from_set_of_values(query);

            let mut guard = oracle.inner.write().expect("not poisoned");
            guard.push_callstack_witness(&query, current_depth, execute);
            drop(guard);
        },
    );

    // and update registers following our ABI rules

    let new_r1 = final_fat_ptr.into_register(cs);

    let one = Num::allocated_constant(cs, F::ONE);

    let r2_low = Num::fma(
        cs,
        &Num::from_variable(far_call_abi.constructor_call.get_variable()),
        &one,
        &F::ONE,
        &Num::from_variable(far_call_abi.system_call.get_variable()),
        &F::TWO,
    );

    let r2_low = unsafe { UInt32::from_variable_unchecked(r2_low.get_variable()) };

    let new_r2 = VMRegister {
        is_pointer: boolean_false,
        value: UInt256 {
            inner: [
                r2_low, zero_u32, zero_u32, zero_u32, zero_u32, zero_u32, zero_u32, zero_u32,
            ],
        },
    };

    let mut specific_registers_updates = [None; REGISTERS_COUNT];
    specific_registers_updates[0] = Some((execute, new_r1));
    specific_registers_updates[1] = Some((execute, new_r2));

    let non_system_call = far_call_abi.system_call.negated(cs);
    let cleanup_register = Boolean::multi_and(cs, &[execute, non_system_call]);

    let mut register_zero_out = [None; REGISTERS_COUNT];

    for reg_idx in zkevm_opcode_defs::definitions::far_call::CALL_SYSTEM_ABI_REGISTERS {
        register_zero_out[reg_idx as usize] = Some(cleanup_register);
    }
    for reg_idx in zkevm_opcode_defs::definitions::far_call::CALL_RESERVED_RANGE {
        register_zero_out[reg_idx as usize] = Some(execute);
    }
    register_zero_out
        [zkevm_opcode_defs::definitions::far_call::CALL_IMPLICIT_PARAMETER_REG_IDX as usize] =
        Some(execute);

    // erase markers everywhere anyway
    let mut erase_ptr_markers = [None; REGISTERS_COUNT];

    for reg_idx in zkevm_opcode_defs::definitions::far_call::CALL_SYSTEM_ABI_REGISTERS {
        erase_ptr_markers[reg_idx as usize] = Some(execute);
    }
    for reg_idx in zkevm_opcode_defs::definitions::far_call::CALL_RESERVED_RANGE {
        erase_ptr_markers[reg_idx as usize] = Some(execute);
    }
    erase_ptr_markers
        [zkevm_opcode_defs::definitions::far_call::CALL_IMPLICIT_PARAMETER_REG_IDX as usize] =
        Some(execute);

    // if we didn't decommit for ANY reason then we will have target memory page == UNMAPPED PAGE, that will trigger panic
    let full_data = FarCallData {
        apply_far_call: execute,
        old_context: current_callstack_entry,
        new_context: new_callstack_entry,
        new_decommittment_queue_tail,
        new_decommittment_queue_len,
        new_forward_queue_tail,
        new_forward_queue_len,
        new_memory_pages_counter,
        pending_sponges: all_pending_sponges,
        specific_registers_updates,
        specific_registers_zeroing: register_zero_out,
        remove_ptr_on_specific_registers: erase_ptr_markers,
        pending_exception: exception,
    };

    if crate::config::CIRCUIT_VERSOBE {
        if (execute.witness_hook(&*cs))().unwrap_or(false) {
            println!(
                "New frame as a result of FAR CALL: {:?}",
                full_data.new_context.witness_hook(cs)()
            );
        }
    }

    full_data
}

// We read code hash from the storage if we have enough ergs, and mask out
// a case if code hash is 0 into either default AA or 0 if destination is kernel
pub fn may_be_read_code_hash<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
    W: WitnessOracle<F>,
>(
    cs: &mut CS,
    relations_buffer: &mut ArrayVec<
        (
            Boolean<F>,
            [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
            [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
        ),
        MAX_SPONGES_PER_CYCLE,
    >,
    call_target: &UInt160<F>,
    shard_id: &UInt8<F>,
    target_is_zkporter: &Boolean<F>,
    zkporter_is_available: &Boolean<F>,
    should_execute: &Boolean<F>,
    default_aa_code_hash: &UInt256<F>,
    target_is_kernel: &Boolean<F>,
    forward_queue_tail: [Num<F>; QUEUE_STATE_WIDTH],
    forward_queue_length: UInt32<F>,
    timestamp_to_use_for_read_request: UInt32<F>,
    tx_number_in_block: UInt32<F>,
    witness_oracle: &SynchronizedWitnessOracle<F, W>,
    round_function: &R,
) -> (
    Boolean<F>,
    UInt256<F>,
    ([Num<F>; QUEUE_STATE_WIDTH], UInt32<F>),
)
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    let target_is_porter_and_its_available =
        Boolean::multi_and(cs, &[*target_is_zkporter, *zkporter_is_available]);
    let target_is_rollup = target_is_zkporter.negated(cs);
    let zkporter_is_not_available = zkporter_is_available.negated(cs);

    let can_read = Boolean::multi_or(cs, &[target_is_rollup, target_is_porter_and_its_available]);
    let should_read = Boolean::multi_and(cs, &[*should_execute, can_read]);
    let needs_porter_mask =
        Boolean::multi_and(cs, &[*target_is_zkporter, zkporter_is_not_available]);

    let zero_u32 = UInt32::zero(cs);
    let target_as_u256 = UInt256 {
        inner: [
            call_target.inner[0],
            call_target.inner[1],
            call_target.inner[2],
            call_target.inner[3],
            call_target.inner[4],
            zero_u32,
            zero_u32,
            zero_u32,
        ],
    };

    let deployer_contract_address_low = UInt32::allocated_constant(
        cs,
        zkevm_opcode_defs::system_params::DEPLOYER_SYSTEM_CONTRACT_ADDRESS_LOW as u32,
    );
    let deployer_contract_address = UInt160 {
        inner: [
            deployer_contract_address_low,
            zero_u32,
            zero_u32,
            zero_u32,
            zero_u32,
        ],
    };

    let zero_u256 = UInt256::zero(cs);
    let boolean_false = Boolean::allocated_constant(cs, false);
    let aux_byte_for_storage = UInt8::allocated_constant(cs, STORAGE_AUX_BYTE);

    let mut log = LogQuery {
        address: deployer_contract_address,
        key: target_as_u256,
        read_value: zero_u256,
        written_value: zero_u256,
        rw_flag: boolean_false,
        aux_byte: aux_byte_for_storage,
        rollback: boolean_false,
        is_service: boolean_false,
        shard_id: *shard_id,
        tx_number_in_block,
        timestamp: timestamp_to_use_for_read_request,
    };

    let oracle = witness_oracle.clone();
    // we should assemble all the dependencies here, and we will use AllocateExt here
    let mut dependencies =
        Vec::with_capacity(<LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 2);
    dependencies.push(should_read.get_variable().into());
    dependencies.push(should_execute.get_variable().into());
    dependencies.extend(Place::from_variables(log.flatten_as_variables()));

    // we always access witness, as even for writes we have to get a claimed read value!
    let read_value = UInt256::allocate_from_closure_and_dependencies(
        cs,
        move |inputs: &[F]| {
            let is_storage = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[0]);
            let execute = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[1]);
            let mut log_query =
                [F::ZERO; <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN];
            log_query.copy_from_slice(&inputs[2..]);
            let log_query: LogQueryWitness<F> =
                CSAllocatableExt::witness_from_set_of_values(log_query);

            let mut guard = oracle.inner.write().expect("not poisoned");
            let witness = guard.get_storage_read_witness(&log_query, is_storage, execute);
            drop(guard);

            witness
        },
        &dependencies,
    );

    log.read_value = read_value;
    log.written_value = read_value; // our convension as in LOG opcode

    let code_hash_from_storage = read_value;

    let mut bytecode_hash = code_hash_from_storage;
    let limbs_are_zero = bytecode_hash.inner.map(|el| el.is_zero(cs));
    let bytecode_is_empty = Boolean::multi_and(cs, &limbs_are_zero);

    let target_is_userspace = target_is_kernel.negated(cs);
    let mask_for_default_aa =
        Boolean::multi_and(cs, &[should_read, bytecode_is_empty, target_is_userspace]);

    // mask based on some conventions
    // first - mask for default AA
    bytecode_hash = UInt256::conditionally_select(
        cs,
        mask_for_default_aa,
        &default_aa_code_hash,
        &bytecode_hash,
    );

    // - if we couldn't read porter
    bytecode_hash =
        UInt256::conditionally_select(cs, needs_porter_mask, &zero_u256, &bytecode_hash);

    let dont_mask_to_default_aa = mask_for_default_aa.negated(cs);
    let t0 = Boolean::multi_and(cs, &[bytecode_is_empty, dont_mask_to_default_aa]);
    let skip_read = should_read.negated(cs);
    let bytecode_hash_is_trivial = Boolean::multi_or(cs, &[t0, needs_porter_mask, skip_read]);

    // now process the sponges on whether we did read
    let (new_forward_queue_tail, new_forward_queue_length) =
        construct_hash_relations_code_hash_read(
            cs,
            relations_buffer,
            &log,
            &forward_queue_tail,
            &forward_queue_length,
            &should_read,
            round_function,
        );

    let new_forward_queue_tail = Num::parallel_select(
        cs,
        should_read,
        &new_forward_queue_tail,
        &forward_queue_tail,
    );

    (
        bytecode_hash_is_trivial,
        bytecode_hash,
        (new_forward_queue_tail, new_forward_queue_length),
    )
}

fn construct_hash_relations_code_hash_read<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    relations_buffer: &mut ArrayVec<
        (
            Boolean<F>,
            [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
            [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
        ),
        MAX_SPONGES_PER_CYCLE,
    >,
    log: &LogQuery<F>,
    forward_queue_tail: &[Num<F>; 4],
    forward_queue_length: &UInt32<F>,
    should_read: &Boolean<F>,
    _round_function: &R,
) -> ([Num<F>; 4], UInt32<F>) {
    // we absort with replacement

    let mut current_state = R::create_empty_state(cs);
    // TODO: may be decide on length specialization
    use boojum::gadgets::traits::encodable::CircuitEncodable;

    let forward_packed_log = log.encode(cs);

    // NOTE: since we do merged call/ret, we simulate proper relations here always,
    // because we will do join enforcement on call/ret

    let boolean_true = Boolean::allocated_constant(cs, true);

    // absorb by replacement
    let round_0_initial = [
        forward_packed_log[0],
        forward_packed_log[1],
        forward_packed_log[2],
        forward_packed_log[3],
        forward_packed_log[4],
        forward_packed_log[5],
        forward_packed_log[6],
        forward_packed_log[7],
        current_state[8],
        current_state[9],
        current_state[10],
        current_state[11],
    ];

    use boojum::gadgets::round_function::simulate_round_function;

    let round_0_final =
        simulate_round_function::<_, _, 8, 12, 4, R>(cs, round_0_initial, boolean_true);

    current_state = round_0_final;

    // absorb by replacement
    let round_1_initial = [
        forward_packed_log[8],
        forward_packed_log[9],
        forward_packed_log[10],
        forward_packed_log[11],
        forward_packed_log[12],
        forward_packed_log[13],
        forward_packed_log[14],
        forward_packed_log[15],
        current_state[8],
        current_state[9],
        current_state[10],
        current_state[11],
    ];

    let round_1_final =
        simulate_round_function::<_, _, 8, 12, 4, R>(cs, round_1_initial, boolean_true);

    current_state = round_1_final;

    // absorb by replacement
    let round_2_initial = [
        forward_packed_log[16],
        forward_packed_log[17],
        forward_packed_log[18],
        forward_packed_log[19],
        forward_queue_tail[0].get_variable(),
        forward_queue_tail[1].get_variable(),
        forward_queue_tail[2].get_variable(),
        forward_queue_tail[3].get_variable(),
        current_state[8],
        current_state[9],
        current_state[10],
        current_state[11],
    ];

    let round_2_final =
        simulate_round_function::<_, _, 8, 12, 4, R>(cs, round_2_initial, boolean_true);

    let new_forward_queue_tail = [
        round_2_final[0],
        round_2_final[1],
        round_2_final[2],
        round_2_final[3],
    ];

    let new_forward_queue_length_candidate =
        unsafe { forward_queue_length.increment_unchecked(cs) };
    let new_forward_queue_length = UInt32::conditionally_select(
        cs,
        *should_read,
        &new_forward_queue_length_candidate,
        &forward_queue_length,
    );

    relations_buffer.push((
        *should_read,
        round_0_initial.map(|el| Num::from_variable(el)),
        round_0_final.map(|el| Num::from_variable(el)),
    ));

    relations_buffer.push((
        *should_read,
        round_1_initial.map(|el| Num::from_variable(el)),
        round_1_final.map(|el| Num::from_variable(el)),
    ));

    relations_buffer.push((
        *should_read,
        round_2_initial.map(|el| Num::from_variable(el)),
        round_2_final.map(|el| Num::from_variable(el)),
    ));

    (
        new_forward_queue_tail.map(|el| Num::from_variable(el)),
        new_forward_queue_length,
    )
}

pub fn add_to_decommittment_queue<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
    W: WitnessOracle<F>,
>(
    cs: &mut CS,
    relations_buffer: &mut ArrayVec<
        (
            Boolean<F>,
            [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
            [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
        ),
        MAX_SPONGES_PER_CYCLE,
    >,
    should_decommit: &Boolean<F>,
    ergs_remaining: &UInt32<F>,
    bytecode_hash: &UInt256<F>,
    num_words_in_bytecode: &UInt16<F>,
    current_decommittment_queue_tail: &[Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
    current_decommittment_queue_len: &UInt32<F>,
    timestamp_to_use_for_decommittment_request: &UInt32<F>,
    target_memory_page: &UInt32<F>,
    witness_oracle: &SynchronizedWitnessOracle<F, W>,
    _round_function: &R,
) -> (
    Boolean<F>,
    UInt32<F>,
    ([Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH], UInt32<F>),
    UInt32<F>,
)
where
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    // compute any associated extra costs

    let cost_of_decommit_per_word =
        UInt32::allocated_constant(cs, zkevm_opcode_defs::ERGS_PER_CODE_WORD_DECOMMITTMENT);
    let num_words_in_bytecode =
        unsafe { UInt32::from_variable_unchecked(num_words_in_bytecode.get_variable()) };

    let cost_of_decommittment =
        cost_of_decommit_per_word.non_widening_mul(cs, &num_words_in_bytecode);

    let (ergs_after_decommit_may_be, uf) =
        ergs_remaining.overflowing_sub(cs, cost_of_decommittment);

    let not_enough_ergs_to_decommit = uf;
    let have_enough_ergs_to_decommit = uf.negated(cs);
    let should_decommit = Boolean::multi_and(cs, &[*should_decommit, have_enough_ergs_to_decommit]);

    // if we do not decommit then we will eventually map into 0 page for 0 extra ergs
    let ergs_remaining_after_decommit = UInt32::conditionally_select(
        cs,
        should_decommit,
        &ergs_after_decommit_may_be,
        &ergs_remaining,
    );

    if crate::config::CIRCUIT_VERSOBE {
        if should_decommit.witness_hook(&*cs)().unwrap() {
            dbg!(num_words_in_bytecode.witness_hook(&*cs)().unwrap());
            dbg!(ergs_after_decommit_may_be.witness_hook(&*cs)().unwrap());
            dbg!(ergs_remaining_after_decommit.witness_hook(&*cs)().unwrap());
        }
    }

    // decommit and return new code page and queue states

    let boolean_false = Boolean::allocated_constant(cs, false);

    let mut decommittment_request = DecommitQuery {
        code_hash: *bytecode_hash,
        page: *target_memory_page,
        is_first: boolean_false,
        timestamp: *timestamp_to_use_for_decommittment_request,
    };

    let oracle = witness_oracle.clone();
    // we should assemble all the dependencies here, and we will use AllocateExt here
    let mut dependencies =
        Vec::with_capacity(<DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1);
    dependencies.push(should_decommit.get_variable().into());
    dependencies.extend(Place::from_variables(
        decommittment_request.flatten_as_variables(),
    ));

    // we always access witness, as even for writes we have to get a claimed read value!
    let suggested_page = UInt32::allocate_from_closure_and_dependencies(
        cs,
        move |inputs: &[F]| {
            let should_decommit = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[0]);

            let mut query =
                [F::ZERO; <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN];
            query.copy_from_slice(&inputs[1..]);
            let query: DecommitQueryWitness<F> =
                CSAllocatableExt::witness_from_set_of_values(query);

            let mut guard = oracle.inner.write().expect("not poisoned");
            let witness = guard.get_decommittment_request_suggested_page(&query, should_decommit);
            drop(guard);

            witness
        },
        &dependencies,
    );

    let is_first = UInt32::equals(cs, &target_memory_page, &suggested_page);

    decommittment_request.is_first = is_first;
    decommittment_request.page = suggested_page;

    // kind of refund if we didn't decommit

    let was_decommitted_before = is_first.negated(cs);

    let refund = Boolean::multi_and(cs, &[should_decommit, was_decommitted_before]);

    let ergs_remaining_after_decommit =
        UInt32::conditionally_select(cs, refund, &ergs_remaining, &ergs_remaining_after_decommit);

    use boojum::gadgets::traits::encodable::CircuitEncodable;

    let encoded_request = decommittment_request.encode(cs);
    // absorb by replacement
    let initial_state = [
        encoded_request[0],
        encoded_request[1],
        encoded_request[2],
        encoded_request[3],
        encoded_request[4],
        encoded_request[5],
        encoded_request[6],
        encoded_request[7],
        current_decommittment_queue_tail[8].get_variable(),
        current_decommittment_queue_tail[9].get_variable(),
        current_decommittment_queue_tail[10].get_variable(),
        current_decommittment_queue_tail[11].get_variable(),
    ];

    use boojum::gadgets::round_function::simulate_round_function;

    // NOTE: since we do merged call/ret, we simulate proper relations here always,
    // because we will do join enforcement on call/ret

    let final_state =
        simulate_round_function::<_, _, 8, 12, 4, R>(cs, initial_state, should_decommit);

    relations_buffer.push((
        should_decommit,
        initial_state.map(|el| Num::from_variable(el)),
        final_state.map(|el| Num::from_variable(el)),
    ));

    let final_state = final_state.map(|el| Num::from_variable(el));

    let new_decommittment_queue_tail = Num::parallel_select(
        cs,
        should_decommit,
        &final_state,
        &current_decommittment_queue_tail,
    );

    let new_decommittment_queue_len_candidate =
        unsafe { current_decommittment_queue_len.increment_unchecked(cs) };
    let new_decommittment_queue_len = UInt32::conditionally_select(
        cs,
        should_decommit,
        &new_decommittment_queue_len_candidate,
        &current_decommittment_queue_len,
    );
    // we use `should_decommit` as a marker that we did actually execute both read and decommittment (whether fresh or not)

    let target_memory_page = decommittment_request.page;
    let unmapped_page = UInt32::allocated_constant(cs, UNMAPPED_PAGE);
    let target_memory_page =
        UInt32::conditionally_select(cs, should_decommit, &target_memory_page, &unmapped_page);

    (
        not_enough_ergs_to_decommit,
        target_memory_page,
        (new_decommittment_queue_tail, new_decommittment_queue_len),
        ergs_remaining_after_decommit,
    )
}
