use crate::base_structures::register::VMRegister;
use boojum::gadgets::{traits::castable::WitnessCastable, u256::UInt256};
use cs_derive::CSAllocatable;

use super::*;
use crate::base_structures::memory_query::MemoryQueryWitness;
use crate::base_structures::memory_query::MemoryValue;
use crate::main_vm::pre_state::MemoryLocation;
use crate::main_vm::register_input_view::RegisterInputView;
use crate::main_vm::witness_oracle::SynchronizedWitnessOracle;
use crate::main_vm::witness_oracle::WitnessOracle;
use arrayvec::ArrayVec;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::cs::traits::cs::DstBuffer;
use boojum::gadgets::traits::allocatable::CSAllocatableExt;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;

pub(crate) fn apply_uma<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
    W: WitnessOracle<F>,
>(
    cs: &mut CS,
    draft_vm_state: &VmLocalState<F>,
    common_opcode_state: &CommonOpcodeState<F>,
    opcode_carry_parts: &AfterDecodingCarryParts<F>,
    diffs_accumulator: &mut StateDiffsAccumulator<F>,
    witness_oracle: &SynchronizedWitnessOracle<F, W>,
    _round_function: &R,
) where
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    const UMA_HEAP_READ_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::UMA(UMAOpcode::HeapRead);
    const UMA_HEAP_WRITE_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::UMA(UMAOpcode::HeapWrite);
    const UMA_AUX_HEAP_READ_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::UMA(UMAOpcode::AuxHeapRead);
    const UMA_AUX_HEAP_WRITE_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::UMA(UMAOpcode::AuxHeapWrite);
    const UMA_FAT_PTR_READ_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::UMA(UMAOpcode::FatPointerRead);

    let should_apply = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_opcode(UMA_HEAP_READ_OPCODE);

    let is_uma_heap_read = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(UMA_HEAP_READ_OPCODE);
    let is_uma_heap_write = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(UMA_HEAP_WRITE_OPCODE);
    let is_uma_aux_heap_read = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(UMA_AUX_HEAP_READ_OPCODE);
    let is_uma_aux_heap_write = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(UMA_AUX_HEAP_WRITE_OPCODE);
    let is_uma_fat_ptr_read = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(UMA_FAT_PTR_READ_OPCODE);

    let increment_offset = common_opcode_state
        .decoded_opcode
        .properties_bits
        .flag_booleans[UMA_INCREMENT_FLAG_IDX];

    let access_heap = Boolean::multi_or(cs, &[is_uma_heap_read, is_uma_heap_write]);
    let access_aux_heap = Boolean::multi_or(cs, &[is_uma_aux_heap_read, is_uma_aux_heap_write]);

    if crate::config::CIRCUIT_VERSOBE {
        if should_apply.witness_hook(&*cs)().unwrap_or(false) {
            println!("Applying UMA");
            if is_uma_heap_read.witness_hook(&*cs)().unwrap_or(false) {
                println!("Heap read");
            }
            if is_uma_heap_write.witness_hook(&*cs)().unwrap_or(false) {
                println!("Heap write");
            }
            if is_uma_aux_heap_read.witness_hook(&*cs)().unwrap_or(false) {
                println!("Aux heap read");
            }
            if is_uma_aux_heap_write.witness_hook(&*cs)().unwrap_or(false) {
                println!("Aux heap write");
            }
            if is_uma_fat_ptr_read.witness_hook(&*cs)().unwrap_or(false) {
                println!("Fat ptr read");
            }
        }
    }

    let src0_is_integer = common_opcode_state.src0_view.is_ptr.negated(cs);

    // perform basic validation
    let not_a_ptr_when_expected =
        Boolean::multi_and(cs, &[should_apply, is_uma_fat_ptr_read, src0_is_integer]);

    let quasi_fat_ptr = QuasiFatPtrInUMA::parse_and_validate(
        cs,
        &common_opcode_state.src0_view,
        not_a_ptr_when_expected,
        is_uma_fat_ptr_read,
    );

    // this one could wrap around, so we account for it. In case if we wrapped we will skip operation anyway
    let max_accessed = quasi_fat_ptr.incremented_offset;

    let heap_max_accessed = max_accessed.mask(cs, access_heap);
    let heap_bound = draft_vm_state
        .callstack
        .current_context
        .saved_context
        .heap_upper_bound;
    let (mut heap_growth, uf) = heap_max_accessed.overflowing_sub(cs, heap_bound);
    heap_growth = heap_growth.mask_negated(cs, uf); // of we access in bounds then it's 0
    let new_heap_upper_bound =
        UInt32::conditionally_select(cs, uf, &heap_bound, &heap_max_accessed);
    let grow_heap = Boolean::multi_and(cs, &[access_heap, should_apply]);

    let aux_heap_max_accessed = max_accessed.mask(cs, access_aux_heap);
    let aux_heap_bound = draft_vm_state
        .callstack
        .current_context
        .saved_context
        .aux_heap_upper_bound;
    let (mut aux_heap_growth, uf) = aux_heap_max_accessed.overflowing_sub(cs, aux_heap_bound);
    aux_heap_growth = aux_heap_growth.mask_negated(cs, uf); // of we access in bounds then it's 0
    let new_aux_heap_upper_bound =
        UInt32::conditionally_select(cs, uf, &aux_heap_bound, &aux_heap_max_accessed);
    let grow_aux_heap = Boolean::multi_and(cs, &[access_aux_heap, should_apply]);

    let mut growth_cost = heap_growth.mask(cs, access_heap);
    growth_cost = UInt32::conditionally_select(cs, access_aux_heap, &aux_heap_growth, &growth_cost);

    let limbs_to_check = [
        common_opcode_state.src0_view.u32x8_view[1],
        common_opcode_state.src0_view.u32x8_view[2],
        common_opcode_state.src0_view.u32x8_view[3],
        common_opcode_state.src0_view.u32x8_view[4],
        common_opcode_state.src0_view.u32x8_view[5],
        common_opcode_state.src0_view.u32x8_view[6],
        common_opcode_state.src0_view.u32x8_view[7],
    ];

    let limbs_are_zero = limbs_to_check.map(|el| el.is_zero(cs));
    let top_bits_are_clear = Boolean::multi_and(cs, &limbs_are_zero);
    let top_bits_are_non_zero = top_bits_are_clear.negated(cs);

    if crate::config::CIRCUIT_VERSOBE {
        if should_apply.witness_hook(&*cs)().unwrap_or(false) {
            dbg!(quasi_fat_ptr.witness_hook(&*cs)().unwrap());
            dbg!(&common_opcode_state.src0_view.u32x8_view.witness_hook(&*cs)().unwrap()[..4]);
            dbg!(common_opcode_state.src1.witness_hook(&*cs)().unwrap());
        }
    }

    let t: Boolean<F> = Boolean::multi_or(
        cs,
        &[
            top_bits_are_non_zero,
            quasi_fat_ptr.heap_deref_out_of_bounds,
        ],
    );
    let heap_access_like = Boolean::multi_or(cs, &[access_heap, access_aux_heap]);
    let exception_heap_deref_out_of_bounds = Boolean::multi_and(cs, &[heap_access_like, t]);

    if crate::config::CIRCUIT_VERSOBE {
        if should_apply.witness_hook(&*cs)().unwrap_or(false) {
            dbg!(top_bits_are_non_zero.witness_hook(&*cs)().unwrap());
            dbg!(quasi_fat_ptr.heap_deref_out_of_bounds.witness_hook(&*cs)().unwrap());
            dbg!(heap_access_like.witness_hook(&*cs)().unwrap());
            dbg!(exception_heap_deref_out_of_bounds.witness_hook(&*cs)().unwrap());
        }
    }

    // penalize for heap out of bounds access
    let uint32_max = UInt32::allocated_constant(cs, u32::MAX);
    growth_cost = UInt32::conditionally_select(
        cs,
        exception_heap_deref_out_of_bounds,
        &uint32_max,
        &growth_cost,
    );

    let (ergs_left_after_growth, uf) = opcode_carry_parts
        .preliminary_ergs_left
        .overflowing_sub(cs, growth_cost);

    let set_panic = Boolean::multi_or(
        cs,
        &[
            quasi_fat_ptr.should_set_panic,
            uf,
            exception_heap_deref_out_of_bounds,
        ],
    );
    if crate::config::CIRCUIT_VERSOBE {
        if should_apply.witness_hook(&*cs)().unwrap_or(false) {
            dbg!(set_panic.witness_hook(&*cs)().unwrap());
        }
    }
    // burn all the ergs if not enough
    let ergs_left_after_growth = ergs_left_after_growth.mask_negated(cs, uf);

    let should_skip_memory_ops =
        Boolean::multi_or(cs, &[quasi_fat_ptr.skip_memory_access, set_panic]);

    let is_read_access = Boolean::multi_or(
        cs,
        &[is_uma_heap_read, is_uma_aux_heap_read, is_uma_fat_ptr_read],
    );
    let is_write_access = Boolean::multi_or(cs, &[is_uma_heap_write, is_uma_aux_heap_write]);

    // NB: Etherium virtual machine is big endian;
    // we need to determine the memory cells' indexes which will be accessed
    // every memory cell is 32 bytes long, the first cell to be accesed has idx = offset / 32
    // if rem = offset % 32 is zero than it is the only one cell to be accessed
    // 1) cell_idx = offset / cell_length, rem = offset % cell_length =>
    // offset = cell_idx * cell_length + rem
    // we should also enforce that cell_idx /in [0, 2^32-1] - this would require range check
    // we should also enforce that 0 <= rem < cell_length = 2^5;
    // rem is actually the byte offset in the first touched cell, to compute bitoffset and shifts
    // we do bit_offset = rem * 8 and then apply shift computing tables
    // flag does_cross_border = rem != 0
    let offset = quasi_fat_ptr.absolute_address;

    if crate::config::CIRCUIT_VERSOBE {
        if should_apply.witness_hook(&*cs)().unwrap() {
            dbg!(offset.witness_hook(&*cs)().unwrap());
        }
    }

    let (cell_idx, unalignment) = offset.div_by_constant(cs, 32);
    let unalignment_is_zero = unalignment.is_zero(cs);
    let access_is_unaligned = unalignment_is_zero.negated(cs);

    // read both memory cells: in what follows we will call the first memory slot A
    // and the second memory Slot B
    let current_memory_queue_state = draft_vm_state.memory_queue_state;
    let current_memory_queue_length = draft_vm_state.memory_queue_length;

    let mut mem_page = quasi_fat_ptr.page_candidate;
    mem_page =
        UInt32::conditionally_select(cs, access_heap, &opcode_carry_parts.heap_page, &mem_page);
    mem_page = UInt32::conditionally_select(
        cs,
        access_aux_heap,
        &opcode_carry_parts.aux_heap_page,
        &mem_page,
    );

    let a_cell_idx = cell_idx;
    let one_uint32 = UInt32::allocated_constant(cs, 1);
    // wrap around
    let (b_cell_idx, _of) = a_cell_idx.overflowing_add(cs, one_uint32);

    let a_memory_loc = MemoryLocation {
        page: mem_page,
        index: a_cell_idx,
    };
    let b_memory_loc = MemoryLocation {
        page: mem_page,
        index: b_cell_idx,
    };

    let mem_read_timestamp = common_opcode_state.timestamp_for_code_or_src_read;
    let mem_timestamp_write = common_opcode_state.timestamp_for_dst_write;

    let do_not_skip_memory_access = should_skip_memory_ops.negated(cs);

    let is_unaligned_read = Boolean::multi_and(
        cs,
        &[should_apply, access_is_unaligned, do_not_skip_memory_access],
    );

    // we yet access the `a` always
    let should_read_a_cell = Boolean::multi_and(cs, &[should_apply, do_not_skip_memory_access]);
    let should_read_b_cell = is_unaligned_read;

    // we read twice

    let oracle = witness_oracle.clone();
    let memory_value_a = MemoryValue::allocate_from_closure_and_dependencies_non_pointer(
        cs,
        move |inputs: &[F]| {
            debug_assert_eq!(inputs.len(), 4);
            let timestamp = <u32 as WitnessCastable<F, F>>::cast_from_source(inputs[0]);
            let memory_page = <u32 as WitnessCastable<F, F>>::cast_from_source(inputs[1]);
            let index = <u32 as WitnessCastable<F, F>>::cast_from_source(inputs[2]);
            let should_access = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[3]);

            if crate::config::CIRCUIT_VERSOBE {
                if should_access {
                    println!("Will read word A for UMA");
                }
            }

            let mut guard = oracle.inner.write().expect("not poisoned");
            let witness =
                guard.get_memory_witness_for_read(timestamp, memory_page, index, should_access);
            drop(guard);

            witness
        },
        &[
            mem_read_timestamp.get_variable().into(),
            a_memory_loc.page.get_variable().into(),
            a_memory_loc.index.get_variable().into(),
            should_read_a_cell.get_variable().into(),
        ],
    );

    let oracle = witness_oracle.clone();
    let memory_value_b = MemoryValue::allocate_from_closure_and_dependencies_non_pointer(
        cs,
        move |inputs: &[F]| {
            debug_assert_eq!(inputs.len(), 5);
            let timestamp = <u32 as WitnessCastable<F, F>>::cast_from_source(inputs[0]);
            let memory_page = <u32 as WitnessCastable<F, F>>::cast_from_source(inputs[1]);
            let index = <u32 as WitnessCastable<F, F>>::cast_from_source(inputs[2]);
            let should_access = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[3]);

            if crate::config::CIRCUIT_VERSOBE {
                if should_access {
                    println!("Will read word B for UMA");
                }
            }

            let mut guard = oracle.inner.write().expect("not poisoned");
            let witness =
                guard.get_memory_witness_for_read(timestamp, memory_page, index, should_access);
            drop(guard);

            witness
        },
        &[
            mem_read_timestamp.get_variable().into(),
            b_memory_loc.page.get_variable().into(),
            b_memory_loc.index.get_variable().into(),
            should_read_b_cell.get_variable().into(),
            // NOTE: we need to evaluate this closure strictly AFTER we evaluate previous access to witness,
            // so we "bias" it here
            memory_value_a.value.inner[0].get_variable().into(),
        ],
    );

    // now we can update the memory queue state

    let boolean_false = Boolean::allocated_constant(cs, false);
    let boolean_true = Boolean::allocated_constant(cs, true);

    let (
        new_memory_queue_tail_after_read,
        new_memory_queue_length_after_read,
        sponge_candidates_after_read,
    ) = {
        let mut relations = ArrayVec::new();

        // if crate::config::CIRCUIT_VERSOBE {
        //     if should_apply.witness_hook(&*cs)().unwrap() {
        //         dbg!(should_read_a_cell.witness_hook(&*cs)().unwrap());
        //         dbg!(should_read_b_cell.witness_hook(&*cs)().unwrap());
        //     }
        // }

        let query = MemoryQuery {
            timestamp: mem_read_timestamp,
            memory_page: a_memory_loc.page,
            index: a_memory_loc.index,
            is_ptr: boolean_false,
            value: memory_value_a.value,
            rw_flag: boolean_false,
        };

        use boojum::gadgets::traits::encodable::CircuitEncodable;

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
            current_memory_queue_state[8].get_variable(),
            current_memory_queue_state[9].get_variable(),
            current_memory_queue_state[10].get_variable(),
            current_memory_queue_state[11].get_variable(),
        ];

        use boojum::gadgets::round_function::simulate_round_function;

        let final_state_candidate =
            simulate_round_function::<_, _, 8, 12, 4, R>(cs, initial_state, should_read_a_cell);
        let final_state_candidate = final_state_candidate.map(|el| Num::from_variable(el));

        // if crate::config::CIRCUIT_VERSOBE {
        //     if should_apply.witness_hook(&*cs)().unwrap() {
        //         if should_read_a_cell.witness_hook(&*cs)().unwrap() {
        //             dbg!(initial_state.map(|el| Num::from_variable(el)).witness_hook(&*cs)().unwrap());
        //             dbg!(final_state_candidate.witness_hook(&*cs)().unwrap());
        //         }
        //     }
        // }

        relations.push((
            should_read_a_cell,
            initial_state.map(|el| Num::from_variable(el)),
            final_state_candidate,
        ));

        let mut new_memory_queue_state = Num::parallel_select(
            cs,
            should_read_a_cell,
            &final_state_candidate,
            &current_memory_queue_state,
        );

        // for all reasonable execution traces it's fine
        let new_len_candidate = unsafe { current_memory_queue_length.increment_unchecked(cs) };

        let new_length = UInt32::conditionally_select(
            cs,
            should_read_a_cell,
            &new_len_candidate,
            &current_memory_queue_length,
        );

        // now second query

        let query = MemoryQuery {
            timestamp: mem_read_timestamp,
            memory_page: b_memory_loc.page,
            index: b_memory_loc.index,
            is_ptr: boolean_false,
            value: memory_value_b.value,
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
            new_memory_queue_state[8].get_variable(),
            new_memory_queue_state[9].get_variable(),
            new_memory_queue_state[10].get_variable(),
            new_memory_queue_state[11].get_variable(),
        ];

        let final_state_candidate =
            simulate_round_function::<_, _, 8, 12, 4, R>(cs, initial_state, should_read_b_cell);
        let final_state_candidate = final_state_candidate.map(|el| Num::from_variable(el));

        // if crate::config::CIRCUIT_VERSOBE {
        //     if should_apply.witness_hook(&*cs)().unwrap() {
        //         if should_read_b_cell.witness_hook(&*cs)().unwrap() {
        //             dbg!(initial_state.map(|el| Num::from_variable(el)).witness_hook(&*cs)().unwrap());
        //             dbg!(final_state_candidate.witness_hook(&*cs)().unwrap());
        //         }
        //     }
        // }

        relations.push((
            should_read_b_cell,
            initial_state.map(|el| Num::from_variable(el)),
            final_state_candidate,
        ));

        new_memory_queue_state = Num::parallel_select(
            cs,
            should_read_b_cell,
            &final_state_candidate,
            &new_memory_queue_state,
        );

        // for all reasonable execution traces it's fine
        let new_len_candidate = unsafe { new_length.increment_unchecked(cs) };

        let new_length =
            UInt32::conditionally_select(cs, should_read_b_cell, &new_len_candidate, &new_length);

        (new_memory_queue_state, new_length, relations)
    };

    // if crate::config::CIRCUIT_VERSOBE {
    //     if should_apply.witness_hook(&*cs)().unwrap() {
    //         dbg!(new_memory_queue_length_after_read.witness_hook(&*cs)().unwrap());
    //     }
    // }

    // the issue with UMA is that if we cleanup bytes using shifts
    // then it's just too heavy in our arithmetization compared to some implementation of shift
    // register

    // we have a table that is:
    // b1000000.. LSB first if unalignment is 0
    // b0100000.. LSB first if unalignment is 1
    // so it's 32 bits max, and we use parallel select

    let unalignment_bitspread =
        uma_shift_into_bitspread(cs, Num::from_variable(unalignment.get_variable()));
    let unalignment_bit_mask = unalignment_bitspread.spread_into_bits::<_, 32>(cs);

    // implement shift register
    let zero_u8 = UInt8::zero(cs);
    let mut bytes_array = [zero_u8; 64];

    let memory_value_a_bytes = memory_value_a.value.to_be_bytes(cs);
    bytes_array[..32].copy_from_slice(&memory_value_a_bytes);

    let memory_value_b_bytes = memory_value_b.value.to_be_bytes(cs);
    bytes_array[32..].copy_from_slice(&memory_value_b_bytes);

    // now mask-shift
    let mut selected_word = [zero_u8; 32];

    // idx 0 is unalignment of 0 (aligned), idx 31 is unalignment of 31
    for (idx, mask_bit) in unalignment_bit_mask.iter().enumerate() {
        let src = &bytes_array[idx..(idx + 32)]; // source
        debug_assert_eq!(src.len(), selected_word.len());

        for (dst, src) in selected_word
            .array_chunks_mut::<4>()
            .zip(src.array_chunks::<4>())
        {
            *dst = UInt8::parallel_select(cs, *mask_bit, src, &*dst);
        }

        // if crate::config::CIRCUIT_VERSOBE {
        //     if should_apply.witness_hook(&*cs)().unwrap() {
        //         if should_read_a_cell.witness_hook(&*cs)().unwrap() {
        //             let src: [_; 32] = src.to_vec().try_into().unwrap();
        //             dbg!(mask_bit.witness_hook(&*cs)().unwrap());
        //             let src_buffer = src.witness_hook(&*cs)().unwrap();
        //             dbg!(hex::encode(&src_buffer));
        //             let dst_buffer = selected_word.witness_hook(&*cs)().unwrap();
        //             dbg!(hex::encode(&dst_buffer));
        //         }
        //     }
        // }
    }

    // in case of out-of-bounds UMA we should zero-out tail of our array
    // now we need to shift it once again to cleanup from out of bounds part. So we just shift right and left on BE machine
    use crate::tables::uma_ptr_read_cleanup::UMAPtrReadCleanupTable;

    let table_id = cs
        .get_table_id_for_marker::<UMAPtrReadCleanupTable>()
        .expect("table must exist");
    let bytes_to_cleanup_out_of_bound = quasi_fat_ptr.bytes_to_cleanup_out_of_bounds;
    let bytes_to_cleanup_out_of_bound_if_ptr_read =
        bytes_to_cleanup_out_of_bound.mask(cs, is_uma_fat_ptr_read);
    let [uma_cleanup_bitspread, _] = cs.perform_lookup::<1, 2>(
        table_id,
        &[bytes_to_cleanup_out_of_bound_if_ptr_read.get_variable()],
    );
    let uma_ptr_read_cleanup_mask =
        Num::from_variable(uma_cleanup_bitspread).spread_into_bits::<_, 32>(cs);

    for (dst, masking_bit) in selected_word
        .iter_mut()
        .zip(uma_ptr_read_cleanup_mask.iter().rev())
    {
        *dst = dst.mask(cs, *masking_bit);
    }

    if crate::config::CIRCUIT_VERSOBE {
        if should_apply.witness_hook(&*cs)().unwrap() {
            if should_read_a_cell.witness_hook(&*cs)().unwrap() {
                dbg!(unalignment.witness_hook(&*cs)().unwrap());
                let src_buffer = bytes_array.witness_hook(&*cs)().unwrap();
                dbg!(hex::encode(&src_buffer));
                let result_buffer = selected_word.witness_hook(&*cs)().unwrap();
                dbg!(hex::encode(&result_buffer));
            }
        }
    }

    // for "write" we have to keep the "leftovers"
    // and replace the "inner" part with decomposition of the value from src1

    let execute_write = Boolean::multi_and(
        cs,
        &[should_apply, is_write_access, do_not_skip_memory_access],
    ); // we do not need set panic here, as it's "inside" of `should_skip_memory_ops`
    let execute_unaligned_write = Boolean::multi_and(cs, &[execute_write, access_is_unaligned]);

    // make it BE
    let mut written_value_bytes = common_opcode_state.src1_view.u8x32_view;
    written_value_bytes.reverse();

    let mut written_bytes_buffer = bytes_array;
    // now it's a little trickier as we have to kind-of transpose

    if crate::config::CIRCUIT_VERSOBE {
        if should_apply.witness_hook(&*cs)().unwrap() {
            if execute_write.witness_hook(&*cs)().unwrap() {
                dbg!(unalignment.witness_hook(&*cs)().unwrap());
                let to_write = written_value_bytes.witness_hook(&*cs)().unwrap();
                dbg!(hex::encode(&to_write));
                let original_buffer = bytes_array.witness_hook(&*cs)().unwrap();
                dbg!(hex::encode(&original_buffer));
            }
        }
    }

    // place back
    for (idx, mask_bit) in unalignment_bit_mask.iter().enumerate() {
        let dst = &mut written_bytes_buffer[idx..(idx + 32)]; // destination
        for (dst, src) in dst
            .array_chunks_mut::<4>()
            .zip(written_value_bytes.array_chunks::<4>())
        {
            *dst = UInt8::parallel_select(cs, *mask_bit, src, &*dst);
        }
    }

    if crate::config::CIRCUIT_VERSOBE {
        if should_apply.witness_hook(&*cs)().unwrap() {
            if execute_write.witness_hook(&*cs)().unwrap() {
                let result_buffer = written_bytes_buffer.witness_hook(&*cs)().unwrap();
                dbg!(hex::encode(&result_buffer));
            }
        }
    }

    // now we should write both values in corresponding cells

    // update memory queue state again
    let (
        new_memory_queue_tail_after_writes,
        new_memory_queue_length_after_writes,
        sponge_candidates_after_writes,
    ) = {
        let mut relations = sponge_candidates_after_read;

        if crate::config::CIRCUIT_VERSOBE {
            if should_apply.witness_hook(&*cs)().unwrap() {
                dbg!(execute_write.witness_hook(&*cs)().unwrap());
                dbg!(execute_unaligned_write.witness_hook(&*cs)().unwrap());
            }
        }

        let mut a_new_value = UInt256::zero(cs);
        // read value is LE integer, while words are treated as BE
        for (dst, src) in a_new_value
            .inner
            .iter_mut()
            .rev()
            .zip(written_bytes_buffer[..32].array_chunks::<4>())
        {
            let be_bytes = *src;
            let u32_word = UInt32::from_be_bytes(cs, be_bytes);
            *dst = u32_word;
        }

        let mut b_new_value = UInt256::zero(cs);
        // read value is LE integer, while words are treated as BE
        for (dst, src) in b_new_value
            .inner
            .iter_mut()
            .rev()
            .zip(written_bytes_buffer[32..].array_chunks::<4>())
        {
            let be_bytes = *src;
            let u32_word = UInt32::from_be_bytes(cs, be_bytes);
            *dst = u32_word;
        }

        let a_query = MemoryQuery {
            timestamp: mem_timestamp_write,
            memory_page: a_memory_loc.page,
            index: a_memory_loc.index,
            is_ptr: boolean_false,
            value: a_new_value,
            rw_flag: boolean_true,
        };

        use boojum::gadgets::traits::encodable::CircuitEncodable;

        let packed_query = a_query.encode(cs);

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
            new_memory_queue_tail_after_read[8].get_variable(),
            new_memory_queue_tail_after_read[9].get_variable(),
            new_memory_queue_tail_after_read[10].get_variable(),
            new_memory_queue_tail_after_read[11].get_variable(),
        ];

        use boojum::gadgets::round_function::simulate_round_function;

        let final_state_candidate =
            simulate_round_function::<_, _, 8, 12, 4, R>(cs, initial_state, execute_write);
        let final_state_candidate = final_state_candidate.map(|el| Num::from_variable(el));

        // if crate::config::CIRCUIT_VERSOBE {
        //     if should_apply.witness_hook(&*cs)().unwrap() {
        //         if execute_write.witness_hook(&*cs)().unwrap() {
        //             dbg!(initial_state.map(|el| Num::from_variable(el)).witness_hook(&*cs)().unwrap());
        //             dbg!(final_state_candidate.witness_hook(&*cs)().unwrap());
        //         }
        //     }
        // }

        relations.push((
            execute_write,
            initial_state.map(|el| Num::from_variable(el)),
            final_state_candidate,
        ));

        let mut new_memory_queue_state = Num::parallel_select(
            cs,
            execute_write,
            &final_state_candidate,
            &new_memory_queue_tail_after_read,
        );

        // for all reasonable execution traces it's fine
        let new_len_candidate =
            unsafe { new_memory_queue_length_after_read.increment_unchecked(cs) };

        let new_length_after_aligned_write = UInt32::conditionally_select(
            cs,
            execute_write,
            &new_len_candidate,
            &new_memory_queue_length_after_read,
        );

        // now second query

        let b_query = MemoryQuery {
            timestamp: mem_timestamp_write,
            memory_page: b_memory_loc.page,
            index: b_memory_loc.index,
            is_ptr: boolean_false,
            value: b_new_value,
            rw_flag: boolean_true,
        };

        let packed_query = b_query.encode(cs);

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
            new_memory_queue_state[8].get_variable(),
            new_memory_queue_state[9].get_variable(),
            new_memory_queue_state[10].get_variable(),
            new_memory_queue_state[11].get_variable(),
        ];

        let final_state_candidate = simulate_round_function::<_, _, 8, 12, 4, R>(
            cs,
            initial_state,
            execute_unaligned_write,
        );
        let final_state_candidate = final_state_candidate.map(|el| Num::from_variable(el));

        // if crate::config::CIRCUIT_VERSOBE {
        //     if should_apply.witness_hook(&*cs)().unwrap() {
        //         if execute_unaligned_write.witness_hook(&*cs)().unwrap() {
        //             dbg!(initial_state.map(|el| Num::from_variable(el)).witness_hook(&*cs)().unwrap());
        //             dbg!(final_state_candidate.witness_hook(&*cs)().unwrap());
        //         }
        //     }
        // }

        relations.push((
            execute_unaligned_write,
            initial_state.map(|el| Num::from_variable(el)),
            final_state_candidate,
        ));

        new_memory_queue_state = Num::parallel_select(
            cs,
            execute_unaligned_write,
            &final_state_candidate,
            &new_memory_queue_state,
        );

        // for all reasonable execution traces it's fine
        let new_len_candidate = unsafe { new_length_after_aligned_write.increment_unchecked(cs) };

        let new_length_after_unaligned_write = UInt32::conditionally_select(
            cs,
            execute_unaligned_write,
            &new_len_candidate,
            &new_length_after_aligned_write,
        );

        // push witness updates
        {
            let oracle = witness_oracle.clone();
            // we should assemble all the dependencies here, and we will use AllocateExt here
            let mut dependencies = Vec::with_capacity(
                <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN * 2 + 2,
            );
            dependencies.push(execute_write.get_variable().into());
            dependencies.push(execute_unaligned_write.get_variable().into());
            dependencies.extend(Place::from_variables(a_query.flatten_as_variables()));
            dependencies.extend(Place::from_variables(b_query.flatten_as_variables()));

            cs.set_values_with_dependencies_vararg(
                &dependencies,
                &[],
                move |inputs: &[F], _buffer: &mut DstBuffer<'_, '_, F>| {
                    debug_assert_eq!(
                        inputs.len(),
                        2 + 2 * <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN
                    );

                    let execute_0 = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[0]);
                    let execute_1 = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[1]);

                    if crate::config::CIRCUIT_VERSOBE {
                        if execute_0 {
                            println!("Will overwrite word A for UMA")
                        }
                    }

                    let mut query =
                        [F::ZERO; <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN];
                    query.copy_from_slice(
                        &inputs
                            [2..(2 + <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN)],
                    );
                    let a_query: MemoryQueryWitness<F> =
                        CSAllocatableExt::witness_from_set_of_values(query);

                    let mut guard = oracle.inner.write().expect("not poisoned");
                    guard.push_memory_witness(&a_query, execute_0);

                    if crate::config::CIRCUIT_VERSOBE {
                        if execute_1 {
                            println!("Will overwrite word B for UMA")
                        }
                    }

                    let mut query =
                        [F::ZERO; <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN];
                    query.copy_from_slice(
                        &inputs
                            [(2 + <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN)..],
                    );
                    let b_query: MemoryQueryWitness<F> =
                        CSAllocatableExt::witness_from_set_of_values(query);
                    guard.push_memory_witness(&b_query, execute_1);

                    drop(guard);
                },
            );
        }

        (
            new_memory_queue_state,
            new_length_after_unaligned_write,
            relations,
        )
    };

    // if crate::config::CIRCUIT_VERSOBE {
    //     if should_apply.witness_hook(&*cs)().unwrap() {
    //         dbg!(new_memory_queue_length_after_writes.witness_hook(&*cs)().unwrap());
    //     }
    // }

    let mut read_value_u256 = UInt256::zero(cs);
    // read value is LE integer, while words are treated as BE
    for (dst, src) in read_value_u256
        .inner
        .iter_mut()
        .rev()
        .zip(selected_word.array_chunks::<4>())
    {
        let mut le_bytes = *src;
        le_bytes.reverse();
        let u32_word = UInt32::from_le_bytes(cs, le_bytes);
        *dst = u32_word;
    }

    let read_value_as_register = VMRegister {
        is_pointer: boolean_false,
        value: read_value_u256,
    };

    // compute incremented dst0 if we increment
    let mut incremented_src0_register = common_opcode_state.src0;
    incremented_src0_register.value.inner[0] = quasi_fat_ptr.incremented_offset;

    let is_write_access_and_increment =
        Boolean::multi_and(cs, &[is_write_access, increment_offset]);
    let update_dst0 = Boolean::multi_or(cs, &[is_read_access, is_write_access_and_increment]);

    let no_panic = set_panic.negated(cs);
    let apply_any = Boolean::multi_and(cs, &[should_apply, no_panic]);
    let should_update_dst0 = Boolean::multi_and(cs, &[apply_any, update_dst0]);

    let dst0_value = VMRegister::conditionally_select(
        cs,
        is_write_access_and_increment,
        &incremented_src0_register,
        &read_value_as_register,
    );

    let should_update_dst1 = Boolean::multi_and(cs, &[apply_any, is_read_access, increment_offset]);

    let can_write_into_memory =
        UMA_HEAP_READ_OPCODE.can_write_dst0_into_memory(SUPPORTED_ISA_VERSION);

    diffs_accumulator
        .dst_0_values
        .push((can_write_into_memory, should_update_dst0, dst0_value));
    diffs_accumulator
        .dst_1_values
        .push((should_update_dst1, incremented_src0_register));

    // exceptions
    let should_panic = Boolean::multi_and(cs, &[should_apply, set_panic]);
    diffs_accumulator.pending_exceptions.push(should_panic);

    // and memory related staff
    diffs_accumulator
        .new_heap_bounds
        .push((grow_heap, new_heap_upper_bound));
    diffs_accumulator
        .new_aux_heap_bounds
        .push((grow_aux_heap, new_aux_heap_upper_bound));
    // pay for growth
    diffs_accumulator
        .new_ergs_left_candidates
        .push((should_apply, ergs_left_after_growth));
    // update sponges and queue states

    assert!(UMA_HEAP_READ_OPCODE.can_have_src0_from_mem(SUPPORTED_ISA_VERSION) == false);
    assert!(UMA_HEAP_READ_OPCODE.can_write_dst0_into_memory(SUPPORTED_ISA_VERSION) == false);

    diffs_accumulator.sponge_candidates_to_run.push((
        false,
        false,
        apply_any,
        sponge_candidates_after_writes,
    ));
    diffs_accumulator.memory_queue_candidates.push((
        should_apply,
        new_memory_queue_length_after_writes,
        new_memory_queue_tail_after_writes,
    ));
}

use boojum::gadgets::traits::allocatable::CSAllocatable;
use cs_derive::*;

#[derive(CSAllocatable, WitnessHookable)]
pub struct QuasiFatPtrInUMA<F: SmallField> {
    pub absolute_address: UInt32<F>,
    pub page_candidate: UInt32<F>,
    pub incremented_offset: UInt32<F>,
    pub heap_deref_out_of_bounds: Boolean<F>,
    pub skip_memory_access: Boolean<F>,
    pub should_set_panic: Boolean<F>,
    pub bytes_to_cleanup_out_of_bounds: UInt8<F>,
}

impl<F: SmallField> QuasiFatPtrInUMA<F> {
    pub(crate) fn parse_and_validate<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        input: &RegisterInputView<F>,
        already_panicked: Boolean<F>,
        is_fat_ptr: Boolean<F>,
    ) -> Self {
        // we can never address a range [2^32 - 32..2^32] this way, but we don't care because
        // it's impossible to pay for such memory growth

        let offset = input.u32x8_view[0];
        let page = input.u32x8_view[1];
        let start = input.u32x8_view[2];
        let length = input.u32x8_view[3];

        // if crate::config::CIRCUIT_VERSOBE {
        //     dbg!(offset.witness_hook(&*cs)().unwrap());
        //     dbg!(start.witness_hook(&*cs)().unwrap());
        //     dbg!(length.witness_hook(&*cs)().unwrap());
        // }

        // we need to check whether we will or not deref the fat pointer.
        // we only dereference if offset < length (or offset - length < 0)
        let (_, offset_is_strictly_in_slice) = offset.overflowing_sub(cs, length);
        let offset_is_beyond_the_slice = offset_is_strictly_in_slice.negated(cs);
        let skip_if_legitimate_fat_ptr =
            Boolean::multi_and(cs, &[offset_is_beyond_the_slice, is_fat_ptr]);

        // 0 of it's heap/aux heap, otherwise use what we have
        let formal_start = start.mask(cs, is_fat_ptr);
        // by prevalidating fat pointer we know that there is no overflow here,
        // so we ignore the information
        let (absolute_address, _of) = formal_start.overflowing_add(cs, offset);

        let u32_constant_32 = UInt32::allocated_constant(cs, 32);

        let (incremented_offset, is_non_addressable) = offset.overflowing_add(cs, u32_constant_32);

        // check that we agree in logic with out-of-circuit comparisons
        debug_assert_eq!(
            zkevm_opcode_defs::uma::MAX_OFFSET_TO_DEREF_LOW_U32 + 32u32,
            u32::MAX
        );
        let max_offset = UInt32::allocated_constant(cs, u32::MAX);
        let is_non_addressable_extra = UInt32::equals(cs, &incremented_offset, &max_offset);

        let is_non_addressable =
            Boolean::multi_or(cs, &[is_non_addressable, is_non_addressable_extra]);

        let should_set_panic = Boolean::multi_or(cs, &[already_panicked, is_non_addressable]);

        let skip_memory_access = Boolean::multi_or(
            cs,
            &[
                already_panicked,
                skip_if_legitimate_fat_ptr,
                is_non_addressable,
            ],
        );

        // only necessary for fat pointer deref: now many bytes we zero-out beyond the end of fat pointer
        let (mut bytes_out_of_bound, uf) = incremented_offset.overflowing_sub(cs, length);

        bytes_out_of_bound = bytes_out_of_bound.mask_negated(cs, skip_memory_access);
        bytes_out_of_bound = bytes_out_of_bound.mask_negated(cs, uf);

        let (_, bytes_out_of_bound) = bytes_out_of_bound.div_by_constant(cs, 32);
        // remainder fits into 8 bits too
        let bytes_to_cleanup_out_of_bounds =
            unsafe { UInt8::from_variable_unchecked(bytes_out_of_bound.get_variable()) };

        let new = Self {
            absolute_address,
            page_candidate: page,
            incremented_offset,
            heap_deref_out_of_bounds: is_non_addressable,
            skip_memory_access: skip_memory_access,
            should_set_panic,
            bytes_to_cleanup_out_of_bounds,
        };

        new
    }
}

// for integer N returns a field element with value 1 << N
pub fn uma_shift_into_bitspread<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    integer: Num<F>,
) -> Num<F> {
    use crate::tables::integer_to_boolean_mask::UMAShiftToBitmaskTable;

    let table_id = cs
        .get_table_id_for_marker::<UMAShiftToBitmaskTable>()
        .expect("table must be added before");

    let vals = cs.perform_lookup::<1, 2>(table_id, &[integer.get_variable()]);
    let bitspread = vals[0];

    Num::from_variable(bitspread)
}
