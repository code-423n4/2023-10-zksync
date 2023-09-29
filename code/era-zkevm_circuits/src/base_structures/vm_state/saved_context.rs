use boojum::cs::gates::assert_no_placeholder_variables;
use boojum::cs::traits::cs::DstBuffer;
use boojum::cs::Variable;
use boojum::gadgets::traits::allocatable::CSAllocatableExt;
use boojum::gadgets::traits::castable::WitnessCastable;
use boojum::gadgets::traits::encodable::CircuitEncodable;
use boojum::gadgets::traits::selectable::parallel_select_variables;
use cs_derive::*;
use ethereum_types::Address;

use super::*;

// here we store only part of the context that keeps the data that
// needs to be stored or restored between the calls

// repeated note on how joining of rollback queues work
// - first we use some non-determinism to declare a rollback_tail == current_rollback_head
// - when we do write we add element into front as forward_tail = hash(forward_tail, log_element)
// and also declare some rollback_head, such that current_rollback_head = hash(rollback_head, log_element)
// - if we return "ok" then we join as
//      - forward_tail = callee forward_tail
//      - rollback_head = callee rollback_head
// - else
//      - forward_tail = rollback_tail
//      - caller's rollback_head is unchanged
//      - require callee forward_tail == rollback_head
//
// so to proceed with joining we need to only maintain
// - global forward_tail and length of the forward segment
// - per-context declared rollback_tail
// - per-context computed rollback segment length
// - per-context rollback_head

#[derive(Derivative, CSAllocatable, CSVarLengthEncodable, WitnessHookable)]
#[derivative(Clone, Copy, Debug)]
pub struct ExecutionContextRecord<F: SmallField> {
    pub this: UInt160<F>, // unfortunately delegatecall mangles this field - it can not be restored from callee's caller
    pub caller: UInt160<F>,
    pub code_address: UInt160<F>,

    pub code_page: UInt32<F>,
    pub base_page: UInt32<F>,

    pub heap_upper_bound: UInt32<F>,
    pub aux_heap_upper_bound: UInt32<F>,

    pub reverted_queue_head: [Num<F>; 4],
    pub reverted_queue_tail: [Num<F>; 4],
    pub reverted_queue_segment_len: UInt32<F>,

    pub pc: UInt16<F>,
    pub sp: UInt16<F>,
    pub exception_handler_loc: UInt16<F>,
    pub ergs_remaining: UInt32<F>,

    pub is_static_execution: Boolean<F>,
    pub is_kernel_mode: Boolean<F>,

    pub this_shard_id: UInt8<F>,
    pub caller_shard_id: UInt8<F>,
    pub code_shard_id: UInt8<F>,

    pub context_u128_value_composite: [UInt32<F>; 4],

    pub is_local_call: Boolean<F>,
}

impl<F: SmallField> ExecutionContextRecord<F> {
    pub fn uninitialized<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let zero_u160 = UInt160::zero(cs);
        let zero_u32 = UInt32::zero(cs);
        let zero_u16 = UInt16::zero(cs);
        let zero_u8 = UInt8::zero(cs);
        let zero_num = Num::zero(cs);
        let boolean_false = Boolean::allocated_constant(cs, false);
        Self {
            this: zero_u160,
            caller: zero_u160,
            code_address: zero_u160,
            code_page: zero_u32,
            base_page: zero_u32,

            heap_upper_bound: zero_u32,
            aux_heap_upper_bound: zero_u32,

            reverted_queue_head: [zero_num; 4],
            reverted_queue_tail: [zero_num; 4],
            reverted_queue_segment_len: zero_u32,

            pc: zero_u16,
            sp: zero_u16,
            exception_handler_loc: zero_u16,
            ergs_remaining: zero_u32,

            is_static_execution: boolean_false,
            is_kernel_mode: boolean_false,

            this_shard_id: zero_u8,
            caller_shard_id: zero_u8,
            code_shard_id: zero_u8,

            context_u128_value_composite: [zero_u32; 4],

            is_local_call: boolean_false,
        }
    }
}

pub const EXECUTION_CONTEXT_RECORD_ENCODING_WIDTH: usize = 32;

impl<F: SmallField> CircuitEncodable<F, EXECUTION_CONTEXT_RECORD_ENCODING_WIDTH>
    for ExecutionContextRecord<F>
{
    fn encode<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
    ) -> [Variable; EXECUTION_CONTEXT_RECORD_ENCODING_WIDTH] {
        debug_assert!(F::CAPACITY_BITS >= 57);
        // full field elements first for simplicity
        let v0 = self.reverted_queue_head[0].get_variable();
        let v1 = self.reverted_queue_head[1].get_variable();
        let v2 = self.reverted_queue_head[2].get_variable();
        let v3 = self.reverted_queue_head[3].get_variable();

        let v4 = self.reverted_queue_tail[0].get_variable();
        let v5 = self.reverted_queue_tail[1].get_variable();
        let v6 = self.reverted_queue_tail[2].get_variable();
        let v7 = self.reverted_queue_tail[3].get_variable();

        let v8 = self.code_address.inner[0].get_variable();
        let v9 = self.code_address.inner[1].get_variable();
        let v10 = self.code_address.inner[2].get_variable();
        let v11 = self.code_address.inner[3].get_variable();
        let v12 = self.code_address.inner[4].get_variable();

        let v13 = self.this.inner[0].get_variable();
        let v14 = self.this.inner[1].get_variable();
        let v15 = self.this.inner[2].get_variable();
        let v16 = self.this.inner[3].get_variable();
        let v17 = self.this.inner[4].get_variable();

        let v18 = self.caller.inner[0].get_variable();
        let v19 = self.caller.inner[1].get_variable();
        let v20 = self.caller.inner[2].get_variable();
        let v21 = self.caller.inner[3].get_variable();
        let v22 = self.caller.inner[4].get_variable();

        let v23 = self.context_u128_value_composite[0].get_variable();
        let v24 = self.context_u128_value_composite[1].get_variable();
        let v25 = self.context_u128_value_composite[2].get_variable();
        let v26 = self.context_u128_value_composite[3].get_variable();

        // now we have left
        // - code_page
        // - base_page
        // - heap_upper_bound
        // - aux_heap_upper_bound
        // - ergs_remaining
        // - sp
        // - pc
        // - eh
        // - reverted_queue_segment_len
        // - shard ids
        // - few boolean flags

        // as usual, take u32 and add something on top

        let v27 = Num::linear_combination(
            cs,
            &[
                (self.code_page.get_variable(), F::ONE),
                (self.pc.get_variable(), F::from_u64_unchecked(1u64 << 32)),
                (
                    self.this_shard_id.get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
                (
                    self.is_static_execution.get_variable(),
                    F::from_u64_unchecked(1u64 << 56),
                ),
            ],
        )
        .get_variable();

        let v28 = Num::linear_combination(
            cs,
            &[
                (self.base_page.get_variable(), F::ONE),
                (self.sp.get_variable(), F::from_u64_unchecked(1u64 << 32)),
                (
                    self.caller_shard_id.get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
                (
                    self.is_kernel_mode.get_variable(),
                    F::from_u64_unchecked(1u64 << 56),
                ),
            ],
        )
        .get_variable();

        let v29 = Num::linear_combination(
            cs,
            &[
                (self.ergs_remaining.get_variable(), F::ONE),
                (
                    self.exception_handler_loc.get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    self.code_shard_id.get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
                (
                    self.is_local_call.get_variable(),
                    F::from_u64_unchecked(1u64 << 56),
                ),
            ],
        )
        .get_variable();

        // now we have left
        // - heap_upper_bound
        // - aux_heap_upper_bound
        // - reverted_queue_segment_len

        let reverted_queue_segment_len_decomposition =
            self.reverted_queue_segment_len.decompose_into_bytes(cs);
        let v30 = Num::linear_combination(
            cs,
            &[
                (self.heap_upper_bound.get_variable(), F::ONE),
                (
                    reverted_queue_segment_len_decomposition[0].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    reverted_queue_segment_len_decomposition[1].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
            ],
        )
        .get_variable();

        let v31 = Num::linear_combination(
            cs,
            &[
                (self.aux_heap_upper_bound.get_variable(), F::ONE),
                (
                    reverted_queue_segment_len_decomposition[2].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    reverted_queue_segment_len_decomposition[3].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
            ],
        )
        .get_variable();

        [
            v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18,
            v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31,
        ]
    }
}

// we also need allocate extended

impl<F: SmallField> CSAllocatableExt<F> for ExecutionContextRecord<F> {
    const INTERNAL_STRUCT_LEN: usize = 42;

    fn create_without_value<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        // TODO: use more optimal allocation for bytes
        CSAllocatable::allocate_without_value(cs)
    }

    fn flatten_as_variables(&self) -> [Variable; Self::INTERNAL_STRUCT_LEN] {
        [
            self.this.inner[0].get_variable(),
            self.this.inner[1].get_variable(),
            self.this.inner[2].get_variable(),
            self.this.inner[3].get_variable(),
            self.this.inner[4].get_variable(),
            self.caller.inner[0].get_variable(),
            self.caller.inner[1].get_variable(),
            self.caller.inner[2].get_variable(),
            self.caller.inner[3].get_variable(),
            self.caller.inner[4].get_variable(),
            self.code_address.inner[0].get_variable(),
            self.code_address.inner[1].get_variable(),
            self.code_address.inner[2].get_variable(),
            self.code_address.inner[3].get_variable(),
            self.code_address.inner[4].get_variable(),
            self.code_page.get_variable(),
            self.base_page.get_variable(),
            self.heap_upper_bound.get_variable(),
            self.aux_heap_upper_bound.get_variable(),
            self.reverted_queue_head[0].get_variable(),
            self.reverted_queue_head[1].get_variable(),
            self.reverted_queue_head[2].get_variable(),
            self.reverted_queue_head[3].get_variable(),
            self.reverted_queue_tail[0].get_variable(),
            self.reverted_queue_tail[1].get_variable(),
            self.reverted_queue_tail[2].get_variable(),
            self.reverted_queue_tail[3].get_variable(),
            self.reverted_queue_segment_len.get_variable(),
            self.pc.get_variable(),
            self.sp.get_variable(),
            self.exception_handler_loc.get_variable(),
            self.ergs_remaining.get_variable(),
            self.is_static_execution.get_variable(),
            self.is_kernel_mode.get_variable(),
            self.this_shard_id.get_variable(),
            self.caller_shard_id.get_variable(),
            self.code_shard_id.get_variable(),
            self.context_u128_value_composite[0].get_variable(),
            self.context_u128_value_composite[1].get_variable(),
            self.context_u128_value_composite[2].get_variable(),
            self.context_u128_value_composite[3].get_variable(),
            self.is_local_call.get_variable(),
        ]
    }

    fn from_variables_set(variables: [Variable; Self::INTERNAL_STRUCT_LEN]) -> Self {
        unsafe {
            Self {
                this: UInt160::from_variables_unchecked([
                    variables[0],
                    variables[1],
                    variables[2],
                    variables[3],
                    variables[4],
                ]),
                caller: UInt160::from_variables_unchecked([
                    variables[5],
                    variables[6],
                    variables[7],
                    variables[8],
                    variables[9],
                ]),
                code_address: UInt160::from_variables_unchecked([
                    variables[10],
                    variables[11],
                    variables[12],
                    variables[13],
                    variables[14],
                ]),
                code_page: UInt32::from_variable_unchecked(variables[15]),
                base_page: UInt32::from_variable_unchecked(variables[16]),

                heap_upper_bound: UInt32::from_variable_unchecked(variables[17]),
                aux_heap_upper_bound: UInt32::from_variable_unchecked(variables[18]),

                reverted_queue_head: [variables[19], variables[20], variables[21], variables[22]]
                    .map(|el| Num::from_variable(el)),

                reverted_queue_tail: [variables[23], variables[24], variables[25], variables[26]]
                    .map(|el| Num::from_variable(el)),

                reverted_queue_segment_len: UInt32::from_variable_unchecked(variables[27]),

                pc: UInt16::from_variable_unchecked(variables[28]),
                sp: UInt16::from_variable_unchecked(variables[29]),
                exception_handler_loc: UInt16::from_variable_unchecked(variables[30]),
                ergs_remaining: UInt32::from_variable_unchecked(variables[31]),

                is_static_execution: Boolean::from_variable_unchecked(variables[32]),
                is_kernel_mode: Boolean::from_variable_unchecked(variables[33]),

                this_shard_id: UInt8::from_variable_unchecked(variables[34]),
                caller_shard_id: UInt8::from_variable_unchecked(variables[35]),
                code_shard_id: UInt8::from_variable_unchecked(variables[36]),

                context_u128_value_composite: [
                    variables[37],
                    variables[38],
                    variables[39],
                    variables[40],
                ]
                .map(|el| UInt32::from_variable_unchecked(el)),

                is_local_call: Boolean::from_variable_unchecked(variables[41]),
            }
        }
    }

    fn set_internal_variables_values(witness: Self::Witness, dst: &mut DstBuffer<'_, '_, F>) {
        let src = WitnessCastable::cast_into_source(witness.this);
        dst.extend(src);

        let src = WitnessCastable::cast_into_source(witness.caller);
        dst.extend(src);

        let src = WitnessCastable::cast_into_source(witness.code_address);
        dst.extend(src);

        dst.push(WitnessCastable::cast_into_source(witness.code_page));
        dst.push(WitnessCastable::cast_into_source(witness.base_page));
        dst.push(WitnessCastable::cast_into_source(witness.heap_upper_bound));
        dst.push(WitnessCastable::cast_into_source(
            witness.aux_heap_upper_bound,
        ));

        dst.extend(witness.reverted_queue_head);
        dst.extend(witness.reverted_queue_tail);
        dst.push(WitnessCastable::cast_into_source(
            witness.reverted_queue_segment_len,
        ));

        dst.push(WitnessCastable::cast_into_source(witness.pc));
        dst.push(WitnessCastable::cast_into_source(witness.sp));
        dst.push(WitnessCastable::cast_into_source(
            witness.exception_handler_loc,
        ));
        dst.push(WitnessCastable::cast_into_source(witness.ergs_remaining));

        dst.push(WitnessCastable::cast_into_source(
            witness.is_static_execution,
        ));
        dst.push(WitnessCastable::cast_into_source(witness.is_kernel_mode));
        dst.push(WitnessCastable::cast_into_source(witness.this_shard_id));
        dst.push(WitnessCastable::cast_into_source(witness.caller_shard_id));
        dst.push(WitnessCastable::cast_into_source(witness.code_shard_id));

        dst.extend(WitnessCastable::cast_into_source(
            witness.context_u128_value_composite,
        ));

        dst.push(WitnessCastable::cast_into_source(witness.is_local_call));
    }

    fn witness_from_set_of_values(values: [F; Self::INTERNAL_STRUCT_LEN]) -> Self::Witness {
        let this: Address = WitnessCastable::cast_from_source([
            values[0], values[1], values[2], values[3], values[4],
        ]);

        let caller: Address = WitnessCastable::cast_from_source([
            values[5], values[6], values[7], values[8], values[9],
        ]);

        let code_address: Address = WitnessCastable::cast_from_source([
            values[10], values[11], values[12], values[13], values[14],
        ]);

        let code_page: u32 = WitnessCastable::cast_from_source(values[15]);
        let base_page: u32 = WitnessCastable::cast_from_source(values[16]);

        let heap_upper_bound: u32 = WitnessCastable::cast_from_source(values[17]);
        let aux_heap_upper_bound: u32 = WitnessCastable::cast_from_source(values[18]);

        let reverted_queue_head = [values[19], values[20], values[21], values[22]];

        let reverted_queue_tail = [values[23], values[24], values[25], values[26]];

        let reverted_queue_segment_len: u32 = WitnessCastable::cast_from_source(values[27]);

        let pc: u16 = WitnessCastable::cast_from_source(values[28]);
        let sp: u16 = WitnessCastable::cast_from_source(values[29]);
        let exception_handler_loc: u16 = WitnessCastable::cast_from_source(values[30]);

        let ergs_remaining: u32 = WitnessCastable::cast_from_source(values[31]);

        let is_static_execution: bool = WitnessCastable::cast_from_source(values[32]);
        let is_kernel_mode: bool = WitnessCastable::cast_from_source(values[33]);

        let this_shard_id: u8 = WitnessCastable::cast_from_source(values[34]);
        let caller_shard_id: u8 = WitnessCastable::cast_from_source(values[35]);
        let code_shard_id: u8 = WitnessCastable::cast_from_source(values[36]);

        let context_u128_value_composite: [u32; 4] =
            WitnessCastable::cast_from_source([values[37], values[38], values[39], values[40]]);

        let is_local_call: bool = WitnessCastable::cast_from_source(values[41]);

        Self::Witness {
            this,
            caller,
            code_address,

            code_page,
            base_page,

            heap_upper_bound,
            aux_heap_upper_bound,

            reverted_queue_head,
            reverted_queue_tail,
            reverted_queue_segment_len,

            pc,
            sp,
            exception_handler_loc,
            ergs_remaining,

            is_static_execution,
            is_kernel_mode,

            this_shard_id,
            caller_shard_id,
            code_shard_id,

            context_u128_value_composite,

            is_local_call,
        }
    }
}

impl<F: SmallField> Selectable<F> for ExecutionContextRecord<F>
where
    [(); Self::INTERNAL_STRUCT_LEN]:,
{
    fn conditionally_select<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        flag: Boolean<F>,
        a: &Self,
        b: &Self,
    ) -> Self {
        let a_as_variables = a.flatten_as_variables();
        let b_as_variables = b.flatten_as_variables();

        let mut dst = [Variable::placeholder(); ExecutionContextRecord::<F>::INTERNAL_STRUCT_LEN];

        let it = a_as_variables
            .into_iter()
            .zip(b_as_variables.into_iter())
            .zip(dst.iter_mut())
            .filter_map(|((a, b), dst)| {
                if a == b {
                    // skip and assign any
                    *dst = a;

                    None
                } else {
                    Some(((a, b), dst))
                }
            });

        parallel_select_variables(cs, flag, it);

        // cast back

        assert_no_placeholder_variables(&dst);

        Self::from_variables_set(dst)
    }
}
