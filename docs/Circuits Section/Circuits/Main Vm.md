# Main Vm

## MainVm PI

### [Input](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/fsm_input_output/circuit_inputs/main_vm.rs#L9)

```rust
pub struct VmInputData<F: SmallField> {
    pub rollback_queue_tail_for_block: [Num<F>; QUEUE_STATE_WIDTH],
    pub memory_queue_initial_state: QueueTailState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub decommitment_queue_initial_state: QueueTailState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub per_block_context: GlobalContext<F>,
}
```

### [Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/fsm_input_output/circuit_inputs/main_vm.rs#L33)

```rust
pub struct VmOutputData<F: SmallField> {
    pub log_queue_final_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub memory_queue_final_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub decommitment_queue_final_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}
```

### [FSM Input and FSM Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/base_structures/vm_state/mod.rs#L92)

```rust
pub struct VmLocalState<F: SmallField> {
    pub previous_code_word: UInt256<F>,
    pub registers: [VMRegister<F>; REGISTERS_COUNT],
    pub flags: ArithmeticFlagsPort<F>,
    pub timestamp: UInt32<F>,
    pub memory_page_counter: UInt32<F>,
    pub tx_number_in_block: UInt32<F>,
    pub previous_code_page: UInt32<F>,
    pub previous_super_pc: UInt16<F>,
    pub pending_exception: Boolean<F>,
    pub ergs_per_pubdata_byte: UInt32<F>,
    pub callstack: Callstack<F>,
    pub memory_queue_state: [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
    pub memory_queue_length: UInt32<F>,
    pub code_decommittment_queue_state: [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
    pub code_decommittment_queue_length: UInt32<F>,
    pub context_composite_u128: [UInt32<F>; 4],
}
```

## Main circuit logic

Main_vm – is instruction handler. The VM runs in cycles. For each cycle, 

1. Start in a prestate - perform all common operations for every opcode, namely deal with exceptions, resources, edge cases like end of execution, select operands, compute common values. Within the zkEVM framework, numerous entities identified as "opcodes" in the EVM paradigm are elegantly manifested as mere function calls. This modification is rooted in the succinct observation that, from the perspective of an external caller, an inlined function (analogous to an opcode) is inherently indistinguishable from an internal function call.

```rust
let (draft_next_state, common_opcode_state, opcode_carry_parts) =
        create_prestate(cs, current_state, witness_oracle, round_function);
```

1. Compute state diffs for every opcode. List of opcodes:

```rust
pub enum Opcode {
    Invalid(InvalidOpcode),
    Nop(NopOpcode),
    Add(AddOpcode),
    Sub(SubOpcode),
    Mul(MulOpcode),
    Div(DivOpcode),
    Jump(JumpOpcode),
    Context(ContextOpcode),
    Shift(ShiftOpcode),
    Binop(BinopOpcode),
    Ptr(PtrOpcode),
    NearCall(NearCallOpcode),
    Log(LogOpcode),
    FarCall(FarCallOpcode),
    Ret(RetOpcode),
    UMA(UMAOpcode),
}
```

 VM cycle calls such functions for different class of opcodes: nop, add_sup, jump, bind, context, ptr, log, calls_and_ret, mul_div.

 Here we briefly mention all opcodes defined in the system. Each logical "opcode" comes with modifiers, categorized into "exclusive" modifiers (where only one can be applied) and "flags" or "non-exclusive" modifiers (where multiple can be activated simultaneously). The number of permissible "flags" can vary depending on the specific "exclusive" modifier chosen. All data from opcodes we write to StateDiffsAccumulator:

```rust
pub struct StateDiffsAccumulator<F: SmallField> {
    // dst0 candidates
    pub dst_0_values: Vec<(bool, Boolean<F>, VMRegister<F>)>,
    // dst1 candidates
    pub dst_1_values: Vec<(Boolean<F>, VMRegister<F>)>,
    // flags candidates
    pub flags: Vec<(Boolean<F>, ArithmeticFlagsPort<F>)>,
    // specific register updates
    pub specific_registers_updates: [Vec<(Boolean<F>, VMRegister<F>)>; REGISTERS_COUNT],
    // zero out specific registers
    pub specific_registers_zeroing: [Vec<Boolean<F>>; REGISTERS_COUNT],
    // remove ptr markers on specific registers
    pub remove_ptr_on_specific_registers: [Vec<Boolean<F>>; REGISTERS_COUNT],
    // pending exceptions, to be resolved next cycle. Should be masked by opcode applicability already
    pub pending_exceptions: Vec<Boolean<F>>,
    // ergs left, PC
    // new ergs left if it's not one available after decoding
    pub new_ergs_left_candidates: Vec<(Boolean<F>, UInt32<F>)>,
    // new PC in case if it's not just PC+1
    pub new_pc_candidates: Vec<(Boolean<F>, UInt16<F>)>,
    // other meta parameters of VM
    pub new_tx_number: Option<(Boolean<F>, UInt32<F>)>,
    pub new_ergs_per_pubdata: Option<(Boolean<F>, UInt32<F>)>,
    // memory bouds
    pub new_heap_bounds: Vec<(Boolean<F>, UInt32<F>)>,
    pub new_aux_heap_bounds: Vec<(Boolean<F>, UInt32<F>)>,
    // u128 special register, one from context, another from call/ret
    pub context_u128_candidates: Vec<(Boolean<F>, [UInt32<F>; 4])>,
    // internal machinery
    pub callstacks: Vec<(Boolean<F>, Callstack<F>)>,
    // memory page counter
    pub memory_page_counters: Option<UInt32<F>>,
    // decommittment queue
    pub decommitment_queue_candidates: Option<(
        Boolean<F>,
        UInt32<F>,
        [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
    )>,
    // memory queue
    pub memory_queue_candidates: Vec<(
        Boolean<F>,
        UInt32<F>,
        [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
    )>,
    // forward piece of log queue
    pub log_queue_forward_candidates: Vec<(Boolean<F>, UInt32<F>, [Num<F>; QUEUE_STATE_WIDTH])>,
    // rollback piece of log queue
    pub log_queue_rollback_candidates: Vec<(Boolean<F>, UInt32<F>, [Num<F>; QUEUE_STATE_WIDTH])>,
    // sponges to run. Should not include common sponges for src/dst operands
    pub sponge_candidates_to_run: Vec<(
        bool,
        bool,
        Boolean<F>,
        ArrayVec<
            (
                Boolean<F>,
                [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
                [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
            ),
            MAX_SPONGES_PER_CYCLE,
        >,
    )>,
    // add/sub relations to enforce
    pub add_sub_relations: Vec<(
        Boolean<F>,
        ArrayVec<AddSubRelation<F>, MAX_ADD_SUB_RELATIONS_PER_CYCLE>,
    )>,
    // mul/div relations to enforce
    pub mul_div_relations: Vec<(
        Boolean<F>,
        ArrayVec<MulDivRelation<F>, MAX_MUL_DIV_RELATIONS_PER_CYCLE>,
    )>,
}
```

1. Update the memory
2. Update the registers
3. Apply changes to the VM State
    1. Including pushing data to queues for other circuits