# KeccakRoundFunction

## KeccakRoundFunction PI

### [Input](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/fsm_input_output/circuit_inputs/main_vm.rs#L9)

```rust
pub struct PrecompileFunctionInputData<F: SmallField> {
    pub initial_log_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub initial_memory_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}
```

### [Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/base_structures/precompile_input_outputs/mod.rs#L42)

```rust
pub struct PrecompileFunctionOutputData<F: SmallField> {
    pub final_memory_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}
```

### [FSM Input and FSM Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/keccak256_round_function/input.rs#L59)

```rust
pub struct Keccak256RoundFunctionFSMInputOutput<F: SmallField> {
    pub internal_fsm: Keccak256RoundFunctionFSM<F>,
    pub log_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub memory_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}

pub struct Keccak256RoundFunctionFSM<F: SmallField> {
    pub read_precompile_call: Boolean<F>,
    pub read_unaligned_words_for_round: Boolean<F>,
    pub completed: Boolean<F>,
    pub keccak_internal_state: [[[UInt8<F>; BYTES_PER_WORD]; LANE_WIDTH]; LANE_WIDTH],
    pub timestamp_to_use_for_read: UInt32<F>,
    pub timestamp_to_use_for_write: UInt32<F>,
    pub precompile_call_params: Keccak256PrecompileCallParams<F>,
    pub u8_words_buffer: [UInt8<F>; BYTES_BUFFER_SIZE],
    pub u64_words_buffer_markers: [Boolean<F>; BUFFER_SIZE_IN_U64_WORDS],
}
```

## Main circuit logic

Keccak is a precompile for the keccak hash function.