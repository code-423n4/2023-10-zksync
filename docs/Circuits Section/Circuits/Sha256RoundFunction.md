# Sha256RoundFunction

## Sha256RoundFunction PI

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
pub struct Sha256RoundFunctionFSMInputOutput<F: SmallField> {
    pub internal_fsm: Sha256RoundFunctionFSM<F>,
    pub log_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub memory_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}

pub struct Sha256RoundFunctionFSM<F: SmallField> {
    pub read_precompile_call: Boolean<F>,
    pub read_words_for_round: Boolean<F>,
    pub completed: Boolean<F>,
    pub sha256_inner_state: [UInt32<F>; 8],
    pub timestamp_to_use_for_read: UInt32<F>,
    pub timestamp_to_use_for_write: UInt32<F>,
    pub precompile_call_params: Sha256PrecompileCallParams<F>,
}
```

## Main circuit logic

This is a precompile for the SHA256 hash function’s round function.