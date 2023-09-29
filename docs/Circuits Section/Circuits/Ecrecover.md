# Ecrecover

## Ecrecover PI

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
pub struct EcrecoverCircuitFSMInputOutput<F: SmallField> {
    pub log_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub memory_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}
```

## Main circuit logic

This circuit implements the ecrecover precompile described in the Ethereum yellow paper: [https://ethereum.github.io/yellowpaper/paper.pdf](https://ethereum.github.io/yellowpaper/paper.pdf)

The purpose of ecrecover is to recover the signer’s public key from digital signature.