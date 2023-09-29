# RAMPermutation

## RAMPermutation PI

### [Input](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/ram_permutation/input.rs#L27)

```rust
pub struct RamPermutationInputData<F: SmallField> {
    pub unsorted_queue_initial_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub sorted_queue_initial_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub non_deterministic_bootloader_memory_snapshot_length: UInt32<F>,
}
```

### Output

```rust
()
```

### [FSM Input and FSM Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/ram_permutation/input.rs#L52)

```rust
pub struct RamPermutationFSMInputOutput<F: SmallField> {
    pub lhs_accumulator: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    pub rhs_accumulator: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    pub current_unsorted_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub current_sorted_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub previous_sorting_key: [UInt32<F>; RAM_SORTING_KEY_LENGTH],
    pub previous_full_key: [UInt32<F>; RAM_FULL_KEY_LENGTH],
    pub previous_value: UInt256<F>,
    pub previous_is_ptr: Boolean<F>,
    pub num_nondeterministic_writes: UInt32<F>,
}
```

## Main circuit logic