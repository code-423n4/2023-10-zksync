# StorageSorter

## StorageSorter PI

### [Input](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/storage_validity_by_grand_product/input.rs#L84C57-L84C57)

```rust
pub struct StorageDeduplicatorInputData<F: SmallField> {
    pub shard_id_to_process: UInt8<F>,
    pub unsorted_log_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub intermediate_sorted_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
}
```

### [Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/storage_validity_by_grand_product/input.rs#L103)

```rust
pub struct StorageDeduplicatorOutputData<F: SmallField> {
    pub final_sorted_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
}
```

### [FSM Input and FSM Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/storage_validity_by_grand_product/input.rs#L37)

```rust
pub struct StorageDeduplicatorFSMInputOutput<F: SmallField> {
    pub lhs_accumulator: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    pub rhs_accumulator: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    pub current_unsorted_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub current_intermediate_sorted_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub current_final_sorted_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub cycle_idx: UInt32<F>,
    pub previous_packed_key: [UInt32<F>; PACKED_KEY_LENGTH],
    pub previous_key: UInt256<F>,
    pub previous_address: UInt160<F>,
    pub previous_timestamp: UInt32<F>,
    pub this_cell_has_explicit_read_and_rollback_depth_zero: Boolean<F>,
    pub this_cell_base_value: UInt256<F>,
    pub this_cell_current_value: UInt256<F>,
    pub this_cell_current_depth: UInt32<F>,
}
```

## Main circuit logic