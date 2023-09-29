# LogSorter

`LogSorter` is one circuit that is used as both `EventsSorter` and `L1MessagesSorter`.

## LogSorter PI

### [Input](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/log_sorter/input.rs#L57)

```rust
pub struct EventsDeduplicatorInputData<F: SmallField> {
    pub initial_log_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub intermediate_sorted_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
}
```

### [Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/log_sorter/input.rs#L74)

```rust
pub struct EventsDeduplicatorOutputData<F: SmallField> {
    pub final_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
}
```

### [FSM Input and FSM Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/log_sorter/input.rs#L28)

```rust
pub struct EventsDeduplicatorFSMInputOutput<F: SmallField> {
    pub lhs_accumulator: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    pub rhs_accumulator: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    pub initial_unsorted_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub intermediate_sorted_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub final_result_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub previous_key: UInt32<F>,
    pub previous_item: LogQuery<F>,
}
```

## Main circuit logic