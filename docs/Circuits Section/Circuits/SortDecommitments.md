# SortDecommitments

## SortDecommitments PI

### [Input](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/sort_decommittment_requests/input.rs#L62)

```rust
pub struct CodeDecommittmentsDeduplicatorInputData<F: SmallField> {
    pub initial_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub sorted_queue_initial_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}
```

### [Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/sort_decommittment_requests/input.rs#L81)

```rust
pub struct CodeDecommittmentsDeduplicatorOutputData<F: SmallField> {
    pub final_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}
```

### [FSM Input and FSM Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/sort_decommittment_requests/input.rs#L26)

```rust
pub struct CodeDecommittmentsDeduplicatorFSMInputOutput<F: SmallField> {
    pub initial_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub sorted_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub final_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,

    pub lhs_accumulator: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],
    pub rhs_accumulator: [Num<F>; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS],

    pub previous_packed_key: [UInt32<F>; PACKED_KEY_LENGTH],
    pub first_encountered_timestamp: UInt32<F>,
    pub previous_record: DecommitQuery<F>,
}
```

## Main circuit logic

This circuit handles the sorting and deduplication of code cancellation requests. Before starting, during the pre-start phase, the first decommiter queue is generated. To decommiter a code, the input will receive the hash root of the code, the length of the code, the code hash of the opcode, the number of opcodes and the code of the page. Next, it sorts the queue and, in the process, identifies and removes identical requests, serving as a filtering mechanism in case the same contract is called several times.

[Sorting and deduplicating](SortDecommitments%208b6c67c18d4b456a835ddbe87fd0175e/Sorting%20and%20deduplicating%2068cc6e7170ef4d44aa1b1c33ff037d32.md)