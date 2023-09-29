# DemuxLogQueue

## DemuxLogQueue PI

### [Input](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/demux_log_queue/input.rs#L49)

```rust
pub struct LogDemuxerInputData<F: SmallField> {
    pub initial_log_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
}
```

### [Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/fsm_input_output/circuit_inputs/main_vm.rs#L33)

```rust
pub struct LogDemuxerOutputData<F: SmallField> {
    pub storage_access_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub events_access_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub l1messages_access_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub keccak256_access_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub sha256_access_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub ecrecover_access_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
}
```

### [FSM Input and FSM Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/demux_log_queue/input.rs#L22)

```rust
pub struct LogDemuxerFSMInputOutput<F: SmallField> {
    pub initial_log_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub storage_access_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub events_access_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub l1messages_access_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub keccak256_access_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub sha256_access_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub ecrecover_access_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
}
```

## Main circuit logic