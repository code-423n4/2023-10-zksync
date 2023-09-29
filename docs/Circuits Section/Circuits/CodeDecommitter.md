# CodeDecommitter

## CodeDecommitter PI

### [Input](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/code_unpacker_sha256/input.rs#L80)

```rust
pub struct CodeDecommitterInputData<F: SmallField> {
    pub memory_queue_initial_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub sorted_requests_queue_initial_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}
```

### [Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/code_unpacker_sha256/input.rs#L100)

```rust
pub struct CodeDecommitterOutputData<F: SmallField> {
    pub memory_queue_final_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}
```

### [FSM Input and FSM Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/code_unpacker_sha256/input.rs#L61)

```rust
pub struct CodeDecommitterFSMInputOutput<F: SmallField> {
    pub internal_fsm: CodeDecommittmentFSM<F>,
    pub decommittment_requests_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub memory_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}

pub struct CodeDecommittmentFSM<F: SmallField> {
    pub sha256_inner_state: [UInt32<F>; 8], // 8 uint32 words of internal sha256 state
    pub hash_to_compare_against: UInt256<F>,
    pub current_index: UInt32<F>,
    pub current_page: UInt32<F>,
    pub timestamp: UInt32<F>,
    pub num_rounds_left: UInt16<F>,
    pub length_in_bits: UInt32<F>,
    pub state_get_from_queue: Boolean<F>,
    pub state_decommit: Boolean<F>,
    pub finished: Boolean<F>,
}
```

## Main circuit logic

This circuit receive the queue of bytecodes