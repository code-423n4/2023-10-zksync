# StorageApplication

## StorageApplication PI

### [Input](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/storage_application/input.rs#L56)

```rust
pub struct StorageApplicationInputData<F: SmallField> {
    pub shard: UInt8<F>,
    pub initial_root_hash: [UInt8<F>; 32],
    pub initial_next_enumeration_counter: [UInt32<F>; 2],
    pub storage_application_log_state: QueueState<F, QUEUE_STATE_WIDTH>,
}
```

### [Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/storage_application/input.rs#L77)

```rust
pub struct StorageApplicationOutputData<F: SmallField> {
    pub new_root_hash: [UInt8<F>; 32],
    pub new_next_enumeration_counter: [UInt32<F>; 2],
    pub state_diffs_keccak256_hash: [UInt8<F>; 32],
}
```

### [FSM Input and FSM Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/storage_application/input.rs#L29)

```rust
pub struct StorageApplicationFSMInputOutput<F: SmallField> {
    pub current_root_hash: [UInt8<F>; 32],
    pub next_enumeration_counter: [UInt32<F>; 2],
    pub current_storage_application_log_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub current_diffs_keccak_accumulator_state:
        [[[UInt8<F>; keccak256::BYTES_PER_WORD]; keccak256::LANE_WIDTH]; keccak256::LANE_WIDTH],
}
```

## Main circuit logic