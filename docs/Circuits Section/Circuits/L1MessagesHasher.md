# L1MessagesHasher

## L1MessagesHasher PI

### [Input](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/linear_hasher/input.rs#L27)

```rust
pub struct LinearHasherInputData<F: SmallField> {
    pub queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
}
```

### [Output](https://github.com/matter-labs/era-zkevm_circuits/blob/4fba537ccecc238e2da9c80844dc8c185e42466f/src/linear_hasher/input.rs#L42)

```rust
pub struct LinearHasherOutputData<F: SmallField> {
    pub keccak256_hash: [UInt8<F>; 32],
}
```

### FSM Input and FSM Output

```rust
() // this circuit has big capacity, so we don't need several instances
```

## Main circuit logic