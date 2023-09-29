# L2→L1 communication before Boojum

# Main instrument: L2→L1 log

The only “provable” part of the communication from L2 to L1 are native L2→L1 logs emitted by VM. These can be emitted by the `to_l1` opcode (TODO: link). Each log consists of the following fields:

```solidity
struct L2Log {
    uint8 l2ShardId;
    bool isService;
    uint16 txNumberInBatch;
    address sender;
    bytes32 key;
    bytes32 value;
}
```

Where:

- `l2ShardId` is the id of the shard the opcode was called (it is currently always 0).
- `isService` a boolean flag that is not used right now
- `txNumberInBatch` the number of the transaction in the batch where the log has happened. This number is taken from the internal counter which is incremented each time the `increment_tx_counter` is called (TODO: link).
- `sender` is the value of `this` in the frame where the L2→L1 log was emitted.
- `key` and `value` are just two 32-byte values that could be used to carry some data with the log.

The hashed array of these opcodes is then included into the block commitment: (TODO: link). Because of that we know that if the proof verifies, then the L2→L1 logs provided by the operator were correct, so we can use that fact to produce more complex structures. Before Boojum such logs were also Merklized within the circuits and so the Merkle tree’s root hash was included into the block commitment: (TODO link).

## Important system values

Two `key` and `value` fields are enough for a lot of system-related use-cases, such as sending timestamp of the batch, previous batch hash, etc. (TODO: links to block processing).  

## Long L2→L1 messages & bytecodes

However, sometimes users want to send long messages beyond 64 bytes which `key` and `value` allow us. But as already said, these L2→L1 logs are the only ways that the L2 can communicate with the outside world. How do we provide long messages? 

Let’s add an `sendToL1` method in L1Messenger, where the main idea is the following:

- Let’s submit an L2→L1 log with `key = msg.sender` (the actual sender of the long message) and `value = keccak256(message)`.
- Now, during block commitment the operator will have to provide an array of such long L2→L1 messages and it will be checked on L1 that indeed for each such log the correct preimage was provided.

A very similar idea is used to publish uncompressed bytecodes on L1 (the compressed bytecodes were sent via the long L1→L2 messages mechanism as explained above). 

Note, however, that whenever someone wants to prove that a certain message was present, they need to compose the L2→L1 log and prove its presence. 

## Priority operations

Also, for each priority operation, we would send its hash and it status via an L2→L1 log. On L1 we would then reconstruct the rolling hash of the processed priority transactions, allowing to correctly verify during the `executeBatches` method that indeed the batch contained the correct priority operations.

Importantly, the fact that both hash and status were sent, it made it possible to prove that the L2 part of a deposit has failed and ask the bridge to release funds: (TODO link).