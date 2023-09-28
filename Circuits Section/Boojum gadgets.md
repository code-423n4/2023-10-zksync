# Boojum gadgets

Boojum gadgets are low-level implementations of tools for constraint systems. They consist of various types: curves, hash functions, lookup tables, and different circuit types. These gadgets are mostly a reference from [franklin-crypto](https://github.com/matter-labs/franklin-crypto), with additional hash functions added. These gadgets have been changed to use the Goldilocks field (order 2^64 - 2^32 + 1), which is much smaller than bn256. This allows us to reduce the proof system.

# Circuits types

 We have next types with we use for circuits:

**Num (Number):**

```rust
pub struct Num<F: SmallField> {
    pub(crate) variable: Variable,
    pub(crate) _marker: std::marker::PhantomData<F>,
}
```

**Boolean:**

```rust
pub struct Boolean<F: SmallField> {
    pub(crate) variable: Variable,
    pub(crate) _marker: std::marker::PhantomData<F>,
}
```

**U8:**

```rust
pub struct UInt8<F: SmallField> {
    pub(crate) variable: Variable,
    pub(crate) _marker: std::marker::PhantomData<F>,
}
```

**U16:**

```rust
pub struct UInt16<F: SmallField> {
    pub(crate) variable: Variable,
    pub(crate) _marker: std::marker::PhantomData<F>,
}
```

**U32:**

```rust
pub struct UInt32<F: SmallField> {
    pub(crate) variable: Variable,
    pub(crate) _marker: std::marker::PhantomData<F>,
}
```

**U160:**

```rust
pub struct UInt160<F: SmallField> {
    pub inner: [UInt32<F>; 5],
}
```

**U256:**

```rust
pub struct UInt256<F: SmallField> {
    pub inner: [UInt32<F>; 8],
}
```

**U512:**

```rust
pub struct UInt512<F: SmallField> {
    pub inner: [UInt32<F>; 16],
}
```

      Every type consists of a Variable (the number inside Variable is just the index):

```rust
pub struct Variable(pub(crate) u64); 
```

which is represented in the current Field. Variable is quite diverse, and to have "good" alignment and size we manually do encoding management to be able to represent it as both copiable variable or witness.

The implementation of this circuit type itself is similar. We can also divide them into classes as main and dependent: Such type like U8-U512 decoding inside functions to Num<F> for using them in logical operations.
      As mentioned above, the property of these types is to perform logical operations and allocate witnesses.

Let's demonstrate this in a Boolean example:

```rust
impl<F: SmallField> CSAllocatable<F> for Boolean<F> {
    type Witness = bool;
    fn placeholder_witness() -> Self::Witness {
        false
    }

    #[inline(always)]
    fn allocate_without_value<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let var = cs.alloc_variable_without_value();

        Self::from_variable_checked(cs, var)
    }

    fn allocate<CS: ConstraintSystem<F>>(cs: &mut CS, witness: Self::Witness) -> Self {
        let var = cs.alloc_single_variable_from_witness(F::from_u64_unchecked(witness as u64));

        Self::from_variable_checked(cs, var)
    }
}
```

As you see, you can allocate both with and without witnesses. 

# Hash function

In gadgets we have a lot of hast implementation:

- blake2s
- keccak256
- poseidon/poseidon2
- sha256

Each of them perform different functions in our proof system.