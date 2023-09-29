use super::*;
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::cs::traits::cs::DstBuffer;
use boojum::cs::Variable;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::num::Num;
use boojum::gadgets::traits::allocatable::CSPlaceholder;
use boojum::gadgets::traits::allocatable::{CSAllocatable, CSAllocatableExt};
use boojum::gadgets::traits::castable::WitnessCastable;
use boojum::gadgets::traits::encodable::CircuitEncodableExt;
use boojum::gadgets::traits::encodable::{CircuitEncodable, CircuitVarLengthEncodable};
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::traits::witnessable::WitnessHookable;
use boojum::gadgets::u160::{recompose_address_from_u32x5, UInt160};
use boojum::gadgets::u256::{recompose_u256_as_u32x8, UInt256};
use boojum::gadgets::u32::UInt32;
use boojum::gadgets::u8::UInt8;
use cs_derive::*;

#[derive(Derivative, CSAllocatable, CSSelectable, WitnessHookable, CSVarLengthEncodable)]
#[derivative(Clone, Copy, Debug, Hash)]
pub struct LogQuery<F: SmallField> {
    pub address: UInt160<F>,
    pub key: UInt256<F>,
    pub read_value: UInt256<F>,
    pub written_value: UInt256<F>,
    pub aux_byte: UInt8<F>,
    pub rw_flag: Boolean<F>,
    pub rollback: Boolean<F>,
    pub is_service: Boolean<F>,
    pub shard_id: UInt8<F>,
    pub tx_number_in_block: UInt32<F>,
    pub timestamp: UInt32<F>,
}
impl<F: SmallField> CircuitEncodableExt<F, LOG_QUERY_PACKED_WIDTH> for LogQuery<F> {}

pub const LOG_QUERY_PACKED_WIDTH: usize = 20;
pub const LOG_QUERY_ABSORBTION_ROUNDS: usize = 3;

// NOTE: (shamatar): workaround for cost generics for now
pub(crate) const FLATTENED_VARIABLE_LENGTH: usize = 36;

// because two logs that we add to the queue on write-like operation only differ by
// rollback flag, we want to specially define offset for rollback, so we can
// pack two cases for free. Also packing of the rollback should go into variable
// number 16 or later, so we can share sponges before it

pub const ROLLBACK_PACKING_FLAG_VARIABLE_IDX: usize = 19;

impl<F: SmallField> LogQuery<F> {
    pub fn update_packing_for_rollback<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        existing_packing: &mut [Variable; LOG_QUERY_PACKED_WIDTH],
    ) {
        let boolean_true = Boolean::allocated_constant(cs, true);
        existing_packing[ROLLBACK_PACKING_FLAG_VARIABLE_IDX] = boolean_true.get_variable();
    }

    pub(crate) fn flatten_as_variables_impl(&self) -> [Variable; FLATTENED_VARIABLE_LENGTH] {
        [
            self.address.inner[0].get_variable(),
            self.address.inner[1].get_variable(),
            self.address.inner[2].get_variable(),
            self.address.inner[3].get_variable(),
            self.address.inner[4].get_variable(),
            self.key.inner[0].get_variable(),
            self.key.inner[1].get_variable(),
            self.key.inner[2].get_variable(),
            self.key.inner[3].get_variable(),
            self.key.inner[4].get_variable(),
            self.key.inner[5].get_variable(),
            self.key.inner[6].get_variable(),
            self.key.inner[7].get_variable(),
            self.read_value.inner[0].get_variable(),
            self.read_value.inner[1].get_variable(),
            self.read_value.inner[2].get_variable(),
            self.read_value.inner[3].get_variable(),
            self.read_value.inner[4].get_variable(),
            self.read_value.inner[5].get_variable(),
            self.read_value.inner[6].get_variable(),
            self.read_value.inner[7].get_variable(),
            self.written_value.inner[0].get_variable(),
            self.written_value.inner[1].get_variable(),
            self.written_value.inner[2].get_variable(),
            self.written_value.inner[3].get_variable(),
            self.written_value.inner[4].get_variable(),
            self.written_value.inner[5].get_variable(),
            self.written_value.inner[6].get_variable(),
            self.written_value.inner[7].get_variable(),
            self.aux_byte.get_variable(),
            self.rw_flag.get_variable(),
            self.rollback.get_variable(),
            self.is_service.get_variable(),
            self.shard_id.get_variable(),
            self.tx_number_in_block.get_variable(),
            self.timestamp.get_variable(),
        ]
    }
}

impl<F: SmallField> CSPlaceholder<F> for LogQuery<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let boolean_false = Boolean::allocated_constant(cs, false);
        Self {
            address: UInt160::<F>::zero(cs),
            key: UInt256::zero(cs),
            read_value: UInt256::zero(cs),
            written_value: UInt256::zero(cs),
            rw_flag: boolean_false,
            aux_byte: UInt8::zero(cs),
            rollback: boolean_false,
            is_service: boolean_false,
            shard_id: UInt8::zero(cs),
            tx_number_in_block: UInt32::zero(cs),
            timestamp: UInt32::zero(cs),
        }
    }
}

impl<F: SmallField> CircuitEncodable<F, LOG_QUERY_PACKED_WIDTH> for LogQuery<F> {
    fn encode<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> [Variable; LOG_QUERY_PACKED_WIDTH] {
        debug_assert!(F::CAPACITY_BITS >= 56);
        // we decompose "key" and mix it into other limbs because with high probability
        // in VM decomposition of "key" will always exist beforehand
        let key_bytes = self.key.inner.map(|el| el.decompose_into_bytes(cs));
        let address_bytes = self.address.inner.map(|el| el.decompose_into_bytes(cs));

        // we want to pack tightly, so we "base" our packing on read and written values

        let v0 = Num::linear_combination(
            cs,
            &[
                (self.read_value.inner[0].get_variable(), F::ONE),
                (
                    key_bytes[0][0].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    key_bytes[0][1].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    key_bytes[0][2].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v1 = Num::linear_combination(
            cs,
            &[
                (self.read_value.inner[1].get_variable(), F::ONE),
                (
                    key_bytes[0][3].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    key_bytes[1][0].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    key_bytes[1][1].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v2 = Num::linear_combination(
            cs,
            &[
                (self.read_value.inner[2].get_variable(), F::ONE),
                (
                    key_bytes[1][2].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    key_bytes[1][3].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    key_bytes[2][0].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v3 = Num::linear_combination(
            cs,
            &[
                (self.read_value.inner[3].get_variable(), F::ONE),
                (
                    key_bytes[2][1].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    key_bytes[2][2].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    key_bytes[2][3].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v4 = Num::linear_combination(
            cs,
            &[
                (self.read_value.inner[4].get_variable(), F::ONE),
                (
                    key_bytes[3][0].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    key_bytes[3][1].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    key_bytes[3][2].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v5 = Num::linear_combination(
            cs,
            &[
                (self.read_value.inner[5].get_variable(), F::ONE),
                (
                    key_bytes[3][3].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    key_bytes[4][0].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    key_bytes[4][1].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v6 = Num::linear_combination(
            cs,
            &[
                (self.read_value.inner[6].get_variable(), F::ONE),
                (
                    key_bytes[4][2].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    key_bytes[4][3].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    key_bytes[5][0].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v7 = Num::linear_combination(
            cs,
            &[
                (self.read_value.inner[7].get_variable(), F::ONE),
                (
                    key_bytes[5][1].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    key_bytes[5][2].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    key_bytes[5][3].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        // continue with written value

        let v8 = Num::linear_combination(
            cs,
            &[
                (self.written_value.inner[0].get_variable(), F::ONE),
                (
                    key_bytes[6][0].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    key_bytes[6][1].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    key_bytes[6][2].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v9 = Num::linear_combination(
            cs,
            &[
                (self.written_value.inner[1].get_variable(), F::ONE),
                (
                    key_bytes[6][3].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    key_bytes[7][0].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    key_bytes[7][1].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        // continue mixing bytes, now from "address"

        let v10 = Num::linear_combination(
            cs,
            &[
                (self.written_value.inner[2].get_variable(), F::ONE),
                (
                    key_bytes[7][2].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    key_bytes[7][3].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    address_bytes[0][0].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v11 = Num::linear_combination(
            cs,
            &[
                (self.written_value.inner[3].get_variable(), F::ONE),
                (
                    address_bytes[0][1].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    address_bytes[0][2].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    address_bytes[0][3].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v12 = Num::linear_combination(
            cs,
            &[
                (self.written_value.inner[4].get_variable(), F::ONE),
                (
                    address_bytes[1][0].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    address_bytes[1][1].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    address_bytes[1][2].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v13 = Num::linear_combination(
            cs,
            &[
                (self.written_value.inner[5].get_variable(), F::ONE),
                (
                    address_bytes[1][3].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    address_bytes[2][0].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    address_bytes[2][1].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v14 = Num::linear_combination(
            cs,
            &[
                (self.written_value.inner[6].get_variable(), F::ONE),
                (
                    address_bytes[2][2].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    address_bytes[2][3].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    address_bytes[3][0].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v15 = Num::linear_combination(
            cs,
            &[
                (self.written_value.inner[7].get_variable(), F::ONE),
                (
                    address_bytes[3][1].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    address_bytes[3][2].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    address_bytes[3][3].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        // now we can pack using some other "large" items as base

        let v16 = Num::linear_combination(
            cs,
            &[
                (self.timestamp.get_variable(), F::ONE),
                (
                    address_bytes[4][0].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    address_bytes[4][1].get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    address_bytes[4][2].get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v17 = Num::linear_combination(
            cs,
            &[
                (self.tx_number_in_block.get_variable(), F::ONE),
                (
                    address_bytes[4][3].get_variable(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    self.aux_byte.get_variable(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    self.shard_id.get_variable(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        )
        .get_variable();

        let v18 = Num::linear_combination(
            cs,
            &[
                (self.rw_flag.get_variable(), F::ONE),
                (self.is_service.get_variable(), F::TWO),
            ],
        )
        .get_variable();

        // and the final variable is just rollback flag itself

        // NOTE: if you even change this encoding please ensure that corresponding part
        // is updated in TimestampedStorageLogRecord
        let v19 = self.rollback.get_variable();

        [
            v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18,
            v19,
        ]
    }
}

pub(crate) fn log_query_witness_from_values<F: SmallField>(
    values: [F; FLATTENED_VARIABLE_LENGTH],
) -> <LogQuery<F> as CSAllocatable<F>>::Witness {
    let address: [u32; 5] = [
        WitnessCastable::cast_from_source(values[0]),
        WitnessCastable::cast_from_source(values[1]),
        WitnessCastable::cast_from_source(values[2]),
        WitnessCastable::cast_from_source(values[3]),
        WitnessCastable::cast_from_source(values[4]),
    ];
    let address = recompose_address_from_u32x5(address);

    let key: [u32; 8] = [
        WitnessCastable::cast_from_source(values[5]),
        WitnessCastable::cast_from_source(values[6]),
        WitnessCastable::cast_from_source(values[7]),
        WitnessCastable::cast_from_source(values[8]),
        WitnessCastable::cast_from_source(values[9]),
        WitnessCastable::cast_from_source(values[10]),
        WitnessCastable::cast_from_source(values[11]),
        WitnessCastable::cast_from_source(values[12]),
    ];
    let key = recompose_u256_as_u32x8(key);

    let read_value: [u32; 8] = [
        WitnessCastable::cast_from_source(values[13]),
        WitnessCastable::cast_from_source(values[14]),
        WitnessCastable::cast_from_source(values[15]),
        WitnessCastable::cast_from_source(values[16]),
        WitnessCastable::cast_from_source(values[17]),
        WitnessCastable::cast_from_source(values[18]),
        WitnessCastable::cast_from_source(values[19]),
        WitnessCastable::cast_from_source(values[20]),
    ];
    let read_value = recompose_u256_as_u32x8(read_value);

    let written_value: [u32; 8] = [
        WitnessCastable::cast_from_source(values[21]),
        WitnessCastable::cast_from_source(values[22]),
        WitnessCastable::cast_from_source(values[23]),
        WitnessCastable::cast_from_source(values[24]),
        WitnessCastable::cast_from_source(values[25]),
        WitnessCastable::cast_from_source(values[26]),
        WitnessCastable::cast_from_source(values[27]),
        WitnessCastable::cast_from_source(values[28]),
    ];
    let written_value = recompose_u256_as_u32x8(written_value);

    let aux_byte: u8 = WitnessCastable::cast_from_source(values[29]);
    let rw_flag: bool = WitnessCastable::cast_from_source(values[30]);
    let rollback: bool = WitnessCastable::cast_from_source(values[31]);
    let is_service: bool = WitnessCastable::cast_from_source(values[32]);
    let shard_id: u8 = WitnessCastable::cast_from_source(values[33]);
    let tx_number_in_block: u32 = WitnessCastable::cast_from_source(values[34]);
    let timestamp: u32 = WitnessCastable::cast_from_source(values[35]);

    <LogQuery<F> as CSAllocatable<F>>::Witness {
        address,
        key,
        read_value,
        written_value,
        aux_byte,
        rw_flag,
        rollback,
        is_service,
        shard_id,
        tx_number_in_block,
        timestamp,
    }
}

impl<F: SmallField> CSAllocatableExt<F> for LogQuery<F> {
    const INTERNAL_STRUCT_LEN: usize = FLATTENED_VARIABLE_LENGTH;

    fn witness_from_set_of_values(values: [F; Self::INTERNAL_STRUCT_LEN]) -> Self::Witness {
        log_query_witness_from_values(values)
    }

    // we should be able to allocate without knowing values yet
    fn create_without_value<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            address: UInt160::allocate_without_value(cs),
            key: UInt256::allocate_without_value(cs),
            read_value: UInt256::allocate_without_value(cs),
            written_value: UInt256::allocate_without_value(cs),
            rw_flag: Boolean::allocate_without_value(cs),
            aux_byte: UInt8::allocate_without_value(cs),
            rollback: Boolean::allocate_without_value(cs),
            is_service: Boolean::allocate_without_value(cs),
            shard_id: UInt8::allocate_without_value(cs),
            tx_number_in_block: UInt32::allocate_without_value(cs),
            timestamp: UInt32::allocate_without_value(cs),
        }
    }

    fn flatten_as_variables(&self) -> [Variable; Self::INTERNAL_STRUCT_LEN]
    where
        [(); Self::INTERNAL_STRUCT_LEN]:,
    {
        self.flatten_as_variables_impl()
    }

    fn set_internal_variables_values(witness: Self::Witness, dst: &mut DstBuffer<'_, '_, F>) {
        // NOTE: must be same sequence as in `flatten_as_variables`
        UInt160::set_internal_variables_values(witness.address, dst);
        UInt256::set_internal_variables_values(witness.key, dst);
        UInt256::set_internal_variables_values(witness.read_value, dst);
        UInt256::set_internal_variables_values(witness.written_value, dst);
        UInt8::set_internal_variables_values(witness.aux_byte, dst);
        Boolean::set_internal_variables_values(witness.rw_flag, dst);
        Boolean::set_internal_variables_values(witness.rollback, dst);
        Boolean::set_internal_variables_values(witness.is_service, dst);
        UInt8::set_internal_variables_values(witness.shard_id, dst);
        UInt32::set_internal_variables_values(witness.tx_number_in_block, dst);
        UInt32::set_internal_variables_values(witness.timestamp, dst);
    }
}

use crate::base_structures::vm_state::QUEUE_STATE_WIDTH;
use boojum::gadgets::queue::CircuitQueue;

pub type LogQueryQueue<F, const AW: usize, const SW: usize, const CW: usize, R> =
    CircuitQueue<F, LogQuery<F>, AW, SW, CW, QUEUE_STATE_WIDTH, LOG_QUERY_PACKED_WIDTH, R>;

// we will output L2 to L1 messages as byte packed messages, so let's make it

pub const L2_TO_L1_MESSAGE_BYTE_LENGTH: usize = 88;

impl<F: SmallField> ByteSerializable<F, L2_TO_L1_MESSAGE_BYTE_LENGTH> for LogQuery<F> {
    fn into_bytes<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
    ) -> [UInt8<F>; L2_TO_L1_MESSAGE_BYTE_LENGTH] {
        let zero_u8 = UInt8::zero(cs);

        let mut result = [zero_u8; L2_TO_L1_MESSAGE_BYTE_LENGTH];
        let mut offset = 0;
        result[offset] = self.shard_id;
        offset += 1;
        result[offset] = unsafe { UInt8::from_variable_unchecked(self.is_service.get_variable()) };
        offset += 1;

        let bytes_be = self.tx_number_in_block.to_be_bytes(cs);
        result[offset..(offset + (bytes_be.len() - 2))].copy_from_slice(&bytes_be[2..]);
        offset += bytes_be.len() - 2;

        // we truncated, so let's enforce that those were unsused
        for el in bytes_be[..2].iter() {
            Num::enforce_equal(cs, &zero_u8.into_num(), &el.into_num());
        }

        let bytes_be = self.address.to_be_bytes(cs);
        result[offset..(offset + bytes_be.len())].copy_from_slice(&bytes_be);
        offset += bytes_be.len();

        let bytes_be = self.key.to_be_bytes(cs);
        result[offset..(offset + bytes_be.len())].copy_from_slice(&bytes_be);
        offset += bytes_be.len();

        let bytes_be = self.written_value.to_be_bytes(cs);
        result[offset..(offset + bytes_be.len())].copy_from_slice(&bytes_be);
        offset += bytes_be.len();

        assert_eq!(offset, L2_TO_L1_MESSAGE_BYTE_LENGTH);

        result
    }
}
