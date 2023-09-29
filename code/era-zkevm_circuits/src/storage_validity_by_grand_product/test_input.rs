use super::TimestampedStorageLogRecord;
use crate::base_structures::log_query::LogQuery;
use crate::ethereum_types::{Address, U256};
use boojum::cs::gates::{assert_no_placeholder_variables, assert_no_placeholders};
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::field::goldilocks::GoldilocksField;
use boojum::gadgets::{boolean::Boolean, u160::*, u256::*, u32::*, u8::*};

type F = GoldilocksField;

// This witness input is generated from the old test harness, and remodeled to work in the current type system.
pub fn generate_test_input_unsorted<CS: ConstraintSystem<F>>(cs: &mut CS) -> Vec<LogQuery<F>> {
    let mut queries = vec![];
    let bool_false = Boolean::allocated_constant(cs, false);
    let bool_true = Boolean::allocated_constant(cs, true);
    let zero_8 = UInt8::allocated_constant(cs, 0);
    let zero_32 = UInt32::allocated_constant(cs, 0);

    let q = LogQuery::<F> {
        address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32770)),
        key: UInt256::allocated_constant(cs, U256::from_dec_str("32779").unwrap()),
        read_value: UInt256::allocated_constant(
            cs,
            U256::from_dec_str(
                "452319300877325313852488925888724764263521004047156906617735320131041551860",
            )
            .unwrap(),
        ),
        written_value: UInt256::allocated_constant(
            cs,
            U256::from_dec_str(
                "452319300877325313852488925888724764263521004047156906617735320131041551860",
            )
            .unwrap(),
        ),
        rw_flag: bool_false,
        aux_byte: zero_8,
        rollback: bool_false,
        is_service: bool_false,
        shard_id: zero_8,
        tx_number_in_block: zero_32,
        timestamp: UInt32::allocated_constant(cs, 1205),
    };
    queries.push(q);

    let q = LogQuery::<F> {
        address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32779)),
        key: UInt256::allocated_constant(cs, U256::from_dec_str("1").unwrap()),
        read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        rw_flag: bool_false,
        aux_byte: zero_8,
        rollback: bool_false,
        is_service: bool_false,
        shard_id: zero_8,
        tx_number_in_block: zero_32,
        timestamp: UInt32::allocated_constant(cs, 1425),
    };
    queries.push(q);

    let q = LogQuery::<F> {
        address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32770)),
        key: UInt256::allocated_constant(cs, U256::from_dec_str("32779").unwrap()),
        read_value: UInt256::allocated_constant(
            cs,
            U256::from_dec_str(
                "452319300877325313852488925888724764263521004047156906617735320131041551860",
            )
            .unwrap(),
        ),
        written_value: UInt256::allocated_constant(
            cs,
            U256::from_dec_str(
                "452319300877325313852488925888724764263521004047156906617735320131041551860",
            )
            .unwrap(),
        ),
        rw_flag: bool_false,
        aux_byte: zero_8,
        rollback: bool_false,
        is_service: bool_false,
        shard_id: zero_8,
        tx_number_in_block: zero_32,
        timestamp: UInt32::allocated_constant(cs, 1609),
    };
    queries.push(q);

    let q = LogQuery::<F> {
        address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32779)),
        key: UInt256::allocated_constant(cs, U256::from_dec_str("7").unwrap()),
        read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        rw_flag: bool_false,
        aux_byte: zero_8,
        rollback: bool_false,
        is_service: bool_false,
        shard_id: zero_8,
        tx_number_in_block: zero_32,
        timestamp: UInt32::allocated_constant(cs, 1777),
    };
    queries.push(q);

    let q = LogQuery::<F> {
        address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32770)),
        key: UInt256::allocated_constant(cs, U256::from_dec_str("32779").unwrap()),
        read_value: UInt256::allocated_constant(
            cs,
            U256::from_dec_str(
                "452319300877325313852488925888724764263521004047156906617735320131041551860",
            )
            .unwrap(),
        ),
        written_value: UInt256::allocated_constant(
            cs,
            U256::from_dec_str(
                "452319300877325313852488925888724764263521004047156906617735320131041551860",
            )
            .unwrap(),
        ),
        rw_flag: bool_false,
        aux_byte: zero_8,
        rollback: bool_false,
        is_service: bool_false,
        shard_id: zero_8,
        tx_number_in_block: zero_32,
        timestamp: UInt32::allocated_constant(cs, 1969),
    };
    queries.push(q);

    let q = LogQuery::<F> {
        address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32779)),
        key: UInt256::allocated_constant(cs, U256::from_dec_str("5").unwrap()),
        read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        rw_flag: bool_false,
        aux_byte: zero_8,
        rollback: bool_false,
        is_service: bool_false,
        shard_id: zero_8,
        tx_number_in_block: zero_32,
        timestamp: UInt32::allocated_constant(cs, 2253),
    };
    queries.push(q);

    let q = LogQuery::<F> {
        address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
        key: UInt256::allocated_constant(cs, U256::from_dec_str("10").unwrap()),
        read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        rw_flag: bool_true,
        aux_byte: zero_8,
        rollback: bool_false,
        is_service: bool_false,
        shard_id: zero_8,
        tx_number_in_block: zero_32,
        timestamp: UInt32::allocated_constant(cs, 2357),
    };
    queries.push(q);

    let q = LogQuery::<F> {
        address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32770)),
        key: UInt256::allocated_constant(cs, U256::from_dec_str("32779").unwrap()),
        read_value: UInt256::allocated_constant(
            cs,
            U256::from_dec_str(
                "452319300877325313852488925888724764263521004047156906617735320131041551860",
            )
            .unwrap(),
        ),
        written_value: UInt256::allocated_constant(
            cs,
            U256::from_dec_str(
                "452319300877325313852488925888724764263521004047156906617735320131041551860",
            )
            .unwrap(),
        ),
        rw_flag: bool_false,
        aux_byte: zero_8,
        rollback: bool_false,
        is_service: bool_false,
        shard_id: zero_8,
        tx_number_in_block: zero_32,
        timestamp: UInt32::allocated_constant(cs, 2429),
    };
    queries.push(q);

    let q = LogQuery::<F> {
        address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32779)),
        key: UInt256::allocated_constant(cs, U256::from_dec_str("4").unwrap()),
        read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        rw_flag: bool_false,
        aux_byte: zero_8,
        rollback: bool_false,
        is_service: bool_false,
        shard_id: zero_8,
        tx_number_in_block: zero_32,
        timestamp: UInt32::allocated_constant(cs, 2681),
    };
    queries.push(q);

    let q = LogQuery::<F> {
        address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
        key: UInt256::allocated_constant(cs, U256::from_dec_str("9").unwrap()),
        read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        rw_flag: bool_false,
        aux_byte: zero_8,
        rollback: bool_false,
        is_service: bool_false,
        shard_id: zero_8,
        tx_number_in_block: zero_32,
        timestamp: UInt32::allocated_constant(cs, 2797),
    };
    queries.push(q);

    let q = LogQuery::<F> {
        address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
        key: UInt256::allocated_constant(cs, U256::from_dec_str("9").unwrap()),
        read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        rw_flag: bool_true,
        aux_byte: zero_8,
        rollback: bool_false,
        is_service: bool_false,
        shard_id: zero_8,
        tx_number_in_block: zero_32,
        timestamp: UInt32::allocated_constant(cs, 2829),
    };
    queries.push(q);

    let q = LogQuery::<F> {
        address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32770)),
        key: UInt256::allocated_constant(cs, U256::from_dec_str("32779").unwrap()),
        read_value: UInt256::allocated_constant(
            cs,
            U256::from_dec_str(
                "452319300877325313852488925888724764263521004047156906617735320131041551860",
            )
            .unwrap(),
        ),
        written_value: UInt256::allocated_constant(
            cs,
            U256::from_dec_str(
                "452319300877325313852488925888724764263521004047156906617735320131041551860",
            )
            .unwrap(),
        ),
        rw_flag: bool_false,
        aux_byte: zero_8,
        rollback: bool_false,
        is_service: bool_false,
        shard_id: zero_8,
        tx_number_in_block: zero_32,
        timestamp: UInt32::allocated_constant(cs, 2901),
    };
    queries.push(q);

    let q = LogQuery::<F> {
        address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32779)),
        key: UInt256::allocated_constant(cs, U256::from_dec_str("3").unwrap()),
        read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        rw_flag: bool_false,
        aux_byte: zero_8,
        rollback: bool_false,
        is_service: bool_false,
        shard_id: zero_8,
        tx_number_in_block: zero_32,
        timestamp: UInt32::allocated_constant(cs, 3089),
    };
    queries.push(q);

    let q = LogQuery::<F> {
        address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
        key: UInt256::allocated_constant(cs, U256::from_dec_str("8").unwrap()),
        read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        rw_flag: bool_true,
        aux_byte: zero_8,
        rollback: bool_false,
        is_service: bool_false,
        shard_id: zero_8,
        tx_number_in_block: zero_32,
        timestamp: UInt32::allocated_constant(cs, 3193),
    };
    queries.push(q);

    let q = LogQuery::<F> {
        address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32770)),
        key: UInt256::allocated_constant(cs, U256::from_dec_str("32779").unwrap()),
        read_value: UInt256::allocated_constant(
            cs,
            U256::from_dec_str(
                "452319300877325313852488925888724764263521004047156906617735320131041551860",
            )
            .unwrap(),
        ),
        written_value: UInt256::allocated_constant(
            cs,
            U256::from_dec_str(
                "452319300877325313852488925888724764263521004047156906617735320131041551860",
            )
            .unwrap(),
        ),
        rw_flag: bool_false,
        aux_byte: zero_8,
        rollback: bool_false,
        is_service: bool_false,
        shard_id: zero_8,
        tx_number_in_block: zero_32,
        timestamp: UInt32::allocated_constant(cs, 3265),
    };
    queries.push(q);

    let q = LogQuery::<F> {
        address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32779)),
        key: UInt256::allocated_constant(cs, U256::from_dec_str("2").unwrap()),
        read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
        rw_flag: bool_false,
        aux_byte: zero_8,
        rollback: bool_false,
        is_service: bool_false,
        shard_id: zero_8,
        tx_number_in_block: zero_32,
        timestamp: UInt32::allocated_constant(cs, 3421),
    };
    queries.push(q);

    queries
}

pub fn generate_test_input_sorted<CS: ConstraintSystem<F>>(
    cs: &mut CS,
) -> Vec<TimestampedStorageLogRecord<F>> {
    let mut records = vec![];
    let bool_false = Boolean::allocated_constant(cs, false);
    let bool_true = Boolean::allocated_constant(cs, true);
    let zero_8 = UInt8::allocated_constant(cs, 0);
    let zero_32 = UInt32::allocated_constant(cs, 0);

    let r = TimestampedStorageLogRecord::<F> {
        timestamp: UInt32::allocated_constant(cs, 27),
        record: LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("2").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 4785),
        },
    };
    records.push(r);

    let r = TimestampedStorageLogRecord::<F> {
        timestamp: UInt32::allocated_constant(cs, 28),
        record: LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("2").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_true,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 4817),
        },
    };
    records.push(r);

    let r = TimestampedStorageLogRecord::<F> {
        timestamp: UInt32::allocated_constant(cs, 22),
        record: LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("3").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_true,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 4317),
        },
    };
    records.push(r);

    let r = TimestampedStorageLogRecord::<F> {
        timestamp: UInt32::allocated_constant(cs, 25),
        record: LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("4").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 4721),
        },
    };
    records.push(r);

    let r = TimestampedStorageLogRecord::<F> {
        timestamp: UInt32::allocated_constant(cs, 26),
        record: LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("4").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_true,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 4753),
        },
    };
    records.push(r);

    let r = TimestampedStorageLogRecord::<F> {
        timestamp: UInt32::allocated_constant(cs, 31),
        record: LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("5").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_true,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 5177),
        },
    };
    records.push(r);

    let r = TimestampedStorageLogRecord::<F> {
        timestamp: UInt32::allocated_constant(cs, 19),
        record: LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("6").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_true,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 3929),
        },
    };
    records.push(r);

    let r = TimestampedStorageLogRecord::<F> {
        timestamp: UInt32::allocated_constant(cs, 16),
        record: LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("7").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_true,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 3525),
        },
    };
    records.push(r);

    let r = TimestampedStorageLogRecord::<F> {
        timestamp: UInt32::allocated_constant(cs, 13),
        record: LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("8").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_true,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 3193),
        },
    };
    records.push(r);

    let r = TimestampedStorageLogRecord::<F> {
        timestamp: UInt32::allocated_constant(cs, 9),
        record: LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("9").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 2797),
        },
    };
    records.push(r);

    let r = TimestampedStorageLogRecord::<F> {
        timestamp: UInt32::allocated_constant(cs, 10),
        record: LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("9").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_true,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 2829),
        },
    };
    records.push(r);

    let r = TimestampedStorageLogRecord::<F> {
        timestamp: UInt32::allocated_constant(cs, 6),
        record: LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("10").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_true,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 2357),
        },
    };
    records.push(r);

    let r = TimestampedStorageLogRecord::<F> {
        timestamp: UInt32::allocated_constant(cs, 32),
        record: LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("11").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_true,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 5197),
        },
    };
    records.push(r);

    let r = TimestampedStorageLogRecord::<F> {
        timestamp: UInt32::allocated_constant(cs, 35),
        record: LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("12").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 7093),
        },
    };
    records.push(r);

    let r = TimestampedStorageLogRecord::<F> {
        timestamp: UInt32::allocated_constant(cs, 36),
        record: LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("12").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("0").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("1").unwrap()),
            rw_flag: bool_true,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 7129),
        },
    };
    records.push(r);

    let r = TimestampedStorageLogRecord::<F> {
        timestamp: UInt32::allocated_constant(cs, 38),
        record: LogQuery::<F> {
            address: UInt160::allocated_constant(cs, Address::from_low_u64_le(32769)),
            key: UInt256::allocated_constant(cs, U256::from_dec_str("13").unwrap()),
            read_value: UInt256::allocated_constant(cs, U256::from_dec_str("1").unwrap()),
            written_value: UInt256::allocated_constant(cs, U256::from_dec_str("1").unwrap()),
            rw_flag: bool_false,
            aux_byte: zero_8,
            rollback: bool_false,
            is_service: bool_false,
            shard_id: zero_8,
            tx_number_in_block: zero_32,
            timestamp: UInt32::allocated_constant(cs, 7177),
        },
    };
    records.push(r);

    records
}
