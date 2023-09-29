#![allow(clippy::drop_ref)]
#![allow(dead_code)]
#![allow(dropping_references)]
#![allow(unused_imports)]
#![feature(generic_const_exprs)]
#![feature(array_chunks)]
#![feature(more_qualified_paths)]

use derivative::*;

pub use boojum;
pub use boojum::ethereum_types;

pub mod config;

pub mod base_structures;
pub mod code_unpacker_sha256;
pub mod demux_log_queue;
pub mod ecrecover;
pub mod fsm_input_output;
pub mod keccak256_round_function;
pub mod linear_hasher;
pub mod log_sorter;
pub mod main_vm;
pub mod ram_permutation;
pub mod recursion;
pub mod scheduler;
pub mod sha256_round_function;
pub mod sort_decommittment_requests;
pub mod storage_application;
pub mod storage_validity_by_grand_product;
pub mod tables;
pub mod utils;

use boojum::pairing::ff;

pub const DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS: usize = 2;

pub const fn bit_width_to_bitmask(width: usize) -> u64 {
    (1u64 << width) - 1
}
