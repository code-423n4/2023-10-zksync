use super::*;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::traits::allocatable::CSAllocatable;
use boojum::gadgets::u16::UInt16;
use boojum::serde_utils::BigArraySerde;
use cs_derive::*;

use zkevm_opcode_defs::{
    ISAVersion, ImmMemHandlerFlags, OPCODE_INPUT_VARIANT_FLAGS, OPCODE_OUTPUT_VARIANT_FLAGS,
    OPCODE_TYPE_BITS, TOTAL_AUX_BITS,
};

// opcode defs only provide runtime-computeable variable, so we have to pin ISA version and assert

pub const SUPPORTED_ISA_VERSION: ISAVersion = ISAVersion(1);

const _: () = if SUPPORTED_ISA_VERSION.0 != zkevm_opcode_defs::DEFAULT_ISA_VERSION.0 {
    panic!()
} else {
    ()
};

pub(crate) const OPCODE_VARIANT_BITS: usize = 10;
pub(crate) const OPCODE_FLAGS_BITS: usize = 2;
pub(crate) const TOTAL_OPCODE_MEANINGFULL_DESCRIPTION_BITS: usize = 38;
pub(crate) const TOTAL_OPCODE_DESCRIPTION_BITS_FLATTENED: usize = 48;
pub(crate) const TOTAL_OPCODE_DESCRIPTION_AND_AUX_BITS: usize =
    TOTAL_OPCODE_DESCRIPTION_BITS_FLATTENED + TOTAL_AUX_BITS;

/// We hide all the source selection and updating in preprocessing,
/// so we only need imms and some variant properties
#[derive(Derivative)]
#[derivative(Debug)]
pub struct UsedOpcode<F: SmallField> {
    pub properties_bitmask: OpcodeBitmask<F>,
    pub imm0: UInt16<F>,
    pub imm1: UInt16<F>,
}

#[derive(Derivative, CSAllocatable, WitnessHookable)]
#[derivative(Debug)]
pub struct OpcodeBitmask<F: SmallField> {
    pub opcode_type_booleans: [Boolean<F>; OPCODE_TYPE_BITS],
    pub opcode_variant_booleans: [Boolean<F>; OPCODE_VARIANT_BITS],
    pub flag_booleans: [Boolean<F>; OPCODE_FLAGS_BITS],
    pub input_variant_booleans: [Boolean<F>; OPCODE_INPUT_VARIANT_FLAGS],
    pub output_variant_booleans: [Boolean<F>; OPCODE_OUTPUT_VARIANT_FLAGS],
}

use zkevm_opcode_defs::Opcode;

impl<F: SmallField> OpcodeBitmask<F> {
    pub fn boolean_for_opcode(&self, opcode: Opcode) -> Boolean<F> {
        let opcode_idx = opcode.variant_idx();
        self.opcode_type_booleans[opcode_idx]
    }

    pub fn boolean_for_variant(&self, opcode: Opcode) -> Boolean<F> {
        let variant_idx = opcode.materialize_subvariant_idx();
        self.opcode_variant_booleans[variant_idx]
    }

    pub fn boolean_for_src_mem_access(&self, access_type: ImmMemHandlerFlags) -> Boolean<F> {
        let variant_idx = access_type.variant_index();
        self.input_variant_booleans[variant_idx]
    }

    pub fn boolean_for_dst_mem_access(&self, access_type: ImmMemHandlerFlags) -> Boolean<F> {
        assert!(access_type.is_allowed_for_dst());
        let variant_idx = access_type.variant_index();
        self.output_variant_booleans[variant_idx]
    }

    pub fn from_full_mask(mask: [Boolean<F>; TOTAL_OPCODE_MEANINGFULL_DESCRIPTION_BITS]) -> Self {
        // assert to not mismatch alignments
        debug_assert_eq!(
            OPCODE_VARIANT_BITS,
            zkevm_opcode_defs::max_num_variants_for_version(SUPPORTED_ISA_VERSION)
        );
        debug_assert_eq!(
            OPCODE_FLAGS_BITS,
            zkevm_opcode_defs::max_num_flags_for_version(SUPPORTED_ISA_VERSION)
        );
        debug_assert_eq!(
            TOTAL_OPCODE_DESCRIPTION_BITS_FLATTENED,
            zkevm_opcode_defs::total_description_bits_rounded_for_version(SUPPORTED_ISA_VERSION)
        );
        debug_assert_eq!(
            TOTAL_OPCODE_MEANINGFULL_DESCRIPTION_BITS,
            zkevm_opcode_defs::total_description_bits_for_version(SUPPORTED_ISA_VERSION)
        );

        let mut offset = 0;
        let opcode_type_booleans: [Boolean<F>; OPCODE_TYPE_BITS] = mask
            [offset..(offset + OPCODE_TYPE_BITS)]
            .try_into()
            .unwrap();
        offset += OPCODE_TYPE_BITS;
        let opcode_variant_booleans: [Boolean<F>; OPCODE_VARIANT_BITS] = mask
            [offset..(offset + OPCODE_VARIANT_BITS)]
            .try_into()
            .unwrap();
        offset += OPCODE_VARIANT_BITS;
        let flag_booleans: [Boolean<F>; OPCODE_FLAGS_BITS] = mask
            [offset..(offset + OPCODE_FLAGS_BITS)]
            .try_into()
            .unwrap();
        offset += OPCODE_FLAGS_BITS;
        let input_variant_booleans: [Boolean<F>; OPCODE_INPUT_VARIANT_FLAGS] = mask
            [offset..(offset + OPCODE_INPUT_VARIANT_FLAGS)]
            .try_into()
            .unwrap();
        offset += OPCODE_INPUT_VARIANT_FLAGS;
        let output_variant_booleans: [Boolean<F>; OPCODE_OUTPUT_VARIANT_FLAGS] = mask
            [offset..(offset + OPCODE_OUTPUT_VARIANT_FLAGS)]
            .try_into()
            .unwrap();
        offset += OPCODE_OUTPUT_VARIANT_FLAGS;
        debug_assert_eq!(offset, TOTAL_OPCODE_MEANINGFULL_DESCRIPTION_BITS);

        Self {
            opcode_type_booleans,
            opcode_variant_booleans,
            flag_booleans,
            input_variant_booleans,
            output_variant_booleans,
        }
    }
}
