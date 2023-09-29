use super::*;

#[inline(always)]
pub(crate) fn apply_nop<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    _draft_vm_state: &VmLocalState<F>,
    common_opcode_state: &CommonOpcodeState<F>,
    _opcode_carry_parts: &AfterDecodingCarryParts<F>,
    _diffs_accumulator: &mut StateDiffsAccumulator<F>,
) {
    const NOP_OPCODE: zkevm_opcode_defs::Opcode = Opcode::Nop(NopOpcode);

    // now we need to properly select and enforce
    let apply_nop = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_opcode(NOP_OPCODE);

    if crate::config::CIRCUIT_VERSOBE {
        if (apply_nop.witness_hook(&*cs))().unwrap_or(false) {
            println!("Applying NOP");
        }
    }
}
