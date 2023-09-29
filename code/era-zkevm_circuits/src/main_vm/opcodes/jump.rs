use super::*;

pub(crate) fn apply_jump<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    _draft_vm_state: &VmLocalState<F>,
    common_opcode_state: &CommonOpcodeState<F>,
    _opcode_carry_parts: &AfterDecodingCarryParts<F>,
    diffs_accumulator: &mut StateDiffsAccumulator<F>,
) {
    const JUMP_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Jump(zkevm_opcode_defs::definitions::jump::JumpOpcode);

    let should_apply = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_opcode(JUMP_OPCODE);

    if crate::config::CIRCUIT_VERSOBE {
        if (should_apply.witness_hook(&*cs))().unwrap_or(false) {
            println!("Applying JUMP");
        }
    }

    // main point of merging add/sub is to enforce single add/sub relation, that doesn't leak into any
    // other opcodes

    let jump_dst = UInt16::from_le_bytes(
        cs,
        [
            common_opcode_state.src0_view.u8x32_view[0],
            common_opcode_state.src0_view.u8x32_view[1],
        ],
    );

    diffs_accumulator
        .new_pc_candidates
        .push((should_apply, jump_dst));
}
