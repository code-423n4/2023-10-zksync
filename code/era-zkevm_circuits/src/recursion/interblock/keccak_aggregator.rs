use boojum::gadgets::{traits::selectable::Selectable, u8::UInt8};

use super::*;

pub struct KeccakPublicInputAggregator<
    F: SmallField,
    const N: usize,
    const IS_BE: bool,
    const NUM_OUTS: usize,
> {
    pub masking_value: u8,
    _marker: std::marker::PhantomData<F>,
}

impl<F: SmallField, const N: usize, const IS_BE: bool, const NUM_OUTS: usize>
    InputAggregationFunction<F> for KeccakPublicInputAggregator<F, N, IS_BE, NUM_OUTS>
{
    type Params = u8;

    fn new<CS: ConstraintSystem<F>>(_cs: &mut CS, params: Self::Params) -> Self {
        Self {
            masking_value: params,
            _marker: std::marker::PhantomData,
        }
    }
    fn aggregate_inputs<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        inputs: &[Vec<Num<F>>],
        validity_flags: &[Boolean<F>],
    ) -> Vec<Num<F>> {
        assert_eq!(inputs.len(), N);
        assert_eq!(validity_flags.len(), N);

        let masking_value = UInt8::allocated_constant(cs, self.masking_value);

        let mut input_flattened_bytes = Vec::with_capacity(32 * N);
        let zero_u8 = UInt8::zero(cs);
        let take_by = F::CAPACITY_BITS / 8;

        let mut total_byte_len = take_by;
        if F::CAPACITY_BITS % 8 != 0 {
            total_byte_len += 1;
        }

        for (validity_flag, input) in validity_flags.iter().zip(inputs.iter()) {
            assert_eq!(input.len(), INPUT_OUTPUT_COMMITMENT_LENGTH);

            // transform to bytes
            for src in input.iter() {
                let mut bytes: arrayvec::ArrayVec<UInt8<F>, 8> =
                    src.constraint_bit_length_as_bytes(cs, total_byte_len); // le
                if F::CAPACITY_BITS % 8 != 0 {
                    for el in bytes[take_by..].iter() {
                        // assert byte is 0
                        Num::conditionally_enforce_equal(
                            cs,
                            *validity_flag,
                            &el.into_num(),
                            &zero_u8.into_num(),
                        );
                    }
                }
                // mask if necessary
                for el in bytes[..take_by].iter_mut() {
                    *el = UInt8::conditionally_select(cs, *validity_flag, &*el, &masking_value);
                }

                if IS_BE {
                    input_flattened_bytes.extend(bytes[..take_by].iter().copied().rev());
                } else {
                    input_flattened_bytes.extend_from_slice(&bytes[..take_by]);
                }
            }
        }

        // run keccak over it
        use boojum::gadgets::keccak256;
        let aggregated_keccak_hash = keccak256::keccak256(cs, &input_flattened_bytes);

        let mut result = Vec::with_capacity(NUM_OUTS);

        // and make it our publid input
        for chunk in aggregated_keccak_hash.chunks_exact(take_by).take(NUM_OUTS) {
            let mut lc = Vec::with_capacity(chunk.len());
            // treat as BE
            for (idx, el) in chunk.iter().rev().enumerate() {
                lc.push((el.get_variable(), F::SHIFTS[idx * 8]));
            }
            let as_num = Num::linear_combination(cs, &lc);
            result.push(as_num);
        }

        result
    }
}
