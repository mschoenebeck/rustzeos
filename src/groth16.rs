
use std::convert::TryInto;
use std::num::ParseIntError;
use std::fmt::Write;

use bellman::groth16;
use bls12_381::{Bls12, Scalar};

pub type Proof = groth16::Proof<Bls12>;
pub type Inputs = Vec<Scalar>;
pub type VerifyingKey = groth16::VerifyingKey<Bls12>;
pub type PreparedVerifyingKey = groth16::PreparedVerifyingKey<Bls12>;

pub fn prepare_verifying_key(vk: &VerifyingKey) -> PreparedVerifyingKey
{
    groth16::prepare_verifying_key(&vk)
}

pub fn verify_proof(pvk: &PreparedVerifyingKey, proof: &Proof, inputs: &Inputs) -> bool
{
    groth16::verify_proof(&pvk, &proof, &inputs).is_ok()
}


/// inputs should be a list of 4*64 bit values (field elements) encoded in little endian byte order
/// panics if length is incorrect
pub fn deserialize_inputs(inputs: &[u8]) -> Inputs
{
    // first byte is number of scalars
    let n = inputs[0] as usize;
    // enforce correct length (size(Scalar) = 4*8 bytes), len()-1 because of leading byte 'n'
    assert_eq!((inputs.len()-1)%(4*8*n), 0);
    
    let mut vec = Vec::with_capacity(n);
    for i in 0..n
    {
        let s = Scalar::from_bytes(&inputs[1+i*32..1+i*32+32].try_into().unwrap()).unwrap();
        vec.push(s);
    }

    vec
}

/// needs to be implemented exactly like this on smart contract side
pub fn serialize_inputs(vec: &Inputs) -> Vec<u8>
{
    let mut inputs = Vec::new();
    let n = vec.len();
    inputs.push(n as u8);

    for i in 0..vec.len()
    {
        inputs.extend_from_slice(&vec[i].to_bytes());
    }

    inputs
}

/// serialize vk
pub fn serialize_vk(vk: &VerifyingKey) -> Vec<u8>
{
    let mut bytes = Vec::new();
    assert!(vk.write(&mut bytes).is_ok());
    bytes
}

/// serialize proof
pub fn serialize_proof(proof: &Proof) -> Vec<u8>
{
    let mut bytes = Vec::new();
    assert!(proof.write(&mut bytes).is_ok());
    bytes
}

// converts a byte array to hex string as required by EOSIO
pub fn bytes_to_hex_str(vec: &Vec<u8>) -> String
{
    struct ByteBuf<'a>(&'a [u8]);

    impl<'a> std::fmt::LowerHex for ByteBuf<'a> {
        fn fmt(&self, fmtr: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
            for byte in self.0 {
                fmtr.write_fmt(format_args!("{:02x}", byte))?;
            }
            Ok(())
        }
    }

    format!("{:x}", ByteBuf(&vec))
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

#[cfg(test)]
mod tests{

    use crate::groth16::Scalar;
    use super::{serialize_inputs, deserialize_inputs, bytes_to_hex_str, verify_proof};

    #[test]
    fn test_serialize_deserialize()
    {
        let mut vec = Vec::<Scalar>::new();
        vec.push(Scalar::from(1337));
        vec.push(Scalar::from(54321));
        vec.push(Scalar::from(11111));
        vec.push(Scalar::from(963));

        let arr = serialize_inputs(&vec);
        let vec_r = deserialize_inputs(&arr);

        assert_eq!(vec, vec_r);
    }

    #[test]
    fn test_serialize_bytes()
    {
        let buff = [1_u8; 24];
        assert_eq!(bytes_to_hex_str(&buff.to_vec()), "010101010101010101010101010101010101010101010101")
    }

    /// This is the main example of the bellman crate taken from:
    /// https://docs.rs/bellman/0.10.0/bellman/
    use bellman::{
        gadgets::{
            boolean::{AllocatedBit, Boolean},
            multipack,
            sha256::sha256,
        },
        groth16, Circuit, ConstraintSystem, SynthesisError,
    };
    use bls12_381::Bls12;
    use ff::PrimeField;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    /// Our own SHA-256d gadget. Input and output are in little-endian bit order.
    fn sha256d<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        data: &[Boolean],
    ) -> Result<Vec<Boolean>, SynthesisError> {
        // Flip endianness of each input byte
        let input: Vec<_> = data
            .chunks(8)
            .map(|c| c.iter().rev())
            .flatten()
            .cloned()
            .collect();

        let mid = sha256(cs.namespace(|| "SHA-256(input)"), &input)?;
        let res = sha256(cs.namespace(|| "SHA-256(mid)"), &mid)?;

        // Flip endianness of each output byte
        Ok(res
            .chunks(8)
            .map(|c| c.iter().rev())
            .flatten()
            .cloned()
            .collect())
    }

    #[test]
    fn test_groth16_circuit()
    {
        struct MyCircuit {
            /// The input to SHA-256d we are proving that we know. Set to `None` when we
            /// are verifying a proof (and do not have the witness data).
            preimage: Option<[u8; 80]>,
        }

        impl<Scalar: PrimeField> Circuit<Scalar> for MyCircuit {
            fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
                // Compute the values for the bits of the preimage. If we are verifying a proof,
                // we still need to create the same constraints, so we return an equivalent-size
                // Vec of None (indicating that the value of each bit is unknown).
                let bit_values = if let Some(preimage) = self.preimage {
                    preimage
                        .into_iter()
                        .map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
                        .flatten()
                        .map(|b| Some(b))
                        .collect()
                } else {
                    vec![None; 80 * 8]
                };
                assert_eq!(bit_values.len(), 80 * 8);

                // Witness the bits of the preimage.
                let preimage_bits = bit_values
                    .into_iter()
                    .enumerate()
                    // Allocate each bit.
                    .map(|(i, b)| {
                        AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {}", i)), b)
                    })
                    // Convert the AllocatedBits into Booleans (required for the sha256 gadget).
                    .map(|b| b.map(Boolean::from))
                    .collect::<Result<Vec<_>, _>>()?;

                // Compute hash = SHA-256d(preimage).
                let hash = sha256d(cs.namespace(|| "SHA-256d(preimage)"), &preimage_bits)?;

                // Expose the vector of 32 boolean variables as compact public inputs.
                multipack::pack_into_inputs(cs.namespace(|| "pack hash"), &hash)
            }
        }

        // Create parameters for our circuit. In a production deployment these would
        // be generated securely using a multiparty computation.
        let params = {
            let c = MyCircuit { preimage: None };
            groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
        };

        // Prepare the verification key (for proof verification).
        let pvk = groth16::prepare_verifying_key(&params.vk);

        // Pick a preimage and compute its hash.
        let preimage = [42; 80];
        let hash = Sha256::digest(&Sha256::digest(&preimage));

        // Create an instance of our circuit (with the preimage as a witness).
        let c = MyCircuit {
            preimage: Some(preimage),
        };

        // Create a Groth16 proof with our parameters.
        let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();

        // Pack the hash as inputs for proof verification.
        let hash_bits = multipack::bytes_to_bits_le(&hash);
        let inputs: Vec<bls12_381::Scalar> = multipack::compute_multipacking(&hash_bits);

        // Check the proof!
        assert!(verify_proof(&pvk, &proof, &inputs));
    }
}