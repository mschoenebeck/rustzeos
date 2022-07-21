
use std::convert::TryInto;

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

#[cfg(test)]
mod tests{

    use crate::groth16::Scalar;

    use super::{serialize_inputs, deserialize_inputs, bytes_to_hex_str};

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
}