pub mod groth16;
pub mod halo2;

pub mod zeos
{
    use pasta_curves::{vesta, Fp};
    use byteorder::{ByteOrder, LittleEndian};

    /// ZEOS application specific deserializing and packing of halo2 public inputs
    /// inputs should be of the following structure (all values encoded in little endian byte order):
    ///
    /// anchor (32 bytes)
    /// nf (32 bytes)
    /// rk_x (32 bytes)
    /// rk_y (32 bytes)
    /// nft (1 byte)
    /// b_d1 (8 bytes)
    /// b_d2 (8 bytes)
    /// b_sc (8 bytes)
    /// c_d1 (8 bytes)
    /// cmb (32 bytes)
    /// cmc (32 bytes)
    /// accb (8 bytes)
    /// accc (8 bytes)      // == ZI_SIZE (241)
    ///
    /// panics if length is incorrect
    pub fn deserialize_instances(inputs: &[u8]) -> Vec<Vec<Vec<vesta::Scalar>>>
    {
        let zi_size = 32 + 32 + 32 + 32 + 1 + 8 + 8 + 8 + 8 + 32 + 32 + 8 + 8;
        // the number of inputs structs (instances) can be calculated from the length
        let n = inputs.len() / zi_size;
        // enforce correct length
        assert_eq!(inputs.len() % zi_size, 0);

        let mut vec_m = Vec::new();
        for j in 0..n
        {
            let mut offset = j * zi_size;
            let mut vec_n = Vec::new();
            // anchor
            vec_n.push(Fp([
                LittleEndian::read_u64(&inputs[offset + 0*8..offset + 1*8]),
                LittleEndian::read_u64(&inputs[offset + 1*8..offset + 2*8]),
                LittleEndian::read_u64(&inputs[offset + 2*8..offset + 3*8]),
                LittleEndian::read_u64(&inputs[offset + 3*8..offset + 4*8]),
            ]));
            offset += 32;
            // nf
            vec_n.push(Fp([
                LittleEndian::read_u64(&inputs[offset + 0*8..offset + 1*8]),
                LittleEndian::read_u64(&inputs[offset + 1*8..offset + 2*8]),
                LittleEndian::read_u64(&inputs[offset + 2*8..offset + 3*8]),
                LittleEndian::read_u64(&inputs[offset + 3*8..offset + 4*8]),
            ]));
            offset += 32;
            // rk_x
            vec_n.push(Fp([
                LittleEndian::read_u64(&inputs[offset + 0*8..offset + 1*8]),
                LittleEndian::read_u64(&inputs[offset + 1*8..offset + 2*8]),
                LittleEndian::read_u64(&inputs[offset + 2*8..offset + 3*8]),
                LittleEndian::read_u64(&inputs[offset + 3*8..offset + 4*8]),
            ]));
            offset += 32;
            // rk_y
            vec_n.push(Fp([
                LittleEndian::read_u64(&inputs[offset + 0*8..offset + 1*8]),
                LittleEndian::read_u64(&inputs[offset + 1*8..offset + 2*8]),
                LittleEndian::read_u64(&inputs[offset + 2*8..offset + 3*8]),
                LittleEndian::read_u64(&inputs[offset + 3*8..offset + 4*8]),
            ]));
            offset += 32;
            // nft
            vec_n.push(vesta::Scalar::from(
                inputs[offset] != 0,
            ));
            offset += 1;
            // b_d1
            vec_n.push(vesta::Scalar::from(
                LittleEndian::read_u64(&inputs[offset..offset + 8]),
            ));
            offset += 8;
            // b_d2
            vec_n.push(vesta::Scalar::from(
                LittleEndian::read_u64(&inputs[offset..offset + 8]),
            ));
            offset += 8;
            // b_sc
            vec_n.push(vesta::Scalar::from(
                LittleEndian::read_u64(&inputs[offset..offset + 8]),
            ));
            offset += 8;
            // c_d1
            vec_n.push(vesta::Scalar::from(
                LittleEndian::read_u64(&inputs[offset..offset + 8]),
            ));
            offset += 8;
            // cmb
            vec_n.push(Fp([
                LittleEndian::read_u64(&inputs[offset + 0*8..offset + 1*8]),
                LittleEndian::read_u64(&inputs[offset + 1*8..offset + 2*8]),
                LittleEndian::read_u64(&inputs[offset + 2*8..offset + 3*8]),
                LittleEndian::read_u64(&inputs[offset + 3*8..offset + 4*8]),
            ]));
            offset += 32;
            // cmc
            vec_n.push(Fp([
                LittleEndian::read_u64(&inputs[offset + 0*8..offset + 1*8]),
                LittleEndian::read_u64(&inputs[offset + 1*8..offset + 2*8]),
                LittleEndian::read_u64(&inputs[offset + 2*8..offset + 3*8]),
                LittleEndian::read_u64(&inputs[offset + 3*8..offset + 4*8]),
            ]));
            offset += 32;
            // accb
            vec_n.push(vesta::Scalar::from(
                LittleEndian::read_u64(&inputs[offset..offset + 8]),
            ));
            offset += 8;
            // accc
            vec_n.push(vesta::Scalar::from(
                LittleEndian::read_u64(&inputs[offset..offset + 8]),
            ));

            let mut vec_1 = Vec::new();
            vec_1.push(vec_n);
            vec_m.push(vec_1);
        }

        vec_m
    }
}