use core::fmt;
use halo2_proofs::{
    plonk::{self, BatchVerifier, SingleVerifier},
    transcript::{Blake2bRead, Blake2bWrite},
};
use crate::halo2::plonk::Circuit;
use memuse::DynamicUsage;
use pasta_curves::{pallas, vesta, Fp};
use rand::RngCore;
use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};


/// The verifying key for the Orchard Action circuit.
#[derive(Debug)]
pub struct VerifyingKey {
    pub params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
    pub vk: plonk::VerifyingKey<vesta::Affine>,
}

impl VerifyingKey {
    /// Builds the verifying key.
    pub fn build<ConcreteCircuit>(circuit: ConcreteCircuit, k: u32) -> Self
    where
        ConcreteCircuit: Circuit<pallas::Base>,
    {
        let params = halo2_proofs::poly::commitment::Params::new(k);
        //let circuit: Circuit = Default::default();

        let vk = plonk::keygen_vk(&params, &circuit).unwrap();

        VerifyingKey { params, vk }
    }

    /// serializes verifying key to byte vector
    pub fn serialize(&self, arr: &mut Vec<u8>) -> ()
    {
        // TODO: handle errors
        let res = arr.write_u32::<LittleEndian>(self.params.k);
        if res.is_err()
        {
            return ();
        }
        let res = bincode::serialize_into(arr, &self.vk);
        if res.is_err()
        {
            return ();
        }
    }

    /// deserializes byte vector to verifying key
    pub fn deserialize(arr: &Vec<u8>) -> Self
    {
        let k = LittleEndian::read_u32(&arr);
        VerifyingKey{
            params: halo2_proofs::poly::commitment::Params::new(k),
            vk: bincode::deserialize(&arr[4..]).unwrap()
        }
    }
}

/// The proving key for the Orchard Action circuit.
#[derive(Debug)]
pub struct ProvingKey {
    params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
    pk: plonk::ProvingKey<vesta::Affine>,
}

impl ProvingKey {
    /// Builds the proving key.
    pub fn build<ConcreteCircuit>(circuit: ConcreteCircuit, k: u32) -> Self 
    where
        ConcreteCircuit: Circuit<pallas::Base>,
    {
        let params = halo2_proofs::poly::commitment::Params::new(k);
        //let circuit: Circuit = Default::default();

        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk, &circuit).unwrap();

        ProvingKey { params, pk }
    }
}

/// A proof of the validity of an Orchard [`Bundle`].
///
/// [`Bundle`]: crate::bundle::Bundle
#[derive(Clone)]
pub struct Proof(Vec<u8>);

impl fmt::Debug for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.debug_tuple("Proof").field(&self.0).finish()
        } else {
            // By default, only show the proof length, not its contents.
            f.debug_tuple("Proof")
                .field(&format_args!("{} bytes", self.0.len()))
                .finish()
        }
    }
}

impl AsRef<[u8]> for Proof {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl DynamicUsage for Proof {
    fn dynamic_usage(&self) -> usize {
        self.0.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        self.0.dynamic_usage_bounds()
    }
}

impl Proof {
    /// Creates a proof for the given circuits and instances.
    pub fn create<ConcreteCircuit, ConcreteInstance>(
        pk: &ProvingKey,
        circuits: &[ConcreteCircuit],
        instances: &[ConcreteInstance],
        mut rng: impl RngCore,
    ) -> Result<Self, plonk::Error>
    where
        ConcreteCircuit: Circuit<pallas::Base>,
        ConcreteInstance: Instance
    {
        let instances: Vec<_> = instances.iter().map(|i| i.to_halo2_instance_vec()).collect();
        let instances: Vec<Vec<_>> = instances
            .iter()
            .map(|i| i.iter().map(|c| &c[..]).collect())
            .collect();
        let instances: Vec<_> = instances.iter().map(|i| &i[..]).collect();

        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        plonk::create_proof(
            &pk.params,
            &pk.pk,
            circuits,
            &instances,
            &mut rng,
            &mut transcript,
        )?;
        Ok(Proof(transcript.finalize()))
    }

    /// Verifies this proof with the given instances.
    pub fn verify(&self, vk: &VerifyingKey, instances: &[Vec<Vec<vesta::Scalar>>]) -> Result<(), plonk::Error> 
    {
        let instances: Vec<_> = instances.to_vec();
        let instances: Vec<Vec<_>> = instances
            .iter()
            .map(|i| i.iter().map(|c| &c[..]).collect())
            .collect();
        let instances: Vec<_> = instances.iter().map(|i| &i[..]).collect();

        let strategy = SingleVerifier::new(&vk.params);
        let mut transcript = Blake2bRead::init(&self.0[..]);
        plonk::verify_proof(&vk.params, &vk.vk, strategy, &instances, &mut transcript)
    }

    pub fn add_to_batch<ConcreteInstance>(
        &self,
        batch: &mut BatchVerifier<vesta::Affine>,
        instances: Vec<ConcreteInstance>,
    ) 
    where
    ConcreteInstance: Instance
    {
        let instances = instances
            .iter()
            .map(|i| {
                i.to_halo2_instance_vec()
                    .into_iter()
                    .map(|c| c.into_iter().collect())
                    .collect()
            })
            .collect();

        batch.add_proof(instances, self.0.clone());
    }

    /// Constructs a new Proof value.
    pub fn new(bytes: Vec<u8>) -> Self {
        Proof(bytes)
    }
}

pub trait Instance
{
    fn to_halo2_instance_vec(&self) -> Vec<Vec<vesta::Scalar>>;
}

pub type Inputs = Vec<Vec<Vec<vesta::Scalar>>>;

pub fn verify_proof(vk: &VerifyingKey, proof: &Proof, inputs: &Inputs) -> bool
{
    proof.verify(&vk, &inputs).is_ok()
}

/// inputs should be a list of 4*64 bit values (field elements) encoded in little endian byte order
/// panics if length is incorrect
pub fn deserialize_instances(inputs: &[u8]) -> Inputs
{
    // first byte is number of public inputs per instance
    let n = inputs[0] as usize;
    // enforce correct length (size(Fp) = 4*8 bytes), len()-1 because of leading byte 'n'
    assert_eq!((inputs.len()-1)%(4*8*n), 0);
    // number of instances
    let m = (inputs.len()-1)/(4*8*n);
    
    let mut vec_m = Vec::new();
    for j in 0..m
    {
        let mut vec_n = Vec::new();
        for i in 0..n
        {
            // 1+.. to skip first element of inputs
            let offset = 1 + j*n + i*32;
            let fp = Fp([
                LittleEndian::read_u64(&inputs[offset + 0*8..offset + 1*8]),
                LittleEndian::read_u64(&inputs[offset + 1*8..offset + 2*8]),
                LittleEndian::read_u64(&inputs[offset + 2*8..offset + 3*8]),
                LittleEndian::read_u64(&inputs[offset + 3*8..offset + 4*8]),
            ]);
            vec_n.push(fp);
        }
        let mut vec_1 = Vec::new();
        vec_1.push(vec_n);
        vec_m.push(vec_1);
    }

    vec_m
}

/// needs to be implemented exactly like this on smart contract side
pub fn serialize_instances(vec: &Inputs) -> Vec<u8>
{
    let mut inputs = Vec::new();
    let n = vec[0][0].len(); // the length of the very inner vector is the number of input field elements
    inputs.push(n as u8);

    for j in 0..vec.len()
    {
        for i in 0..n
        {
            let mut buf = [0; 8];
            LittleEndian::write_u64(&mut buf, vec[j][0][i].0[0]);
            inputs.append(&mut buf.to_vec());
            LittleEndian::write_u64(&mut buf, vec[j][0][i].0[1]);
            inputs.append(&mut buf.to_vec());
            LittleEndian::write_u64(&mut buf, vec[j][0][i].0[2]);
            inputs.append(&mut buf.to_vec());
            LittleEndian::write_u64(&mut buf, vec[j][0][i].0[3]);
            inputs.append(&mut buf.to_vec());
        }
    }

    inputs
}
