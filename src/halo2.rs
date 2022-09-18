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
            let offset = 1 + j*n*32 + i*32;
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

#[cfg(test)]
mod tests
{
    /// This is the main example of the halo2 crate taken from:
    /// https://zcash.github.io/halo2/user/simple-example.html

    use std::marker::PhantomData;
    use halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
        poly::Rotation,
    };

    use super::{Proof, ProvingKey, VerifyingKey, Instance as ConcreteInstance, verify_proof};
    use rand::rngs::OsRng;

    // ANCHOR: instructions
    trait NumericInstructions<F: FieldExt>: Chip<F> {
        /// Variable representing a number.
        type Num;

        /// Loads a number into the circuit as a private input.
        fn load_private(&self, layouter: impl Layouter<F>, a: Value<F>) -> Result<Self::Num, Error>;

        /// Loads a number into the circuit as a fixed constant.
        fn load_constant(&self, layouter: impl Layouter<F>, constant: F) -> Result<Self::Num, Error>;

        /// Returns `c = a * b`.
        fn mul(
            &self,
            layouter: impl Layouter<F>,
            a: Self::Num,
            b: Self::Num,
        ) -> Result<Self::Num, Error>;

        /// Exposes a number as a public input to the circuit.
        fn expose_public(
            &self,
            layouter: impl Layouter<F>,
            num: Self::Num,
            row: usize,
        ) -> Result<(), Error>;
    }
    // ANCHOR_END: instructions

    // ANCHOR: chip
    /// The chip that will implement our instructions! Chips store their own
    /// config, as well as type markers if necessary.
    struct FieldChip<F: FieldExt> {
        config: FieldConfig,
        _marker: PhantomData<F>,
    }
    // ANCHOR_END: chip

    // ANCHOR: chip-config
    /// Chip state is stored in a config struct. This is generated by the chip
    /// during configuration, and then stored inside the chip.
    #[derive(Clone, Debug)]
    struct FieldConfig {
        /// For this chip, we will use two advice columns to implement our instructions.
        /// These are also the columns through which we communicate with other parts of
        /// the circuit.
        advice: [Column<Advice>; 2],

        /// This is the public input (instance) column.
        instance: Column<Instance>,

        // We need a selector to enable the multiplication gate, so that we aren't placing
        // any constraints on cells where `NumericInstructions::mul` is not being used.
        // This is important when building larger circuits, where columns are used by
        // multiple sets of instructions.
        s_mul: Selector,
    }

    impl<F: FieldExt> FieldChip<F> {
        fn construct(config: <Self as Chip<F>>::Config) -> Self {
            Self {
                config,
                _marker: PhantomData,
            }
        }

        fn configure(
            meta: &mut ConstraintSystem<F>,
            advice: [Column<Advice>; 2],
            instance: Column<Instance>,
            constant: Column<Fixed>,
        ) -> <Self as Chip<F>>::Config {
            meta.enable_equality(instance);
            meta.enable_constant(constant);
            for column in &advice {
                meta.enable_equality(*column);
            }
            let s_mul = meta.selector();

            // Define our multiplication gate!
            meta.create_gate("mul", |meta| {
                // To implement multiplication, we need three advice cells and a selector
                // cell. We arrange them like so:
                //
                // | a0  | a1  | s_mul |
                // |-----|-----|-------|
                // | lhs | rhs | s_mul |
                // | out |     |       |
                //
                // Gates may refer to any relative offsets we want, but each distinct
                // offset adds a cost to the proof. The most common offsets are 0 (the
                // current row), 1 (the next row), and -1 (the previous row), for which
                // `Rotation` has specific constructors.
                let lhs = meta.query_advice(advice[0], Rotation::cur());
                let rhs = meta.query_advice(advice[1], Rotation::cur());
                let out = meta.query_advice(advice[0], Rotation::next());
                let s_mul = meta.query_selector(s_mul);

                // Finally, we return the polynomial expressions that constrain this gate.
                // For our multiplication gate, we only need a single polynomial constraint.
                //
                // The polynomial expressions returned from `create_gate` will be
                // constrained by the proving system to equal zero. Our expression
                // has the following properties:
                // - When s_mul = 0, any value is allowed in lhs, rhs, and out.
                // - When s_mul != 0, this constrains lhs * rhs = out.
                vec![s_mul * (lhs * rhs - out)]
            });

            FieldConfig {
                advice,
                instance,
                s_mul,
            }
        }
    }
    // ANCHOR_END: chip-config

    // ANCHOR: chip-impl
    impl<F: FieldExt> Chip<F> for FieldChip<F> {
        type Config = FieldConfig;
        type Loaded = ();

        fn config(&self) -> &Self::Config {
            &self.config
        }

        fn loaded(&self) -> &Self::Loaded {
            &()
        }
    }
    // ANCHOR_END: chip-impl

    // ANCHOR: instructions-impl
    /// A variable representing a number.
    #[derive(Clone)]
    struct Number<F: FieldExt>(AssignedCell<F, F>);

    impl<F: FieldExt> NumericInstructions<F> for FieldChip<F> {
        type Num = Number<F>;

        fn load_private(
            &self,
            mut layouter: impl Layouter<F>,
            value: Value<F>,
        ) -> Result<Self::Num, Error> {
            let config = self.config();

            layouter.assign_region(
                || "load private",
                |mut region| {
                    region
                        .assign_advice(|| "private input", config.advice[0], 0, || value)
                        .map(Number)
                },
            )
        }

        fn load_constant(
            &self,
            mut layouter: impl Layouter<F>,
            constant: F,
        ) -> Result<Self::Num, Error> {
            let config = self.config();

            layouter.assign_region(
                || "load constant",
                |mut region| {
                    region
                        .assign_advice_from_constant(|| "constant value", config.advice[0], 0, constant)
                        .map(Number)
                },
            )
        }

        fn mul(
            &self,
            mut layouter: impl Layouter<F>,
            a: Self::Num,
            b: Self::Num,
        ) -> Result<Self::Num, Error> {
            let config = self.config();

            layouter.assign_region(
                || "mul",
                |mut region: Region<'_, F>| {
                    // We only want to use a single multiplication gate in this region,
                    // so we enable it at region offset 0; this means it will constrain
                    // cells at offsets 0 and 1.
                    config.s_mul.enable(&mut region, 0)?;

                    // The inputs we've been given could be located anywhere in the circuit,
                    // but we can only rely on relative offsets inside this region. So we
                    // assign new cells inside the region and constrain them to have the
                    // same values as the inputs.
                    a.0.copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                    b.0.copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;

                    // Now we can assign the multiplication result, which is to be assigned
                    // into the output position.
                    let value = a.0.value().copied() * b.0.value();

                    // Finally, we do the assignment to the output, returning a
                    // variable to be used in another part of the circuit.
                    region
                        .assign_advice(|| "lhs * rhs", config.advice[0], 1, || value)
                        .map(Number)
                },
            )
        }

        fn expose_public(
            &self,
            mut layouter: impl Layouter<F>,
            num: Self::Num,
            row: usize,
        ) -> Result<(), Error> {
            let config = self.config();

            layouter.constrain_instance(num.0.cell(), config.instance, row)
        }
    }
    // ANCHOR_END: instructions-impl

    // ANCHOR: circuit
    /// The full circuit implementation.
    ///
    /// In this struct we store the private input variables. We use `Option<F>` because
    /// they won't have any value during key generation. During proving, if any of these
    /// were `None` we would get an error.
    #[derive(Default)]
    struct MyCircuit<F: FieldExt> {
        constant: F,
        a: Value<F>,
        b: Value<F>,
    }

    impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
        // Since we are using a single chip for everything, we can just reuse its config.
        type Config = FieldConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            // We create the two advice columns that FieldChip uses for I/O.
            let advice = [meta.advice_column(), meta.advice_column()];

            // We also need an instance column to store public inputs.
            let instance = meta.instance_column();

            // Create a fixed column to load constants.
            let constant = meta.fixed_column();

            FieldChip::configure(meta, advice, instance, constant)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let field_chip = FieldChip::<F>::construct(config);

            // Load our private values into the circuit.
            let a = field_chip.load_private(layouter.namespace(|| "load a"), self.a)?;
            let b = field_chip.load_private(layouter.namespace(|| "load b"), self.b)?;

            // Load the constant factor into the circuit.
            let constant =
                field_chip.load_constant(layouter.namespace(|| "load constant"), self.constant)?;

            // We only have access to plain multiplication.
            // We could implement our circuit as:
            //     asq  = a*a
            //     bsq  = b*b
            //     absq = asq*bsq
            //     c    = constant*asq*bsq
            //
            // but it's more efficient to implement it as:
            //     ab   = a*b
            //     absq = ab^2
            //     c    = constant*absq
            let ab = field_chip.mul(layouter.namespace(|| "a * b"), a, b)?;
            let absq = field_chip.mul(layouter.namespace(|| "ab * ab"), ab.clone(), ab)?;
            let c = field_chip.mul(layouter.namespace(|| "constant * absq"), constant, absq)?;

            // Expose the result as a public input to the circuit.
            field_chip.expose_public(layouter.namespace(|| "expose c"), c, 0)
        }
    }
    // ANCHOR_END: circuit

    #[test]
    fn test_halo2_circuit()
    {
        use halo2_proofs::pasta::Fp;

        // ANCHOR: test-circuit
        // The number of rows in our circuit cannot exceed 2^k. Since our example
        // circuit is very small, we can pick a very small value here.
        let k = 4;

        // Prepare the private and public inputs to the circuit!
        let constant = Fp::from(7);
        let a = Fp::from(2);
        let b = Fp::from(3);
        let c = constant * a.square() * b.square();

        // Instantiate the circuit with the private inputs.
        let circuit = MyCircuit {
            constant,
            a: Value::known(a),
            b: Value::known(b),
        };
        let circuit_vk = MyCircuit {
            constant,
            a: Value::default(),
            b: Value::default(),
        };
        let circuit_pk = MyCircuit {
            constant,
            a: Value::default(),
            b: Value::default(),
        };

        // Arrange the public input. We expose the multiplication result in row 0
        // of the instance column, so we position it there in our public inputs.
        let public_inputs = vec![c];

        let mut rng = OsRng;

        pub struct Instance(Vec<Vec<Fp>>);
        impl ConcreteInstance for Instance{
            fn to_halo2_instance_vec(&self) -> Vec<Vec<Fp>> {
                self.0.clone()
            }
        }

        let vk = VerifyingKey::build(circuit_vk, k);
        let pk = ProvingKey::build(circuit_pk, k);
        let proof = Proof::create(&pk, &[circuit], &[Instance(vec![public_inputs.clone()])], &mut rng).unwrap();

        // Arrange the public input. We expose the multiplication result in row 0
        // of the instance column, so we position it there in our public inputs.
        let public_inputs = vec![vec![vec![c]]];

        // Check the proof!
        assert!(verify_proof(&vk, &proof, &public_inputs));
    }
}