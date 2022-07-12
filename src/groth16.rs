
use bellman::{
    groth16::{
        VerifyingKey,
        Proof
    },
};
use bls12_381::{Bls12};
use blake2s_simd::{Hash};

// returns the type name of a variable
fn type_of<T>(_: &T) -> &'static str
{
    std::any::type_name::<T>()
}

// to smart contract json function (VK, Proof, Inputs)
pub fn json_str<T>(var: &T) -> String
{
    // struct definitions
    pub struct Choice(pub u8);
    pub struct Fp(pub [u64; 6]);
    pub struct Scalar(pub [u64; 4]);
    pub struct Fp2
    {
        pub c0: Fp,
        pub c1: Fp,
    }
    pub struct G1Affine
    {
        pub x: Fp,
        pub y: Fp,
        pub infinity: Choice,
    }
    pub struct G2Affine
    {
        pub x: Fp2,
        pub y: Fp2,
        pub infinity: Choice,
    }

    let mut json = String::new();

    match type_of(var)
    {
        "bellman::groth16::VerifyingKey<bls12_381::pairings::Bls12>" =>
        {
            json.push('{');

            let vk: &VerifyingKey<Bls12> = unsafe {&*(var as *const T as *const VerifyingKey<Bls12>)};
               
            json.push_str("\"alpha_g1\":");
            json.push_str(json_str(&vk.alpha_g1).as_str());
            json.push(',');
               
            json.push_str("\"beta_g1\":");
            json.push_str(json_str(&vk.beta_g1).as_str());
            json.push(',');
               
            json.push_str("\"beta_g2\":");
            json.push_str(json_str(&vk.beta_g2).as_str());
            json.push(',');
               
            json.push_str("\"gamma_g2\":");
            json.push_str(json_str(&vk.gamma_g2).as_str());
            json.push(',');
               
            json.push_str("\"delta_g1\":");
            json.push_str(json_str(&vk.delta_g1).as_str());
            json.push(',');
               
            json.push_str("\"delta_g2\":");
            json.push_str(json_str(&vk.delta_g2).as_str());
            json.push(',');
               
            json.push_str("\"ic\":");
            json.push_str(json_str(&vk.ic).as_str());
            
            json.push('}');
        },
        "bellman::groth16::Proof<bls12_381::pairings::Bls12>" =>
        {
            json.push('{');

            let proof: &Proof<Bls12> = unsafe {&*(var as *const T as *const Proof<Bls12>)};
               
            json.push_str("\"a\":");
            json.push_str(json_str(&proof.a).as_str());
            json.push(',');
               
            json.push_str("\"b\":");
            json.push_str(json_str(&proof.b).as_str());
            json.push(',');
               
            json.push_str("\"c\":");
            json.push_str(json_str(&proof.c).as_str());
            
            json.push('}');
        },
        "rustzeos::json_str::G1Affine" |
        "bls12_381::g1::G1Affine" =>
        {
            json.push('{');

            let g1: &G1Affine = unsafe {&*(var as *const T as *const G1Affine)};
               
            json.push_str("\"x\":");
            json.push_str(json_str(&g1.x).as_str());
            json.push(',');
               
            json.push_str("\"y\":");
            json.push_str(json_str(&g1.y).as_str());
            json.push(',');
               
            json.push_str("\"infinity\":");
            json.push_str(json_str(&g1.infinity).as_str());
            
            json.push('}');
        },
        "rustzeos::json_str::G2Affine" |
        "bls12_381::g2::G2Affine" =>
        {
            json.push('{');

            let g2: &G2Affine = unsafe {&*(var as *const T as *const G2Affine)};
               
            json.push_str("\"x\":");
            json.push_str(json_str(&g2.x).as_str());
            json.push(',');
               
            json.push_str("\"y\":");
            json.push_str(json_str(&g2.y).as_str());
            json.push(',');
               
            json.push_str("\"infinity\":");
            json.push_str(json_str(&g2.infinity).as_str());
            
            json.push('}');
        },
        "alloc::vec::Vec<bls12_381::g1::G1Affine>" =>
        {
            json.push('[');

            let vec: &Vec<G1Affine> = unsafe {&*(var as *const T as *const Vec<G1Affine>)};

            for v in vec
            {
                json.push_str(json_str(v).as_str());
                json.push(',');
            }
            json.pop();

            json.push(']');
        },
        "alloc::vec::Vec<bls12_381::scalar::Scalar>" =>
        {
            json.push('[');

            let vec: &Vec<Scalar> = unsafe {&*(var as *const T as *const Vec<Scalar>)};

            for v in vec
            {
                json.push_str(json_str(v).as_str());
                json.push(',');
            }
            json.pop();

            json.push(']');
        },
        "rustzeos::json_str::Fp" => 
        {
            json.push_str("{\"data\":[");
            
            let fp: &Fp = unsafe {&*(var as *const T as *const Fp)};

            for v in fp.0
            {
                json.push_str(format!("{}", v).as_str());
                json.push(',');
            }
            json.pop();

            json.push_str("]}");
        },
        "rustzeos::json_str::Scalar" => 
        {
            json.push_str("{\"data\":[");
            
            let scalar: &Scalar = unsafe {&*(var as *const T as *const Scalar)};

            for v in scalar.0
            {
                json.push_str(format!("{}", v).as_str());
                json.push(',');
            }
            json.pop();

            json.push_str("]}");
        },
        "rustzeos::json_str::Fp2" => 
        {
            json.push('{');

            let fp2: &Fp2 = unsafe {&*(var as *const T as *const Fp2)};
               
            json.push_str("\"c0\":");
            json.push_str(json_str(&fp2.c0).as_str());
            json.push(',');
               
            json.push_str("\"c1\":");
            json.push_str(json_str(&fp2.c1).as_str());
            
            json.push('}');
        },
        "rustzeos::json_str::Choice" =>
        {
            json.push_str("{\"data\":");
            
            let c: &Choice = unsafe {&*(var as *const T as *const Choice)};
            
            json.push_str(format!("{}", c.0).as_str());
            
            json.push('}');
        },
        "blake2s_simd::Hash" =>
        {
            let h: &Hash = unsafe {&*(var as *const T as *const Hash)};
            
            for byte in h.as_array()
            {
                json.push_str(format!("{:02x}", byte).as_str());
            }
        },
        "alloc::vec::Vec<[u8; 16]>" =>
        {
            let v: &Vec<[u8; 16]> = unsafe {&*(var as *const T as *const Vec<[u8; 16]>)};
            json.push_str(&serde_json::to_string(v).unwrap());
        }
        _ =>
        {
            json.push_str("ERROR: unknown type: ");
            json.push_str(type_of(var));
        }
    }

    return json;
}
