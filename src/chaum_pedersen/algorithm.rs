use num_bigint::{ToBigInt, BigInt, RandBigInt, Sign, BigUint};
use num_primes::{Generator};
use rand::{rngs::StdRng, SeedableRng};

pub trait ChaumPedersen {
    fn find_parameters(bit_size: u16) -> ChaumPedersenParameters;
    fn get_parameters(&self) -> &ChaumPedersenParameters;
    fn exponentiation(&self, x: &BigInt) -> (BigInt, BigInt);
    fn generate_random(&mut self) -> BigInt;
    fn solve_challenge(&self, x: &BigInt, k: &BigInt, c: &BigInt) -> BigInt;
    fn verify(&self, y1: &BigInt, y2: &BigInt, r1: &BigInt, r2: &BigInt, s: &BigInt, c: &BigInt) -> bool;
}

#[derive(Clone, Debug)]
pub struct ChaumPedersenParameters {
    pub p: BigInt,
    pub q: BigInt,
    pub g: BigInt,
    pub h: BigInt,
    pub bit_size: u16,
}

#[derive(Debug)]
pub struct ChaumPedersenAlgorthim {
    parameters: ChaumPedersenParameters,
    rng: StdRng,
}

impl ChaumPedersenAlgorthim {
    pub fn new(parameters: &ChaumPedersenParameters) -> ChaumPedersenAlgorthim {
        println!("Algorithm initialized with parameters: {:?}", parameters);
        ChaumPedersenAlgorthim { parameters: parameters.clone(), rng: StdRng::from_entropy() }
    }
}

impl ChaumPedersen for ChaumPedersenAlgorthim {
    fn find_parameters(bit_size: u16) -> ChaumPedersenParameters {
        let p = BigInt::from_biguint(Sign::Plus, BigUint::from_bytes_be(&Generator::safe_prime(bit_size.into()).to_bytes_be()));
        let q = (&p - 1.to_bigint().unwrap()) / 2.to_bigint().unwrap();
        let g = 4.to_bigint().unwrap();
        let h = 9.to_bigint().unwrap();
        ChaumPedersenParameters { p, q, g, h, bit_size }
    }

    fn get_parameters(&self) -> &ChaumPedersenParameters {
        &self.parameters
    }

    fn exponentiation(&self, x: &BigInt) -> (BigInt, BigInt) {
        let y1 = self.parameters.g.modpow(x, &self.parameters.p);
        let y2 = self.parameters.h.modpow(x, &self.parameters.p);
        (y1, y2)
    }

    fn generate_random(&mut self) -> BigInt {
        let mut c = 0.to_bigint().unwrap();
        while c <= 1.to_bigint().unwrap() {
            c = BigInt::from_biguint(Sign::Plus, self.rng.gen_biguint(self.parameters.bit_size.into()));
        }
        c
    }

    fn solve_challenge(&self, x: &BigInt, k: &BigInt, c: &BigInt) -> BigInt {
        let mut s = (k - (c * x)) % &self.parameters.q;
        if s < 0.to_bigint().unwrap() {
            s = s + &self.parameters.q;
        }
        s
    }

    fn verify(&self, y1: &BigInt, y2: &BigInt, r1: &BigInt, r2: &BigInt, s: &BigInt, c: &BigInt) -> bool {
        let v1 = (self.parameters.g.modpow(s, &self.parameters.p) * 
            y1.modpow(c, &self.parameters.p)) % &self.parameters.p;
        let v2 = (self.parameters.h.modpow(s, &self.parameters.p) * 
            y2.modpow(c, &self.parameters.p)) % &self.parameters.p;
        &v1 == r1 && &v2 == r2
    }
}