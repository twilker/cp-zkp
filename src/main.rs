mod chaum_pedersen;

use num_bigint::{ToBigInt, BigInt};
use std::{hash::{Hash, Hasher}};
use rustc_hash::FxHasher;
use std::time::{Instant};
use chaum_pedersen::algorithm as pedersen;

const BIT_SIZE: u16 = 256;

fn main() {
    let mut now = Instant::now();
    let parameters = pedersen::ChaumPedersenAlgorthim::find_parameters(BIT_SIZE);
    let mut algorithm = pedersen::ChaumPedersenAlgorthim::new(&parameters);
    println!("Time to generate p: {}ms", now.elapsed().as_millis());

    now = Instant::now();
    println!("Registration");
    let mut x = calculate_hash(&"My Super Secret Password".to_string());
    let (y1, y2) = algorithm.exponentiation(&x);
    println!("y1: {} y2: {}", y1, y2);
    println!("Time to register: {}ms", now.elapsed().as_millis());

    now = Instant::now();
    println!("Authentication");
    println!("Commitment");
    let k = algorithm.generate_random();
    let (r1, r2) = algorithm.exponentiation(&k);
    println!("r1: {} r2: {}", r1, r2);

    println!("Challenge");
    x = calculate_hash(&"My Super Secret Password".to_string());
    let c = algorithm.generate_random();
    let s = algorithm.solve_challenge(&x, &k, &c);
    println!("s: {}", s);
    
    println!("Verification");
    let result = algorithm.verify(&y1, &y2, &r1, &r2, &s, &c);
    println!("Result: {}", result);

    println!("Time to authenticate: {}ms", now.elapsed().as_millis());
}


fn calculate_hash<T: Hash>(t: &T) -> BigInt {
    let mut s = FxHasher::default();
    t.hash(&mut s);
    s.finish().to_bigint().unwrap()
}