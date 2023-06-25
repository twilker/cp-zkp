mod chaum_pedersen;

use auth_client::{RegisterRequest, AuthenticationChallengeRequest, AuthenticationAnswerRequest};
use auth_client::auth_client::AuthClient;
use chaum_pedersen::algorithm as pedersen;
use chaum_pedersen::algorithm::ChaumPedersen;
use num_bigint::{BigInt, Sign, ToBigInt};
use uuid::Uuid;
use std::{hash::{Hash, Hasher}};
use rustc_hash::FxHasher;
use std::time::{Instant};

pub mod auth_client {
    tonic::include_proto!("zkp_auth"); // The string specified here must match the proto package name
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = AuthClient::connect("http://[::1]:50051").await?;

    println!("Get parameters");

    let parameter_response = client.get_authentication_parameters(tonic::Request::new({})).await?;
    
    let encoded_parameters = parameter_response.into_inner();    
    let parameters = pedersen::ChaumPedersenParameters {
        p: BigInt::from_bytes_be(Sign::Plus, &encoded_parameters.p),
        q: BigInt::from_bytes_be(Sign::Plus, &encoded_parameters.q),
        g: BigInt::from_bytes_be(Sign::Plus, &encoded_parameters.g),
        h: BigInt::from_bytes_be(Sign::Plus, &encoded_parameters.h),
        bit_size: encoded_parameters.bit_size as u16
    };
    let mut algorithm = pedersen::ChaumPedersenAlgorthim::new(&parameters);

    println!("Register user");

    let mut x = calculate_hash(&"My Super Secret Password".to_string());
    let (y1, y2) = algorithm.exponentiation(&x);
    let user = Uuid::new_v4().to_string();

    let register_request = tonic::Request::new(RegisterRequest{
        user: user.clone(),
        y1: y1.to_bytes_be().1,
        y2: y2.to_bytes_be().1
    });
    client.register(register_request).await?;

    println!("Registered user");

    let now = Instant::now();

    println!("Authentication process");

    x = calculate_hash(&"My Super Secret Password".to_string());
    let k = algorithm.generate_random();
    let (r1, r2) = algorithm.exponentiation(&k);
    
    let challenge_request = tonic::Request::new(AuthenticationChallengeRequest{
        user: user.clone(),
        r1: r1.to_bytes_be().1,
        r2: r2.to_bytes_be().1
    });
    let challenge_response = client.create_authentication_challenge(challenge_request).await?;
    let challenge = challenge_response.into_inner();
    let c = BigInt::from_bytes_be(Sign::Plus, &challenge.c);

    println!("Received challenge {:?}", challenge);

    let s = algorithm.solve_challenge(&x, &k, &c);

    let answer_request = tonic::Request::new(AuthenticationAnswerRequest{
        auth_id: challenge.auth_id,
        s: s.to_bytes_be().1
    });
    let answer_response = client.verify_authentication(answer_request).await?;
    let answer = answer_response.into_inner();

    println!("Received answer {:?}", answer);

    println!("Time to authenticate: {}ms", now.elapsed().as_millis());

    Ok(())
}


fn calculate_hash<T: Hash>(t: &T) -> BigInt {
    let mut s = FxHasher::default();
    t.hash(&mut s);
    s.finish().to_bigint().unwrap()
}