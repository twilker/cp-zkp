mod server;

use auth_lib::cp_grpc::{RegisterRequest, AuthenticationChallengeRequest, AuthenticationAnswerRequest};
use server::*;
use uuid::Uuid;
use auth_lib::chaum_pedersen::algorithm::ChaumPedersen;

#[tokio::test]
async fn can_get_parameters() {
    let context = TestContext::new();
    
    let paramters = context.server.get_authentication_parameters(tonic::Request::new({})).await;

    assert!(paramters.is_ok());
    let paramters = paramters.unwrap().into_inner();
    assert!(paramters.p.len() > 0, "parameters are empty");
    assert!(paramters.q.len() > 0, "parameters are empty");
    assert!(paramters.g.len() > 0, "parameters are empty");
    assert!(paramters.h.len() > 0, "parameters are empty");
    assert!(paramters.bit_size > 0, "parameters are empty");
}

#[tokio::test]
async fn can_register_user() {
    let context = TestContext::new().with_algorithm().await;
    let locked_algorithm = context.algorithm.unwrap();
    let algorithm = locked_algorithm.read().unwrap();
    
    let x = auth_lib::calculate_hash(&"My Super Secret Password".to_string());
    let (y1, y2) = algorithm.exponentiation(&x);
    let register_request = RegisterRequest{
        user: Uuid::new_v4().to_string(),
        y1: y1.to_bytes_be().1,
        y2: y2.to_bytes_be().1,
    };

    let response = context.server.register(tonic::Request::new(register_request)).await;

    assert!(response.is_ok());
}

#[tokio::test]
async fn can_get_challenge() {
    let context = TestContext::new()
        .with_algorithm().await
        .with_registered_user().await;
    let locked_algorithm = context.algorithm.unwrap();
    let mut algorithm = locked_algorithm.write().unwrap();

    let k = algorithm.generate_random();
    let (r1, r2) = algorithm.exponentiation(&k);
    let challenge_request = AuthenticationChallengeRequest{
        user: context.user.unwrap().user.clone(),
        r1: r1.to_bytes_be().1,
        r2: r2.to_bytes_be().1,
    };

    let response = context.server.create_authentication_challenge(tonic::Request::new(challenge_request)).await;

    assert!(response.is_ok());
    let challenge = response.unwrap().into_inner();
    assert!(challenge.c.len() > 0, "challenge is empty");
    assert!(!challenge.auth_id.is_empty(), "no auth id provided");
}

#[tokio::test]
async fn solving_challenge_returns_session() {
    let context = TestContext::new()
        .with_algorithm().await
        .with_registered_user().await
        .with_challenge().await;
    let locked_algorithm = context.algorithm.unwrap();
    let algorithm = locked_algorithm.read().unwrap();

    let challenge = &context.challenge.unwrap();
    let s = algorithm.solve_challenge(&context.user.unwrap().x, &challenge.k, &challenge.c);
    let solution_request = AuthenticationAnswerRequest{
        auth_id: challenge.auth_id.clone(),
        s: s.to_bytes_be().1,
    };
    
    let response = context.server.verify_authentication(tonic::Request::new(solution_request)).await;

    assert!(response.is_ok());
    let session = response.unwrap().into_inner();
    assert!(!session.session_id.is_empty(), "no session id provided");
}