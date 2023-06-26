mod server;

use std::fmt;

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
async fn register_user_twice_panics() {
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

    assert!(context.server.register(tonic::Request::new(register_request.clone())).await.is_ok());
    expect_already_exists(context.server.register(tonic::Request::new(register_request)).await)
}

#[tokio::test]
async fn register_user_with_zero_password_panics() {
    let context = TestContext::new().with_algorithm().await;
    
    let register_request = RegisterRequest{
        user: Uuid::new_v4().to_string(),
        y1: [0x00].to_vec(),
        y2: [0x00].to_vec(),
    };

    expect_invalid_argument(context.server.register(tonic::Request::new(register_request)).await)
}

#[tokio::test]
async fn register_user_with_empty_password_panics() {
    let context = TestContext::new().with_algorithm().await;
    
    let register_request = RegisterRequest{
        user: Uuid::new_v4().to_string(),
        y1: [].to_vec(),
        y2: [].to_vec(),
    };

    expect_invalid_argument(context.server.register(tonic::Request::new(register_request)).await)
}

#[tokio::test]
async fn register_user_with_empty_name_panics() {
    let context = TestContext::new().with_algorithm().await;
    let locked_algorithm = context.algorithm.unwrap();
    let algorithm = locked_algorithm.read().unwrap();
    
    let x = auth_lib::calculate_hash(&"My Super Secret Password".to_string());
    let (y1, y2) = algorithm.exponentiation(&x);
    let register_request = RegisterRequest{
        user: String::from(""),
        y1: y1.to_bytes_be().1,
        y2: y2.to_bytes_be().1,
    };

    expect_invalid_argument(context.server.register(tonic::Request::new(register_request)).await)
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
async fn can_get_challenge_twice() {
    let context = TestContext::new()
        .with_algorithm().await
        .with_registered_user().await
        .with_challenge().await;
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
async fn get_challenge_with_non_existing_user_panics() {
    let context = TestContext::new()
        .with_algorithm().await;
    let locked_algorithm = context.algorithm.unwrap();
    let mut algorithm = locked_algorithm.write().unwrap();

    let k = algorithm.generate_random();
    let (r1, r2) = algorithm.exponentiation(&k);
    let challenge_request = AuthenticationChallengeRequest{
        user: Uuid::new_v4().to_string(),
        r1: r1.to_bytes_be().1,
        r2: r2.to_bytes_be().1,
    };

    expect_unauthenticated(context.server.create_authentication_challenge(tonic::Request::new(challenge_request)).await);
}

#[tokio::test]
async fn get_challenge_with_zero_commitment_panics() {
    let context = TestContext::new()
        .with_algorithm().await
        .with_registered_user().await;

    let challenge_request = AuthenticationChallengeRequest{
        user: context.user.unwrap().user.clone(),
        r1: [0x00].to_vec(),
        r2: [0x00].to_vec(),
    };

    expect_invalid_argument(context.server.create_authentication_challenge(tonic::Request::new(challenge_request)).await);
}

#[tokio::test]
async fn get_challenge_with_empty_commitment_panics() {
    let context = TestContext::new()
        .with_algorithm().await
        .with_registered_user().await;
    
    let challenge_request = AuthenticationChallengeRequest{
        user: context.user.unwrap().user.clone(),
        r1: [].to_vec(),
        r2: [].to_vec(),
    };

    expect_invalid_argument(context.server.create_authentication_challenge(tonic::Request::new(challenge_request)).await);
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

#[tokio::test]
async fn solving_challenge_of_first_challenge_panics() {
    let context = TestContext::new()
        .with_algorithm().await
        .with_registered_user().await
        .with_challenge().await;
    
    let first_challenge = context.challenge.clone().unwrap();
    let context = context.with_challenge().await;

    let locked_algorithm = context.algorithm.as_ref().unwrap();
    let algorithm = locked_algorithm.read().unwrap();

    let s = algorithm.solve_challenge(&context.user.unwrap().x, &first_challenge.k, &first_challenge.c);
    let solution_request = AuthenticationAnswerRequest{
        auth_id: first_challenge.auth_id.clone(),
        s: s.to_bytes_be().1,
    };
    
    expect_unauthenticated(context.server.verify_authentication(tonic::Request::new(solution_request)).await);
}

#[tokio::test]
async fn wrongly_solving_challenge_panics() {
    let context = TestContext::new()
        .with_algorithm().await
        .with_registered_user().await
        .with_challenge().await;

    let challenge = &context.challenge.unwrap();
    let solution_request = AuthenticationAnswerRequest{
        auth_id: challenge.auth_id.clone(),
        s: [0xAA].to_vec(),
    };
    
    expect_unauthenticated(context.server.verify_authentication(tonic::Request::new(solution_request)).await);
}

#[tokio::test]
async fn not_solving_challenge_panics() {
    let context = TestContext::new()
        .with_algorithm().await
        .with_registered_user().await
        .with_challenge().await;

    let challenge = &context.challenge.unwrap();
    let solution_request = AuthenticationAnswerRequest{
        auth_id: challenge.auth_id.clone(),
        s: [].to_vec(),
    };
    
    expect_invalid_argument(context.server.verify_authentication(tonic::Request::new(solution_request)).await);
}

#[tokio::test]
async fn solving_challenge_with_unkown_auth_id_panics() {
    let context = TestContext::new()
        .with_algorithm().await
        .with_registered_user().await
        .with_challenge().await;
    let locked_algorithm = context.algorithm.unwrap();
    let algorithm = locked_algorithm.read().unwrap();

    let challenge = &context.challenge.unwrap();
    let s = algorithm.solve_challenge(&context.user.unwrap().x, &challenge.k, &challenge.c);
    let solution_request = AuthenticationAnswerRequest{
        auth_id: Uuid::new_v4().to_string(),
        s: s.to_bytes_be().1,
    };
    
    expect_unauthenticated(context.server.verify_authentication(tonic::Request::new(solution_request)).await)
}

fn expect_unauthenticated<T: fmt::Debug>(result: Result<T, tonic::Status>) {
    assert!(result.is_err(), "expected error");
    assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated, "expected unauthenticated error");
}

fn expect_already_exists<T: fmt::Debug>(result: Result<T, tonic::Status>) {
    assert!(result.is_err(), "expected error");
    assert_eq!(result.unwrap_err().code(), tonic::Code::AlreadyExists, "expected unauthenticated error");
}

fn expect_invalid_argument<T: fmt::Debug>(result: Result<T, tonic::Status>) {
    assert!(result.is_err(), "expected error");
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument, "expected unauthenticated error");
}