use std::sync::{Arc, RwLock};

use auth_lib::chaum_pedersen::algorithm::{ChaumPedersenParameters, ChaumPedersenAlgorthim, ChaumPedersen};
use auth_lib::cp_grpc::auth_server::Auth;
use auth_lib::{bootstrap, Config};
use num_bigint::{BigInt, Sign};
use auth_lib::cp_grpc::{RegisterRequest, AuthenticationChallengeRequest};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct TestUser {
    pub user: String,
    pub x: BigInt,
    pub y1: BigInt,
    pub y2: BigInt
}

#[derive(Debug, Clone)]
pub struct TestChallenge {
    pub c: BigInt,
    pub k: BigInt,
    pub r1: BigInt,
    pub r2: BigInt,
    pub auth_id: String
}

pub struct TestContext
{
    pub server: Arc<Box<dyn Auth>>,
    //I probably overcomplicated here with Arc<RwLock<ChaumPedersenAlgorthim>>
    pub algorithm: Option<Arc<RwLock<ChaumPedersenAlgorthim>>>,
    pub user: Option<TestUser>,
    pub challenge: Option<TestChallenge>
}

impl TestContext
{
    pub fn new() -> TestContext 
    {        
        let mut config = Config::build();
        config.fixed_parameters = true;
        let server = bootstrap(Some(config));
        
        TestContext {
            server: Arc::new(Box::new(server)),
            algorithm: None,
            user: None,
            challenge: None
        }
    }

    pub async fn with_algorithm(&self) -> TestContext {
        let encoded_parameters = self.server.get_authentication_parameters(tonic::Request::new({})).await.unwrap().into_inner();
        let parameters = ChaumPedersenParameters {
            p: BigInt::from_bytes_be(Sign::Plus, &encoded_parameters.p),
            q: BigInt::from_bytes_be(Sign::Plus, &encoded_parameters.q),
            g: BigInt::from_bytes_be(Sign::Plus, &encoded_parameters.g),
            h: BigInt::from_bytes_be(Sign::Plus, &encoded_parameters.h),
            bit_size: encoded_parameters.bit_size as u16
        };

        TestContext {
            server: self.server.clone(),
            algorithm: Some(Arc::new(RwLock::new(ChaumPedersenAlgorthim::new(&parameters)))),
            user: self.user.clone(),
            challenge: self.challenge.clone()
        }
    }

    pub async fn with_registered_user(&self) -> TestContext {
        assert!(self.algorithm.is_some());
        let algorithm = self.algorithm.as_ref().unwrap().read().unwrap();
        
        let x = auth_lib::calculate_hash(&"My Super Secret Password".to_string());
        let (y1, y2) = algorithm.exponentiation(&x);
        let register_request = RegisterRequest{
            user: Uuid::new_v4().to_string(),
            y1: y1.to_bytes_be().1,
            y2: y2.to_bytes_be().1,
        };
        let user = register_request.user.clone();

        self.server.register(tonic::Request::new(register_request)).await.unwrap();

        TestContext {
            server: self.server.clone(),
            algorithm: self.algorithm.clone(),
            user: Some(TestUser{
                user,
                x: x,
                y1: y1,
                y2: y2
            }),
            challenge: self.challenge.clone()
        }
    }

    pub async fn with_challenge(&self) -> TestContext {
        assert!(self.algorithm.is_some());
        let mut algorithm = self.algorithm.as_ref().unwrap().write().unwrap();
    
        let k = algorithm.generate_random();
        let (r1, r2) = algorithm.exponentiation(&k);
        let challenge_request = AuthenticationChallengeRequest{
            user: self.user.as_ref().unwrap().user.clone(),
            r1: r1.to_bytes_be().1,
            r2: r2.to_bytes_be().1,
        };
    
        let response = self.server.create_authentication_challenge(tonic::Request::new(challenge_request)).await;
        let challenge = response.unwrap().into_inner();


        TestContext {
            server: self.server.clone(),
            algorithm: self.algorithm.clone(),
            user: self.user.clone(),
            challenge: Some(TestChallenge{
                c: BigInt::from_bytes_be(Sign::Plus, &challenge.c),
                k: k.clone(),
                r1: r1.clone(),
                r2: r2.clone(),
                auth_id: challenge.auth_id
            })
        }
    }
}