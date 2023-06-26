use num_bigint::{BigInt, Sign};
use tokio::sync::RwLock;
use std::sync::Arc;
use crate::chaum_pedersen::algorithm::{ChaumPedersen};
use crate::cp_grpc::{RegisterRequest, AuthenticationChallengeRequest, AuthenticationAnswerRequest};
use crate::cp_grpc::auth_client::AuthClient as GrpcAuthClient;
use tonic::transport::Channel;
use async_trait::async_trait;

#[async_trait]
pub trait AuthClient {
    async fn register_user(&self, user: &String, x: &BigInt) -> Result<(), Box<dyn std::error::Error>>;
    async fn authenticate_user(&self, user: &String, x: &BigInt) -> Result<String, Box<dyn std::error::Error>>;
}

pub struct CPAuthClient<Algorithm> 
where 
    Algorithm: ChaumPedersen + Send + Sync + 'static,
{
    connection: Arc<RwLock<GrpcAuthClient<Channel>>>,
    algorithm: Arc<RwLock<Algorithm>>,
}

impl <Algorithm> CPAuthClient<Algorithm> 
where 
    Algorithm: ChaumPedersen + Send + Sync + 'static,
{
    pub fn new(connection: Arc<RwLock<GrpcAuthClient<Channel>>>, algorithm: Arc<RwLock<Algorithm>>) -> Self {
        Self {
            connection: connection,
            algorithm: algorithm
        }
    }
}

#[async_trait]
impl <Algorithm> AuthClient for CPAuthClient<Algorithm> 
where 
    Algorithm: ChaumPedersen + Send + Sync + 'static,
{
    async fn register_user(&self, user: &String, x: &BigInt) -> Result<(), Box<dyn std::error::Error>> {
        let algorithm = self.algorithm.read().await;
        let mut connection = self.connection.write().await;

        let (y1, y2) = algorithm.exponentiation(&x);

        let register_request = tonic::Request::new(RegisterRequest{
            user: user.clone(),
            y1: y1.to_bytes_be().1,
            y2: y2.to_bytes_be().1
        });
        connection.register(register_request).await?;

        Ok(())
    }

    async fn authenticate_user(&self, user: &String, x: &BigInt) -> Result<String, Box<dyn std::error::Error>> {
        let mut algorithm = self.algorithm.write().await;
        let mut connection = self.connection.write().await;

        let k = algorithm.generate_random();
        let (r1, r2) = algorithm.exponentiation(&k);
        
        let challenge_request = tonic::Request::new(AuthenticationChallengeRequest{
            user: user.clone(),
            r1: r1.to_bytes_be().1,
            r2: r2.to_bytes_be().1
        });
        let challenge_response = connection.create_authentication_challenge(challenge_request).await?;
        let challenge = challenge_response.into_inner();
        let c = BigInt::from_bytes_be(Sign::Plus, &challenge.c);

        let s = algorithm.solve_challenge(&x, &k, &c);

        let answer_request = tonic::Request::new(AuthenticationAnswerRequest{
            auth_id: challenge.auth_id,
            s: s.to_bytes_be().1
        });
        let answer_response = connection.verify_authentication(answer_request).await?;
        let answer = answer_response.into_inner();

        Ok(answer.session_id)
    }
}