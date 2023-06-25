mod chaum_pedersen;
mod data_access;

use std::sync::Arc;

use auth_server::*;
use auth_server::auth_server::{Auth, AuthServer};
use num_bigint::{BigInt, Sign};
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};
use chaum_pedersen::algorithm as pedersen;
use data_access::access as da;
use uuid::Uuid;

pub mod auth_server {
    tonic::include_proto!("zkp_auth"); // The string specified here must match the proto package name
}

const BIT_SIZE: u16 = 256;

#[derive(Debug)]
pub struct CPAuthServer {
    algorithm: Arc<RwLock<pedersen::ChaumPedersenAlgorthim>>,
    data_access: Arc<RwLock<da::DataAccess>>
}

impl CPAuthServer {
    pub fn new(algorithm: pedersen::ChaumPedersenAlgorthim) -> Self {
        Self {
            algorithm: Arc::new(RwLock::new(algorithm)),
            data_access: Arc::new(RwLock::new(da::DataAccess::new()))
        }
    }
}

#[tonic::async_trait]
impl Auth for CPAuthServer {
    async fn get_authentication_parameters(&self, _request: Request<()>) -> Result<Response<AuthenticationParametersResponse>, Status> {
        let algorithm = self.algorithm.read().await;

        let parameters = algorithm.get_parameters();

        let response = AuthenticationParametersResponse {
            p: parameters.p.to_bytes_be().1,
            q: parameters.q.to_bytes_be().1,
            g: parameters.g.to_bytes_be().1,
            h: parameters.h.to_bytes_be().1,
            bit_size: parameters.bit_size.into()
        };
        Ok(Response::new(response))
    }

    async fn register(&self, _request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        let mut data_access = self.data_access.write().await;

        let data = _request.get_ref();
        let y1 = BigInt::from_bytes_be(Sign::Plus, &data.y1);
        let y2 = BigInt::from_bytes_be(Sign::Plus, &data.y2);
        data_access.create_user(&data.user, &y1, &y2);

        Ok(Response::new(RegisterResponse::default()))
    }

    async fn create_authentication_challenge(&self, _request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        let mut algorithm = self.algorithm.write().await;
        let mut data_access = self.data_access.write().await;

        let c = algorithm.generate_random();
        let data = _request.get_ref();
        let r1 = BigInt::from_bytes_be(Sign::Plus, &data.r1);
        let r2 = BigInt::from_bytes_be(Sign::Plus, &data.r2);
        let auth_id = Uuid::new_v4().to_string();
        data_access.create_auth_challenge(&data.user, &auth_id, &c, &r1, &r2);
        //TODO delete previous challenges

        let challenge_response = AuthenticationChallengeResponse {
            c: c.to_bytes_be().1,
            auth_id: auth_id.clone()
        };
        Ok(Response::new(challenge_response))
    }

    async fn verify_authentication(&self, _request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        let mut data_access = self.data_access.write().await;
        let algorithm = self.algorithm.read().await;

        let data = _request.get_ref();
        let s = BigInt::from_bytes_be(Sign::Plus, &data.s);
        let challenge = data_access.get_challenge(&data.auth_id).unwrap();
        let user = data_access.get_user(&challenge.user_id).unwrap();

        let result = algorithm.verify(&user.y1, &user.y2, &challenge.r1, &challenge.r2, &s, &challenge.c);
        let user_id = challenge.user_id.clone();
        if !result {
            return Err(Status::unauthenticated("Authentication failed"));
        }

        drop(challenge);
        drop(user);

        let session_id = Uuid::new_v4().to_string();
        data_access.create_session(&user_id, &session_id);
        data_access.delete_auth_challenge(&data.auth_id);

        
        println!("Data layer state: {:?}", data_access);

        let response = AuthenticationAnswerResponse {
            session_id: session_id
        };
        Ok(Response::new(response))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let parameters = pedersen::ChaumPedersenAlgorthim::find_parameters(BIT_SIZE);
    let algorithm = pedersen::ChaumPedersenAlgorthim::new(&parameters);
    let auth_server = CPAuthServer::new(algorithm);

    Server::builder()
        .add_service(AuthServer::new(auth_server))
        .serve(addr)
        .await?;

    Ok(())
}