mod chaum_pedersen;

use auth_server::*;
use auth_server::auth_server::{Auth, AuthServer};
use tonic::{transport::Server, Request, Response, Status};
use chaum_pedersen::algorithm as pedersen;

pub mod auth_server {
    tonic::include_proto!("zkp_auth"); // The string specified here must match the proto package name
}

#[derive(Debug)]
pub struct CPAuthServer {
    algorithm: pedersen::ChaumPedersenAlgorthim
}

impl CPAuthServer {
    pub fn new(algorithm: pedersen::ChaumPedersenAlgorthim) -> Self {
        Self {
            algorithm
        }
    }
}

#[tonic::async_trait]
impl Auth for CPAuthServer {
    async fn get_authentication_parameters(&self, _request: Request<()>) -> Result<Response<AuthenticationParametersResponse>, Status> {
        let parameters = self.algorithm.get_parameters();
        let response = AuthenticationParametersResponse {
            p: parameters.p.to_bytes_be().1,
            q: parameters.q.to_bytes_be().1,
            g: parameters.g.to_bytes_be().1,
            h: parameters.h.to_bytes_be().1,
            bit_size: pedersen::ChaumPedersenAlgorthim::get_bit_size().into()
        };

        Ok(Response::new(response))
    }

    async fn register(&self, _request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        unimplemented!()
    }

    async fn create_authentication_challenge(&self, _request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        unimplemented!()
    }

    async fn verify_authentication(&self, _request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        unimplemented!()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let parameters = pedersen::ChaumPedersenAlgorthim::find_parameters();
    let algorithm = pedersen::ChaumPedersenAlgorthim::new(&parameters);
    let auth_server = CPAuthServer::new(algorithm);

    Server::builder()
        .add_service(AuthServer::new(auth_server))
        .serve(addr)
        .await?;

    Ok(())
}