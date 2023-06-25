use std::sync::Arc;

use crate::auth_server::*;
use crate::auth_server::auth_server::Auth;
use num_bigint::{BigInt, Sign};
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
use uuid::Uuid;
use crate::chaum_pedersen::algorithm::ChaumPedersen;
use crate::data_access::access::DataAccess;

#[derive(Debug)]
pub struct CPAuthServer<Algorithm, Access> 
where 
    Algorithm: ChaumPedersen + Send + Sync + 'static,
    Access: DataAccess + Send + Sync + 'static, 
{
    algorithm: Arc<RwLock<Algorithm>>,
    data_access: Arc<RwLock<Access>>
}

impl<Algorithm, Access> CPAuthServer<Algorithm, Access> 
where 
    Algorithm: ChaumPedersen + Send + Sync + 'static,
    Access: DataAccess + Send + Sync + 'static, 
{
    pub fn new(algorithm: Arc<RwLock<Algorithm>>, data_access: Arc<RwLock<Access>>) -> Self {
        Self {
            algorithm: algorithm,
            data_access: data_access
        }
    }
}

#[tonic::async_trait]
impl<Algorithm, Access> Auth for CPAuthServer<Algorithm, Access> 
where 
    Algorithm: ChaumPedersen + Send + Sync + 'static,
    Access: DataAccess + Send + Sync + 'static, 
{
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

        let response = AuthenticationAnswerResponse {
            session_id: session_id
        };
        Ok(Response::new(response))
    }
}