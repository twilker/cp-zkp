use std::sync::{RwLock, Arc};

use crate::logic::chaum_pedersen_model::{ValidationErrors, UserChallengeRequest, UserSolution};
use crate::{cp_grpc::*, logic::chaum_pedersen_model::UserRegistration};
use crate::cp_grpc::auth_server::Auth;
use crate::logic::chaum_pedersen_logic::ChaumPedersenLogic;
use num_bigint::{BigInt, Sign};
use tonic::{Request, Response, Status};

#[derive(Debug)]
pub struct CPAuthServer<Logic> 
where 
    Logic: ChaumPedersenLogic + Send + Sync + 'static,
{
    logic: Arc<RwLock<Logic>>,
}

impl<Logic> CPAuthServer<Logic> 
where 
    Logic: ChaumPedersenLogic + Send + Sync + 'static,
{
    pub fn new(logic: Arc<RwLock<Logic>>) -> Self {
        Self {
            logic: logic
        }
    }
}

#[tonic::async_trait]
impl<Logic> Auth for CPAuthServer<Logic> 
where 
    Logic: ChaumPedersenLogic + Send + Sync + 'static,
{
    async fn get_authentication_parameters(&self, _request: Request<()>) -> Result<Response<AuthenticationParametersResponse>, Status> {
        let logic = self.logic.read().unwrap();

        let parameters = logic.get_parameters().map_err(to_tonic_error)?;

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
        let logic = self.logic.read().unwrap();

        let data = _request.get_ref();
        let y1 = BigInt::from_bytes_be(Sign::Plus, &data.y1);
        let y2 = BigInt::from_bytes_be(Sign::Plus, &data.y2);

        logic.register_user(&UserRegistration{
            user: data.user.clone(),
            y1: y1,
            y2: y2
        }).map_err(to_tonic_error)?;

        Ok(Response::new(RegisterResponse::default()))
    }

    async fn create_authentication_challenge(&self, _request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        let logic = self.logic.read().unwrap();

        let data = _request.get_ref();
        let r1 = BigInt::from_bytes_be(Sign::Plus, &data.r1);
        let r2 = BigInt::from_bytes_be(Sign::Plus, &data.r2);
        
        let challenge = logic.authentication_challenge(&UserChallengeRequest{
            user: data.user.clone(),
            r1: r1,
            r2: r2
        }).map_err(to_tonic_error)?;

        let challenge_response = AuthenticationChallengeResponse {
            c: challenge.c.to_bytes_be().1,
            auth_id: challenge.auth_id.clone()
        };
        Ok(Response::new(challenge_response))
    }

    async fn verify_authentication(&self, _request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        let logic = self.logic.read().unwrap();

        let data = _request.get_ref();
        let s = BigInt::from_bytes_be(Sign::Plus, &data.s);

        let user_solution = UserSolution{
            auth_id: data.auth_id.clone(),
            s: s
        };
        
        let session = logic.solve_challenge(&user_solution).map_err(to_tonic_error)?;

        let response = AuthenticationAnswerResponse {
            session_id: session.session_id.clone(),
        };
        Ok(Response::new(response))
    }
}

//Use internal messages to make errors more secific
fn to_tonic_error(error: ValidationErrors) -> Status {
    match error {
        ValidationErrors::InvalidArgument => Status::invalid_argument("Invalid argument"),
        ValidationErrors::NotFound => Status::not_found("Not found"),
        ValidationErrors::AlreadyExists => Status::already_exists("Already exists"),
        ValidationErrors::Unauthenticated => Status::unauthenticated("Unauthenticated"),
    }
}