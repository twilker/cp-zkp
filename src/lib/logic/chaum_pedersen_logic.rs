use std::sync::{Arc, RwLock};

use crate::chaum_pedersen::algorithm::{ChaumPedersen};
use crate::data_access::access::DataAccess;

use uuid::Uuid;

use super::chaum_pedersen_model::Parameters;
use super::{chaum_pedersen_model::{UserRegistration, ValidationErrors, UserChallengeRequest, UserChallengeResponse, UserSolution, SessionResponse}, chaum_pedesen_validation::ChaumPedersenValidation};

pub trait ChaumPedersenLogic {
    fn get_parameters(&self) -> Result<Parameters, ValidationErrors>;
    fn register_user(&self, user: &UserRegistration) -> Result<(), ValidationErrors>;
    fn authentication_challenge(&self, challenge: &UserChallengeRequest) -> Result<UserChallengeResponse, ValidationErrors>;
    fn solve_challenge(&self, solution: &UserSolution) -> Result<SessionResponse, ValidationErrors>;
}

pub struct ChaumPedersenLogicImpl<Algorithm, Access, Validation> 
where 
    Algorithm: ChaumPedersen + Send + Sync + 'static,
    Access: DataAccess + Send + Sync + 'static,
    Validation: ChaumPedersenValidation + Send + Sync + 'static 
{
    algorithm: Arc<RwLock<Algorithm>>,
    data_access: Arc<RwLock<Access>>,
    validation: Arc<RwLock<Validation>>
}

impl<Algorithm, Access, Validation> ChaumPedersenLogicImpl<Algorithm, Access, Validation> 
where 
    Algorithm: ChaumPedersen + Send + Sync + 'static,
    Access: DataAccess + Send + Sync + 'static,
    Validation: ChaumPedersenValidation + Send + Sync + 'static 
{
    pub fn new(algorithm: Arc<RwLock<Algorithm>>, data_access: Arc<RwLock<Access>>, validation: Arc<RwLock<Validation>>) -> Self {
        Self {
            algorithm: algorithm,
            data_access: data_access,
            validation: validation
        }
    }
}

impl<Algorithm, Access, Validation> ChaumPedersenLogic for ChaumPedersenLogicImpl<Algorithm, Access, Validation> 
where 
    Algorithm: ChaumPedersen + Send + Sync + 'static,
    Access: DataAccess + Send + Sync + 'static,
    Validation: ChaumPedersenValidation + Send + Sync + 'static
{
    fn get_parameters(&self) -> Result<Parameters, ValidationErrors> {
        let algorithm = self.algorithm.read().unwrap();

        let parameters = algorithm.get_parameters();
        Ok(Parameters{
            p: parameters.p.clone(),
            q: parameters.q.clone(),
            g: parameters.g.clone(),
            h: parameters.h.clone(),
            bit_size: parameters.bit_size
        })
    }

    fn authentication_challenge(&self, challenge: &UserChallengeRequest) -> Result<UserChallengeResponse, ValidationErrors> {
        self.validation.read().unwrap().validate_user_challenge_request(&challenge)?;
        
        let c = self.algorithm.write().unwrap().generate_random();
        let auth_id = Uuid::new_v4().to_string();
        
        let mut data_access = self.data_access.write().unwrap();

        let user = data_access.get_user(&challenge.user).unwrap();

        if user.auth_id.is_some() {         
            let id = user.auth_id.clone().unwrap();   
            data_access.delete_auth_challenge(&id);
        }
        data_access.create_auth_challenge(&challenge.user, &auth_id, &c, &challenge.r1, &challenge.r2);
        
        Ok(UserChallengeResponse{auth_id, c})
    }

    fn register_user(&self, user: &UserRegistration) -> Result<(), ValidationErrors> {
        self.validation.read().unwrap().validate_user_registration(&user)?;

        self.data_access.write().unwrap().create_user(&user.user, &user.y1, &user.y2);

        Ok(())
    }

    fn solve_challenge(&self, solution: &UserSolution) -> Result<SessionResponse, ValidationErrors> {
        let validation = self.validation.read().unwrap();
        validation.validate_user_solution(&solution)?;
        
        let mut data_access = self.data_access.write().unwrap();

        let challenge = data_access.get_challenge(&solution.auth_id).unwrap();
        let user = data_access.get_user(&challenge.user_id).unwrap();

        let result = self.algorithm.read().unwrap().verify(&user.y1, &user.y2, &challenge.r1, &challenge.r2, &solution.s, &challenge.c);
        let user_id = challenge.user_id.clone();
        if !result {
            return Err(ValidationErrors::Unauthenticated);
        }

        drop(challenge);
        drop(user);

        let session_id = Uuid::new_v4().to_string();
        data_access.create_session(&user_id, &session_id);
        data_access.delete_auth_challenge(&solution.auth_id);

        Ok(SessionResponse{session_id})
    }
}