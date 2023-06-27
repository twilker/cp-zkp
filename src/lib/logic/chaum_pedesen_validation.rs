use std::sync::{Arc, RwLock};

use num_traits::Zero;

use crate::data_access::access::DataAccess;

use super::chaum_pedersen_model::{UserRegistration, UserChallengeRequest, UserSolution, ValidationErrors};

pub trait ChaumPedersenValidation {
    fn validate_user_registration(&self, user: &UserRegistration) -> Result<(), ValidationErrors>;
    fn validate_user_challenge_request(&self, challenge: &UserChallengeRequest) -> Result<(), ValidationErrors>;
    fn validate_user_solution(&self, solution: &UserSolution) -> Result<(), ValidationErrors>;
}

pub struct ChaumPedersenValidationImpl<Access>
where 
    Access: DataAccess + Send + Sync + 'static,
{
    data_access: Arc<RwLock<Access>>
}

impl<Access> ChaumPedersenValidationImpl<Access> 
where 
    Access: DataAccess + Send + Sync + 'static,
{
    pub fn new(data_access: Arc<RwLock<Access>>) -> Self {
        Self {
            data_access: data_access
        }
    }
}

impl<Access> ChaumPedersenValidation for ChaumPedersenValidationImpl<Access>
where 
    Access: DataAccess + Send + Sync + 'static
{
    fn validate_user_challenge_request(&self, challenge: &UserChallengeRequest) -> Result<(), ValidationErrors> {
        let data_access = self.data_access.read().unwrap();

        if challenge.user.is_empty() {
            return Err(ValidationErrors::InvalidArgument);
        }
        if challenge.r1.is_zero() {
            return Err(ValidationErrors::InvalidArgument);
        }
        if challenge.r2.is_zero() {
            return Err(ValidationErrors::InvalidArgument);
        }

        let user = data_access.get_user(&challenge.user);
        if user.is_none() {
            return Err(ValidationErrors::Unauthenticated);
        }

        Ok(())
    }

    fn validate_user_registration(&self, user: &UserRegistration) -> Result<(), ValidationErrors> {
        let data_access = self.data_access.read().unwrap();

        if user.user.is_empty() {
            return Err(ValidationErrors::InvalidArgument);
        }
        if user.y1.is_zero() {
            return Err(ValidationErrors::InvalidArgument);
        }
        if user.y2.is_zero() {
            return Err(ValidationErrors::InvalidArgument);
        }

        let user = data_access.get_user(&user.user);
        if user.is_some() {
            return Err(ValidationErrors::AlreadyExists);
        }

        Ok(())
    }

    fn validate_user_solution(&self, solution: &UserSolution) -> Result<(), ValidationErrors> {
        let data_access = self.data_access.read().unwrap();
        let auth_challenge = data_access.get_challenge(&solution.auth_id);
        
        if auth_challenge.is_none() {
            return Err(ValidationErrors::Unauthenticated);
        }
        if solution.s.is_zero() {
            return Err(ValidationErrors::InvalidArgument);
        }

        Ok(())
    }
}