use num_bigint::BigInt;

#[derive(Debug)]
pub struct Parameters{
    pub p: BigInt,
    pub q: BigInt,
    pub g: BigInt,
    pub h: BigInt,
    pub bit_size: u16
}

#[derive(Debug)]
pub struct UserRegistration {
    pub user: String,
    pub y1: BigInt,
    pub y2: BigInt
}

#[derive(Debug)]
pub struct UserChallengeRequest {
    pub user: String,
    pub r1: BigInt,
    pub r2: BigInt
}

#[derive(Debug)]
pub struct UserChallengeResponse {    
    pub auth_id: String,
    pub c: BigInt
}

#[derive(Debug)]
pub struct UserSolution {
    pub auth_id: String,
    pub s: BigInt
}

#[derive(Debug)]
pub struct SessionResponse {
    pub session_id: String
}

#[derive(Debug)]
pub enum ValidationErrors {
    InvalidArgument,
    Unauthenticated,
    NotFound,
    AlreadyExists
}