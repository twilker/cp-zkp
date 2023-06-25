use num_bigint::BigInt;


#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub y1: BigInt,
    pub y2: BigInt,
    pub auth_id: Option<String>,
    pub session_id: Option<String>
}

#[derive(Debug, Clone)]
pub struct Challenge {
    pub id: String,
    pub c: BigInt,
    pub r1: BigInt,
    pub r2: BigInt,
    pub user_id: String
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub user_id: String
}