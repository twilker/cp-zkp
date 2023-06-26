use num_bigint::BigInt;

use super::{model::User, model::Challenge};

pub trait DataAccess {
    fn create_user(&mut self, user_name: &String, y1: &BigInt, y2: &BigInt);
    fn create_auth_challenge(&mut self, user_id: &String, auth_id: &String, c: &BigInt, r1: &BigInt, r2: &BigInt);
    fn delete_auth_challenge(&mut self, auth_id: &String);
    fn create_session(&mut self, user_id: &String, session_id: &String);
    fn get_user(&self, name: &String) -> Option<&User>;
    fn get_challenge(&self, id: &String) -> Option<&Challenge>;
}
