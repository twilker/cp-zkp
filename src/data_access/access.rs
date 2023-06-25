use num_bigint::BigInt;

use super::{map_access::MapDataAccess, model::User, model::Challenge, model::Session};


#[derive(Debug)]
pub struct DataAccess {
    access: MapDataAccess
}

impl DataAccess {
    pub fn new() -> Self {
        Self {
            access: MapDataAccess::new()
        }
    }

    pub fn create_user(&mut self, user_name: &String, y1: &BigInt, y2: &BigInt) {
        self.access.create_user(&User{
            id: user_name.clone(),
            y1: y1.clone(),
            y2: y2.clone(),
            auth_id: None,
            session_id: None
        });
    }

    pub fn create_auth_challenge(&mut self, user_id: &String, auth_id: &String, c: &BigInt, r1: &BigInt, r2: &BigInt) {
        self.access.create_auth_challenge(user_id, &Challenge{
            id: auth_id.clone(),
            c: c.clone(),
            r1: r1.clone(),
            r2: r2.clone(),
            user_id: user_id.clone()
        });
    }

    pub fn delete_auth_challenge(&mut self, auth_id: &String) {
        self.access.delete_auth_challenge(auth_id);
    }

    pub fn create_session(&mut self, user_id: &String, session_id: &String) {
        self.access.create_session(user_id, &Session{
            id: session_id.clone(),
            user_id: user_id.clone()
        });
    }

    pub fn get_user(&self, name: &String) -> Option<&User> {
        self.access.get_user(name)
    }

    pub fn get_challenge(&self, id: &String) -> Option<&Challenge> {
        self.access.get_challenge(id)
    }
}