use std::collections::HashMap;

use num_bigint::BigInt;

use super::access::DataAccess;
use super::model::User;
use super::model::Challenge;
use super::model::Session;


#[derive(Debug)]
pub struct MapDataAccess{
    users: HashMap<String, User>,
    challenges: HashMap<String, Challenge>,
    session: HashMap<String, Session>
}

impl MapDataAccess {    
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            challenges: HashMap::new(),
            session: HashMap::new()
        }
    }
}

impl DataAccess for MapDataAccess {
    fn create_user(&mut self, user_name: &String, y1: &BigInt, y2: &BigInt) {
        self.users.insert(user_name.clone(), User{
            id: user_name.clone(),
            y1: y1.clone(),
            y2: y2.clone(),
            auth_id: None,
            session_id: None
        });
    }

    fn create_auth_challenge(&mut self, user_id: &String, auth_id: &String, c: &BigInt, r1: &BigInt, r2: &BigInt) {
        self.users.get_mut(user_id).unwrap().auth_id = Some(auth_id.clone());
        self.challenges.insert(auth_id.clone(), Challenge{
            id: auth_id.clone(),
            c: c.clone(),
            r1: r1.clone(),
            r2: r2.clone(),
            user_id: user_id.clone()
        });
    }

    fn delete_auth_challenge(&mut self, auth_id: &String) {
        //TODO check if auth_id exists and user exists
        let challenge = self.challenges.remove(auth_id);
        self.users.get_mut(&challenge.unwrap().user_id).unwrap().auth_id = None;
    }

    fn create_session(&mut self, user_name: &String, session_id: &String) {
        self.users.get_mut(user_name).unwrap().session_id = Some(session_id.clone());
        self.session.insert(session_id.clone(), Session { id: session_id.clone(), user_id: user_name.clone() });
    }

    fn get_user(&self, name: &String) -> Option<&User> {
        self.users.get(name)
    }
    
    fn get_challenge(&self, id: &String) -> Option<&Challenge> {
        self.challenges.get(id)
    }
}