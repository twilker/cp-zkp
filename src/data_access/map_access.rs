use std::collections::HashMap;

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

    pub fn create_user(&mut self, user: &User) {
        self.users.insert(user.id.clone(), user.clone());
    }

    pub fn create_auth_challenge(&mut self, user_id: &String, challenge: &Challenge) {
        self.users.get_mut(user_id).unwrap().auth_id = Some(challenge.id.clone());
        self.challenges.insert(challenge.id.clone(), challenge.clone());
    }

    pub fn delete_auth_challenge(&mut self, auth_id: &String) {
        //TODO check if auth_id exists and user exists
        let challenge = self.challenges.remove(auth_id);
        self.users.get_mut(&challenge.unwrap().user_id).unwrap().auth_id = None;
    }

    pub fn create_session(&mut self, user_name: &String, session: & Session) {
        self.users.get_mut(user_name).unwrap().session_id = Some(session.id.clone());
        self.session.insert(session.id.clone(), session.clone());
    }

    pub fn get_user(&self, name: &String) -> Option<&User> {
        self.users.get(name)
    }
    
    pub fn get_challenge(&self, id: &String) -> Option<&Challenge> {
        self.challenges.get(id)
    }
}