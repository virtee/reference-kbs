use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

pub mod attester;
use attester::Attester;
pub mod sev;

#[derive(Eq, PartialEq)]
pub enum SessionStatus {
    Authorized,
    Unauthorized,
}

pub struct Session {
    id: String,
    workload_id: String,
    attester: Box<dyn Attester>,
    status: SessionStatus,
    expires_on: Instant,
}

// Session will only be accessed through Arc<Mutex<Session>>
unsafe impl Send for Session {}

impl Session {
    pub fn new(id: String, workload_id: String, attester: Box<dyn Attester>) -> Session {
        Session {
            id,
            workload_id,
            attester,
            status: SessionStatus::Unauthorized,
            expires_on: Instant::now() + Duration::from_secs(3 * 60 * 60),
        }
    }

    pub fn id(&self) -> String {
        self.id.clone()
    }

    pub fn workload_id(&self) -> String {
        self.workload_id.clone()
    }

    pub fn attester(&mut self) -> &mut Box<dyn Attester> {
        &mut self.attester
    }

    pub fn is_valid(&self) -> bool {
        if self.status != SessionStatus::Authorized {
            println!("Session is not authorized");
        }
        if Instant::now() > self.expires_on {
            println!("Session expired");
        }
        self.status == SessionStatus::Authorized && Instant::now() < self.expires_on
    }

    pub fn approve(&mut self) {
        self.status = SessionStatus::Authorized;
    }
}

pub struct SessionState {
    pub sessions: RwLock<HashMap<String, Arc<Mutex<Session>>>>,
}
