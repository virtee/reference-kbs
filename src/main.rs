#![allow(clippy::extra_unused_lifetimes)]

use std::collections::HashMap;
use std::sync::RwLock;

#[macro_use]
extern crate rocket;

use reference_kbs::*;

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/kbs/v0", routes![index, auth, attest, key])
        .manage(SessionState {
            sessions: RwLock::new(HashMap::new()),
        })
        .attach(Db::fairing())
}
