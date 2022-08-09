#![allow(clippy::extra_unused_lifetimes)]
#![feature(option_result_contains)]

use std::collections::HashMap;
use std::sync::RwLock;

#[macro_use]
extern crate rocket;

use reference_kbs::secrets_store::SecretStore;
use reference_kbs::*;

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/kbs/v0", routes![index, auth, attest, key])
        .mount(
            "/secret-store",
            routes![register_secret_store, get_secret_store],
        )
        .manage(SessionState {
            sessions: RwLock::new(HashMap::new()),
            secret_store: RwLock::new(SecretStore::new("http://127.0.0.1:8200", "myroot")),
        })
        .attach(Db::fairing())
}
