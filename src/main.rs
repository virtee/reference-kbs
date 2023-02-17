#![allow(clippy::extra_unused_lifetimes)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

#[macro_use]
extern crate rocket;
use rocket::fairing::AdHoc;
use rocket::http::{Cookie, CookieJar};
use rocket::response::status::{BadRequest, Unauthorized};
use rocket::serde::json::{json, Json, Value};
use rocket::serde::{Deserialize, Serialize};
use rocket::{Build, Rocket, State};

use kbs_types::{Attestation, Request, SevRequest, SnpRequest, Tee};
use uuid::Uuid;

use reference_kbs::attester::Attester;
use reference_kbs::sev::SevAttester;
use reference_kbs::snp::SnpAttester;
use reference_kbs::{Session, SessionState};

use rocket_sync_db_pools::database;

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;

use diesel::prelude::*;
use diesel_migrations::embed_migrations;

#[derive(Debug, Clone, Deserialize, Serialize, Queryable, Insertable)]
#[serde(crate = "rocket::serde")]
#[table_name = "configs"]
struct TeeConfig {
    workload_id: String,
    tee_config: String,
}

table! {
    configs (workload_id) {
        workload_id -> Text,
        tee_config -> Text,
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Queryable, Insertable)]
#[serde(crate = "rocket::serde")]
#[table_name = "measurements"]
struct Measurement {
    workload_id: String,
    launch_measurement: String,
}

table! {
    measurements (workload_id) {
        workload_id -> Text,
        launch_measurement -> Text,
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Queryable, Insertable)]
#[serde(crate = "rocket::serde")]
#[table_name = "secrets"]
struct Secret {
    key_id: String,
    secret: String,
}

table! {
    secrets (key_id) {
        key_id -> Text,
        secret -> Text,
    }
}

#[database("diesel")]
struct Db(diesel::SqliteConnection);

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
struct Workload {
    workload_id: String,
    launch_measurement: String,
    tee_config: String,
    passphrase: String,
}

#[get("/")]
fn index() -> Result<String, Unauthorized<String>> {
    //Ok("Hello, world!".to_string())
    Err(Unauthorized(None))
}

#[post("/auth", format = "application/json", data = "<request>")]
async fn auth(
    db: Db,
    state: &State<SessionState>,
    cookies: &CookieJar<'_>,
    request: Json<Request>,
) -> Result<Value, BadRequest<String>> {
    let session_id = Uuid::new_v4().to_simple().to_string();

    let mut attester: Box<dyn Attester> = match request.tee {
        Tee::Sev => {
            let sev_request: SevRequest = serde_json::from_str(&request.extra_params)
                .map_err(|e| BadRequest(Some(e.to_string())))?;

            let workload_id = sev_request.workload_id.clone();
            let tee_config: Option<String> = match db
                .run(move |conn| {
                    configs::table
                        .filter(configs::workload_id.eq(workload_id))
                        .first::<TeeConfig>(conn)
                })
                .await
            {
                Ok(e) => Some(e.tee_config),
                Err(_) => None,
            };

            Box::new(SevAttester::new(
                sev_request.workload_id.clone(),
                session_id.clone(),
                sev_request.build,
                sev_request.chain,
                tee_config,
            )) as Box<dyn Attester>
        }
        Tee::Snp => {
            let snp_request: SnpRequest = serde_json::from_str(&request.extra_params)
                .map_err(|e| BadRequest(Some(e.to_string())))?;

            let workload_id = snp_request.workload_id.clone();
            let tee_config: Option<String> = match db
                .run(move |conn| {
                    configs::table
                        .filter(configs::workload_id.eq(workload_id))
                        .first::<TeeConfig>(conn)
                })
                .await
            {
                Ok(e) => Some(e.tee_config),
                Err(_) => None,
            };

            /*
             * There needs to be a TEE config for each TEE workload.
             */
            if tee_config.is_none() {
                return Err(BadRequest(Some("No TEE config found".to_string())));
            }

            /*
             * We've already checked for the None case, it is now safe to
             * unwrap() the TEE config.
             */
            let tee_config = tee_config.unwrap();

            Box::new(SnpAttester::new(
                snp_request.workload_id.clone(),
                session_id.clone(),
                tee_config,
            )) as Box<dyn Attester>
        }
        _ => return Err(BadRequest(Some("Unsupported TEE".to_string()))),
    };

    let challenge = attester
        .challenge()
        .map_err(|e| BadRequest(Some(e.to_string())))?;

    let session = Session::new(session_id, attester.workload_id().clone(), attester);
    cookies.add(Cookie::new("session_id", session.id()));

    state
        .sessions
        .write()
        .unwrap()
        .insert(session.id(), Arc::new(Mutex::new(session)));
    Ok(json!(challenge))
}

#[post("/register_workload", format = "application/json", data = "<workload>")]
async fn register_workload(db: Db, workload: Json<Workload>) -> Result<(), BadRequest<String>> {
    let measurement = Measurement {
        workload_id: workload.workload_id.clone(),
        launch_measurement: workload.launch_measurement.clone(),
    };
    db.run(move |conn| {
        diesel::replace_into(measurements::table)
            .values(&measurement)
            .execute(conn)
    })
    .await
    .map_err(|e| BadRequest(Some(e.to_string())))?;

    let tee_config = TeeConfig {
        workload_id: workload.workload_id.clone(),
        tee_config: workload.tee_config.clone(),
    };
    db.run(move |conn| {
        diesel::replace_into(configs::table)
            .values(&tee_config)
            .execute(conn)
    })
    .await
    .map_err(|e| BadRequest(Some(e.to_string())))?;

    let secret = Secret {
        key_id: workload.workload_id.clone(),
        secret: workload.passphrase.clone(),
    };
    db.run(move |conn| {
        diesel::replace_into(secrets::table)
            .values(&secret)
            .execute(conn)
    })
    .await
    .map_err(|e| BadRequest(Some(e.to_string())))?;

    Ok(())
}

#[post("/attest", format = "application/json", data = "<attestation>")]
async fn attest(
    db: Db,
    state: &State<SessionState>,
    cookies: &CookieJar<'_>,
    attestation: Json<Attestation>,
) -> Result<(), BadRequest<String>> {
    let session_id = cookies
        .get("session_id")
        .ok_or_else(|| BadRequest(Some("Missing cookie".to_string())))?
        .value();

    // We're just cloning an Arc, looks like a false positive to me...
    #[allow(clippy::significant_drop_in_scrutinee)]
    let session_lock = match state.sessions.read().unwrap().get(session_id) {
        Some(s) => s.clone(),
        None => return Err(BadRequest(Some("Invalid cookie".to_string()))),
    };

    let workload_id = session_lock.lock().unwrap().workload_id();

    let measurement_entry: Measurement = db
        .run(move |conn| {
            measurements::table
                .filter(measurements::workload_id.eq(workload_id))
                .first(conn)
        })
        .await
        .map_err(|e| BadRequest(Some(e.to_string())))?;

    let mut session = session_lock.lock().unwrap();
    session
        .attester()
        .attest(&attestation, &measurement_entry.launch_measurement)
        .map_err(|e| BadRequest(Some(e.to_string())))?;
    session.approve();

    Ok(())
}

#[get("/key/<key_id>")]
async fn key(
    db: Db,
    state: &State<SessionState>,
    cookies: &CookieJar<'_>,
    key_id: &str,
) -> Result<Value, Unauthorized<String>> {
    let session_id = cookies
        .get("session_id")
        .ok_or_else(|| Unauthorized(Some("Missing cookie".to_string())))?
        .value();

    // We're just cloning an Arc, looks like a false positive to me...
    #[allow(clippy::significant_drop_in_scrutinee)]
    let session_lock = match state.sessions.read().unwrap().get(session_id) {
        Some(s) => s.clone(),
        None => return Err(Unauthorized(Some("Invalid cookie".to_string()))),
    };

    if !session_lock.lock().unwrap().is_valid() {
        return Err(Unauthorized(Some("Invalid session".to_string())));
    }

    let owned_key_id = key_id.to_string();
    let secrets_entry: Secret = db
        .run(move |conn| {
            secrets::table
                .filter(secrets::key_id.eq(owned_key_id))
                .first(conn)
        })
        .await
        .map_err(|e| Unauthorized(Some(e.to_string())))?;

    let mut session = session_lock.lock().unwrap();
    let secret = session
        .attester()
        .encrypt_secret(secrets_entry.secret.as_bytes())
        .unwrap();
    Ok(secret)
}

async fn run_migrations(rocket: Rocket<Build>) -> Rocket<Build> {
    // This macro from `diesel_migrations` defines an `embedded_migrations`
    // module containing a function named `run` that runs the migrations in the
    // specified directory, initializing the database.
    embed_migrations!("db/diesel/migrations");

    let conn = Db::get_one(&rocket).await.expect("database connection");
    conn.run(|c| embedded_migrations::run(c))
        .await
        .expect("diesel migrations");

    rocket
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount(
            "/kbs/v0",
            routes![index, auth, attest, key, register_workload],
        )
        .manage(SessionState {
            sessions: RwLock::new(HashMap::new()),
        })
        .attach(Db::fairing())
        .attach(AdHoc::on_ignite("Diesel Migrations", run_migrations))
}
