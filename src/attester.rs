use std::fmt;
use std::io;

use kbs_types::{Attestation, Challenge};
use rocket::serde::json::Value;

#[derive(Debug)]
pub enum AttesterError {
    InvalidAttestation(serde_json::Error),
    InvalidMeasurement(io::Error),
    InvalidRequest(serde_json::Error),
    InvalidTee,
    SevChallengeJson(serde_json::Error),
    SevInvalidPolicy(serde_json::Error),
    SevMissingChain,
    SevMissingSession,
    SevMissingVerified,
    SevPolicy(io::Error),
    SevSecret(io::Error),
    SevSecretTooLong,
    SevSession(io::Error),
    SevSessionMeasure(io::Error),
    SnpNoncePubkeyHashInvalid,
    SnpMeasurementInvalid,
    TeePubkeyInvalid,
    SnpCertChainInvalid,
    SnpSignatureInvalid,
    SnpSecretEncryption,
}

impl fmt::Display for AttesterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub trait Attester {
    fn workload_id(&self) -> &String;
    fn challenge(&mut self) -> Result<Challenge, AttesterError>;
    fn attest(&mut self, attestation: &Attestation, measurement: &str)
        -> Result<(), AttesterError>;
    fn encrypt_secret(&self, plain_secret: &[u8]) -> Result<Value, AttesterError>;
}
