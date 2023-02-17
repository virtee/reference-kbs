use crate::attester::{Attester, AttesterError};

use std::fs::File;

use codicon::Read;
use curl::easy::Easy;
use kbs_types::{Attestation, Challenge, SnpAttestation, TeePubKey};
use openssl::{
    bn::BigNum,
    ecdsa::EcdsaSig,
    error::ErrorStack,
    pkey::{PKey, Public},
    rsa::{Padding, Rsa},
    sha::{Sha384, Sha512},
    x509::X509,
};
use rocket::serde::json;
use rocket::serde::json::Value;
use sev::firmware::guest::types::AttestationReport;

pub enum SnpGeneration {
    Milan,
    Genoa,
}

impl TryFrom<&String> for SnpGeneration {
    type Error = AttesterError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        match &value.to_ascii_lowercase()[..] {
            "milan" => Ok(Self::Milan),
            "genoa" => Ok(Self::Genoa),
            _ => Err(AttesterError::InvalidTee),
        }
    }
}

impl SnpGeneration {
    fn to_lower(&self) -> String {
        match self {
            SnpGeneration::Milan => "milan".to_string(),
            SnpGeneration::Genoa => "genoa".to_string(),
        }
    }

    fn to_proper(&self) -> String {
        match self {
            SnpGeneration::Milan => "Milan".to_string(),
            SnpGeneration::Genoa => "Genoa".to_string(),
        }
    }
}

pub struct CaChain {
    pub ark: X509,
    pub ask: X509,
}

impl CaChain {
    pub fn get(gen: &SnpGeneration) -> Self {
        let mut ark_buf: Vec<u8> = Vec::new();
        let mut ask_buf: Vec<u8> = Vec::new();

        let gen_str = gen.to_lower();

        let mut ark_file = File::open(format!("certs/{}/ark.pem", gen_str)).unwrap();
        let mut ask_file = File::open(format!("certs/{}/ask.pem", gen_str)).unwrap();

        ark_file.read_to_end(&mut ark_buf).unwrap();
        ask_file.read_to_end(&mut ask_buf).unwrap();

        let ark = X509::from_pem(&ark_buf[..]).unwrap();
        let ask = X509::from_pem(&ask_buf[..]).unwrap();

        Self { ark, ask }
    }

    pub fn pkeys(&self) -> (PKey<Public>, PKey<Public>) {
        (
            self.ark.public_key().unwrap(),
            self.ask.public_key().unwrap(),
        )
    }
}

pub struct SnpAttester {
    workload_id: String,
    nonce: String,
    #[allow(dead_code)]
    tee_config: String,
    rsa: Option<Rsa<Public>>,
}

impl SnpAttester {
    pub fn new(workload_id: String, nonce: String, tee_config: String) -> Self {
        Self {
            workload_id,
            nonce,
            tee_config,
            rsa: None,
        }
    }
}

impl Attester for SnpAttester {
    fn workload_id(&self) -> &String {
        &self.workload_id
    }

    fn challenge(&mut self) -> Result<Challenge, AttesterError> {
        /*
         * For SNP, we're really only concerned about the nonce in the
         * Challenge. Therefore, we have no reason to create an SnpChallenge
         * struct. Use the generic Challenge to send back to the client.
         */
        Ok(Challenge {
            nonce: self.nonce.clone(),
            extra_params: "".to_string(),
        })
    }

    fn attest(
        &mut self,
        attestation: &Attestation,
        measurement: &str,
    ) -> Result<(), AttesterError> {
        let snp: SnpAttestation = json::from_str(&attestation.tee_evidence).unwrap();
        let pkey: &TeePubKey = &attestation.tee_pubkey;
        let gen = match SnpGeneration::try_from(&snp.gen) {
            Ok(g) => g,
            Err(_) => return Err(AttesterError::InvalidTee),
        };

        let report_bytes = hex::decode(snp.report.into_bytes()).unwrap();
        let report: AttestationReport =
            unsafe { std::ptr::read(report_bytes.as_ptr() as *const _) };

        if !nonce_pkey_hash(&report, pkey, &self.nonce) {
            return Err(AttesterError::SnpNoncePubkeyHashInvalid);
        }

        if validate_chain(&report, gen).is_err() {
            return Err(AttesterError::SnpCertChainInvalid);
        }

        let measurement = hex::decode(measurement).unwrap();
        if measurement[..] != report.measurement {
            return Err(AttesterError::SnpMeasurementInvalid);
        }

        self.rsa = match rsa_from_tee_pubkey_components(pkey) {
            Ok(key) => Some(key),
            Err(_) => return Err(AttesterError::TeePubkeyInvalid),
        };

        Ok(())
    }

    fn encrypt_secret(&self, plain_secret: &[u8]) -> Result<Value, AttesterError> {
        /*
         * At this point, self.rsa should contain a valid Rsa, and thus it is
         * safe to unwrap().
         */
        let rsa = self.rsa.as_ref().unwrap();
        let mut encrypted_secret = vec![0; rsa.size() as usize];

        if rsa
            .public_encrypt(plain_secret, &mut encrypted_secret, Padding::PKCS1)
            .is_err()
        {
            return Err(AttesterError::SnpSecretEncryption);
        }

        let hex_json = json::json!(hex::encode(encrypted_secret));

        Ok(hex_json)
    }
}

fn nonce_pkey_hash(report: &AttestationReport, pkey: &TeePubKey, nonce: &str) -> bool {
    let hash_expect = {
        let mut sha = Sha512::new();

        sha.update(nonce.as_bytes());
        sha.update(pkey.k_mod[..].as_bytes());
        sha.update(pkey.k_exp[..].as_bytes());

        sha.finish()
    };

    hash_expect == report.report_data
}

fn validate_chain(report: &AttestationReport, gen: SnpGeneration) -> Result<(), AttesterError> {
    let ca = CaChain::get(&gen);
    let vcek = {
        let id = hex::encode(report.chip_id);
        let url = format!("https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                gen.to_proper(), id, report.current_tcb.boot_loader, report.current_tcb.tee,
                report.current_tcb.snp, report.current_tcb.microcode);

        /*
         * Use a cURL GET request to obtain the bytes of the VCEK.
         */
        let mut handle = Easy::new();
        let mut buf: Vec<u8> = Vec::new();

        handle.url(&url).unwrap();
        handle.get(true).unwrap();

        let mut transfer = handle.transfer();
        transfer
            .write_function(|data| {
                buf.extend_from_slice(data);
                Ok(data.len())
            })
            .unwrap();
        transfer.perform().unwrap();
        drop(transfer);

        X509::from_der(buf.as_slice()).unwrap()
    };

    let (ark_pkey, ask_pkey) = ca.pkeys();

    /*
     * Ensure ARK is self-signed.
     */
    if ca.ark.verify(&ark_pkey).unwrap() {
        /*
         * Ensure ARK signs ASK.
         */
        if ca.ask.verify(&ark_pkey).unwrap() {
            /*
             * Ensure ASK signs VCEK.
             */
            if vcek.verify(&ask_pkey).unwrap() {
                let ar_sig = EcdsaSig::try_from(&report.signature).unwrap();

                let measurable_bytes: &[u8] = &bincode::serialize(&report).unwrap()[0x0..0x2A0];
                let mut hasher = Sha384::new();
                hasher.update(measurable_bytes);
                let base_message_digest: [u8; 48] = hasher.finish();

                let vcek_ec = {
                    let pkey = vcek.public_key().unwrap();

                    pkey.ec_key().unwrap()
                };

                /*
                 * Ensure VCEK signs attestation report signature.
                 */
                if ar_sig.verify(&base_message_digest, &vcek_ec).unwrap() {
                    return Ok(());
                }
            }
        }
    }

    Err(AttesterError::SnpCertChainInvalid)
}

fn rsa_from_tee_pubkey_components(pkey: &TeePubKey) -> Result<Rsa<Public>, ErrorStack> {
    let bin_modulo = openssl::base64::decode_block(&pkey.k_mod).expect("decode modulo");
    let bin_exponent = openssl::base64::decode_block(&pkey.k_exp).expect("decode exponent");

    let m: &[u8] = &bin_modulo;
    let e: &[u8] = &bin_exponent;

    let modulo = BigNum::from_slice(m)?;
    let exponent = BigNum::from_slice(e)?;

    Rsa::from_public_components(modulo, exponent)
}
