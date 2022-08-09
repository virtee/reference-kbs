use bincode;
use rocket::serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::kv2;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct Secret {
    pub secret: String,
}

impl Secret {
    pub fn as_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(crate = "rocket::serde")]
pub struct SecretStore {
    url: String,
    token: String,
}

impl SecretStore {
    pub fn new(url: &str, token: &str) -> SecretStore {
        SecretStore {
            url: url.to_string(),
            token: token.to_string(),
        }
    }
    pub fn update(&mut self, url: String, token: String) {
        self.url = url;
        self.token = token;
    }
    pub fn get_url(&self) -> String {
        self.url.to_string()
    }
    pub fn get_token(&self) -> String {
        self.token.to_string()
    }
}

pub async fn get_secret_from_vault(url: &str, token: &str, path: &str) -> Secret {
    let client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(url.clone())
            .token(token.clone())
            .build()
            .unwrap(),
    )
    .unwrap();
    kv2::read(&client, "secret", path).await.unwrap()
}

#[derive(Debug, Clone)]
pub struct InvalidSecretStoreError {
    details: String,
}

impl InvalidSecretStoreError {
    pub fn new(msg: &str) -> InvalidSecretStoreError {
        InvalidSecretStoreError {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for InvalidSecretStoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for InvalidSecretStoreError {
    fn description(&self) -> &str {
        &self.details
    }
}

impl SecretStore {
    pub fn validate(&self) -> Result<(), InvalidSecretStoreError> {
        if self.token.is_empty() {
            Err(InvalidSecretStoreError::new("token cannot be empty"))
        } else if self.url.is_empty() {
            Err(InvalidSecretStoreError::new("url cannot be empty"))
        } else {
            Ok(())
        }
    }
}
