use serde::Deserialize;
use std::fs;

const CONFIG_PATH: &str = "/etc/gatekeeper-pam.conf";

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub gatekeeper_url: String,
    pub server_token: String,
    pub nfc_device: String,
    #[serde(default = "default_timeout")]
    pub nfc_timeout_secs: u64,
    pub auth_key: String,
    pub read_key: String,
    pub desfire_signing_public_key: String,
    pub mobile_decryption_private_key: String,
    pub mobile_signing_private_key: String,
}

fn default_timeout() -> u64 {
    7
}

impl Config {
    pub fn load() -> Result<Self, String> {
        let contents = fs::read_to_string(CONFIG_PATH)
            .map_err(|e| format!("cannot read {}: {}", CONFIG_PATH, e))?;
        toml::from_str(&contents)
            .map_err(|e| format!("cannot parse {}: {}", CONFIG_PATH, e))
    }
}
