use serde::Deserialize;
use std::fs;
const CONFIG_PATH: &str = "/etc/gatekeeper-pam.conf";

#[derive(Deserialize, Debug, Clone)]
pub struct Config{
pub gatekeeper_url: String,
pub gk_server_token: String,
pub nfc_device: String,
#[serde(default = "default_chunk")]
pub nfc_poll_chunk_secs: u64,
pub gk_realm_member_projects_auth_key: String,
pub gk_realm_member_projects_read_key: String,
pub gk_realm_member_projects_public_key: String,
pub gk_realm_member_projects_mobile_crypt_private_key: String,
pub gk_realm_member_projects_mobile_private_key: String,
}

fn default_chunk() -> u64 { 86400 }

impl Config {
pub fn load() -> Result<Self, String> {
        let contents = fs::read_to_string(CONFIG_PATH).map_err(|e| format!("cannot read {CONFIG_PATH}: {e}"))?;
        toml::from_str(&contents).map_err(|e| format!("cannot parse {CONFIG_PATH}: {e}"))
    }
}