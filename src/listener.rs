use gatekeeper_core::{GatekeeperReader, NfcTag, Realm, RealmType, UndifferentiatedTag};
use reqwest::header::AUTHORIZATION;
use reqwest::StatusCode;
use serde_json::Value;
use std::thread;
use std::time::Duration;

use crate::config::Config;

pub enum FetchError {
    NotFound,
    ParseError,
    NetworkError,
    Unknown,
}

pub fn parse_uid(value: &Value) -> Option<String> {
    value
        .get("uid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned())
}

pub struct GateKeeperMemberListener<'a> {
    nfc_device: GatekeeperReader<'a>,
    http: reqwest::blocking::Client,
    server_token: String,
    endpoint: String,
    just_scanned: bool,
    route: &'static str,
}

impl<'a> GateKeeperMemberListener<'a> {
    pub fn new(config: &Config) -> Option<Self> {
        let realm = Realm::new(
            RealmType::MemberProjects,
            config.auth_key.clone().into_bytes(),
            config.read_key.clone().into_bytes(),
            config.desfire_signing_public_key.as_bytes(),
            config.mobile_decryption_private_key.as_bytes(),
            config.mobile_signing_private_key.as_bytes(),
            None,
        );

        Some(Self {
            nfc_device: GatekeeperReader::new(config.nfc_device.clone(), realm)?,
            http: reqwest::blocking::Client::new(),
            server_token: config.server_token.clone(),
            endpoint: config.gatekeeper_url.clone(),
            just_scanned: false,
            route: "projects",
        })
    }

    pub fn poll_for_tag(&mut self) -> Option<UndifferentiatedTag<'_>> {
        let nearby_tags = self.nfc_device.get_nearby_tags();
        if nearby_tags.is_empty() {
            self.just_scanned = false;
        }
        if self.just_scanned {
            thread::sleep(Duration::from_millis(250));
            return None;
        }
        self.just_scanned = !nearby_tags.is_empty();
        nearby_tags.into_iter().next()
    }

    pub fn poll_for_user(&mut self) -> Option<String> {
        self.poll_for_tag().and_then(|tag| tag.authenticate().ok())
    }

    pub fn wait_for_user(&mut self, timeout_secs: u64) -> Option<String> {
        let deadline = std::time::Instant::now()
            + Duration::from_secs(timeout_secs);
        loop {
            if std::time::Instant::now() >= deadline {
                return None;
            }
            if let Some(key) = self.poll_for_user() {
                return Some(key);
            }
        }
    }

    pub fn fetch_user(&self, key: String) -> Result<Value, FetchError> {
        let url = format!("{}/{}/by-key/{}", self.endpoint, self.route, key);
        match self.http.get(&url)
            .header(AUTHORIZATION, &self.server_token)
            .send()
        {
            Ok(res) => match res.status() {
                StatusCode::OK => res.text()
                    .ok()
                    .and_then(|t| serde_json::from_str(&t).ok())
                    .ok_or(FetchError::ParseError),
                StatusCode::NOT_FOUND => Err(FetchError::NotFound),
                _ => Err(FetchError::Unknown),
            },
            Err(_) => Err(FetchError::NetworkError),
        }
    }
}
