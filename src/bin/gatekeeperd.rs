use gatekeeper_core::{GatekeeperReader, NfcTag, Realm, RealmType};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[path = "../config.rs"]
mod config;
#[path = "../daemon.rs"]
mod daemon;
use config::Config;
use daemon::{DaemonResponse, SOCKET_PATH};

struct PendingTap {
    uid: String,
}

struct Shared {
    tp: Mutex<Option<PendingTap>>,
    tap_ready: Condvar,
}

fn main() {
    let config = Config::load().unwrap_or_else(|e| {
        eprintln!("gatekeeperd: {e}");
        std::process::exit(1);
    });

    let shared = Arc::new(Shared {
        tp: Mutex::new(None),
        tap_ready: Condvar::new(),
    });

    // Create the reader INSIDE the spawned thread
    {
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || poll_loop(config, shared));
    }

    let _ = std::fs::create_dir_all("/run/gatekeeperd");
    let _ = std::fs::remove_file(SOCKET_PATH);
    let listener = UnixListener::bind(SOCKET_PATH).unwrap_or_else(|e| {
        eprintln!("gatekeeperd: failed to bind {SOCKET_PATH}: {e}");
        std::process::exit(1);
    });
    let _ = std::fs::set_permissions(
        SOCKET_PATH,
        std::os::unix::fs::PermissionsExt::from_mode(0o666),
    );

    eprintln!("gatekeeperd: listening on {SOCKET_PATH}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || handle_client(stream, &shared));
            }
            Err(e) => eprintln!("gatekeeperd: accept error: {e}"),
        }
    }
}

fn poll_loop(config: Config, shared: Arc<Shared>) {
    let realm = Realm::new(
        RealmType::MemberProjects,
        config
            .gk_realm_member_projects_auth_key
            .clone()
            .into_bytes(),
        config
            .gk_realm_member_projects_read_key
            .clone()
            .into_bytes(),
        config.gk_realm_member_projects_public_key.as_bytes(),
        config
            .gk_realm_member_projects_mobile_crypt_private_key
            .as_bytes(),
        config
            .gk_realm_member_projects_mobile_private_key
            .as_bytes(),
        None,
    );

    let mut reader = match GatekeeperReader::new(config.nfc_device.clone(), realm) {
        Some(r) => r,
        None => {
            eprintln!(
                "gatekeeperd: failed to open NFC device {}",
                config.nfc_device
            );
            return;
        }
    };

    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("failed to build http client");

    let endpoint = config.gatekeeper_url.clone();
    let server_token = config.gk_server_token.clone();

    let mut last_emit = Instant::now();

    loop {
        if last_emit.elapsed() < Duration::from_millis(300) {
            std::thread::sleep(Duration::from_millis(25));
            continue;
        }

        let tags = reader.get_nearby_tags();

        for tag in tags {
            if let Ok(key) = tag.authenticate() {
                match fetch_uid(&http, &endpoint, &server_token, &key) {
                    Ok(Some(uid)) => {
                        let mut tp = shared.tp.lock().unwrap();

                        // IMPORTANT: only accept one tap at a time
                        if tp.is_none() {
                            eprintln!("gatekeeperd: tap resolved uid '{uid}'");
                            *tp = Some(PendingTap { uid });
                            shared.tap_ready.notify_all();
                        }
                    }
                    Ok(None) => {
                        eprintln!("gatekeeperd: tap authenticated but uid lookup failed");
                    }
                    Err(e) => {
                        eprintln!("gatekeeperd: fetch error: {e}");
                    }
                }
            }
        }

        last_emit = Instant::now();
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn fetch_uid(
    http: &reqwest::blocking::Client,
    endpoint: &str,
    server_token: &str,
    key: &str,
) -> Result<Option<String>, reqwest::Error> {
    let url = format!("{endpoint}/projects/by-key/{key}");
    let res = http
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, server_token)
        .send()?;

    if !res.status().is_success() {
        return Ok(None);
    }

    let value: serde_json::Value = res.json()?;
    Ok(value["user"]["uid"].as_str().map(String::from))
}

fn handle_client(stream: UnixStream, shared: &Arc<Shared>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone failed"));
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }

    let response = match parse_wait_request(&line) {
        Some(timeout_secs) => wait_for_tap(shared, Duration::from_secs(timeout_secs)),
        None => DaemonResponse::Error(format!("bad request: {line:?}")),
    };

    let mut stream = stream;
    let _ = stream.write_all(response.to_wire().as_bytes());
}

fn parse_wait_request(line: &str) -> Option<u64> {
    let line = line.trim();
    let rest = line.strip_prefix("WAIT ")?;
    rest.parse::<u64>().ok()
}

//this is like... idk what to say
fn wait_for_tap(shared: &Arc<Shared>, timeout: Duration) -> DaemonResponse {
    let deadline = Instant::now() + timeout;

    let mut tp = shared.tp.lock().unwrap();
    loop {
        if let Some(tap) = tp.take() {
            return DaemonResponse::Ok(tap.uid);
        }

        let now = Instant::now();
        if now >= deadline {
            return DaemonResponse::Timeout;
        }

        let (guard, _) = shared.tap_ready.wait_timeout(tp, deadline - now).unwrap();
        tp = guard;
    }
}
