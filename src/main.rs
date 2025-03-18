mod client;
mod errors;

use errors::NcError;

use client::{AuthData, NextcloudClient};
use std::{fs, io};

use log::{error, info};

fn load_auth_data(path: &str) -> Option<AuthData> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
}

fn save_auth_data(file_path: &str, auth_data: &AuthData) -> Result<(), NcError> {
    if auth_data.server_url().is_none() {
        return Err(NcError::MissingField("server_url".into()));
    }
    let contents = serde_json::to_string_pretty(auth_data)?;
    fs::write(file_path, contents)?;
    Ok(())
}

fn main() -> Result<(), NcError> {
    env_logger::init();

    let mut client = NextcloudClient::new();

    let mut login_required = true;
    if let Some(auth) = load_auth_data("auth_data.json") {
        match client.login_from_auth_data(&auth) {
            Ok(()) => login_required = false,
            Err(e) => {
                error!("Failed to log in with saved credentials: {}", e);
                fs::remove_file("auth_data.json")?;
            }
        }
    }

    if login_required {
        println!("Enter your Nextcloud server URL:");
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let server_url = input.trim();

        let auth_data = client.login(server_url)?;
        save_auth_data("auth_data.json", &auth_data)?;
    }

    info!("Successfully logged in");

    Ok(())
}
