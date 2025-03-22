use nextcloud_rs::client::{AuthData, NextcloudClient};

use nextcloud_rs::errors::NcError;

use std::{fs, io};

use log::{error, info};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct AppConfig {
    url: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        println!("Enter your Nextcloud server URL:");
        let mut input = String::new();
        io::stdin().read_line(&mut input).ok(); // meh, can theoretically fail
        let url = input.trim();

        Self { url: url.into() }
    }
}

fn load_auth_data(path: &str) -> Option<AuthData> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
}

fn save_auth_data(file_path: &str, auth_data: &AuthData) -> Result<(), NcError> {
    let contents = serde_json::to_string_pretty(auth_data)?;
    fs::write(file_path, contents)?;
    Ok(())
}

fn main() -> Result<(), NcError> {
    env_logger::init();

    let home_dir = dirs::home_dir().ok_or(NcError::MissingHomeDir)?;
    let conf_path = home_dir.join(".nextcloud-rs/");
    let config: AppConfig = confy::load(
        conf_path.to_str().ok_or(NcError::ConfigToStrError())?,
        "config",
    )?;

    let mut client = NextcloudClient::new(&config.url);

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
        let auth_data = client.login()?;
        save_auth_data("auth_data.json", &auth_data)?;
    }

    info!("Successfully logged in");

    Ok(())
}
