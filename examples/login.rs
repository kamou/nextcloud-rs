use nextcloud_rs::client::{AuthData, NextcloudClient};

use nextcloud_rs::errors::NcError;

use std::io::Write;
use std::{fs, io};

use log::{error, info};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio;

#[derive(Debug, Serialize, Deserialize)]
struct AppConfig {
    url: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        loop {
            print!("Enter your Nextcloud server URL: ");
            io::stdout().flush().unwrap();

            let mut input = String::new();
            io::stdin().read_line(&mut input).ok();

            let url = input.trim();
            if url.is_empty() {
                continue;
            }

            if url::Url::parse(url).is_ok() {
                return Self {
                    url: url.to_string(),
                };
            }

            println!("Invalid URL.");
        }
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

#[tokio::main]
async fn main() -> Result<(), NcError> {
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
        match client.login_from_auth_data(&auth).await {
            Ok(()) => login_required = false,
            Err(e) => {
                error!("Failed to log in with saved credentials: {}", e);
                fs::remove_file("auth_data.json")?;
            }
        }
    }

    if login_required {
        let login_url = client.login().await?;

        if webbrowser::open(&login_url).is_err() {
            info!("Open the following URL in your browser to login:");
            info!("{}", login_url);
        }

        client
            .wait_for_authentication(Duration::from_secs(30))
            .await?;

        let auth_data = client.get_auth_data().await;

        if auth_data.is_some() {
            println!("Logged in successfully.");
            save_auth_data("auth_data.json", &auth_data.unwrap())?;
        }
    } else {
        let auth_data = client
            .wait_for_authentication(Duration::from_secs(30))
            .await;

        if auth_data.is_ok() {
            println!("Already logged in.");
        }
    }

    Ok(())
}
