use keyring::{Entry, Error as KeyringError};
use nextcloud_rs::client::{AuthData, NextcloudClient};

use dialoguer::Password;
use nextcloud_rs::errors::NcError;
use nextcloud_rs::passwords::Passwords;

use std::io::Write;
use std::{fs, io};

use log::{error, info};
use serde::{Deserialize, Serialize};
use std::time::Duration;

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

async fn authenticate(client: &mut NextcloudClient) -> Result<(), NcError> {
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
        } else {
            println!("Check your browser to login.");
        }
    }

    client
        .wait_for_authentication(Duration::from_secs(60))
        .await?;

    let auth_data = client.get_auth_data().await.unwrap();
    save_auth_data("auth_data.json", &auth_data)?;
    Ok(())
}

async fn get_master_password(username: &str) -> Result<String, NcError> {
    let service = "nextcloud_passwords";
    let entry = Entry::new(service, username).map_err(|e| NcError::Generic(e.to_string()))?;

    match entry.get_password() {
        Ok(password) => Ok(password),
        Err(KeyringError::NoEntry) => {
            let password = Password::new()
                .with_prompt("Enter your Nextcloud Passwords app master password")
                .interact()
                .map_err(|e| NcError::Generic(format!("Password input error: {}", e)))?;

            entry
                .set_password(&password)
                .map_err(|e| NcError::Generic(format!("Failed to save password: {}", e)))?;

            Ok(password)
        }
        Err(e) => Err(NcError::Generic(format!("Keyring error: {}", e))),
    }
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
    authenticate(&mut client).await?;

    let mut passwords_session = Passwords::new(&client);
    let auth_data = client.get_auth_data().await.unwrap();

    let username = auth_data.get_login_name();
    let master_password = get_master_password(username).await?;

    passwords_session.session_open(master_password).await?;
    println!("Passowrd session opened successfully.");
    Ok(())
}
