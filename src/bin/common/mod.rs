use libc::{STDOUT_FILENO, write};
use log::{error, info};
use nextcloud_rs::client::AuthData;
use nextcloud_rs::client::NextcloudClient;
use nextcloud_rs::errors::NcError;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::time::Duration;
use std::{fs, io};

#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub url: String,
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

pub async fn authenticate(client: &mut NextcloudClient) -> Result<(), NcError> {
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

pub fn load_auth_data(filename: &str) -> Option<AuthData> {
    let home_dir = dirs::home_dir().ok_or(NcError::MissingHomeDir).unwrap();
    let conf_dir = home_dir.join(".nextcloud-rs/");
    let auth_data_path = conf_dir.join(filename);

    std::fs::read_to_string(auth_data_path)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
}

pub fn save_auth_data(filename: &str, auth_data: &AuthData) -> Result<(), NcError> {
    let home_dir = dirs::home_dir().ok_or(NcError::MissingHomeDir).unwrap();
    let conf_dir = home_dir.join(".nextcloud-rs/");
    let auth_data_path = conf_dir.join(filename);

    let contents = serde_json::to_string_pretty(auth_data)?;
    fs::write(auth_data_path, contents)?;
    Ok(())
}

pub fn print(s: &str) -> std::io::Result<()> {
    let bytes = s.as_bytes();
    unsafe {
        let ret = write(STDOUT_FILENO, bytes.as_ptr() as *const _, bytes.len());
        if ret == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

pub fn println(s: &str) -> std::io::Result<()> {
    unsafe {
        print(s)?;
        let ret = write(STDOUT_FILENO, b"\n".as_ptr() as *const _, 1);
        if ret == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
// does not copy the password to the heap
#[allow(dead_code)]
pub fn print_secret(secret: &SecretString) -> std::io::Result<()> {
    print(secret.expose_secret())
}
#[allow(dead_code)]
pub fn println_secret(secret: &SecretString) -> std::io::Result<()> {
    println(secret.expose_secret())
}
