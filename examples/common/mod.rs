use libc::{STDOUT_FILENO, write};
use log::{error, info};
use nextcloud_rs::errors::NcError;
use nextcloud_rs::ocs_client::AuthData;
use nextcloud_rs::ocs_client::NextcloudOCSClient;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::time::Duration;
use std::{fs, io};

#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub url: String,
}

pub async fn authenticate(client: &mut NextcloudOCSClient) -> Result<(), NcError> {
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

pub fn load_auth_data(path: &str) -> Option<AuthData> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
}

pub fn save_auth_data(file_path: &str, auth_data: &AuthData) -> Result<(), NcError> {
    let contents = serde_json::to_string_pretty(auth_data)?;
    fs::write(file_path, contents)?;
    Ok(())
}

// does not copy the password to the heap
#[allow(dead_code)]
pub fn secure_println(secret: &SecretString) -> std::io::Result<()> {
    let password_bytes = secret.expose_secret().as_bytes();

    unsafe {
        let ret = write(
            STDOUT_FILENO,
            password_bytes.as_ptr() as *const _,
            password_bytes.len(),
        );
        if ret == -1 {
            return Err(std::io::Error::last_os_error());
        }

        // print newline
        let ret = write(STDOUT_FILENO, b"\n".as_ptr() as *const _, 1);
        if ret == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
