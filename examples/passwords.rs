mod common;
use common::{AppConfig, authenticate};
use keyring::{Entry, Error as KeyringError};
use nextcloud_rs::client::NextcloudClient;

use dialoguer::Password;
use nextcloud_rs::errors::NcError;
use nextcloud_rs::passwords::Passwords;

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
