mod common;
use common::{AppConfig, authenticate, secure_println};
use nextcloud_rs::ocs_client::NextcloudOCSClient;
use secrecy::{ExposeSecret, SecretString};
use std::io::Write;

use log::error;
use nextcloud_rs::errors::NcError;
use nextcloud_rs::passwords::Passwords;
use rpassword::read_password;

#[tokio::main]
async fn main() -> Result<(), NcError> {
    env_logger::init();

    let home_dir = dirs::home_dir().ok_or(NcError::MissingHomeDir)?;
    let conf_path = home_dir.join(".nextcloud-rs/");
    let config: AppConfig = confy::load(
        conf_path.to_str().ok_or(NcError::ConfigToStrError())?,
        "config",
    )?;

    let mut client = NextcloudOCSClient::new(&config.url);
    authenticate(&mut client).await?;

    let mut passwords = Passwords::new(&client);

    loop {
        print!("Please enter your Nextcloud Passwords app master password: ");
        std::io::stdout().flush().unwrap();
        let input = SecretString::new(
            read_password()
                .map_err(|e| NcError::Generic(format!("Password input error: {}", e)))?
                .into(),
        );

        if input.expose_secret().is_empty() {
            error!("Password cannot be empty.");
            continue;
        }

        match passwords.open(input).await {
            Ok(mp) => break mp,
            Err(NcError::UnexpectedResponse { status: 401, .. }) => {
                error!("Invalid password, please try again.");
                continue;
            }

            Err(NcError::UnexpectedResponse { status: 403, .. }) => {
                error!("Too many failed attempts, app password have been revoked.");
                return Ok(());
            }
            Err(e) => return Err(e),
        }
    }

    println!("Passowrd session opened successfully.");

    let passwords = passwords.get_passwords().await?;
    for password in passwords {
        secure_println(&password.password()?)?;
    }

    Ok(())
}
