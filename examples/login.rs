mod common;
use common::{AppConfig, authenticate};
use nextcloud_rs::client::NextcloudClient;

use nextcloud_rs::errors::NcError;

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
    println!("successfully authenticated");

    Ok(())
}
