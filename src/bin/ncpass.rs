mod common;
use clap::{Arg, Command, arg};
use common::{AppConfig, authenticate, println_secret};
use log::error;
use rpassword::read_password;
use secrecy::{ExposeSecret, SecretString};
use std::io::Write;

use nextcloud_rs::client::NextcloudClient;
use nextcloud_rs::errors::NcError;
use nextcloud_rs::passwords::Passwords;
// FIXME: can do better than this (prelude?)
use nextcloud_rs::passwords::password::Password;

fn cli() -> Command {
    let get_fields = ["label", "username", "password", "url", "notes"];
    let get_args = get_fields.iter().map(|&name| {
        Arg::new(name)
            .long(name)
            .required(false)
            .action(clap::ArgAction::SetTrue)
    });

    Command::new("passwords")
        .about("A password management tool for Nextcloud Passwords")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(Command::new("list").about("List all passwords"))
        .subcommand(
            Command::new("find")
                .about("Find passwords by keyword")
                .arg(arg!(<KEYWORD> "the keyword to search for"))
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("get")
                .about("Get a password")
                .arg(arg!(<ID> "the id of the password"))
                .arg_required_else_help(true)
                .args(get_args),
        )
}

fn load_config() -> Result<AppConfig, NcError> {
    let home_dir = dirs::home_dir().ok_or(NcError::MissingHomeDir)?;
    let conf_path = home_dir.join(".nextcloud-rs/");
    let config: AppConfig = confy::load(
        conf_path.to_str().ok_or(NcError::ConfigToStrError())?,
        "config",
    )?;
    Ok(config)
}

async fn get_passwords(client: &mut NextcloudClient) -> Result<Passwords, NcError> {
    let mut passwords = Passwords::new(client);

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

            Err(e @ NcError::UnexpectedResponse { status: 403, .. }) => {
                error!("Too many failed attempts, app password have been revoked.");
                return Err(e);
            }
            Err(e) => return Err(e),
        }
    }

    Ok(passwords)
}

async fn print_password_info(password: &Password) -> Result<(), NcError> {
    println!(
        "[{}] {} from {} ({})",
        password.id(),
        password.label()?.expose_secret(),
        password.url()?.expose_secret(),
        password.username()?.expose_secret()
    );

    Ok(())
}

fn is_configured() -> bool {
    let home_dir = dirs::home_dir().ok_or(NcError::MissingHomeDir).unwrap();
    let conf_dir = home_dir.join(".nextcloud-rs/");
    let config_path = conf_dir.join("config.toml");
    config_path.exists()
}

fn check_config() -> Result<(), NcError> {
    if !is_configured() {
        return Err(NcError::Generic(
            "Configuration not found. Please run `passwords configure` first.".to_string(),
        ));
    }
    Ok(())
}

async fn prerequisits() -> Result<(Passwords, AppConfig), NcError> {
    check_config()?;
    let config = load_config()?;
    let mut client = NextcloudClient::new(&config.url);
    authenticate(&mut client).await?;
    let passwords = get_passwords(&mut client).await?;
    Ok((passwords, config))
}

async fn list_passwords() -> Result<(), NcError> {
    let (passwords, _) = prerequisits().await?;
    for password in passwords.get_passwords().await? {
        print_password_info(password).await?;
    }
    Ok(())
}

async fn find_passwords(keyword: &str) -> Result<(), NcError> {
    let (passwords, _) = prerequisits().await?;

    for password in passwords.get_passwords().await? {
        let is_match = password.label()?.expose_secret().contains(keyword)
            || password.url()?.expose_secret().contains(keyword)
            || password.username()?.expose_secret().contains(keyword);
        if is_match {
            print_password_info(password).await?;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), NcError> {
    env_logger::init();
    let matches = cli().get_matches();
    match matches.subcommand() {
        Some(("", _)) => unreachable!(),
        Some(("list", _)) => list_passwords().await?,
        Some(("find", sub_matches)) => {
            let keyword = sub_matches.get_one::<String>("KEYWORD").unwrap();
            find_passwords(keyword).await?
        }
        Some(("get", sub_matches)) => {
            let id = sub_matches.get_one::<String>("ID").unwrap();
            let possible_fields = ["label", "username", "password", "url", "notes"];
            let fields: Vec<_> = possible_fields
                .iter()
                .filter(|&&field| sub_matches.get_flag(field))
                .collect();

            let (passwords, _) = prerequisits().await?;
            let password = passwords.get_password(id).await?;

            if !fields.is_empty() {
                for field in fields {
                    match *field {
                        "label" => println!("{}", password.label()?.expose_secret()),
                        "username" => println!("{}", password.username()?.expose_secret()),
                        "password" => println_secret(&password.password()?)?,
                        "url" => println!("{}", password.url()?.expose_secret()),
                        "notes" => println!("{}", password.notes()?.expose_secret()),
                        _ => unreachable!(),
                    };
                }
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}
