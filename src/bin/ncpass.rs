mod common;

use clap::{Arg, Command, arg};
use common::{AppConfig, authenticate, println_secret};
use log::error;
use rpassword::read_password;
use secrecy::{ExposeSecret, SecretString};
use std::io::Write;

use nextcloud_rs::errors::NcError;
use nextcloud_rs::ocs_client::NextcloudOCSClient;
use nextcloud_rs::passwords::fields::FieldAccess;
use nextcloud_rs::passwords::password::Password;
use nextcloud_rs::passwords::store::PasswordStore;

fn cli() -> Command {
    let get_fields = ["label", "username", "password", "url", "notes"];
    let get_args = get_fields.iter().map(|&name| {
        Arg::new(name)
            .long(name)
            .required(false)
            .action(clap::ArgAction::SetTrue)
    });

    let set_args = get_fields.iter().map(|&name| {
        let upper_name = match name {
            "label" => "LABEL",
            "username" => "USERNAME",
            "password" => "PASSWORD",
            "url" => "URL",
            "notes" => "NOTES",
            _ => unreachable!(),
        };

        Arg::new(name)
            .long(name)
            .required(false)
            .num_args(1)
            .value_name(upper_name)
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
            // get id with no option means all
            Command::new("get")
                .about("Get password details.")
                .arg(arg!(<ID> "the id of the password"))
                .arg_required_else_help(true)
                .args(get_args),
        )
        .subcommand(
            // set
            Command::new("set")
                .about("Set password details.")
                .arg(arg!(<ID> "the id of the password"))
                .arg_required_else_help(true)
                .args(set_args),
        )

    // TODO: other options might be:
    // - add
    // - edit
    // - delete
    // - import
    // - export
    // - sync
    //
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

async fn get_store<'p>(client: NextcloudOCSClient) -> Result<PasswordStore, NcError> {
    let mut store = PasswordStore::new(client);

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

        match store.open(input).await {
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

    Ok(store)
}

async fn print_password_info(password: &Password) -> Result<(), NcError> {
    println!(
        "[{}] {} from {} ({})",
        password.id(),
        password.label.get().unwrap(),
        password.url.get().unwrap(),
        password.username.get().unwrap()
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
        load_config().ok();
    }
    Ok(())
}

async fn prerequisits() -> Result<(PasswordStore, AppConfig), NcError> {
    check_config()?;
    let config = load_config()?;
    let mut client = NextcloudOCSClient::new(&config.url);
    authenticate(&mut client).await?;
    let passwords = get_store(client).await?;
    Ok((passwords, config))
}

async fn list_passwords() -> Result<(), NcError> {
    let (store, _) = prerequisits().await?;
    for password in &mut store.get_passwords().await?.iter() {
        print_password_info(password).await?;
    }
    Ok(())
}

async fn find_passwords(keyword: &str) -> Result<(), NcError> {
    let (store, _) = prerequisits().await?;

    for password in &mut store.get_passwords().await?.iter() {
        let is_match = password.label.get().unwrap().contains(keyword)
            || password.url.get().unwrap().contains(keyword)
            || password.username.get().unwrap().contains(keyword);
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

            let (store, _) = prerequisits().await?;
            let passwords = store.get_passwords().await?;
            let password = passwords
                .iter()
                .find(|p| p.id() == *id)
                .ok_or(NcError::Generic(format!(
                    "Password with id {} not found",
                    id
                )))?;

            if fields.is_empty() {
                return print_password_info(password).await;
            }

            for field in fields {
                match *field {
                    "label" => println!("{}", password.label.get().unwrap()),
                    "username" => println!("{}", password.username.get().unwrap()),
                    "password" => println!("{}", password.password.get().unwrap()), // FIXME: println will copy the password into heap
                    "url" => println!("{}", password.url.get().unwrap()),
                    "notes" => println!("{}", password.notes.get().unwrap()),
                    _ => unreachable!(),
                };
            }
        }
        Some(("set", sub_matches)) => {
            let id = sub_matches.get_one::<String>("ID").unwrap();
            let possible_fields = ["label", "username", "password", "url", "notes"];
            let fields: Vec<(&str, &String)> = possible_fields
                .iter()
                .filter_map(|field| {
                    sub_matches
                        .get_one::<String>(field)
                        .map(|value| (*field, value))
                })
                .collect();

            let (mut store, _) = prerequisits().await?;
            let passwords = store.get_passwords().await?;
            let mut password =
                passwords
                    .into_iter()
                    .find(|p| p.id() == *id)
                    .ok_or(NcError::Generic(format!(
                        "Password with id {} not found",
                        id
                    )))?;
            // arg is required
            if fields.is_empty() {
                return Err(NcError::Generic("No fields to set".to_string()));
            }

            for (field, value) in fields.iter() {
                match *field {
                    "label" => password.label.set((*value).clone()).unwrap(),
                    "password" => password.password.set((*value).clone()).unwrap(),
                    "username" => password.username.set((*value).clone()).unwrap(),
                    "url" => password.url.set((*value).clone()).unwrap(),
                    "notes" => password.notes.set((*value).clone()).unwrap(),
                    _ => unreachable!(),
                }
            }

            store.update(&mut password).await?;
        }
        _ => unreachable!(),
    }
    Ok(())
}
