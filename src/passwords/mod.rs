pub mod password;
pub mod session;
use crate::client::NextcloudClient;
use crate::errors::NcError;
use crate::passwords::password::Password;
use crate::passwords::session::Session;
use secrecy::SecretString;

#[derive(Debug)]
pub struct PasswordInfo {
    pub id: String,
    pub label: String,
    pub username: String,
    pub url: String,
}

use std::fmt::{self, Display, Formatter};
impl Display for PasswordInfo {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let url = if self.url.is_empty() {
            String::new()
        } else {
            format!(" @ {}", self.url.clone())
        };
        write!(f, "[{}] {} ({}{})", self.id, self.label, self.username, url)
    }
}

pub struct Passwords {
    session: Session,
    cache: Vec<Password>,
}

impl Passwords {
    pub fn new(client: &NextcloudClient) -> Passwords {
        let session = Session::new(client);

        Passwords {
            session,
            cache: Vec::new(),
        }
    }

    pub async fn open(&mut self, master_password: SecretString) -> Result<(), NcError> {
        self.session.open(master_password).await?;
        self.cache = self
            .session
            .get_passwords()
            .await?
            .iter()
            .map(|o| Password::new(self.session.clone(), o.clone()))
            .collect();
        Ok(())
    }

    pub async fn session_close(&mut self) {
        self.session.close().await;
    }

    pub async fn get_passwords(&self) -> Result<Vec<&Password>, NcError> {
        Ok(self.cache.iter().collect())
    }

    pub async fn get_password(&self, id: &str) -> Result<&Password, NcError> {
        self.cache
            .iter()
            .find(|p| p.id() == id)
            .ok_or_else(|| NcError::PasswordNotFound(id.to_string()))
    }
}
