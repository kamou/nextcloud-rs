use crate::client::NextcloudClient;
use crate::errors::NcError;
use crate::passwords::password::{Password, UpdatePassword};
use crate::passwords::session::Session;
use secrecy::SecretString;
use std::collections::HashMap;

pub struct PasswordStore {
    session: Session,
    cache: Vec<Password>,
}

impl PasswordStore {
    pub fn new(client: NextcloudClient) -> Self {
        PasswordStore {
            session: Session::new(client),
            cache: Vec::new(),
        }
    }

    pub async fn open(&mut self, master_password: SecretString) -> Result<(), NcError> {
        self.session.open(master_password).await?;
        self.update_cache().await?;
        for password in self.cache.iter_mut() {
            password.label.inject_session(self.session.clone());
            password.username.inject_session(self.session.clone());
            password.password.inject_session(self.session.clone());
            password.url.inject_session(self.session.clone());
            password.notes.inject_session(self.session.clone());
            password.custom_fields.inject_session(self.session.clone());
        }

        Ok(())
    }

    pub async fn get_passwords(&self) -> Result<Vec<Password>, NcError> {
        Ok(self.cache.clone())
    }

    pub async fn update_cache(&mut self) -> Result<(), NcError> {
        self.cache = self.session.request(None).await?;
        Ok(())
    }

    pub async fn update(&mut self, password: &mut Password) -> Result<(), NcError> {
        password.label.inject_session(self.session.clone());
        let encrypted_json = password.serialize_encrypted()?;
        let ej_to_hm: HashMap<&str, &str> = serde_json::from_str(&encrypted_json)?;
        let _: UpdatePassword = self.session.request(Some(ej_to_hm)).await?;
        Ok(())
    }
}
