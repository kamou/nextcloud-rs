use crate::errors::NcError;
use crate::passwords::session::Session;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

pub trait EncryptedJson {}
#[derive(Clone, Serialize)]
pub struct EncryptedField<T> {
    encrypted_data: String,
    #[serde(skip)]
    session: Option<Session>,
    _phantom: std::marker::PhantomData<T>,
}

impl<'de, T> serde::Deserialize<'de> for EncryptedField<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encrypted_data = String::deserialize(deserializer)?;
        Ok(EncryptedField {
            encrypted_data,
            session: None,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<T> EncryptedField<T>
where
    T: for<'de> serde::Deserialize<'de> + serde::Serialize + EncryptedJson,
{
    pub fn inject_session(&mut self, session: Session) {
        self.session = Some(session);
    }

    pub fn get(&self) -> Result<T, NcError> {
        let session = self.session.as_ref().unwrap();
        let decrypted_json = session.decrypt(&self.encrypted_data)?; // Adjust for your real API
        let exposed_secret = decrypted_json.expose_secret();
        Ok(serde_json::from_str(exposed_secret)?) // this fails because the decrypted string is not
    }

    pub fn set(&mut self, value: T) -> Result<(), NcError> {
        let session = self.session.as_ref().unwrap();
        let json = serde_json::to_string(&value)?;
        let encrypted_data = session.encrypt(json.as_str())?;
        self.encrypted_data = encrypted_data;
        Ok(())
    }
}

impl EncryptedField<String> {
    pub fn inject_session(&mut self, session: Session) {
        self.session = Some(session);
    }
    pub fn get(&self) -> Result<String, NcError> {
        self.session
            .as_ref()
            .ok_or_else(|| NcError::SessionUnavailable)?
            .decrypt(&self.encrypted_data)
            .map(|secret| secret.expose_secret().to_string())
    }

    pub fn set(&mut self, value: String) -> Result<(), NcError> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| NcError::SessionUnavailable)?;
        let encrypted_data = session.encrypt(value.as_str())?;
        self.encrypted_data = encrypted_data;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClearField<T>(pub T);
impl<T> ClearField<T> {
    pub fn get(&self) -> &T {
        &self.0
    }

    pub fn set(&mut self, value: T) {
        self.0 = value;
    }
}
