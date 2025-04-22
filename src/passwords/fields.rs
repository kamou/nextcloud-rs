use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::errors::NcError;
use crate::passwords::session::Session;

pub trait EncryptedJson {}
pub trait FieldAccess<T> {
    fn get(&self) -> Result<T, NcError>;
    fn set(&mut self, value: T) -> Result<(), NcError>;
}

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

    pub fn get_session(&self) -> Option<&Session> {
        self.session.as_ref()
    }
}

impl<T> FieldAccess<T> for EncryptedField<T>
where
    T: for<'de> serde::Deserialize<'de> + serde::Serialize + EncryptedJson,
{
    fn get(&self) -> Result<T, NcError> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| NcError::SessionUnavailable)?;
        let decrypted_json = session.decrypt(&self.encrypted_data)?;
        let exposed_secret = decrypted_json.expose_secret();
        Ok(serde_json::from_str(exposed_secret)?)
    }

    fn set(&mut self, value: T) -> Result<(), NcError> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| NcError::SessionUnavailable)?;
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
}

impl FieldAccess<String> for EncryptedField<String> {
    fn get(&self) -> Result<String, NcError> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| NcError::SessionUnavailable)?;
        let decrypted_json = session.decrypt(&self.encrypted_data)?;
        let exposed_secret = decrypted_json.expose_secret();
        Ok(exposed_secret.to_string())
    }

    fn set(&mut self, value: String) -> Result<(), NcError> {
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
impl<T> FieldAccess<T> for ClearField<T>
where
    T: for<'de> serde::Deserialize<'de> + serde::Serialize + Copy,
{
    fn get(&self) -> Result<T, NcError> {
        Ok(self.0)
    }

    fn set(&mut self, value: T) -> Result<(), NcError> {
        self.0 = value;
        Ok(())
    }
}
