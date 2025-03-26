use crate::errors::NcError;
use crate::passwords::session::{EncryptedField, EncryptedPasswordObject, Session, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;

pub struct Password {
    session: Session,
    encrypted: EncryptedPasswordObject,
}

impl Password {
    pub fn new(session: Session, encrypted: EncryptedPasswordObject) -> Password {
        Password { session, encrypted }
    }

    pub fn id(&self) -> String {
        self.encrypted.id.clone()
    }

    pub fn label(&self) -> Result<SecretString, NcError> {
        self.session
            .decrypt_field(&self.encrypted, EncryptedField::Label)
    }

    pub fn username(&self) -> Result<SecretString, NcError> {
        self.session
            .decrypt_field(&self.encrypted, EncryptedField::Username)
    }

    pub fn password(&self) -> Result<SecretString, NcError> {
        self.session
            .decrypt_field(&self.encrypted, EncryptedField::Password)
    }

    pub fn url(&self) -> Result<SecretString, NcError> {
        self.session
            .decrypt_field(&self.encrypted, EncryptedField::Url)
    }

    pub fn notes(&self) -> Result<SecretString, NcError> {
        self.session
            .decrypt_field(&self.encrypted, EncryptedField::Notes)
    }

    pub fn custom_fields(&self) -> Result<HashMap<String, SecretString>, NcError> {
        let json_str = self
            .session
            .decrypt_field(&self.encrypted, EncryptedField::CustomFields)?;
        Ok(serde_json::from_str(json_str.expose_secret())?)
    }

    pub fn status(&self) -> u32 {
        self.encrypted.status
    }

    pub fn status_code(&self) -> StatusCode {
        self.encrypted.status_code.clone()
    }

    pub fn hash(&self) -> String {
        self.encrypted.hash.clone()
    }

    pub fn folder(&self) -> String {
        self.encrypted.folder.clone()
    }

    pub fn revision(&self) -> String {
        self.encrypted.revision.clone()
    }

    pub fn share(&self) -> Option<String> {
        self.encrypted.share.clone()
    }

    pub fn shared(&self) -> bool {
        self.encrypted.shared
    }

    pub fn cse_type(&self) -> String {
        self.encrypted.cse_type.clone()
    }

    pub fn sse_type(&self) -> String {
        self.encrypted.sse_type.clone()
    }

    pub fn client(&self) -> String {
        self.encrypted.client.clone()
    }

    pub fn hidden(&self) -> bool {
        self.encrypted.hidden
    }

    pub fn trashed(&self) -> bool {
        self.encrypted.trashed
    }

    pub fn editable(&self) -> bool {
        self.encrypted.editable
    }

    pub fn edited(&self) -> u64 {
        self.encrypted.edited
    }

    pub fn created(&self) -> u64 {
        self.encrypted.created
    }

    pub fn updated(&self) -> u64 {
        self.encrypted.updated
    }
}
