use crate::endpoint::{Endpoint, EndpointInfo};
use crate::errors::NcError;
use crate::passwords::fields::{ClearField, EncryptedField, EncryptedJson};
use crate::passwords::session::Session;
use reqwest::Method;
use serde::{Deserialize, Serialize};
// macro json!
use serde_json::json;

#[derive(Clone, Serialize, Deserialize, Debug)]
enum CustomFieldType {
    #[serde(rename = "text")]
    Text, // Generic text value
    #[serde(rename = "secret")]
    Secret, // A secret value which should be treated like a password
    #[serde(rename = "email")]
    Email, // An email address
    #[serde(rename = "url")]
    Url, // A valid full url. Any protocol is allowed
    #[serde(rename = "file")]
    File, // The path to a file accessible over WebDav. The base url of the WebDav service is defined in the setting server.baseUrl.webdav
    #[serde(rename = "data")]
    Data, // A field with technical information. Should not be displayed to the user
}

#[allow(dead_code)]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct CustomField {
    label: String,
    #[serde(rename = "type")]
    type_: CustomFieldType,
    value: String,
}

impl EncryptedJson for Option<Vec<CustomField>> {}

#[derive(Serialize, Deserialize, Debug)]
enum SecurityStatus {
    #[serde(rename = "0")]
    Good,
    #[serde(rename = "1")]
    Duplicate,
    #[serde(rename = "2")]
    Breached,
    #[serde(rename = "3")]
    NotChecked,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum StatusCode {
    #[serde(rename = "GOOD")]
    Good,
    #[serde(rename = "DUPLICATE")]
    Duplicate,
    #[serde(rename = "BREACHED")]
    Breached,
    #[serde(rename = "NOT_CHECKED")]
    NotChecked,
}

#[derive(Clone, Deserialize)]
pub struct Password {
    id: ClearField<String>,
    pub label: EncryptedField<String>,
    pub username: EncryptedField<String>,
    pub password: EncryptedField<String>,
    pub url: EncryptedField<String>,
    pub notes: EncryptedField<String>,
    #[serde(rename = "customFields")]
    pub custom_fields: EncryptedField<Option<Vec<CustomField>>>,
    pub status: ClearField<u32>,
    #[serde(rename = "statusCode")]
    pub status_code: ClearField<StatusCode>,
    pub hash: ClearField<String>,
    pub folder: ClearField<String>,
    pub revision: ClearField<String>,
    pub share: ClearField<Option<String>>,
    pub shared: ClearField<bool>,
    #[serde(rename = "cseType")]
    pub cse_type: ClearField<String>,
    #[serde(rename = "cseKey")]
    pub cse_key: ClearField<String>,
    #[serde(rename = "sseType")]
    pub sse_type: ClearField<Option<String>>,
    pub client: ClearField<String>,
    pub hidden: ClearField<bool>,
    pub trashed: ClearField<bool>,
    pub editable: ClearField<bool>,
    pub edited: ClearField<u64>,
    pub created: ClearField<u64>,
    pub updated: ClearField<u64>,
    #[serde(skip)]
    pub dirty: bool,
    #[serde(skip)]
    pub session: Option<Session>,
}

impl Password {
    pub fn id(&self) -> String {
        self.id.value.clone()
    }
    pub fn set_dirty(&mut self, dirty: bool) {
        self.dirty = dirty;
    }

    pub fn serialize_encrypted(&self) -> Result<String, NcError> {
        Ok(json!({
            "id": &self.id.value,

            "label": self.label.get_encrypted_data(),
            "username": self.username.get_encrypted_data(),
            "password": self.password.get_encrypted_data(),
            "url": self.url.get_encrypted_data(),
            "notes": self.notes.get_encrypted_data(),
            "customFields": self.custom_fields.get_encrypted_data(),
            "status": serde_json::to_string(&self.status.value).unwrap(),
            "statusCode": &self.status_code.value,
            "hash": &self.hash.value,
            "folder": &self.folder.value,
            "revision": &self.revision.value,
            "share": serde_json::to_string(&self.share.value).unwrap(),
            "shared": serde_json::to_string(&self.shared.value).unwrap(),
            "cseType": self.cse_type.value,
            "cseKey": self.cse_key.value,
            "client": self.client.value,
            "hidden": serde_json::to_string(&self.hidden.value).unwrap(),
            "trashed": serde_json::to_string(&self.trashed.value).unwrap(),
            "editable": serde_json::to_string(&self.editable.value).unwrap(),
            "edited": serde_json::to_string(&self.edited.value).unwrap(),
            "created": serde_json::to_string(&self.created.value).unwrap(),
            "updated": serde_json::to_string(&self.updated.value).unwrap()
        })
        .to_string())
    }
}

impl EndpointInfo for Vec<Password> {
    fn get_info() -> Endpoint {
        Endpoint {
            path: "index.php/apps/passwords/api/1.0/password/list".into(),
            require_auth: true,
            method: Method::POST,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UpdatePassword {
    id: String,
    revision: String,
}

impl EndpointInfo for UpdatePassword {
    fn get_info() -> Endpoint {
        Endpoint {
            path: "index.php/apps/passwords/api/1.0/password/update".into(),
            require_auth: true,
            method: Method::PATCH,
        }
    }
}
