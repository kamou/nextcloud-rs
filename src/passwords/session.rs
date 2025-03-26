use crate::client::NextcloudClient;
use crate::endpoint::{Endpoint, EndpointInfo};
use crate::errors::NcError;
use reqwest::Method;
use reqwest::header::{HeaderMap, HeaderName};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::generichash;
use sodiumoxide::crypto::pwhash::argon2id13;
use sodiumoxide::crypto::secretbox;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
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
#[derive(Deserialize, Debug)]
struct CustomField {
    label: SecretString,
    #[serde(rename = "type")]
    type_: CustomFieldType,
    value: SecretString,
}

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

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct PasswordObject {
    id: String,
    label: SecretString,
    username: SecretString,
    password: SecretString,
    url: SecretString,
    notes: SecretString,
    #[serde(rename = "customFields")]
    custom_fields: Option<Vec<CustomField>>,
    status: u32,
    #[serde(rename = "statusCode")]
    status_code: StatusCode,
    hash: String,
    folder: String,
    revision: String,
    share: Option<String>,
    shared: bool,
    #[serde(rename = "cseType")]
    cse_type: String,
    #[serde(rename = "sseType")]
    sse_type: String,
    client: String,
    hidden: bool,
    trashed: bool,
    editable: bool,
    edited: u64,
    created: u64,
    updated: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedPasswordObject {
    pub id: String,
    pub label: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    #[serde(rename = "customFields")]
    pub custom_fields: String,
    pub status: u32,
    #[serde(rename = "statusCode")]
    pub status_code: StatusCode,
    pub hash: String,
    pub folder: String,
    pub revision: String,
    pub share: Option<String>,
    pub shared: bool,
    #[serde(rename = "cseType")]
    pub cse_type: String,
    #[serde(rename = "sseType")]
    pub sse_type: String,
    pub client: String,
    pub hidden: bool,
    pub trashed: bool,
    pub editable: bool,
    pub edited: u64,
    pub created: u64,
    pub updated: u64,
}

impl EndpointInfo for EncryptedPasswordObject {
    fn get_info() -> Endpoint {
        Endpoint {
            path: "index.php/apps/passwords/api/1.0/password/show".into(),
            require_auth: true,
            method: Method::POST,
        }
    }
}

impl EndpointInfo for Vec<EncryptedPasswordObject> {
    fn get_info() -> Endpoint {
        Endpoint {
            path: "index.php/apps/passwords/api/1.0/password/list".into(),
            require_auth: true,
            method: Method::POST,
        }
    }
}

#[derive(Debug)]
pub enum EncryptedField {
    Label,
    Username,
    Password,
    Url,
    Notes,
    CustomFields,
}

#[derive(Deserialize, Debug)]
pub struct KeyChain {
    keys: HashMap<String, SecretString>,
    current: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionRequest {
    pub challenge: Option<Challenge>,
    pub token: Option<Vec<Token>>,
}

impl EndpointInfo for SessionRequest {
    fn get_info() -> Endpoint {
        Endpoint {
            path: "index.php/apps/passwords/api/1.0/session/request".into(),
            require_auth: true,
            method: Method::GET,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub challenge_type: String,
    pub salts: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Token {
    pub id: String,
    pub name: String,
}

#[derive(Deserialize, Debug)]
pub struct SessionOpen {
    pub success: bool,
    #[serde(default)]
    pub keys: Option<HashMap<String, SecretString>>,
}

impl EndpointInfo for SessionOpen {
    fn get_info() -> Endpoint {
        Endpoint {
            path: "index.php/apps/passwords/api/1.0/session/open".into(),
            require_auth: true,
            method: Method::POST,
        }
    }
}

fn solve_pwdv1_challenge(
    master_password: &SecretString,
    challenge: &[String],
) -> Result<SecretString, NcError> {
    if challenge.len() != 3 {
        return Err(NcError::Generic("Invalid challenge length".into()));
    }

    let password_salt = hex::decode(&challenge[0])?;
    let generic_hash_key = hex::decode(&challenge[1])?;
    let password_hash_salt = hex::decode(&challenge[2])?;

    if password_salt.len() != 256 {
        return Err(NcError::Generic("Invalid password salt length".into()));
    }

    if generic_hash_key.len() != generichash::KEY_MAX {
        return Err(NcError::Generic("Invalid generic hash key length".into()));
    }

    if password_hash_salt.len() != argon2id13::SALTBYTES {
        return Err(NcError::Generic("Invalid password hash salt length".into()));
    }

    let mut combined = SecretBox::new(Box::new(Vec::with_capacity(
        master_password.expose_secret().len() + password_salt.len(),
    )));
    combined
        .expose_secret_mut()
        .extend_from_slice(master_password.expose_secret().as_bytes());
    combined
        .expose_secret_mut()
        .extend_from_slice(password_salt.as_slice());

    let generic_hash = generichash::hash(
        combined.expose_secret(),
        Some(generichash::DIGEST_MAX),
        Some(generic_hash_key.as_slice()),
    )
    .map_err(|_| NcError::Generic("Generic hash failed".into()))?;

    let argon_salt = argon2id13::Salt::from_slice(password_hash_salt.as_slice())
        .ok_or_else(|| NcError::Generic("Invalid password hash salt".into()))?;

    let mut derived_key = SecretBox::new(Box::new([0u8; secretbox::KEYBYTES]));

    argon2id13::derive_key(
        derived_key.expose_secret_mut(),
        generic_hash.as_ref(),
        &argon_salt,
        argon2id13::OPSLIMIT_INTERACTIVE,
        argon2id13::MEMLIMIT_INTERACTIVE,
    )
    .map_err(|_| NcError::Generic("Argon2id key derivation failed".into()))?;

    Ok(SecretString::new(
        hex::encode(derived_key.expose_secret()).into(),
    ))
}

fn decrypt_keychain(master_password: &SecretString, keychain: &[u8]) -> Result<KeyChain, NcError> {
    let salt = &keychain[0..argon2id13::SALTBYTES];
    let payload = &keychain[argon2id13::SALTBYTES..];
    let mut derived_key = SecretBox::new(Box::new([0u8; secretbox::KEYBYTES]));

    let argon_salt = argon2id13::Salt::from_slice(salt).ok_or_else(|| {
        NcError::Generic("Failed to create argon2id salt from keychain salt".into())
    })?;

    argon2id13::derive_key(
        derived_key.expose_secret_mut(),
        master_password.expose_secret().as_bytes(),
        &argon_salt,
        argon2id13::OPSLIMIT_INTERACTIVE,
        argon2id13::MEMLIMIT_INTERACTIVE,
    )
    .map_err(|_| NcError::Generic("Failed to derive key".into()))?;

    let nonce = secretbox::Nonce::from_slice(&payload[0..secretbox::NONCEBYTES])
        .ok_or_else(|| NcError::Generic("Failed to create nonce from keychain payload".into()))?;
    let cipher_text = &payload[secretbox::NONCEBYTES..];
    let key = secretbox::Key::from_slice(derived_key.expose_secret_mut().as_ref())
        .ok_or_else(|| NcError::Generic("Failed to create key from derived key".into()))?;
    let decrypted_json_bytes =
        secretbox::open(cipher_text, &nonce, &key).expect("Failed to decrypt cipher text");
    let keychain_json_text =
        SecretString::new(String::from_utf8(decrypted_json_bytes)?.into_boxed_str());

    let keychain_json: KeyChain = serde_json::from_str(keychain_json_text.expose_secret())?;

    Ok(keychain_json)
}

fn decrypt_field(encrypted_str: &String, key: &secretbox::Key) -> Result<SecretString, NcError> {
    let encrypted_bytes = hex::decode(encrypted_str)?;
    if encrypted_bytes.is_empty() {
        return Ok("".into());
    }

    let nonce_bytes = &encrypted_bytes[0..secretbox::NONCEBYTES];
    let cipher_bytes = &encrypted_bytes[secretbox::NONCEBYTES..];

    let nonce =
        secretbox::Nonce::from_slice(nonce_bytes).ok_or(NcError::Generic("Nonce error".into()))?;
    let clear_bytes = secretbox::open(cipher_bytes, &nonce, key)
        .map_err(|_| NcError::Generic("Decryption error".into()))?;
    let secret_str =
        String::from_utf8(clear_bytes).map_err(|_| NcError::Generic("UTF-8 error".into()))?;
    Ok(SecretString::new(secret_str.into()))
}

#[derive(Clone)]
pub struct Session {
    client: NextcloudClient,
    enc_keychain: Option<HashMap<String, SecretString>>,
    master_password: Option<SecretString>,
}

impl Session {
    pub fn new(client: &NextcloudClient) -> Session {
        Session {
            client: client.clone(),
            enc_keychain: None,
            master_password: None,
        }
    }

    pub async fn session_open(&mut self, master_password: SecretString) -> Result<(), NcError> {
        self.master_password = Some(master_password);

        let challenge_data: SessionRequest = self.client.request(None).await?;
        match challenge_data {
            SessionRequest{challenge: Some(_), token: _} => Ok(()),
            SessionRequest{challenge: None, token: Some(_)} => Err(NcError::Generic("2FA not supported yet".into())),
            SessionRequest{challenge: None, token: None} => Err(NcError::Generic( "No Master Password is set, get your shit together and please set a master password. Clear password store is not and will neer be supported.".into())),

        }?;

        let challenge_response = solve_pwdv1_challenge(
            self.master_password.as_ref().unwrap(),
            &challenge_data.challenge.unwrap().salts,
        )?;

        let (session, headers): (SessionOpen, HeaderMap) = self
            .client
            .request_with_headers(Some(HashMap::from([(
                "challenge",
                challenge_response.expose_secret(),
            )])))
            .await?;

        if !session.success {
            return Err(NcError::Generic(
                "Unknown error while opening session".into(),
            ));
        }

        self.enc_keychain = session.keys;
        drop(challenge_response);

        let api_session = headers
            .get("X-API-SESSION")
            .ok_or(NcError::MissingField("X-API-SESSION header".into()))?
            .to_str()?
            .to_owned();

        self.client
            .add_header("X-API-SESSION".parse::<HeaderName>()?, api_session)
            .await?;

        Ok(())
    }

    pub async fn session_close(&mut self) {
        self.enc_keychain = None;
        self.master_password = None;
    }

    pub async fn get_encrypted_pobjects(
        &mut self,
    ) -> Result<Vec<EncryptedPasswordObject>, NcError> {
        self.client.request(None).await
    }

    pub fn decrypt_pobject_field(
        &self,
        object: &EncryptedPasswordObject,
        field: EncryptedField,
    ) -> Result<SecretString, NcError> {
        let cse_type = &object.cse_type;
        let hex_keychain = self
            .enc_keychain
            .as_ref()
            .unwrap()
            .get(cse_type)
            .unwrap()
            .expose_secret();

        let keychain_bytes = hex::decode(hex_keychain)?;
        let keychain = decrypt_keychain(
            self.master_password.as_ref().unwrap(),
            keychain_bytes.as_slice(),
        )?;
        drop(keychain_bytes);

        let key_id = keychain.current;
        let key_str = keychain
            .keys
            .get(&key_id)
            .ok_or_else(|| NcError::Generic("Current key ID not found in keychain".into()))?;

        let key = secretbox::Key::from_slice(hex::decode(key_str.expose_secret())?.as_slice())
            .ok_or_else(|| NcError::Generic("Invalid secret key format".into()))?;

        match field {
            EncryptedField::Label => decrypt_field(&object.label, &key),
            EncryptedField::Username => decrypt_field(&object.username, &key),
            EncryptedField::Password => decrypt_field(&object.password, &key),
            EncryptedField::Url => decrypt_field(&object.url, &key),
            EncryptedField::Notes => decrypt_field(&object.notes, &key),
            EncryptedField::CustomFields => {
                if !object.custom_fields.is_empty() {
                    let json_str = decrypt_field(&object.custom_fields, &key)?;
                    Ok(serde_json::from_str(json_str.expose_secret())?)
                } else {
                    Ok(SecretString::default())
                }
            }
        }
    }
}
