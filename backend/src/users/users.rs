use argon2::{self, Config};
use chrono::Utc;
use rand::Rng;
use ring::digest;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::{Validate, ValidationError};

fn passhash_verify(pass: &str, hash: &str) -> bool {
    argon2::verify_encoded(&hash, pass.as_bytes()).unwrap()
}

type SqlDateTime = chrono::DateTime<Utc>;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: Uuid,
    pub first_name: String,
    pub last_name: String,
    pub username: String,
    pub email: String,
    // not return password
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub created_date: SqlDateTime,
    pub modified_date: SqlDateTime,
    pub is_admin: bool,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug, Validate)]
pub struct Login {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 16))]
    pub password: String,
}

impl Login {
    pub fn verify(&self, hash: &str) -> bool {
        passhash_verify(&self.password, hash)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UsersRequest {
    pub sort_by: String,
    pub last_record: String,
    pub ascending: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UsersResponse {
    pub users: Vec<User>,
    pub count: u64,
}

fn validate_status(status: &str) -> Result<(), ValidationError> {
    if status != "active" || status != "terminated" || status != "onLeave" {
        // the value of the username will automatically be added later
        return Err(ValidationError::new("Bad status!"));
    }

    Ok(())
}

// TODO: move into utils
pub fn passhash(pass: &str) -> String {
    let config = Config::default();
    const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;

    let mut salt = [0_u8; CREDENTIAL_LEN];
    rand::thread_rng().fill(&mut salt);
    let hash = argon2::hash_encoded(pass.as_bytes(), &salt, &config).unwrap();

    hash
}

#[derive(Serialize, Deserialize, Debug, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserRequest {
    #[validate(email)]
    pub email: String,
    pub username: String,
    #[validate(length(min = 16))]
    pub password: String,
    #[validate(length(min = 16))]
    pub confirm_password: String,
    #[validate(length(min = 2))]
    pub first_name: String,
    #[validate(length(min = 2))]
    pub last_name: String,
    pub is_admin: bool,
    pub title: String,
    pub department: String,
    pub phone_home: String,
    pub phone_mobile: String,
    pub phone_work: String,
    pub phone_other: String,
    pub phone_fax: String,
    #[validate(custom = "validate_status")]
    pub status: String,
    pub address_street: String,
    pub address_city: String,
    pub address_state: String,
    pub address_country: String,
    pub address_postalcode: String,
    pub employee_status: String,
    pub messenger_id: String,
    pub messenger_type: String,
    pub reports_to_id: String,
    pub factor_auth: bool,
    pub whatsapp: String,
    pub telegram: String,
}

#[derive(Serialize, Deserialize, Debug, Validate)]
#[serde(rename_all = "camelCase")]
pub struct EditUserRequest {
    #[validate(email)]
    pub email: String,
    pub username: String,
    #[validate(length(min = 2))]
    pub first_name: String,
    #[validate(length(min = 2))]
    pub last_name: String,
    pub is_admin: bool,
    pub title: String,
    pub department: String,
    pub phone_home: String,
    pub phone_mobile: String,
    pub phone_work: String,
    pub phone_other: String,
    pub phone_fax: String,
    #[validate(custom = "validate_status")]
    pub status: String,
    pub address_street: String,
    pub address_city: String,
    pub address_state: String,
    pub address_country: String,
    pub address_postalcode: String,
    pub employee_status: String,
    pub messenger_id: String,
    pub messenger_type: String,
    pub reports_to_id: String,
    pub factor_auth: bool,
    pub whatsapp: String,
    pub telegram: String,
}

#[derive(Serialize, Deserialize, Debug, Validate)]
pub struct EmailExistsRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Serialize, Deserialize, Debug, Validate)]
pub struct UsernameExistsRequest {
    pub username: String,
}

#[derive(Serialize, Deserialize, Debug, Validate)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    pub email: String,
    pub username: String,
    #[validate(length(min = 2))]
    pub first_name: String,
    #[validate(length(min = 2))]
    pub last_name: String,
    pub is_admin: bool,
    pub status: String,
}
