#[derive(Debug, Clone, PartialEq, Eq)]
/// `password` field of `RequiredAuth`
pub enum RequiredPassword {
    Plain(String),
    Sha256(Vec<u8>),
    Sha512(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Authentication structure to match `BasicAuthParams` against
pub struct RequiredAuth {
    pub username: String,
    pub password: RequiredPassword,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum AuthParseError {
    /// Might occur if the HTTP credential string does not respect the expected format
    #[error(
        "Invalid format for credentials string. Expected username:password, username:sha256:hash or username:sha512:hash"
    )]
    InvalidAuthFormat,
    /// Might occur if the hash method is neither sha256 nor sha512
    #[error("{0} is not a valid hashing method. Expected sha256 or sha512")]
    InvalidHashMethod(String),
    /// Might occur if the HTTP auth hash password is not a valid hex code
    #[error("Invalid format for password hash. Expected hex code")]
    InvalidPasswordHash,
    /// Might occur if the HTTP auth password exceeds 255 characters
    #[error("HTTP password length exceeds 255 characters")]
    PassowrdTooLong,
}

pub fn parse_auth(src: &str) -> Result<RequiredAuth, AuthParseError> {
    use AuthParseError as E;

    let mut split = src.splitn(3, ':');
    let invalid_auth_fotmat = Err(E::InvalidAuthFormat);

    let username = match split.next() {
        Some(username) => username,
        None => return invalid_auth_fotmat,
    };

    // second_part is either password in username:password or method in username:method:hash
    let sencond_part = match split.next() {
        Some(password) => password,
        None => return invalid_auth_fotmat,
    };

    let password = if let Some(hash_hex) = split.next() {
        let hash_bin = hex::decode(hash_hex).map_err(|_| E::InvalidPasswordHash)?;

        match sencond_part {
            "sha256" => RequiredPassword::Sha256(hash_bin),
            "sha512" => RequiredPassword::Sha512(hash_bin),
            _ => return Err(E::InvalidHashMethod(sencond_part.to_owned())),
        }
    } else {
        // To make it Windows-compatible, the password needs to be shorter than 255 characters.
        // After 255 characters, Windows will truncate the value.
        // As for the username, the spec does not mention a limit in length
        if sencond_part.len() > 255 {
            return Err(E::PassowrdTooLong);
        }

        RequiredPassword::Plain(sencond_part.to_owned())
    };

    Ok(RequiredAuth {
        username: username.to_owned(),
        password,
    })
}
