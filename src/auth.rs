use sha2::{Digest, Sha256, Sha512};

#[derive(Clone)]
pub struct CurrentUser {
    pub name: String,
}

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

#[derive(Debug, Clone)]
/// HTTP Basic authentication parameters
pub struct BasicAuthParams {
    pub username: String,
    pub password: String,
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

    let password = if let Some(hash_src) = split.next() {
        // If a hash method is provided, accept either:
        // - Full hex digest (sha256: 64 hex chars; sha512: 128 hex chars)
        // - Otherwise, treat the provided string as plaintext and hash it
        // - If the string contains non-hex chars when a hash is specified, return error
        match sencond_part {
            "sha256" => {
                let is_hex = hash_src.chars().all(|c| c.is_ascii_hexdigit());
                if is_hex && hash_src.len() == 64 {
                    let hash_bin = hex::decode(hash_src).map_err(|_| E::InvalidPasswordHash)?;
                    RequiredPassword::Sha256(hash_bin)
                } else if is_hex {
                    RequiredPassword::Sha256(get_hash::<Sha256>(hash_src))
                } else {
                    return Err(E::InvalidPasswordHash);
                }
            }
            "sha512" => {
                let is_hex = hash_src.chars().all(|c| c.is_ascii_hexdigit());
                if is_hex && hash_src.len() == 128 {
                    let hash_bin = hex::decode(hash_src).map_err(|_| E::InvalidPasswordHash)?;
                    RequiredPassword::Sha512(hash_bin)
                } else if is_hex {
                    RequiredPassword::Sha512(get_hash::<Sha512>(hash_src))
                } else {
                    return Err(E::InvalidPasswordHash);
                }
            }
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

/// Get hash of a `text`
fn get_hash<T: Digest>(text: &str) -> Vec<u8> {
    let mut hasher = T::new();
    hasher.update(text);
    hasher.finalize().to_vec()
}

/// Return `true` if hashing of `password` by `T` algorithm equals to `hash`
fn compare_hash<T: Digest>(password: &str, hash: &[u8]) -> bool {
    get_hash::<T>(password) == hash
}

/// Return `true` if `basic_auth_pwd` meets `required_auth_pwd`'s requirement
pub fn compare_password(basic_auth_pwd: &str, required_auth_pwd: &RequiredPassword) -> bool {
    match &required_auth_pwd {
        RequiredPassword::Plain(required_password) => *basic_auth_pwd == *required_password,
        RequiredPassword::Sha256(password_hash) => {
            compare_hash::<Sha256>(basic_auth_pwd, password_hash)
        }
        RequiredPassword::Sha512(password_hash) => {
            compare_hash::<Sha512>(basic_auth_pwd, password_hash)
        }
    }
}

/// Return `true` if `basic_auth` is matches any of `required_auth`
pub fn match_auth(basic_auth: &BasicAuthParams, required_auth: &[RequiredAuth]) -> bool {
    required_auth
        .iter()
        .any(|RequiredAuth { username, password }| {
            basic_auth.username == *username && compare_password(&basic_auth.password, password)
        })
}

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use super::*;
    use RequiredPassword::*;
    use rstest::{rstest, fixture};
    use pretty_assertions::assert_eq;

    /// Helper function that creates a `RequireAuth` structure
    fn create_required_auth(username: &str, password: &str, encrypt: &str) -> RequiredAuth {
        let password = match encrypt {
          "plain" => Plain(password.to_owned()),
          "sha256" => Sha256(get_hash::<sha2::Sha256>(password)),
          "sha512" => Sha512(get_hash::<sha2::Sha512>(password)),
          _ => panic!("Unknown encryption type"),
        };

        RequiredAuth { username: username.to_owned(), password }
    }

    #[rstest(
        auth_string, username, password, encrypt,
        case("username:password", "username", "password", "plain"),
        case("username:sha256:abcd", "username", "abcd", "sha256"),
        case("username:sha512:abcd", "username", "abcd", "sha512"),
    )]
    fn parse_auth_valid(auth_string: &str, username: &str, password: &str, encrypt: &str) {
        assert_eq!(
            parse_auth(auth_string).unwrap(),
            create_required_auth(username, password, encrypt)
        );
    }

    #[rstest(
        auth_string, err_msg,
        case("foo", "Invalid format for credentials string. Expected username:password, username:sha256:hash or username:sha512:hash"),
        case("username:blahblah:abcd", "blahblah is not a valid hashing method. Expected sha256 or sha512"),
        case("username:sha256:invalid", "Invalid format for password hash. Expected hex code"),
        case("username:sha512:invalid", "Invalid format for password hash. Expected hex code"),
    )]
    fn parse_auth_invalid(auth_string: &str, err_msg: &str) {
        let err = parse_auth(auth_string).unwrap_err();
        assert_eq!(format!("{err}"), err_msg.to_owned());
    }

    /// Return a hashing function corresponds to given name
    fn get_hash_func(name: &str) -> impl FnOnce(&str) -> Vec<u8> {
        match name {
            "sha256" => get_hash::<sha2::Sha256>,
            "sha512" => get_hash::<sha2::Sha512>,
            _ => panic!("Invalid hash method"),
        }
    }

    #[rstest(
        password, hash_method, hash,
        case("abc", "sha256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        case("abc", "sha512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
    )]
    fn test_get_hash(password: &str, hash_method: &str, hash: &str) {
        let hash_func = get_hash_func(hash_method);
        let expected = hex::decode(hash).expect("Provided hash is not a valid hex code");
        let received = hash_func(password);
        assert_eq!(received, expected);
    }

    #[rstest(
        should_pass, param_username, param_password, required_username, required_password, encrypt,
        case(true, "obi", "hello there", "obi", "hello there", "plain"),
        case(false, "obi", "hello there", "obi", "hi!", "plain"),
        case(true, "obi", "hello there", "obi", "hello there", "sha256"),
        case(false, "obi", "hello there", "obi", "hi!", "sha256"),
        case(true, "obi", "hello there", "obi", "hello there", "sha512"),
        case(false, "obi", "hello there", "obi", "hi!", "sha512")
    )]
    fn test_single_auth(
        should_pass: bool,
        param_username: &str,
        param_password: &str,
        required_username: &str,
        required_password: &str,
        encrypt: &str,
    ) {
        assert_eq!(
          match_auth(
              &BasicAuthParams {
                  username: param_username.to_owned(),
                  password: param_password.to_owned()
              },
              &[create_required_auth(required_username, required_password, encrypt)]
          ),
          should_pass
        );
    }

    #[fixture]
    fn account_sample() -> Vec<RequiredAuth> {
        [
            ("usr0", "pwd0", "plain"),
            ("usr1", "pwd1", "plain"),
            ("usr2", "pwd2", "sha256"),
            ("usr3", "pwd3", "sha256"),
            ("usr4", "pwd4", "sha512"),
            ("usr5", "pwd5", "sha512"),
        ]
        .iter()
        .map(|(username, password, encrypt)| create_required_auth(username, password, encrypt))
        .collect()
    }

    #[rstest(
        username, password,
        case("usr0", "pwd0"),
        case("usr1", "pwd1"),
        case("usr2", "pwd2"),
        case("usr3", "pwd3"),
        case("usr4", "pwd4"),
        case("usr5", "pwd5"),
    )]
    fn test_multiple_auth_pass(
        account_sample: Vec<RequiredAuth>,
        username: &str,
        password: &str,
    ) {
        assert!(match_auth(
            &BasicAuthParams {
                username: username.to_owned(),
                password: password.to_owned()
            },
            &account_sample
        ));
    }

    #[rstest]
    fn test_multiple_auth_wrong_username(account_sample: Vec<RequiredAuth>) {
        assert_eq!(match_auth(
            &BasicAuthParams {
                username: "unregistered user".to_owned(),
                password: "pwd0".to_owned(),
            },
            &account_sample,
        ), false);
    }

    #[rstest(
        username, password,
        case("usr0", "pwd5"),
        case("usr1", "pwd4"),
        case("usr2", "pwd3"),
        case("usr3", "pwd2"),
        case("usr4", "pwd1"),
        case("usr5", "pwd0"),
    )]
    fn test_multiple_auth_wrong_password(
        account_sample: Vec<RequiredAuth>,
        username: &str,
        password: &str,
    ) {
        assert_eq!(match_auth(
            &BasicAuthParams {
                username: username.to_owned(),
                password: password.to_owned(),
            },
            &account_sample,
        ), false);
    }
}
