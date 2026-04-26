use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

const PROFILE_PREFIX: &str = "heel";
const PROFILE_MAX_LEN: usize = 64;
const PROFILE_HASH_HEX_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProfileName(String);

impl ProfileName {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) fn profile_name(app_id: &str, seed: &str) -> Result<ProfileName> {
    let app_slug = slug(app_id)?;
    let mut hasher = Sha256::new();
    hasher.update(app_id.as_bytes());
    hasher.update([0]);
    hasher.update(seed.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    let suffix = &hash[..PROFILE_HASH_HEX_LEN];
    let candidate = format!("{PROFILE_PREFIX}.{app_slug}.{suffix}");

    if candidate.len() <= PROFILE_MAX_LEN {
        Ok(ProfileName(candidate))
    } else {
        let reserved = PROFILE_PREFIX.len() + 1 + 1 + suffix.len();
        let max_slug = PROFILE_MAX_LEN.saturating_sub(reserved);
        Ok(ProfileName(format!(
            "{PROFILE_PREFIX}.{}.{suffix}",
            app_slug.chars().take(max_slug).collect::<String>()
        )))
    }
}

fn slug(input: &str) -> Result<String> {
    let mut out = String::new();
    let mut last_dash = false;

    for ch in input.chars().flat_map(char::to_lowercase) {
        let keep = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        if keep {
            out.push(ch);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }

    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        return Err(Error::ConfigError(
            "AppContainer profile app id cannot be empty after sanitization".to_string(),
        ));
    }

    Ok(trimmed)
}

#[cfg(target_os = "windows")]
pub(crate) struct AppContainerProfile {
    sid: windows::Win32::Security::PSID,
}

#[cfg(target_os = "windows")]
impl AppContainerProfile {
    pub(crate) fn create_or_open(name: ProfileName) -> Result<Self> {
        use windows::Win32::Security::Isolation::{
            CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
        };
        use windows::core::HSTRING;

        let profile_name = HSTRING::from(name.as_str());
        let display_name = HSTRING::from(name.as_str());
        let description = HSTRING::from("Heel sandbox profile");

        let sid = unsafe {
            match CreateAppContainerProfile(&profile_name, &display_name, &description, None) {
                Ok(sid) => sid,
                Err(error) if is_already_exists(&error) => {
                    DeriveAppContainerSidFromAppContainerName(&profile_name).map_err(|error| {
                        Error::FfiError(format!(
                            "DeriveAppContainerSidFromAppContainerName failed for '{}': {error}",
                            name.as_str()
                        ))
                    })?
                }
                Err(error) => {
                    return Err(Error::FfiError(format!(
                        "CreateAppContainerProfile failed for '{}': {error}",
                        name.as_str()
                    )));
                }
            }
        };

        if sid.is_invalid() {
            return Err(Error::FfiError(format!(
                "AppContainer SID for '{}' was null",
                name.as_str()
            )));
        }

        Ok(Self { sid })
    }

    pub(crate) fn sid(&self) -> windows::Win32::Security::PSID {
        self.sid
    }
}

#[cfg(target_os = "windows")]
impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        if !self.sid.is_invalid() {
            unsafe {
                windows::Win32::Security::FreeSid(self.sid);
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn is_already_exists(error: &windows::core::Error) -> bool {
    use windows::Win32::Foundation::ERROR_ALREADY_EXISTS;

    let code = error.code().0 as u32;
    code == hresult_from_win32(ERROR_ALREADY_EXISTS.0)
}

#[cfg(target_os = "windows")]
fn hresult_from_win32(error: u32) -> u32 {
    if error == 0 {
        error
    } else {
        (error & 0x0000_FFFF) | 0x8007_0000
    }
}

#[cfg(test)]
mod tests {
    use super::{PROFILE_HASH_HEX_LEN, PROFILE_MAX_LEN, profile_name};

    #[test]
    fn profile_name_is_stable_and_sanitized() {
        let first = profile_name("Heel Test App", "abc/DEF:123").expect("profile name");
        let second = profile_name("Heel Test App", "abc/DEF:123").expect("profile name");

        assert_eq!(first, second);
        assert!(first.as_str().starts_with("heel.heel-test-app."));
        assert!(first.as_str().len() <= 64);
        assert!(
            first
                .as_str()
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '.')
        );
    }

    #[test]
    fn profile_name_uses_128_bit_hash_suffix() {
        let name = profile_name("Heel Test App", "abc/DEF:123").expect("profile name");
        let suffix = name.as_str().rsplit('.').next().expect("suffix");

        assert_eq!(suffix.len(), PROFILE_HASH_HEX_LEN);
        assert!(suffix.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn profile_name_changes_with_seed() {
        let first = profile_name("Heel Test App", "seed-a").expect("profile name");
        let second = profile_name("Heel Test App", "seed-b").expect("profile name");

        assert_ne!(first, second);
    }

    #[test]
    fn profile_name_truncates_long_app_id_to_limit() {
        let name = profile_name(
            "Heel Test App With A Very Long Application Identifier",
            "seed",
        )
        .expect("profile name");

        assert_eq!(name.as_str().len(), PROFILE_MAX_LEN);
        assert!(name.as_str().starts_with("heel."));
        assert!(name.as_str().rsplit('.').next().expect("suffix").len() == PROFILE_HASH_HEX_LEN);
    }

    #[test]
    fn profile_name_rejects_empty_slug() {
        let err = profile_name("   ", "seed").expect_err("empty app id should be rejected");

        assert!(
            err.to_string()
                .contains("AppContainer profile app id cannot be empty")
        );
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::{AppContainerProfile, hresult_from_win32, profile_name};
    use windows::Win32::Foundation::ERROR_ALREADY_EXISTS;

    #[test]
    fn hresult_from_win32_maps_already_exists() {
        assert_eq!(hresult_from_win32(ERROR_ALREADY_EXISTS.0), 0x8007_00B7);
    }

    #[test]
    #[ignore = "creates local AppContainer profile state"]
    fn appcontainer_profile_create_or_open_returns_sid() {
        let name = profile_name("heel-test", "profile-create-or-open").expect("name");
        let name_text = name.as_str().to_string();
        let profile = AppContainerProfile::create_or_open(name).expect("profile");

        assert!(!profile.sid().is_invalid());
        assert!(name_text.starts_with("heel."));
    }
}
