use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const GUARD_DIRECTORY_NAME: &str = "AppPassword";
pub const GUARD_SERVICE_NAME: &str = "AppPasswordGuard";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardStateFile {
    pub schema_version: u32,
    pub password_hash: Option<String>,
    pub apps: Vec<GuardApplication>,
    pub grants: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardApplication {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardEvent {
    pub name: String,
    pub path: String,
    pub created_at: u64,
}

pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn normalized_path_key(path: &str) -> String {
    path.trim()
        .trim_matches('"')
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

pub fn guard_data_dir() -> Option<PathBuf> {
    env::var_os("PROGRAMDATA").map(|root| PathBuf::from(root).join(GUARD_DIRECTORY_NAME))
}

pub fn guard_state_path() -> Option<PathBuf> {
    guard_data_dir().map(|directory| directory.join("guard-state.json"))
}

pub fn guard_events_dir() -> Option<PathBuf> {
    guard_data_dir().map(|directory| directory.join("events"))
}

pub fn guard_heartbeat_path() -> Option<PathBuf> {
    guard_data_dir().map(|directory| directory.join("heartbeat"))
}

pub fn load_guard_state(path: &Path) -> GuardStateFile {
    try_load_guard_state(path).unwrap_or_default()
}

pub fn try_load_guard_state(path: &Path) -> Option<GuardStateFile> {
    fs::read_to_string(path)
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
}

pub fn save_guard_state(path: &Path, state: &GuardStateFile) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("보호 서비스 데이터 폴더를 만들지 못했습니다: {error}"))?;
    }
    let contents = serde_json::to_vec(state)
        .map_err(|error| format!("보호 서비스 설정을 직렬화하지 못했습니다: {error}"))?;
    fs::write(path, contents)
        .map_err(|error| format!("보호 서비스 설정을 저장하지 못했습니다: {error}"))
}

pub fn guard_is_active() -> bool {
    let Some(path) = guard_heartbeat_path() else {
        return false;
    };
    fs::read_to_string(path)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .is_some_and(|heartbeat| now_seconds().saturating_sub(heartbeat) <= 3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_keys_are_case_and_separator_insensitive() {
        assert_eq!(
            normalized_path_key(r#""C:/Program Files/Test/App.exe""#),
            normalized_path_key(r"c:\Program Files\Test\App.exe\")
        );
    }
}
