use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{
    image::Image,
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, State,
};
use uuid::Uuid;

const MAX_FAILED_ATTEMPTS: u32 = 5;
const LOCKOUT_SECONDS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProtectedApp {
    id: String,
    name: String,
    path: String,
    protection_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Settings {
    unlock_minutes: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self { unlock_minutes: 15 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    schema_version: u32,
    password_hash: Option<String>,
    apps: Vec<ProtectedApp>,
    settings: Settings,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 1,
            password_hash: None,
            apps: Vec::new(),
            settings: Settings::default(),
        }
    }
}

#[derive(Debug, Default)]
struct RuntimeSecurity {
    failed_attempts: u32,
    locked_until: Option<u64>,
    grants: HashMap<String, u64>,
}

struct AppState {
    config_path: PathBuf,
    config: Mutex<Config>,
    runtime: Mutex<RuntimeSecurity>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppView {
    id: String,
    name: String,
    path: String,
    protection_enabled: bool,
    exists: bool,
    granted_until: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    initialized: bool,
    apps: Vec<AppView>,
    settings: Settings,
    lockout_remaining_seconds: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LaunchResponse {
    status: String,
    message: String,
    attempts_remaining: u32,
    lockout_remaining_seconds: u64,
    granted_until: Option<u64>,
}

enum VerifyOutcome {
    Accepted,
    Rejected { attempts_remaining: u32 },
    Locked { seconds_remaining: u64 },
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| format!("비밀번호를 안전하게 처리하지 못했습니다: {error}"))
}

fn password_matches(password: &str, encoded_hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(encoded_hash) else {
        return false;
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

fn validate_new_password(password: &str) -> Result<(), String> {
    if password.chars().count() < 8 {
        return Err("마스터 비밀번호는 8자 이상이어야 합니다.".into());
    }
    if password.chars().count() > 128 {
        return Err("마스터 비밀번호는 128자 이하여야 합니다.".into());
    }
    Ok(())
}

fn load_config(path: &Path) -> Config {
    fs::read_to_string(path)
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
        .unwrap_or_default()
}

fn save_config(path: &Path, config: &Config) -> Result<(), String> {
    let contents = serde_json::to_string_pretty(config)
        .map_err(|error| format!("설정을 직렬화하지 못했습니다: {error}"))?;
    fs::write(path, contents).map_err(|error| format!("설정을 저장하지 못했습니다: {error}"))
}

fn verify_with_rate_limit(
    runtime: &mut RuntimeSecurity,
    password: &str,
    encoded_hash: &str,
) -> VerifyOutcome {
    let now = now_seconds();
    if let Some(locked_until) = runtime.locked_until {
        if locked_until > now {
            return VerifyOutcome::Locked {
                seconds_remaining: locked_until - now,
            };
        }
        runtime.locked_until = None;
        runtime.failed_attempts = 0;
    }

    if password_matches(password, encoded_hash) {
        runtime.failed_attempts = 0;
        runtime.locked_until = None;
        return VerifyOutcome::Accepted;
    }

    runtime.failed_attempts += 1;
    if runtime.failed_attempts >= MAX_FAILED_ATTEMPTS {
        runtime.failed_attempts = 0;
        runtime.locked_until = Some(now + LOCKOUT_SECONDS);
        VerifyOutcome::Locked {
            seconds_remaining: LOCKOUT_SECONDS,
        }
    } else {
        VerifyOutcome::Rejected {
            attempts_remaining: MAX_FAILED_ATTEMPTS - runtime.failed_attempts,
        }
    }
}

fn current_snapshot(state: &AppState) -> Result<Snapshot, String> {
    let config = state
        .config
        .lock()
        .map_err(|_| "설정 잠금이 손상되었습니다.".to_string())?;
    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "보안 상태 잠금이 손상되었습니다.".to_string())?;
    let now = now_seconds();

    runtime.grants.retain(|_, expires_at| *expires_at > now);
    let lockout_remaining_seconds = runtime
        .locked_until
        .map(|until| until.saturating_sub(now))
        .unwrap_or(0);

    let apps = config
        .apps
        .iter()
        .map(|app| AppView {
            id: app.id.clone(),
            name: app.name.clone(),
            path: app.path.clone(),
            protection_enabled: app.protection_enabled,
            exists: Path::new(&app.path).is_file(),
            granted_until: runtime.grants.get(&app.id).copied(),
        })
        .collect();

    Ok(Snapshot {
        initialized: config.password_hash.is_some(),
        apps,
        settings: config.settings.clone(),
        lockout_remaining_seconds,
    })
}

#[tauri::command]
fn get_snapshot(state: State<'_, AppState>) -> Result<Snapshot, String> {
    current_snapshot(state.inner())
}

#[tauri::command]
fn set_master_password(password: String, state: State<'_, AppState>) -> Result<Snapshot, String> {
    validate_new_password(&password)?;
    let encoded_hash = hash_password(&password)?;

    {
        let mut config = state
            .config
            .lock()
            .map_err(|_| "설정 잠금이 손상되었습니다.".to_string())?;
        if config.password_hash.is_some() {
            return Err("마스터 비밀번호가 이미 설정되어 있습니다.".into());
        }
        config.password_hash = Some(encoded_hash);
        save_config(&state.config_path, &config)?;
    }

    current_snapshot(state.inner())
}

#[tauri::command]
fn change_master_password(
    current_password: String,
    new_password: String,
    state: State<'_, AppState>,
) -> Result<Snapshot, String> {
    validate_new_password(&new_password)?;

    {
        let config = state
            .config
            .lock()
            .map_err(|_| "설정 잠금이 손상되었습니다.".to_string())?;
        let Some(encoded_hash) = config.password_hash.as_deref() else {
            return Err("먼저 마스터 비밀번호를 설정해 주세요.".into());
        };
        if !password_matches(&current_password, encoded_hash) {
            return Err("현재 비밀번호가 올바르지 않습니다.".into());
        }
    }

    let new_hash = hash_password(&new_password)?;
    {
        let mut config = state
            .config
            .lock()
            .map_err(|_| "설정 잠금이 손상되었습니다.".to_string())?;
        config.password_hash = Some(new_hash);
        save_config(&state.config_path, &config)?;
    }
    state
        .runtime
        .lock()
        .map_err(|_| "보안 상태 잠금이 손상되었습니다.".to_string())?
        .grants
        .clear();

    current_snapshot(state.inner())
}

#[tauri::command]
fn add_application(state: State<'_, AppState>) -> Result<Option<Snapshot>, String> {
    let mut dialog = rfd::FileDialog::new().set_title("보호할 응용 프로그램 선택");
    #[cfg(target_os = "windows")]
    {
        dialog = dialog.add_filter("Windows 응용 프로그램", &["exe"]);
    }

    let Some(selected_path) = dialog.pick_file() else {
        return Ok(None);
    };
    let canonical_path = selected_path
        .canonicalize()
        .map_err(|error| format!("선택한 파일을 확인하지 못했습니다: {error}"))?;

    if !canonical_path.is_file() {
        return Err("실행 가능한 파일을 선택해 주세요.".into());
    }
    #[cfg(target_os = "windows")]
    if canonical_path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| !extension.eq_ignore_ascii_case("exe"))
        .unwrap_or(true)
    {
        return Err("Windows 실행 파일(.exe)만 추가할 수 있습니다.".into());
    }

    let path_string = canonical_path.to_string_lossy().to_string();
    let name = canonical_path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("응용 프로그램")
        .to_string();

    {
        let mut config = state
            .config
            .lock()
            .map_err(|_| "설정 잠금이 손상되었습니다.".to_string())?;
        if config
            .apps
            .iter()
            .any(|app| app.path.eq_ignore_ascii_case(&path_string))
        {
            return Err("이미 목록에 있는 응용 프로그램입니다.".into());
        }
        config.apps.push(ProtectedApp {
            id: Uuid::new_v4().to_string(),
            name,
            path: path_string,
            protection_enabled: true,
        });
        save_config(&state.config_path, &config)?;
    }

    current_snapshot(state.inner()).map(Some)
}

#[tauri::command]
fn remove_application(id: String, state: State<'_, AppState>) -> Result<Snapshot, String> {
    {
        let mut config = state
            .config
            .lock()
            .map_err(|_| "설정 잠금이 손상되었습니다.".to_string())?;
        config.apps.retain(|app| app.id != id);
        save_config(&state.config_path, &config)?;
    }
    state
        .runtime
        .lock()
        .map_err(|_| "보안 상태 잠금이 손상되었습니다.".to_string())?
        .grants
        .remove(&id);
    current_snapshot(state.inner())
}

#[tauri::command]
fn set_protection_enabled(
    id: String,
    enabled: bool,
    state: State<'_, AppState>,
) -> Result<Snapshot, String> {
    {
        let mut config = state
            .config
            .lock()
            .map_err(|_| "설정 잠금이 손상되었습니다.".to_string())?;
        let app = config
            .apps
            .iter_mut()
            .find(|app| app.id == id)
            .ok_or_else(|| "응용 프로그램을 찾을 수 없습니다.".to_string())?;
        app.protection_enabled = enabled;
        save_config(&state.config_path, &config)?;
    }
    if !enabled {
        state
            .runtime
            .lock()
            .map_err(|_| "보안 상태 잠금이 손상되었습니다.".to_string())?
            .grants
            .remove(&id);
    }
    current_snapshot(state.inner())
}

#[tauri::command]
fn update_unlock_minutes(minutes: u32, state: State<'_, AppState>) -> Result<Snapshot, String> {
    if ![1, 5, 15, 30, 60].contains(&minutes) {
        return Err("지원하지 않는 잠금 해제 시간입니다.".into());
    }
    {
        let mut config = state
            .config
            .lock()
            .map_err(|_| "설정 잠금이 손상되었습니다.".to_string())?;
        config.settings.unlock_minutes = minutes;
        save_config(&state.config_path, &config)?;
    }
    current_snapshot(state.inner())
}

#[tauri::command]
fn lock_all(state: State<'_, AppState>) -> Result<Snapshot, String> {
    state
        .runtime
        .lock()
        .map_err(|_| "보안 상태 잠금이 손상되었습니다.".to_string())?
        .grants
        .clear();
    current_snapshot(state.inner())
}

#[tauri::command]
fn launch_application(
    id: String,
    password: Option<String>,
    state: State<'_, AppState>,
) -> Result<LaunchResponse, String> {
    let (app, encoded_hash, unlock_minutes) = {
        let config = state
            .config
            .lock()
            .map_err(|_| "설정 잠금이 손상되었습니다.".to_string())?;
        let app = config
            .apps
            .iter()
            .find(|app| app.id == id)
            .cloned()
            .ok_or_else(|| "응용 프로그램을 찾을 수 없습니다.".to_string())?;
        (
            app,
            config.password_hash.clone(),
            config.settings.unlock_minutes,
        )
    };

    let now = now_seconds();
    let mut granted_until = None;
    if app.protection_enabled {
        let existing_grant = state
            .runtime
            .lock()
            .map_err(|_| "보안 상태 잠금이 손상되었습니다.".to_string())?
            .grants
            .get(&id)
            .copied()
            .filter(|expires_at| *expires_at > now);

        if let Some(expires_at) = existing_grant {
            granted_until = Some(expires_at);
        } else {
            let Some(password) = password else {
                return Ok(LaunchResponse {
                    status: "needsPassword".into(),
                    message: "마스터 비밀번호를 입력해 주세요.".into(),
                    attempts_remaining: MAX_FAILED_ATTEMPTS,
                    lockout_remaining_seconds: 0,
                    granted_until: None,
                });
            };
            let Some(encoded_hash) = encoded_hash else {
                return Err("마스터 비밀번호가 설정되지 않았습니다.".into());
            };

            let outcome = {
                let mut runtime = state
                    .runtime
                    .lock()
                    .map_err(|_| "보안 상태 잠금이 손상되었습니다.".to_string())?;
                verify_with_rate_limit(&mut runtime, &password, &encoded_hash)
            };

            match outcome {
                VerifyOutcome::Accepted => {
                    let expires_at = now + u64::from(unlock_minutes) * 60;
                    state
                        .runtime
                        .lock()
                        .map_err(|_| "보안 상태 잠금이 손상되었습니다.".to_string())?
                        .grants
                        .insert(id.clone(), expires_at);
                    granted_until = Some(expires_at);
                }
                VerifyOutcome::Rejected { attempts_remaining } => {
                    return Ok(LaunchResponse {
                        status: "invalidPassword".into(),
                        message: format!(
                            "비밀번호가 올바르지 않습니다. {attempts_remaining}회 남았습니다."
                        ),
                        attempts_remaining,
                        lockout_remaining_seconds: 0,
                        granted_until: None,
                    });
                }
                VerifyOutcome::Locked { seconds_remaining } => {
                    return Ok(LaunchResponse {
                        status: "cooldown".into(),
                        message: format!(
                            "잠시 후 다시 시도해 주세요. {seconds_remaining}초 남았습니다."
                        ),
                        attempts_remaining: 0,
                        lockout_remaining_seconds: seconds_remaining,
                        granted_until: None,
                    });
                }
            }
        }
    }

    let path = PathBuf::from(&app.path);
    if !path.is_file() {
        return Ok(LaunchResponse {
            status: "missing".into(),
            message: "실행 파일을 찾을 수 없습니다. 앱을 다시 추가해 주세요.".into(),
            attempts_remaining: MAX_FAILED_ATTEMPTS,
            lockout_remaining_seconds: 0,
            granted_until,
        });
    }

    let mut command = Command::new(&path);
    if let Some(parent) = path.parent() {
        command.current_dir(parent);
    }
    command
        .spawn()
        .map_err(|error| format!("응용 프로그램을 실행하지 못했습니다: {error}"))?;

    Ok(LaunchResponse {
        status: "launched".into(),
        message: format!("{}을(를) 실행했습니다.", app.name),
        attempts_remaining: MAX_FAILED_ATTEMPTS,
        lockout_remaining_seconds: 0,
        granted_until,
    })
}

fn make_tray_icon() -> Image<'static> {
    const SIZE: usize = 32;
    let mut rgba = vec![0_u8; SIZE * SIZE * 4];
    for y in 0..SIZE {
        for x in 0..SIZE {
            let index = (y * SIZE + x) * 4;
            let dx = x as i32 - 16;
            let dy = y as i32 - 16;
            let inside = dx * dx + dy * dy <= 14 * 14;
            if inside {
                rgba[index] = 90;
                rgba[index + 1] = 103;
                rgba[index + 2] = 246;
                rgba[index + 3] = 255;
            }
            let shackle =
                (10..=21).contains(&x) && (7..=17).contains(&y) && (x <= 12 || x >= 19 || y <= 10);
            let lock_body = (9..=22).contains(&x) && (14..=24).contains(&y);
            if inside && (shackle || lock_body) {
                rgba[index] = 248;
                rgba[index + 1] = 250;
                rgba[index + 2] = 252;
                rgba[index + 3] = 255;
            }
            let keyhole = (15..=16).contains(&x) && (18..=22).contains(&y);
            if keyhole {
                rgba[index] = 32;
                rgba[index + 1] = 38;
                rgba[index + 2] = 58;
                rgba[index + 3] = 255;
            }
        }
    }
    Image::new_owned(rgba, SIZE as u32, SIZE as u32)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .map_err(|error| format!("앱 데이터 폴더를 확인하지 못했습니다: {error}"))?;
            fs::create_dir_all(&data_dir)?;
            let config_path = data_dir.join("config.json");
            let config = load_config(&config_path);
            app.manage(AppState {
                config_path,
                config: Mutex::new(config),
                runtime: Mutex::new(RuntimeSecurity::default()),
            });

            TrayIconBuilder::new()
                .icon(make_tray_icon())
                .tooltip("App Password")
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        if let Some(window) = tray.app_handle().get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            set_master_password,
            change_master_password,
            add_application,
            remove_application,
            set_protection_enabled,
            update_unlock_minutes,
            lock_all,
            launch_application
        ])
        .run(tauri::generate_context!())
        .expect("App Password를 실행하지 못했습니다.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_round_trip() {
        let password = "correct horse battery staple";
        let encoded = hash_password(password).expect("hash should be created");
        assert!(password_matches(password, &encoded));
        assert!(!password_matches("wrong password", &encoded));
        assert!(!encoded.contains(password));
    }

    #[test]
    fn rejects_short_passwords() {
        assert!(validate_new_password("1234567").is_err());
        assert!(validate_new_password("12345678").is_ok());
    }

    #[test]
    fn rate_limit_activates_after_five_failures() {
        let encoded = hash_password("abcdefgh").expect("hash should be created");
        let mut runtime = RuntimeSecurity::default();

        for remaining in (1..MAX_FAILED_ATTEMPTS).rev() {
            match verify_with_rate_limit(&mut runtime, "incorrect", &encoded) {
                VerifyOutcome::Rejected { attempts_remaining } => {
                    assert_eq!(attempts_remaining, remaining)
                }
                _ => panic!("expected a rejected password"),
            }
        }
        assert!(matches!(
            verify_with_rate_limit(&mut runtime, "incorrect", &encoded),
            VerifyOutcome::Locked { .. }
        ));
    }
}
