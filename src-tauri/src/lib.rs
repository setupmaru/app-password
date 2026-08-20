pub mod guard_shared;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::Duration,
};
use tauri::{
    image::Image,
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, LogicalSize, Manager, Size, State, WebviewWindow, WindowEvent,
};
use uuid::Uuid;

use guard_shared::{guard_events_dir, guard_is_active, normalized_path_key, now_seconds};
#[cfg(target_os = "windows")]
use guard_shared::{
    guard_state_path, save_guard_state, GuardApplication, GuardEvent, GuardStateFile,
};

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

#[derive(Debug, Default)]
struct InstalledAppCache {
    scanned_at: u64,
    apps: Vec<InstalledApplication>,
}

struct AppState {
    config_path: PathBuf,
    config: Mutex<Config>,
    runtime: Mutex<RuntimeSecurity>,
    installed_apps: Mutex<InstalledAppCache>,
    compact_auth_window: AtomicBool,
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
struct GuardAuthRequest {
    app: AppView,
    compact: bool,
}

#[derive(Debug, Clone)]
struct InstalledApplication {
    name: String,
    path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    initialized: bool,
    apps: Vec<AppView>,
    settings: Settings,
    lockout_remaining_seconds: u64,
    guard_active: bool,
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

#[cfg(target_os = "windows")]
mod installed_apps {
    use super::{normalized_path_key, InstalledApplication};
    use std::{
        env, fs,
        path::{Path, PathBuf},
    };
    use winreg::{
        enums::{
            HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
        },
        RegKey,
    };

    const UNINSTALL_KEY: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

    fn expand_environment_variables(value: &str) -> String {
        let mut expanded = value.to_string();
        let mut cursor = 0;

        while let Some(start_offset) = expanded[cursor..].find('%') {
            let start = cursor + start_offset;
            let Some(end_offset) = expanded[start + 1..].find('%') else {
                break;
            };
            let end = start + 1 + end_offset;
            let variable = &expanded[start + 1..end];
            if variable.is_empty() {
                cursor = end + 1;
                continue;
            }
            if let Ok(replacement) = env::var(variable) {
                expanded.replace_range(start..=end, &replacement);
                cursor = start + replacement.len();
            } else {
                cursor = end + 1;
            }
        }

        expanded
    }

    fn executable_from_reference(value: &str) -> Option<PathBuf> {
        let expanded = expand_environment_variables(value);
        let trimmed = expanded.trim();
        let candidate = if let Some(quoted) = trimmed.strip_prefix('"') {
            quoted.split('"').next()?
        } else {
            let lower = trimmed.to_lowercase();
            let end = lower.find(".exe")? + 4;
            &trimmed[..end]
        };
        let path = PathBuf::from(candidate.trim().trim_matches('"'));
        path.is_file().then_some(path)
    }

    fn normalized_label(value: &str) -> String {
        value
            .chars()
            .filter(|character| character.is_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect()
    }

    fn is_helper_executable(path: &Path) -> bool {
        let stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_lowercase();
        [
            "unins",
            "uninstall",
            "setup",
            "update",
            "updater",
            "installer",
            "repair",
            "crash",
            "helper",
            "service",
            "elevate",
            "maintenance",
        ]
        .iter()
        .any(|blocked| stem.contains(blocked))
    }

    fn collect_executables(
        directory: &Path,
        depth: u8,
        remaining: &mut usize,
        output: &mut Vec<PathBuf>,
    ) {
        if depth > 1 || *remaining == 0 {
            return;
        }
        let Ok(entries) = fs::read_dir(directory) else {
            return;
        };

        for entry in entries.flatten() {
            if *remaining == 0 {
                break;
            }
            *remaining -= 1;
            let path = entry.path();
            if path.is_file()
                && path
                    .extension()
                    .and_then(|value| value.to_str())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
                && !is_helper_executable(&path)
            {
                output.push(path);
            } else if path.is_dir() {
                collect_executables(&path, depth + 1, remaining, output);
            }
        }
    }

    fn executable_from_install_location(location: &str, display_name: &str) -> Option<PathBuf> {
        let expanded = expand_environment_variables(location);
        let directory = PathBuf::from(expanded.trim().trim_matches('"'));
        if !directory.is_dir() {
            return None;
        }

        let mut candidates = Vec::new();
        let mut remaining = 300;
        collect_executables(&directory, 0, &mut remaining, &mut candidates);
        let display_key = normalized_label(display_name);

        candidates.into_iter().max_by_key(|path| {
            let file_key = normalized_label(
                path.file_stem()
                    .and_then(|value| value.to_str())
                    .unwrap_or_default(),
            );
            let name_score = if file_key == display_key {
                20_000
            } else if !file_key.is_empty()
                && (display_key.contains(&file_key) || file_key.contains(&display_key))
            {
                10_000
            } else {
                0
            };
            let size_score = path
                .metadata()
                .map(|metadata| (metadata.len() / 1_000_000).min(5_000) as usize)
                .unwrap_or(0);
            name_score + size_score
        })
    }

    fn should_skip_entry(key: &RegKey, display_name: &str) -> bool {
        if key.get_value::<u32, _>("SystemComponent").unwrap_or(0) == 1
            || key.get_value::<u32, _>("NoDisplay").unwrap_or(0) == 1
        {
            return true;
        }

        let release_type = key
            .get_value::<String, _>("ReleaseType")
            .unwrap_or_default()
            .to_lowercase();
        if ["update", "hotfix", "security update"]
            .iter()
            .any(|value| release_type.contains(value))
        {
            return true;
        }

        let name = display_name.to_lowercase();
        name.starts_with("update for ")
            || name.starts_with("security update for ")
            || name.contains("webview2 runtime")
            || name.contains("visual c++") && name.contains("redistributable")
    }

    pub(super) fn discover() -> Vec<InstalledApplication> {
        let mut applications = Vec::new();
        let mut seen_paths = std::collections::HashSet::new();
        let current_executable = env::current_exe()
            .ok()
            .map(|path| normalized_path_key(&path.to_string_lossy()));

        for (root, view) in [
            (HKEY_CURRENT_USER, KEY_WOW64_64KEY),
            (HKEY_CURRENT_USER, KEY_WOW64_32KEY),
            (HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY),
            (HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY),
        ] {
            let root = RegKey::predef(root);
            let Ok(uninstall) = root.open_subkey_with_flags(UNINSTALL_KEY, KEY_READ | view) else {
                continue;
            };

            for subkey_name in uninstall.enum_keys().flatten() {
                let Ok(entry) = uninstall.open_subkey_with_flags(&subkey_name, KEY_READ) else {
                    continue;
                };
                let Ok(display_name) = entry.get_value::<String, _>("DisplayName") else {
                    continue;
                };
                let display_name = display_name.trim();
                if display_name.is_empty() || should_skip_entry(&entry, display_name) {
                    continue;
                }

                let executable = entry
                    .get_value::<String, _>("DisplayIcon")
                    .ok()
                    .and_then(|value| executable_from_reference(&value))
                    .or_else(|| {
                        entry
                            .get_value::<String, _>("InstallLocation")
                            .ok()
                            .and_then(|value| {
                                executable_from_install_location(&value, display_name)
                            })
                    });
                let Some(executable) = executable else {
                    continue;
                };
                let path = executable.to_string_lossy().to_string();
                let path_key = normalized_path_key(&path);
                if current_executable.as_ref() == Some(&path_key) || !seen_paths.insert(path_key) {
                    continue;
                }

                applications.push(InstalledApplication {
                    name: display_name.to_string(),
                    path,
                });
            }
        }

        applications.sort_by_key(|application| application.name.to_lowercase());
        applications
    }
}

#[cfg(target_os = "windows")]
fn discover_installed_applications() -> Vec<InstalledApplication> {
    installed_apps::discover()
}

#[cfg(not(target_os = "windows"))]
fn discover_installed_applications() -> Vec<InstalledApplication> {
    Vec::new()
}

fn build_app_views(
    config: &Config,
    installed: Vec<InstalledApplication>,
    runtime: &RuntimeSecurity,
) -> Vec<AppView> {
    let configured_by_path: HashMap<String, &ProtectedApp> = config
        .apps
        .iter()
        .map(|app| (normalized_path_key(&app.path), app))
        .collect();
    let mut included_config_ids = HashSet::new();
    let mut views = Vec::new();

    for application in installed {
        let path_key = normalized_path_key(&application.path);
        let configured = configured_by_path.get(&path_key).copied();
        if let Some(app) = configured {
            included_config_ids.insert(app.id.clone());
        }
        views.push(AppView {
            id: configured
                .map(|app| app.id.clone())
                .unwrap_or_else(|| format!("installed:{path_key}")),
            name: application.name,
            path: application.path,
            protection_enabled: configured
                .map(|app| app.protection_enabled)
                .unwrap_or(false),
            exists: true,
            granted_until: configured.and_then(|app| runtime.grants.get(&app.id).copied()),
        });
    }

    for app in config
        .apps
        .iter()
        .filter(|app| !included_config_ids.contains(&app.id))
    {
        views.push(AppView {
            id: app.id.clone(),
            name: app.name.clone(),
            path: app.path.clone(),
            protection_enabled: app.protection_enabled,
            exists: Path::new(&app.path).is_file(),
            granted_until: runtime.grants.get(&app.id).copied(),
        });
    }

    views.sort_by(|left, right| {
        right
            .protection_enabled
            .cmp(&left.protection_enabled)
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
    });
    views
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

#[cfg(target_os = "windows")]
fn sync_guard_state(config: &Config, runtime: &RuntimeSecurity) -> Result<(), String> {
    let Some(path) = guard_state_path() else {
        return Err("Windows 보호 서비스 데이터 경로를 확인하지 못했습니다.".into());
    };
    let now = now_seconds();
    let apps: Vec<GuardApplication> = config
        .apps
        .iter()
        .filter(|app| app.protection_enabled)
        .map(|app| GuardApplication {
            name: app.name.clone(),
            path: app.path.clone(),
        })
        .collect();
    let grants = config
        .apps
        .iter()
        .filter_map(|app| {
            runtime
                .grants
                .get(&app.id)
                .copied()
                .filter(|expires_at| *expires_at > now)
                .map(|expires_at| (normalized_path_key(&app.path), expires_at))
        })
        .collect();
    save_guard_state(
        &path,
        &GuardStateFile {
            schema_version: 1,
            password_hash: config.password_hash.clone(),
            apps,
            grants,
        },
    )
}

#[cfg(not(target_os = "windows"))]
fn sync_guard_state(_config: &Config, _runtime: &RuntimeSecurity) -> Result<(), String> {
    Ok(())
}

fn sync_guard_from_app_state(state: &AppState) -> Result<(), String> {
    let config = state
        .config
        .lock()
        .map_err(|_| "설정 잠금이 손상되었습니다.".to_string())?
        .clone();
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "보안 상태 잠금이 손상되었습니다.".to_string())?;
    sync_guard_state(&config, &runtime)
}

#[cfg(target_os = "windows")]
fn take_guard_event(state: &AppState) -> Result<Option<AppView>, String> {
    let Some(directory) = guard_events_dir() else {
        return Ok(None);
    };
    let Ok(entries) = fs::read_dir(directory) else {
        return Ok(None);
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .collect();
    paths.sort();

    for path in paths {
        let event = fs::read_to_string(&path)
            .ok()
            .and_then(|contents| serde_json::from_str::<GuardEvent>(&contents).ok());
        let _ = fs::remove_file(&path);
        let Some(event) = event else {
            continue;
        };
        let config = state
            .config
            .lock()
            .map_err(|_| "설정 잠금이 손상되었습니다.".to_string())?;
        let Some(app) = config.apps.iter().find(|app| {
            app.protection_enabled
                && normalized_path_key(&app.path) == normalized_path_key(&event.path)
        }) else {
            continue;
        };
        let granted_until = state
            .runtime
            .lock()
            .map_err(|_| "보안 상태 잠금이 손상되었습니다.".to_string())?
            .grants
            .get(&app.id)
            .copied();
        return Ok(Some(AppView {
            id: app.id.clone(),
            name: app.name.clone(),
            path: app.path.clone(),
            protection_enabled: true,
            exists: Path::new(&app.path).is_file(),
            granted_until,
        }));
    }
    Ok(None)
}

#[cfg(not(target_os = "windows"))]
fn take_guard_event(_state: &AppState) -> Result<Option<AppView>, String> {
    Ok(None)
}

fn guard_event_waiting() -> bool {
    guard_events_dir()
        .and_then(|directory| fs::read_dir(directory).ok())
        .is_some_and(|mut entries| {
            entries.any(|entry| {
                entry
                    .ok()
                    .and_then(|entry| entry.path().extension().map(|value| value == "json"))
                    .unwrap_or(false)
            })
        })
}

const DASHBOARD_WIDTH: f64 = 1040.0;
const DASHBOARD_HEIGHT: f64 = 720.0;
const DASHBOARD_MIN_WIDTH: f64 = 760.0;
const DASHBOARD_MIN_HEIGHT: f64 = 560.0;
const AUTH_WINDOW_WIDTH: f64 = 480.0;
const AUTH_WINDOW_HEIGHT: f64 = 500.0;

fn show_compact_auth_window(window: &WebviewWindow) -> Result<(), String> {
    window
        .set_min_size(None::<Size>)
        .map_err(|error| error.to_string())?;
    window
        .set_max_size(None::<Size>)
        .map_err(|error| error.to_string())?;
    window
        .set_size(LogicalSize::new(AUTH_WINDOW_WIDTH, AUTH_WINDOW_HEIGHT))
        .map_err(|error| error.to_string())?;
    window
        .set_resizable(false)
        .map_err(|error| error.to_string())?;
    window
        .set_always_on_top(true)
        .map_err(|error| error.to_string())?;
    window.center().map_err(|error| error.to_string())
}

fn restore_dashboard_window(window: &WebviewWindow) -> Result<(), String> {
    window
        .set_always_on_top(false)
        .map_err(|error| error.to_string())?;
    window
        .set_resizable(true)
        .map_err(|error| error.to_string())?;
    window
        .set_max_size(None::<Size>)
        .map_err(|error| error.to_string())?;
    window
        .set_min_size(Some(LogicalSize::new(
            DASHBOARD_MIN_WIDTH,
            DASHBOARD_MIN_HEIGHT,
        )))
        .map_err(|error| error.to_string())?;
    window
        .set_size(LogicalSize::new(DASHBOARD_WIDTH, DASHBOARD_HEIGHT))
        .map_err(|error| error.to_string())?;
    window.center().map_err(|error| error.to_string())
}

fn show_dashboard_window(app: &tauri::AppHandle) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    if !window.is_visible().unwrap_or(false) {
        let _ = restore_dashboard_window(&window);
        app.state::<AppState>()
            .compact_auth_window
            .store(false, Ordering::Release);
        let _ = window.emit("compact-auth-closed", ());
    }
    let _ = window.show();
    let _ = window.unminimize();
    let _ = window.set_focus();
}

#[cfg(target_os = "windows")]
mod windows_hello {
    use super::WebviewWindow;
    use windows::{
        core::{factory, HSTRING},
        Security::Credentials::UI::{
            UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
        },
        Win32::System::WinRT::IUserConsentVerifierInterop,
    };
    use windows_future::IAsyncOperation;

    pub(super) enum Verification {
        Verified,
        Canceled,
        Failed(String),
    }

    fn interop() -> windows::core::Result<IUserConsentVerifierInterop> {
        factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
    }

    pub(super) fn is_available() -> bool {
        if interop().is_err() {
            return false;
        }
        UserConsentVerifier::CheckAvailabilityAsync()
            .and_then(|operation| operation.get())
            .is_ok_and(|availability| availability == UserConsentVerifierAvailability::Available)
    }

    pub(super) fn verify(window: WebviewWindow, app_name: String) -> Verification {
        let result = (|| {
            let hwnd = window.hwnd().map_err(|error| error.to_string())?;
            let interop = interop().map_err(|error| error.to_string())?;
            let message = HSTRING::from(format!("{app_name} 앱을 열려면 본인 확인이 필요합니다."));
            let operation: IAsyncOperation<UserConsentVerificationResult> = unsafe {
                interop
                    .RequestVerificationForWindowAsync(hwnd, &message)
                    .map_err(|error| error.to_string())?
            };
            operation.get().map_err(|error| error.to_string())
        })();

        match result {
            Ok(UserConsentVerificationResult::Verified) => Verification::Verified,
            Ok(UserConsentVerificationResult::Canceled) => Verification::Canceled,
            Ok(UserConsentVerificationResult::DeviceBusy) => Verification::Failed(
                "Windows Hello 장치가 사용 중입니다. 잠시 후 다시 시도해 주세요.".into(),
            ),
            Ok(UserConsentVerificationResult::RetriesExhausted) => Verification::Failed(
                "Windows Hello 인증 시도 횟수를 초과했습니다. 마스터 비밀번호를 사용해 주세요."
                    .into(),
            ),
            Ok(UserConsentVerificationResult::NotConfiguredForUser) => Verification::Failed(
                "Windows Hello가 설정되어 있지 않습니다. 마스터 비밀번호를 사용해 주세요.".into(),
            ),
            Ok(UserConsentVerificationResult::DisabledByPolicy) => Verification::Failed(
                "Windows 정책에서 Hello 인증을 허용하지 않습니다. 마스터 비밀번호를 사용해 주세요."
                    .into(),
            ),
            Ok(UserConsentVerificationResult::DeviceNotPresent) => Verification::Failed(
                "Windows Hello 장치를 찾지 못했습니다. 마스터 비밀번호를 사용해 주세요.".into(),
            ),
            Ok(_) => Verification::Failed(
                "Windows Hello 인증을 완료하지 못했습니다. 마스터 비밀번호를 사용해 주세요.".into(),
            ),
            Err(error) => Verification::Failed(format!(
                "Windows Hello를 시작하지 못했습니다. 마스터 비밀번호를 사용해 주세요. ({error})"
            )),
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod windows_hello {
    use super::WebviewWindow;

    #[allow(dead_code)]
    pub(super) enum Verification {
        Verified,
        Canceled,
        Failed(String),
    }

    pub(super) fn is_available() -> bool {
        false
    }

    pub(super) fn verify(_window: WebviewWindow, _app_name: String) -> Verification {
        Verification::Failed("Windows Hello는 Windows에서만 사용할 수 있습니다.".into())
    }
}

fn current_snapshot_with_refresh(
    state: &AppState,
    force_refresh: bool,
) -> Result<Snapshot, String> {
    let config = state
        .config
        .lock()
        .map_err(|_| "설정 잠금이 손상되었습니다.".to_string())?
        .clone();
    let installed = if config.password_hash.is_some() {
        let mut cache = state
            .installed_apps
            .lock()
            .map_err(|_| "앱 목록 잠금이 손상되었습니다.".to_string())?;
        let now = now_seconds();
        if force_refresh || cache.scanned_at == 0 || now.saturating_sub(cache.scanned_at) >= 30 {
            cache.apps = discover_installed_applications();
            cache.scanned_at = now;
        }
        cache.apps.clone()
    } else {
        Vec::new()
    };
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

    let _ = sync_guard_state(&config, &runtime);
    let apps = build_app_views(&config, installed, &runtime);

    Ok(Snapshot {
        initialized: config.password_hash.is_some(),
        apps,
        settings: config.settings.clone(),
        lockout_remaining_seconds,
        guard_active: guard_is_active(),
    })
}

fn current_snapshot(state: &AppState) -> Result<Snapshot, String> {
    current_snapshot_with_refresh(state, false)
}

#[tauri::command]
fn get_snapshot(state: State<'_, AppState>) -> Result<Snapshot, String> {
    current_snapshot(state.inner())
}

#[tauri::command]
fn refresh_installed_applications(state: State<'_, AppState>) -> Result<Snapshot, String> {
    current_snapshot_with_refresh(state.inner(), true)
}

#[tauri::command]
fn poll_guard_event(state: State<'_, AppState>) -> Result<Option<GuardAuthRequest>, String> {
    Ok(
        take_guard_event(state.inner())?.map(|app| GuardAuthRequest {
            app,
            compact: state.compact_auth_window.load(Ordering::Acquire),
        }),
    )
}

#[tauri::command]
fn windows_hello_available() -> bool {
    windows_hello::is_available()
}

#[tauri::command]
fn dismiss_auth_window(window: WebviewWindow, state: State<'_, AppState>) -> Result<(), String> {
    if state.compact_auth_window.load(Ordering::Acquire) {
        window.hide().map_err(|error| error.to_string())?;
        restore_dashboard_window(&window)?;
        state.compact_auth_window.store(false, Ordering::Release);
    }
    Ok(())
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
fn set_application_protection(
    name: String,
    path: String,
    enabled: bool,
    state: State<'_, AppState>,
) -> Result<Snapshot, String> {
    let executable = PathBuf::from(path.trim());
    if enabled
        && (!executable.is_file()
            || !executable
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("exe")))
    {
        return Err("실행 가능한 Windows 앱을 찾을 수 없습니다.".into());
    }

    let path_key = normalized_path_key(&path);
    let mut removed_ids = Vec::new();
    {
        let mut config = state
            .config
            .lock()
            .map_err(|_| "설정 잠금이 손상되었습니다.".to_string())?;

        if enabled {
            if let Some(app) = config
                .apps
                .iter_mut()
                .find(|app| normalized_path_key(&app.path) == path_key)
            {
                app.name = name.trim().to_string();
                app.path = path.trim().to_string();
                app.protection_enabled = true;
            } else {
                config.apps.push(ProtectedApp {
                    id: Uuid::new_v4().to_string(),
                    name: name.trim().to_string(),
                    path: path.trim().to_string(),
                    protection_enabled: true,
                });
            }
        } else {
            removed_ids.extend(
                config
                    .apps
                    .iter()
                    .filter(|app| normalized_path_key(&app.path) == path_key)
                    .map(|app| app.id.clone()),
            );
            config
                .apps
                .retain(|app| normalized_path_key(&app.path) != path_key);
        }
        save_config(&state.config_path, &config)?;
    }

    if !removed_ids.is_empty() {
        let mut runtime = state
            .runtime
            .lock()
            .map_err(|_| "보안 상태 잠금이 손상되었습니다.".to_string())?;
        for id in removed_ids {
            runtime.grants.remove(&id);
        }
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

    sync_guard_from_app_state(state.inner())?;

    if application_is_running(&path) {
        return Ok(LaunchResponse {
            status: "authorized".into(),
            message: format!("{}이(가) 이미 실행 중이므로 인증만 완료했습니다.", app.name),
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

#[cfg(target_os = "windows")]
fn application_is_running(path: &Path) -> bool {
    use sysinfo::{ProcessesToUpdate, System};

    let expected_path = normalized_path_key(&path.to_string_lossy());
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::All, false);
    system.processes().values().any(|process| {
        process.exe().is_some_and(|executable| {
            normalized_path_key(&executable.to_string_lossy()) == expected_path
        })
    })
}

#[cfg(not(target_os = "windows"))]
fn application_is_running(_path: &Path) -> bool {
    false
}

#[tauri::command]
async fn launch_application_with_windows_hello(
    id: String,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<LaunchResponse, String> {
    let (app_name, protection_enabled, unlock_minutes) = {
        let config = state
            .config
            .lock()
            .map_err(|_| "설정 잠금이 손상되었습니다.".to_string())?;
        let app = config
            .apps
            .iter()
            .find(|app| app.id == id)
            .ok_or_else(|| "응용 프로그램을 찾을 수 없습니다.".to_string())?;
        (
            app.name.clone(),
            app.protection_enabled,
            config.settings.unlock_minutes,
        )
    };

    if !protection_enabled {
        return launch_application(id, None, state);
    }

    let now = now_seconds();
    let already_granted = state
        .runtime
        .lock()
        .map_err(|_| "보안 상태 잠금이 손상되었습니다.".to_string())?
        .grants
        .get(&id)
        .is_some_and(|expires_at| *expires_at > now);
    if already_granted {
        return launch_application(id, None, state);
    }

    let verification =
        tauri::async_runtime::spawn_blocking(move || windows_hello::verify(window, app_name))
            .await
            .map_err(|error| format!("Windows Hello 작업을 완료하지 못했습니다: {error}"))?;

    match verification {
        windows_hello::Verification::Verified => {
            let expires_at = now_seconds() + u64::from(unlock_minutes) * 60;
            state
                .runtime
                .lock()
                .map_err(|_| "보안 상태 잠금이 손상되었습니다.".to_string())?
                .grants
                .insert(id.clone(), expires_at);
            sync_guard_from_app_state(state.inner())?;
            launch_application(id, None, state)
        }
        windows_hello::Verification::Canceled => Ok(LaunchResponse {
            status: "helloCanceled".into(),
            message: "Windows Hello 인증이 취소되었습니다. 다시 시도하거나 마스터 비밀번호를 사용해 주세요.".into(),
            attempts_remaining: MAX_FAILED_ATTEMPTS,
            lockout_remaining_seconds: 0,
            granted_until: None,
        }),
        windows_hello::Verification::Failed(message) => Ok(LaunchResponse {
            status: "helloFailed".into(),
            message,
            attempts_remaining: MAX_FAILED_ATTEMPTS,
            lockout_remaining_seconds: 0,
            granted_until: None,
        }),
    }
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
        .plugin(tauri_plugin_single_instance::init(
            |app, _arguments, _cwd| {
                show_dashboard_window(app);
            },
        ))
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
                installed_apps: Mutex::new(InstalledAppCache::default()),
                compact_auth_window: AtomicBool::new(false),
            });

            TrayIconBuilder::new()
                .icon(make_tray_icon())
                .tooltip("App Password")
                .on_tray_icon_event(|tray, event| {
                    let should_show = matches!(
                        event,
                        TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } | TrayIconEvent::DoubleClick {
                            button: MouseButton::Left,
                            ..
                        }
                    );
                    if should_show {
                        show_dashboard_window(tray.app_handle());
                    }
                })
                .build(app)?;

            if std::env::args_os().any(|argument| argument == "--background") {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }

            let app_handle = app.handle().clone();
            std::thread::spawn(move || loop {
                if guard_event_waiting() {
                    if let Some(window) = app_handle.get_webview_window("main") {
                        if !window.is_visible().unwrap_or(false) {
                            app_handle
                                .state::<AppState>()
                                .compact_auth_window
                                .store(true, Ordering::Release);
                            let _ = show_compact_auth_window(&window);
                        }
                        let _ = window.show();
                        let _ = window.unminimize();
                        let _ = window.set_focus();
                    }
                }
                std::thread::sleep(Duration::from_millis(500));
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() == "main" {
                if let WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                    if window
                        .state::<AppState>()
                        .compact_auth_window
                        .swap(false, Ordering::AcqRel)
                    {
                        if let Some(webview_window) = window.app_handle().get_webview_window("main")
                        {
                            let _ = restore_dashboard_window(&webview_window);
                        }
                        let _ = window.emit("compact-auth-closed", ());
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            refresh_installed_applications,
            poll_guard_event,
            windows_hello_available,
            dismiss_auth_window,
            set_master_password,
            change_master_password,
            set_application_protection,
            update_unlock_minutes,
            lock_all,
            launch_application,
            launch_application_with_windows_hello
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

    #[test]
    fn installed_apps_are_merged_with_protection_settings() {
        let mut config = Config::default();
        config.apps.push(ProtectedApp {
            id: "protected-id".into(),
            name: "Protected App".into(),
            path: r"C:\Program Files\Protected\protected.exe".into(),
            protection_enabled: true,
        });
        let installed = vec![
            InstalledApplication {
                name: "Protected App".into(),
                path: r"c:\program files\protected\protected.exe".into(),
            },
            InstalledApplication {
                name: "Discovered App".into(),
                path: r"C:\Apps\discovered.exe".into(),
            },
        ];

        let views = build_app_views(&config, installed, &RuntimeSecurity::default());

        assert_eq!(views.len(), 2);
        assert_eq!(views[0].id, "protected-id");
        assert!(views[0].protection_enabled);
        assert_eq!(views[1].name, "Discovered App");
        assert!(!views[1].protection_enabled);
    }
}
