#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("App Password Guard is only supported on Windows.");
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    windows_guard::run()
}

#[cfg(windows)]
mod windows_guard {
    use app_password_lib::guard_shared::{
        guard_data_dir, guard_events_dir, guard_heartbeat_path, guard_state_path,
        normalized_path_key, now_seconds, try_load_guard_state, GuardApplication, GuardEvent,
        GuardStateFile, GUARD_SERVICE_NAME,
    };
    use std::{
        collections::{HashMap, HashSet},
        ffi::{OsStr, OsString},
        fs, io,
        sync::mpsc,
        time::Duration,
    };
    use sysinfo::{Pid, ProcessesToUpdate, System};
    use windows_service::{
        define_windows_service,
        service::{
            ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
            ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
        service_manager::{ServiceManager, ServiceManagerAccess},
        Error, Result,
    };

    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    const EVENT_THROTTLE_SECONDS: u64 = 2;

    pub fn run() -> Result<()> {
        if std::env::args_os().nth(1).as_deref() == Some(OsStr::new("--install")) {
            install_and_start()
        } else {
            service_dispatcher::start(GUARD_SERVICE_NAME, ffi_service_main)
        }
    }

    fn install_and_start() -> Result<()> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )?;
        let executable_path = std::env::current_exe().map_err(Error::Winapi)?;
        let service_info = ServiceInfo {
            name: OsString::from(GUARD_SERVICE_NAME),
            display_name: OsString::from("App Password Guard"),
            service_type: SERVICE_TYPE,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path,
            launch_arguments: Vec::new(),
            dependencies: Vec::new(),
            account_name: None,
            account_password: None,
        };
        let service = manager.create_service(
            &service_info,
            ServiceAccess::START | ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_STATUS,
        )?;
        service.set_description("App Password protected application process guard")?;
        let arguments: [&OsStr; 0] = [];
        service.start(&arguments)?;

        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(100));
            match service.query_status()?.current_state {
                ServiceState::Running => return Ok(()),
                ServiceState::Stopped => break,
                _ => {}
            }
        }

        Err(Error::Winapi(io::Error::other(
            "App Password Guard service did not reach the running state",
        )))
    }

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(error) = run_service() {
            write_error_log(&error.to_string());
        }
    }

    fn run_service() -> Result<()> {
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop => {
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle = service_control_handler::register(GUARD_SERVICE_NAME, event_handler)?;
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        monitor_processes(shutdown_rx);

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;
        Ok(())
    }

    fn monitor_processes(shutdown_rx: mpsc::Receiver<()>) {
        if let Some(directory) = guard_data_dir() {
            let _ = fs::create_dir_all(directory);
        }
        if let Some(directory) = guard_events_dir() {
            let _ = fs::create_dir_all(directory);
        }

        let mut system = System::new();
        system.refresh_processes(ProcessesToUpdate::All, false);
        let mut known_pids: HashSet<Pid> = system.processes().keys().copied().collect();
        let mut last_event_at: HashMap<String, u64> = HashMap::new();
        let mut last_heartbeat = 0;
        let mut state = GuardStateFile::default();

        loop {
            if shutdown_rx.try_recv().is_ok() {
                break;
            }

            let now = now_seconds();
            if now != last_heartbeat {
                write_heartbeat(now);
                last_heartbeat = now;
            }

            if let Some(next_state) = guard_state_path().as_deref().and_then(try_load_guard_state) {
                state = next_state;
            }
            let protected: HashMap<String, GuardApplication> = state
                .apps
                .iter()
                .cloned()
                .map(|app| (normalized_path_key(&app.path), app))
                .collect();

            system.refresh_processes(ProcessesToUpdate::All, false);
            let current_pids: HashSet<Pid> = system.processes().keys().copied().collect();

            for pid in current_pids.difference(&known_pids) {
                let Some(process) = system.process(*pid) else {
                    continue;
                };
                let Some(executable) = process.exe() else {
                    continue;
                };
                let path = executable.to_string_lossy().to_string();
                let path_key = normalized_path_key(&path);
                let Some(application) = protected.get(&path_key) else {
                    continue;
                };
                let granted = state
                    .grants
                    .get(&path_key)
                    .is_some_and(|expires_at| *expires_at > now);
                if !granted && process.kill() {
                    let should_emit = last_event_at
                        .get(&path_key)
                        .is_none_or(|last| now.saturating_sub(*last) >= EVENT_THROTTLE_SECONDS);
                    if should_emit {
                        write_blocked_event(application, &path, now, pid.as_u32());
                        last_event_at.insert(path_key, now);
                    }
                }
            }

            known_pids = current_pids;
            if shutdown_rx.recv_timeout(POLL_INTERVAL).is_ok() {
                break;
            }
        }
    }

    fn write_heartbeat(now: u64) {
        if let Some(path) = guard_heartbeat_path() {
            let _ = fs::write(path, now.to_string());
        }
    }

    fn write_blocked_event(application: &GuardApplication, actual_path: &str, now: u64, pid: u32) {
        let Some(directory) = guard_events_dir() else {
            return;
        };
        let event = GuardEvent {
            name: application.name.clone(),
            path: actual_path.to_string(),
            created_at: now,
        };
        if let Ok(contents) = serde_json::to_vec(&event) {
            let _ = fs::write(directory.join(format!("{now}-{pid}.json")), contents);
        }
    }

    fn write_error_log(message: &str) {
        if let Some(directory) = guard_data_dir() {
            let _ = fs::create_dir_all(&directory);
            let _ = fs::write(directory.join("guard-error.log"), message);
        }
    }
}
