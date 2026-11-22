//! Windows service integration for `fj-agent`.
//!
//! The agent is a cross-platform binary; on Windows it additionally runs as a
//! Service Control Manager (SCM) service so it starts at boot and is managed
//! like any other Windows service — the counterpart of the systemd unit on
//! Linux. The MSI installer registers the service with its image path set to
//! `fj-agent.exe service run`; `install|uninstall|start|stop` provide the same
//! lifecycle from the command line for manual setups and testing.
//!
//! Configuration comes from `%ProgramData%\flamejob-agent\agent.env` (the same
//! `FJ_AGENT_*` keys as the Linux `EnvironmentFile`), loaded into the process
//! environment before the agent reads it. Service logs go to
//! `%ProgramData%\flamejob-agent\logs\agent.log`.
#![cfg(windows)]

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser; // brings `Args::parse_from` into scope
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "flamejob-agent";
const SERVICE_DISPLAY_NAME: &str = "flamejob GPU worker agent";
const SERVICE_DESCRIPTION: &str =
    "Runs hashcat chunk tasks for a flamejob control plane and reports GPU/host telemetry.";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// `%ProgramData%\flamejob-agent` — the config/data root on Windows.
pub(crate) fn program_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("flamejob-agent")
}

/// Load `%ProgramData%\flamejob-agent\agent.env` into the process environment.
///
/// Mirrors a systemd `EnvironmentFile`: simple `KEY=VALUE` lines, `#` comments
/// and blanks ignored, with a single pair of surrounding double quotes stripped
/// from the value. A variable already present in the environment is left as-is,
/// so an explicitly set variable wins over the file (matching systemd, where
/// the unit's `Environment=` overrides `EnvironmentFile=`).
pub fn load_env_file() {
    let path = program_data_dir().join("agent.env");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return, // absent/unreadable: rely on real env + defaults
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        if std::env::var_os(key).is_none() {
            std::env::set_var(key, value);
        }
    }
}

/// Entry point for `fj-agent service <cmd>`.
pub fn dispatch(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        // SCM entry point: no console here, so log to a file and hand control to
        // the service dispatcher.
        Some("run") => run_dispatcher(),
        Some("install") => {
            crate::init_console_logging();
            install()
        }
        Some("uninstall") => {
            crate::init_console_logging();
            uninstall()
        }
        Some("start") => {
            crate::init_console_logging();
            control_start()
        }
        Some("stop") => {
            crate::init_console_logging();
            control_stop()
        }
        // Write %ProgramData%\flamejob-agent\agent.env. Invoked by the MSI as a
        // deferred custom action (values arrive via the CustomActionData env
        // var); also usable manually with --server/--name/--claim-token/--hashcat.
        Some("write-env") => write_env(&args[1..]),
        other => {
            eprintln!(
                "usage: fj-agent service <run|install|uninstall|start|stop>\n\
                 \n\
                 run        SCM entry point (used by the installed service)\n\
                 install    register the '{SERVICE_NAME}' service (run as Administrator)\n\
                 uninstall  stop and delete the service\n\
                 start      start the installed service\n\
                 stop       stop the installed service\n\
                 write-env  write %ProgramData%\\flamejob-agent\\agent.env (used by the installer)"
            );
            match other {
                Some(cmd) => anyhow::bail!("unknown service subcommand: {cmd:?}"),
                None => Ok(()),
            }
        }
    }
}

/// Install a file-based tracing subscriber for the service (no console under the
/// SCM). Daily-rolled under `%ProgramData%\flamejob-agent\logs`. The returned
/// guard must be kept alive for the lifetime of the process.
fn init_file_logging() -> tracing_appender::non_blocking::WorkerGuard {
    let dir = program_data_dir().join("logs");
    let _ = std::fs::create_dir_all(&dir);
    let file_appender = tracing_appender::rolling::daily(&dir, "agent.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(non_blocking)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("FJ_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    guard
}

/// `service run`: set up file logging and enter the SCM dispatcher. Blocks until
/// the service stops.
fn run_dispatcher() -> Result<()> {
    let _guard = init_file_logging();
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("start service control dispatcher")?;
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

/// SCM-invoked service entry (on a dedicated service thread).
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!(error = %format!("{e:#}"), "service terminated with error");
    }
}

fn run_service() -> Result<()> {
    // Config source first, so the agent sees FJ_AGENT_* from the env file.
    load_env_file();

    // Channel the control handler uses to ask the agent loop to stop.
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();

    let event_handler = move |control: ServiceControl| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("register service control handler")?;

    let report = |state: ServiceState, accept: ServiceControlAccept, wait: Duration| {
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: wait,
            process_id: None,
        })
    };

    report(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(10),
    )
    .context("report StartPending")?;

    let runtime = crate::build_runtime()?;

    report(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        Duration::default(),
    )
    .context("report Running")?;

    // Config entirely from the environment (env file + any real env); the CLI
    // carried only `service run`, so parse with no CLI args.
    let args = crate::Args::parse_from(["fj-agent"]);
    tracing::info!("flamejob-agent service starting");

    let result = runtime.block_on(async move {
        tokio::select! {
            r = crate::run_agent(args) => r,
            _ = wait_for_stop(shutdown_rx) => {
                tracing::info!("stop requested; shutting down");
                Ok(())
            }
        }
    });

    report(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        Duration::default(),
    )
    .context("report Stopped")?;

    result
}

/// Await the control handler's stop signal without blocking the async runtime.
async fn wait_for_stop(rx: std::sync::mpsc::Receiver<()>) {
    let _ = tokio::task::spawn_blocking(move || {
        let _ = rx.recv();
    })
    .await;
}

fn install() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&OsStr>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("open the service control manager (run this as Administrator)")?;

    let exe = std::env::current_exe().context("resolve the fj-agent executable path")?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![OsString::from("service"), OsString::from("run")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )
        .context("create the flamejob-agent service")?;
    let _ = service.set_description(SERVICE_DESCRIPTION);

    println!(
        "Installed service '{SERVICE_NAME}'.\n\
         Edit {}\\agent.env (server URL + one-time claim token), ensure hashcat is\n\
         installed, then: fj-agent service start",
        program_data_dir().display()
    );
    Ok(())
}

fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT)
        .context("open the service control manager (run this as Administrator)")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        )
        .context("open the flamejob-agent service")?;
    // Best-effort stop before delete; ignore "not running".
    let _ = service.stop();
    service
        .delete()
        .context("delete the flamejob-agent service")?;
    println!("Deleted service '{SERVICE_NAME}'.");
    Ok(())
}

fn control_start() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT)
        .context("open the service control manager")?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::START)
        .context("open the flamejob-agent service")?;
    let no_args: [&OsStr; 0] = [];
    service.start(&no_args).context("start the service")?;
    println!("Start signal sent to '{SERVICE_NAME}'.");
    Ok(())
}

fn control_stop() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT)
        .context("open the service control manager")?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::STOP)
        .context("open the flamejob-agent service")?;
    service.stop().context("stop the service")?;
    println!("Stop signal sent to '{SERVICE_NAME}'.");
    Ok(())
}

/// Write `agent.env`. The MSI runs this as a deferred custom action and passes
/// the install properties through the `CustomActionData` environment variable
/// (`SERVER=..|NAME=..|TOKEN=..|HASHCAT=..|FORCE=..`); the same keys can be given
/// on the command line (`--server`, `--name`, `--claim-token`, `--hashcat`,
/// `--force`) for manual use. An existing file is left untouched unless `--force`
/// so admin edits and the enrolled identity survive upgrades and repairs.
fn write_env(args: &[String]) -> Result<()> {
    let mut map = std::env::var("CustomActionData")
        .map(|d| parse_custom_action_data(&d))
        .unwrap_or_default();
    apply_env_flags(&mut map, args);

    let force = matches!(
        map.get("FORCE").map(String::as_str),
        Some("1") | Some("true") | Some("yes")
    );
    let dir = program_data_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join("agent.env");
    if path.exists() && !force {
        println!("{} already exists; leaving it unchanged.", path.display());
        return Ok(());
    }
    let get = |k: &str| map.get(k).map(String::as_str).unwrap_or("");
    let content = crate::render_agent_env(get("SERVER"), get("NAME"), get("TOKEN"), get("HASHCAT"));
    std::fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;
    println!("Wrote {}", path.display());
    Ok(())
}

/// Parse the MSI `CustomActionData` string (`KEY=VALUE` pairs, `|`-separated).
fn parse_custom_action_data(data: &str) -> std::collections::HashMap<String, String> {
    data.split('|')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.trim().to_uppercase(), v.trim().to_string()))
        .collect()
}

/// Overlay command-line flags onto the map (manual use / testing).
fn apply_env_flags(map: &mut std::collections::HashMap<String, String>, args: &[String]) {
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let key = match flag.as_str() {
            "--server" => "SERVER",
            "--name" => "NAME",
            "--claim-token" => "TOKEN",
            "--hashcat" => "HASHCAT",
            "--force" => {
                map.insert("FORCE".into(), "1".into());
                continue;
            }
            _ => continue,
        };
        if let Some(val) = it.next() {
            map.insert(key.into(), val.clone());
        }
    }
}
