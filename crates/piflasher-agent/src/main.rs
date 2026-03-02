use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use piflasher_core::paths::{
    agent_socket_path, app_root, ensure_layout, policy_path, validate_root,
};
use piflasher_core::{
    execute_flash, execute_verify, prepare_image, FlashExecutionOptions, PolicyStore,
};
use piflasher_protocol::{
    read_framed_json, write_framed_json, RpcEnvelope, RpcEnvelopeResponse, RpcRequest, RpcResponse,
    PROTOCOL_VERSION,
};
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(
    name = "piflasher-agent",
    version,
    about = "PiFlasher privileged agent"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Serve {
        #[arg(long)]
        app_root: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Command::Serve { app_root: root } => run_server(root).await,
    }
}

async fn run_server(root: Option<PathBuf>) -> anyhow::Result<()> {
    let root = root.unwrap_or_else(app_root);
    validate_root(&root)?;
    ensure_layout(&root)?;

    let socket = agent_socket_path(&root);
    let policy_store = PolicyStore::load_or_default(&policy_path(&root))?;

    let manager = default_manager()?;

    #[cfg(not(target_os = "windows"))]
    {
        run_unix_server(&socket, &root, manager, policy_store).await?;
    }

    #[cfg(target_os = "windows")]
    {
        run_windows_tcp_server(&socket, &root, manager, policy_store).await?;
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
async fn run_unix_server(
    socket: &Path,
    root: &Path,
    manager: Arc<dyn piflasher_core::DeviceManager>,
    policy_store: PolicyStore,
) -> anyhow::Result<()> {
    if socket.exists() {
        let _ = std::fs::remove_file(socket);
    }

    let listener = tokio::net::UnixListener::bind(socket)?;
    info!(socket = %socket.display(), "piflasher agent listening");

    loop {
        let (mut stream, _addr) = listener.accept().await?;
        let manager = Arc::clone(&manager);
        let root = root.to_path_buf();
        let policy_store = policy_store.clone();
        tokio::spawn(async move {
            match read_framed_json::<_, RpcEnvelope>(&mut stream).await {
                Ok(req) => {
                    let payload = handle_request(&root, manager, &policy_store, req.payload).await;
                    let response = RpcEnvelopeResponse {
                        protocol_version: PROTOCOL_VERSION,
                        request_id: req.request_id,
                        payload,
                    };
                    if let Err(err) = write_framed_json(&mut stream, &response).await {
                        error!(error = %err, "failed sending response");
                    }
                }
                Err(err) => {
                    error!(error = %err, "failed reading request");
                }
            }
        });
    }
}

#[cfg(target_os = "windows")]
async fn run_windows_tcp_server(
    socket: &Path,
    root: &Path,
    manager: Arc<dyn piflasher_core::DeviceManager>,
    policy_store: PolicyStore,
) -> anyhow::Result<()> {
    let addr = socket
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid tcp address path"))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(address = %addr, "piflasher agent listening");

    loop {
        let (mut stream, _) = listener.accept().await?;
        let manager = Arc::clone(&manager);
        let root = root.to_path_buf();
        let policy_store = policy_store.clone();
        tokio::spawn(async move {
            match read_framed_json::<_, RpcEnvelope>(&mut stream).await {
                Ok(req) => {
                    let payload = handle_request(&root, manager, &policy_store, req.payload).await;
                    let response = RpcEnvelopeResponse {
                        protocol_version: PROTOCOL_VERSION,
                        request_id: req.request_id,
                        payload,
                    };
                    if let Err(err) = write_framed_json(&mut stream, &response).await {
                        error!(error = %err, "failed sending response");
                    }
                }
                Err(err) => {
                    error!(error = %err, "failed reading request");
                }
            }
        });
    }
}

async fn handle_request(
    root: &Path,
    manager: Arc<dyn piflasher_core::DeviceManager>,
    policy_store: &PolicyStore,
    request: RpcRequest,
) -> RpcResponse {
    match request {
        RpcRequest::Ping => RpcResponse::Pong {
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            ts: chrono::Utc::now(),
        },
        RpcRequest::ListDevices => match manager.list_devices() {
            Ok(devices) => RpcResponse::Devices { devices },
            Err(err) => rpc_error(err),
        },
        RpcRequest::PolicyList => match policy_store.get() {
            Ok(policy) => RpcResponse::Policy { policy },
            Err(err) => rpc_error(err),
        },
        RpcRequest::PolicyEnroll { device_id, label } => match manager.list_devices() {
            Ok(devices) => {
                if let Some(device) = devices.into_iter().find(|d| d.id == device_id) {
                    match policy_store.enroll_from_device(&device, &label) {
                        Ok(()) => RpcResponse::Ack {
                            message: format!("enrolled {device_id} as {label}"),
                        },
                        Err(err) => rpc_error(err),
                    }
                } else {
                    rpc_error(piflasher_core::CoreError::InvalidRequest(format!(
                        "unknown device id {device_id}"
                    )))
                }
            }
            Err(err) => rpc_error(err),
        },
        RpcRequest::PolicyClearQuarantine { device_id } => {
            match policy_store.clear_quarantine(&device_id) {
                Ok(()) => RpcResponse::Ack {
                    message: format!("cleared quarantine for {device_id}"),
                },
                Err(err) => rpc_error(err),
            }
        }
        RpcRequest::ImagePrepare { image_path, force } => {
            match prepare_image(root, image_path.as_deref().map(Path::new), force) {
                Ok(prepared) => RpcResponse::ImagePrepared { prepared },
                Err(err) => rpc_error(err),
            }
        }
        RpcRequest::Flash(request) => {
            match execute_flash(
                root,
                manager,
                policy_store,
                request,
                FlashExecutionOptions::default(),
            )
            .await
            {
                Ok(report) => RpcResponse::JobReport { report },
                Err(err) => rpc_error(err),
            }
        }
        RpcRequest::Verify(request) => {
            match execute_verify(
                root,
                manager,
                policy_store,
                request,
                FlashExecutionOptions::default(),
            )
            .await
            {
                Ok(report) => RpcResponse::JobReport { report },
                Err(err) => rpc_error(err),
            }
        }
    }
}

fn default_manager() -> anyhow::Result<Arc<dyn piflasher_core::DeviceManager>> {
    #[cfg(target_os = "macos")]
    {
        return Ok(piflasher_platform_macos::default_manager()?);
    }
    #[cfg(target_os = "windows")]
    {
        return Ok(piflasher_platform_windows::default_manager()?);
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Ok(piflasher_platform_macos::default_manager()?)
    }
}

fn rpc_error(err: piflasher_core::CoreError) -> RpcResponse {
    RpcResponse::Error {
        code: err.code(),
        message: err.to_string(),
    }
}

fn init_tracing() {
    let fmt = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(true)
        .without_time();

    let _ = fmt.try_init();
}
