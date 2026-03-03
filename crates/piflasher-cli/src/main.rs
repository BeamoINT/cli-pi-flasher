use std::collections::HashSet;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use piflasher_core::paths::{
    app_root, ensure_layout, policy_path, reports_root, validate_root, DEFAULT_IMAGE_PATH,
};
use piflasher_core::{
    execute_flash, execute_verify, prepare_image, CoreError, DeviceManager, FlashExecutionOptions,
    PolicyStore, ProgressPhase, ProgressUpdate, IMAGE_PREP_DEVICE_ID,
};
use piflasher_protocol::{
    DeviceInfo, ErrorCode, EventEnvelope, FlashRequest, TargetSelector, VerifyRequest,
};
use piflasher_report::render_human_summary;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;
use tracing::error;

#[derive(Parser, Debug)]
#[command(name = "piflasher", version, about = "PiFlasher CLI")]
struct Cli {
    #[arg(long)]
    app_root: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Doctor {
        #[arg(long)]
        json: bool,
    },
    Devices {
        #[command(subcommand)]
        command: DevicesCommand,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    Image {
        #[command(subcommand)]
        command: ImageCommand,
    },
    Flash(FlashArgs),
    Verify(VerifyArgs),
    Reports {
        #[command(subcommand)]
        command: ReportsCommand,
    },
}

#[derive(Subcommand, Debug)]
enum DevicesCommand {
    List {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCommand {
    Enroll {
        #[arg(long)]
        device: String,
        #[arg(long)]
        label: String,
    },
    List {
        #[arg(long)]
        json: bool,
    },
    ClearQuarantine {
        #[arg(long)]
        device: String,
    },
}

#[derive(Subcommand, Debug)]
enum ImageCommand {
    Prepare {
        #[arg(long)]
        image: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Args, Debug)]
struct FlashArgs {
    #[arg(long)]
    image: Option<PathBuf>,
    #[arg(
        long,
        help = "Target selector (`all`, `id1,id2`, `label:label1,label2`). If omitted in a terminal, interactive drive selection opens."
    )]
    targets: Option<String>,
    #[arg(long)]
    max_parallel: Option<u8>,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    yes: bool,
    #[arg(
        long,
        help = "Disable auto-eject after target processing (success or failure); auto-eject is enabled by default"
    )]
    no_eject: bool,
    #[arg(long)]
    allow_concurrent_jobs: bool,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    #[arg(long)]
    image: Option<PathBuf>,
    #[arg(
        long,
        help = "Target selector (`all`, `id1,id2`, `label:label1,label2`). If omitted in a terminal, interactive drive selection opens."
    )]
    targets: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum ReportsCommand {
    Show { job_id: String },
}

#[tokio::main]
async fn main() {
    init_tracing();
    let code = match run().await {
        Ok(code) => code,
        Err(err) => {
            error!(error = %err, "command failed");
            eprintln!("error: {err}");
            50
        }
    };
    std::process::exit(code);
}

async fn run() -> anyhow::Result<i32> {
    let cli = Cli::parse();
    let root = cli.app_root.clone().unwrap_or_else(app_root);
    if let Some(code) = maybe_reexec_with_elevation(&cli, &root)? {
        return Ok(code);
    }
    validate_root(&root)?;
    ensure_layout(&root)?;

    let manager = default_manager()?;
    let policy_store = PolicyStore::load_or_default(&policy_path(&root))?;

    match cli.command {
        Command::Doctor { json } => doctor(&root, manager, json).await,
        Command::Devices { command } => devices(manager, command).await,
        Command::Policy { command } => policy(manager, &policy_store, command).await,
        Command::Image { command } => image(&root, command).await,
        Command::Flash(args) => flash(&root, manager, &policy_store, args).await,
        Command::Verify(args) => verify(&root, manager, &policy_store, args).await,
        Command::Reports { command } => reports(&root, command).await,
    }
}

#[cfg(target_os = "macos")]
fn command_requires_raw_disk(command: &Command) -> bool {
    matches!(command, Command::Flash(_) | Command::Verify(_))
}

#[cfg(target_os = "macos")]
fn maybe_reexec_with_elevation(cli: &Cli, root: &Path) -> anyhow::Result<Option<i32>> {
    if !command_requires_raw_disk(&cli.command) {
        return Ok(None);
    }

    // macOS raw block devices require effective UID 0.
    if unsafe { libc::geteuid() } == 0 {
        return Ok(None);
    }

    if std::env::var_os("PIFLASHER_ELEVATION_ATTEMPTED").is_some() {
        return Err(anyhow::anyhow!(
            "raw disk access requires administrator privileges; run with sudo"
        ));
    }

    let exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("failed to resolve current executable path: {e}"))?;
    let mut cmd = std::process::Command::new("sudo");
    cmd.arg("env")
        .arg("PIFLASHER_ELEVATION_ATTEMPTED=1")
        .arg(format!("PIFLASHER_APP_ROOT={}", root.to_string_lossy()));
    if stdin_is_terminal() && stdout_is_terminal() {
        cmd.arg("PIFLASHER_FORCE_TTY=1");
    }
    cmd.arg(exe).args(std::env::args_os().skip(1));
    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!("failed to invoke sudo for raw disk access: {e}"))?;

    Ok(Some(status.code().unwrap_or(1)))
}

#[cfg(not(target_os = "macos"))]
fn maybe_reexec_with_elevation(_cli: &Cli, _root: &Path) -> anyhow::Result<Option<i32>> {
    Ok(None)
}

fn stdout_is_terminal() -> bool {
    if std::env::var_os("PIFLASHER_FORCE_TTY").as_deref() == Some(std::ffi::OsStr::new("1")) {
        return true;
    }
    io::stdout().is_terminal()
}

fn stdin_is_terminal() -> bool {
    if std::env::var_os("PIFLASHER_FORCE_TTY").as_deref() == Some(std::ffi::OsStr::new("1")) {
        return true;
    }
    io::stdin().is_terminal()
}

async fn doctor(root: &Path, manager: Arc<dyn DeviceManager>, json: bool) -> anyhow::Result<i32> {
    let policy = policy_path(root);
    let reports = reports_root(root);
    let image_default = PathBuf::from(DEFAULT_IMAGE_PATH);
    let devices = manager.list_devices().unwrap_or_default();
    let eligible = devices.iter().filter(|d| d.eligible).count();

    let mut map = serde_json::Map::new();
    map.insert(
        "app_root".into(),
        serde_json::Value::String(root.to_string_lossy().to_string()),
    );
    map.insert(
        "backend".into(),
        serde_json::Value::String(default_backend_description().to_string()),
    );
    map.insert(
        "policy_exists".into(),
        serde_json::Value::Bool(policy.exists()),
    );
    map.insert(
        "reports_dir_exists".into(),
        serde_json::Value::Bool(reports.exists()),
    );
    map.insert(
        "default_image_path".into(),
        serde_json::Value::String(image_default.to_string_lossy().to_string()),
    );
    map.insert(
        "default_image_exists".into(),
        serde_json::Value::Bool(image_default.exists()),
    );
    map.insert(
        "detected_devices".into(),
        serde_json::Value::Number((devices.len() as u64).into()),
    );
    map.insert(
        "eligible_devices".into(),
        serde_json::Value::Number((eligible as u64).into()),
    );

    if json {
        println!("{}", serde_json::to_string_pretty(&map)?);
    } else {
        println!("PiFlasher Doctor");
        println!("app_root: {}", root.display());
        println!("backend: {}", default_backend_description());
        println!("policy_exists: {}", policy.exists());
        println!("reports_dir_exists: {}", reports.exists());
        println!("default_image_path: {}", image_default.display());
        println!("default_image_exists: {}", image_default.exists());
        println!("detected_devices: {}", devices.len());
        println!("eligible_devices: {}", eligible);
        if !image_default.exists() {
            println!("note: put rpi.img.xz in the current working folder or pass --image");
        }
    }

    Ok(0)
}

async fn devices(manager: Arc<dyn DeviceManager>, command: DevicesCommand) -> anyhow::Result<i32> {
    match command {
        DevicesCommand::List { json } => {
            let devices = manager.list_devices()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&devices)?);
            } else {
                for d in devices {
                    println!(
                        "{} path={} eligible={} cap={} removable={} system={} reasons={}",
                        d.id,
                        d.path,
                        d.eligible,
                        d.capacity_bytes,
                        d.removable,
                        d.is_system_disk,
                        d.ineligible_reasons.join(",")
                    );
                }
            }
            Ok(0)
        }
    }
}

async fn policy(
    manager: Arc<dyn DeviceManager>,
    policy_store: &PolicyStore,
    command: PolicyCommand,
) -> anyhow::Result<i32> {
    match command {
        PolicyCommand::Enroll { device, label } => {
            let devices = manager.list_devices()?;
            let Some(found) = devices.into_iter().find(|d| d.id == device) else {
                eprintln!("unknown device id: {device}");
                return Ok(20);
            };
            policy_store.enroll_from_device(&found, &label)?;
            println!("enrolled {} as {}", found.id, label);
            Ok(0)
        }
        PolicyCommand::List { json } => {
            let policy = policy_store.get()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&policy)?);
            } else {
                println!("version={}", policy.version);
                println!("max_parallel={}", policy.max_parallel);
                println!(
                    "require_fingerprint_noninteractive={}",
                    policy.require_fingerprint_noninteractive
                );
                println!("allowed_readers={}", policy.allowed_readers.len());
                println!("quarantined_readers={}", policy.quarantined_readers.len());
            }
            Ok(0)
        }
        PolicyCommand::ClearQuarantine { device } => {
            policy_store.clear_quarantine(&device)?;
            println!("cleared quarantine for {device}");
            Ok(0)
        }
    }
}

async fn image(root: &Path, command: ImageCommand) -> anyhow::Result<i32> {
    match command {
        ImageCommand::Prepare { image, force } => {
            let prepared = prepare_image(root, image.as_deref(), force)?;
            println!("{}", serde_json::to_string_pretty(&prepared)?);
            Ok(0)
        }
    }
}

async fn flash(
    root: &Path,
    manager: Arc<dyn DeviceManager>,
    policy_store: &PolicyStore,
    args: FlashArgs,
) -> anyhow::Result<i32> {
    let selector = match resolve_target_selector(
        args.targets.as_deref(),
        manager.as_ref(),
        args.image.as_deref(),
    )? {
        Some(selector) => selector,
        None => {
            eprintln!("flash cancelled by user");
            return Ok(20);
        }
    };

    if selector_is_empty(&selector) {
        eprintln!("no targets selected");
        return Ok(20);
    }

    if !args.yes && stdout_is_terminal() {
        let approved = confirm_flash_tui(args.image.as_deref(), &selector, args.max_parallel)?;
        if !approved {
            eprintln!("flash cancelled by user");
            return Ok(20);
        }
    }

    let request = FlashRequest {
        image_path: args.image.map(|v| v.to_string_lossy().to_string()),
        targets: selector,
        max_parallel: args.max_parallel,
        json: args.json,
        yes: args.yes || !stdin_is_terminal(),
        no_eject: args.no_eject,
        allow_concurrent_jobs: args.allow_concurrent_jobs,
    };

    let report_result = if args.json || !stdout_is_terminal() {
        execute_flash(
            root,
            manager,
            policy_store,
            request,
            FlashExecutionOptions::default(),
        )
        .await
    } else {
        execute_flash_with_tracker(root, manager, policy_store.clone(), request).await
    };

    match report_result {
        Ok(report) => {
            if args.json {
                emit_ndjson_report_events(&report)?;
            } else {
                println!("{}", render_human_summary(&report));
            }
            Ok(exit_code_for_report(&report))
        }
        Err(err) => {
            eprintln!("{}: {}", err.code().as_str(), err);
            Ok(map_error_to_exit(err.code()))
        }
    }
}

async fn verify(
    root: &Path,
    manager: Arc<dyn DeviceManager>,
    policy_store: &PolicyStore,
    args: VerifyArgs,
) -> anyhow::Result<i32> {
    let selector = match resolve_target_selector(
        args.targets.as_deref(),
        manager.as_ref(),
        args.image.as_deref(),
    )? {
        Some(selector) => selector,
        None => {
            eprintln!("verify cancelled by user");
            return Ok(20);
        }
    };

    if selector_is_empty(&selector) {
        eprintln!("no targets selected");
        return Ok(20);
    }

    let request = VerifyRequest {
        image_path: args.image.map(|v| v.to_string_lossy().to_string()),
        targets: selector,
        json: args.json,
    };

    match execute_verify(
        root,
        manager,
        policy_store,
        request,
        FlashExecutionOptions::default(),
    )
    .await
    {
        Ok(report) => {
            if args.json {
                emit_ndjson_report_events(&report)?;
            } else {
                println!("{}", render_human_summary(&report));
            }
            Ok(exit_code_for_report(&report))
        }
        Err(err) => {
            eprintln!("{}: {}", err.code().as_str(), err);
            Ok(map_error_to_exit(err.code()))
        }
    }
}

async fn reports(root: &Path, command: ReportsCommand) -> anyhow::Result<i32> {
    match command {
        ReportsCommand::Show { job_id } => {
            let dir = reports_root(root);
            let mut selected = None;
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                if entry.path().extension().and_then(|v| v.to_str()) != Some("json") {
                    continue;
                }
                let filename = entry.file_name();
                let filename = filename.to_string_lossy();
                if filename.contains(&job_id) {
                    selected = Some(entry.path());
                    break;
                }
            }

            let Some(path) = selected else {
                eprintln!("report not found for job_id={job_id}");
                return Ok(50);
            };

            let raw = std::fs::read(path)?;
            let report = piflasher_report::parse_report_json(&raw)?;
            println!("{}", render_human_summary(&report));
            Ok(0)
        }
    }
}

fn parse_targets(targets: &str) -> TargetSelector {
    if targets.trim().eq_ignore_ascii_case("all") {
        return TargetSelector::All;
    }

    if let Some(rest) = targets.strip_prefix("label:") {
        let labels = rest
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        return TargetSelector::Labels { labels };
    }

    let ids = targets
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    TargetSelector::DeviceIds { ids }
}

fn resolve_target_selector(
    raw_targets: Option<&str>,
    manager: &dyn DeviceManager,
    image_path: Option<&Path>,
) -> anyhow::Result<Option<TargetSelector>> {
    if let Some(raw) = raw_targets {
        return Ok(Some(parse_targets(raw)));
    }

    if !stdout_is_terminal() {
        return Ok(Some(TargetSelector::All));
    }

    let selected = select_devices_tui(manager, image_path)?;
    Ok(selected.map(|ids| TargetSelector::DeviceIds { ids }))
}

fn selector_is_empty(selector: &TargetSelector) -> bool {
    match selector {
        TargetSelector::DeviceIds { ids } => ids.is_empty(),
        TargetSelector::Labels { labels } => labels.is_empty(),
        TargetSelector::All => false,
    }
}

fn emit_ndjson_report_events(report: &piflasher_protocol::RunReport) -> anyhow::Result<()> {
    let start = EventEnvelope {
        event_type: "run_started".to_string(),
        job_id: report.job_id,
        device_id: None,
        ts: report.started_at,
        payload: serde_json::json!({
            "image": report.image,
            "settings": report.settings,
        }),
    };
    println!("{}", serde_json::to_string(&start)?);

    for target in &report.targets {
        let evt = EventEnvelope {
            event_type: "target_completed".to_string(),
            job_id: report.job_id,
            device_id: Some(target.device_id.clone()),
            ts: report.ended_at,
            payload: serde_json::to_value(target)?,
        };
        println!("{}", serde_json::to_string(&evt)?);
    }

    let done = EventEnvelope {
        event_type: "run_completed".to_string(),
        job_id: report.job_id,
        device_id: None,
        ts: report.ended_at,
        payload: serde_json::to_value(&report.summary)?,
    };
    println!("{}", serde_json::to_string(&done)?);
    Ok(())
}

#[derive(Clone, Debug)]
struct LiveDeviceProgress {
    phase: ProgressPhase,
    write_done_bytes: u64,
    write_total_bytes: u64,
    verify_done_bytes: u64,
    verify_total_bytes: u64,
    message: Option<String>,
}

impl Default for LiveDeviceProgress {
    fn default() -> Self {
        Self {
            phase: ProgressPhase::Queued,
            write_done_bytes: 0,
            write_total_bytes: 0,
            verify_done_bytes: 0,
            verify_total_bytes: 0,
            message: None,
        }
    }
}

async fn execute_flash_with_tracker(
    root: &Path,
    manager: Arc<dyn DeviceManager>,
    policy_store: PolicyStore,
    request: FlashRequest,
) -> Result<piflasher_protocol::RunReport, CoreError> {
    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel::<ProgressUpdate>();
    let callback = Arc::new(move |update: ProgressUpdate| {
        let _ = progress_tx.send(update);
    });

    let app_root = root.to_path_buf();
    let task_manager = Arc::clone(&manager);
    let task_policy = policy_store.clone();
    let options = FlashExecutionOptions {
        persist_report: true,
        progress: Some(callback),
    };

    let mut flash_task = tokio::spawn(async move {
        execute_flash(&app_root, task_manager, &task_policy, request, options).await
    });

    let mut state: std::collections::BTreeMap<String, LiveDeviceProgress> =
        std::collections::BTreeMap::new();
    state.insert(
        IMAGE_PREP_DEVICE_ID.to_string(),
        LiveDeviceProgress {
            phase: ProgressPhase::PreparingImage,
            write_done_bytes: 0,
            write_total_bytes: 0,
            verify_done_bytes: 0,
            verify_total_bytes: 0,
            message: Some("Preparing image cache".to_string()),
        },
    );
    let started = Instant::now();

    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)
        .map_err(|e| CoreError::Internal(format!("failed to enter progress screen: {e}")))?;
    enable_raw_mode()
        .map_err(|e| CoreError::Internal(format!("failed to enable raw mode: {e}")))?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)
        .map_err(|e| CoreError::Internal(format!("failed to create progress terminal: {e}")))?;

    let mut tick = tokio::time::interval(Duration::from_millis(120));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_draw = Instant::now();

    let join_result = loop {
        tokio::select! {
            maybe_update = progress_rx.recv() => {
                if let Some(update) = maybe_update {
                    apply_progress_update(&mut state, update);
                    while let Ok(pending) = progress_rx.try_recv() {
                        apply_progress_update(&mut state, pending);
                    }
                    if last_draw.elapsed() >= Duration::from_millis(60) {
                        draw_flash_progress(&mut terminal, &state, started)
                            .map_err(|e| CoreError::Internal(format!("failed to draw progress UI: {e}")))?;
                        last_draw = Instant::now();
                    }
                }
            }
            _ = tick.tick() => {
                draw_flash_progress(&mut terminal, &state, started)
                    .map_err(|e| CoreError::Internal(format!("failed to draw progress UI: {e}")))?;
                last_draw = Instant::now();
            }
            task_result = &mut flash_task => {
                break task_result;
            }
        }
    };

    while let Ok(update) = progress_rx.try_recv() {
        apply_progress_update(&mut state, update);
    }
    let _ = draw_flash_progress(&mut terminal, &state, started);

    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);

    let task_result =
        join_result.map_err(|e| CoreError::Internal(format!("flash task failed to join: {e}")))?;
    task_result
}

fn apply_progress_update(
    state: &mut std::collections::BTreeMap<String, LiveDeviceProgress>,
    update: ProgressUpdate,
) {
    let entry = state.entry(update.device_id).or_default();
    entry.phase = update.phase;
    entry.write_done_bytes = update.write_done_bytes;
    entry.write_total_bytes = update.write_total_bytes;
    entry.verify_done_bytes = update.verify_done_bytes;
    entry.verify_total_bytes = update.verify_total_bytes;
    entry.message = update.message;
}

fn draw_flash_progress(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    state: &std::collections::BTreeMap<String, LiveDeviceProgress>,
    started: Instant,
) -> anyhow::Result<()> {
    terminal.draw(|frame| {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(8),
                Constraint::Length(4),
            ])
            .split(frame.area());

        let title = Paragraph::new(Line::from(vec![Span::styled(
            "PiFlasher Progress",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )]))
        .block(Block::default().borders(Borders::ALL));
        frame.render_widget(title, chunks[0]);

        let items = if state.is_empty() {
            let spinner = spinner_frame(started);
            vec![
                ListItem::new(format!(
                    "{spinner} Preparing image cache before flashing targets..."
                )),
                ListItem::new("First run can take a while for large rpi.img.xz files."),
                ListItem::new("Later runs reuse cache when source file is unchanged."),
            ]
        } else {
            state
                .iter()
                .map(|(device_id, progress)| {
                    if device_id == IMAGE_PREP_DEVICE_ID {
                        let pct = percent(progress.write_done_bytes, progress.write_total_bytes.max(1));
                        let bar = progress_bar(pct, 22);
                        return ListItem::new(format!(
                            "image-cache    {:<10} {bar} {:>5.1}%  {}/{}",
                            phase_label(progress.phase),
                            pct,
                            human_bytes(progress.write_done_bytes),
                            human_bytes(progress.write_total_bytes),
                        ));
                    }
                    let pct = overall_progress_pct(progress);
                    let bar = progress_bar(pct, 22);
                    let line = format!(
                        "{device_id:<14} {:<10} {bar} {:>5.1}%  W:{}/{}  V:{}/{}",
                        phase_label(progress.phase),
                        pct,
                        human_bytes(progress.write_done_bytes),
                        human_bytes(progress.write_total_bytes),
                        human_bytes(progress.verify_done_bytes),
                        human_bytes(progress.verify_total_bytes),
                    );
                    ListItem::new(line)
                })
                .collect::<Vec<_>>()
        };

        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Flashing Targets"),
        );
        frame.render_widget(list, chunks[1]);

        let done = state
            .iter()
            .filter(|(id, _)| id.as_str() != IMAGE_PREP_DEVICE_ID)
            .map(|(_, p)| p)
            .filter(|p| matches!(p.phase, ProgressPhase::Completed))
            .count();
        let failed = state
            .iter()
            .filter(|(id, _)| id.as_str() != IMAGE_PREP_DEVICE_ID)
            .map(|(_, p)| p)
            .filter(|p| matches!(p.phase, ProgressPhase::Failed))
            .count();
        let target_count = state
            .iter()
            .filter(|(id, _)| id.as_str() != IMAGE_PREP_DEVICE_ID)
            .count();
        let footer = Paragraph::new(vec![
            Line::from(format!(
                "Elapsed: {:>5.1}s   Targets: {}   Completed: {}   Failed: {}",
                started.elapsed().as_secs_f64(),
                target_count,
                done,
                failed
            )),
            Line::from(
                "Progress updates every chunk during write/verify. Keep this window open until complete.",
            ),
            Line::from(""),
        ])
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL));
        frame.render_widget(footer, chunks[2]);
    })?;
    Ok(())
}

fn phase_label(phase: ProgressPhase) -> &'static str {
    match phase {
        ProgressPhase::PreparingImage => "preparing",
        ProgressPhase::Queued => "queued",
        ProgressPhase::Writing => "writing",
        ProgressPhase::Verifying => "verifying",
        ProgressPhase::Retrying => "retrying",
        ProgressPhase::Completed => "completed",
        ProgressPhase::Failed => "failed",
    }
}

fn overall_progress_pct(progress: &LiveDeviceProgress) -> f64 {
    match progress.phase {
        ProgressPhase::PreparingImage => {
            percent(progress.write_done_bytes, progress.write_total_bytes.max(1))
        }
        ProgressPhase::Queued => 0.0,
        ProgressPhase::Writing | ProgressPhase::Retrying => {
            percent(progress.write_done_bytes, progress.write_total_bytes.max(1))
        }
        ProgressPhase::Verifying => {
            let write_pct = 50.0;
            write_pct
                + (percent(
                    progress.verify_done_bytes,
                    progress.verify_total_bytes.max(1),
                ) / 2.0)
        }
        ProgressPhase::Completed => 100.0,
        ProgressPhase::Failed => {
            percent(progress.write_done_bytes, progress.write_total_bytes.max(1))
        }
    }
}

fn percent(done: u64, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    (done as f64 / total as f64 * 100.0).clamp(0.0, 100.0)
}

fn progress_bar(pct: f64, width: usize) -> String {
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    let filled = filled.min(width);
    let empty = width.saturating_sub(filled);
    format!("[{}{}]", "#".repeat(filled), "-".repeat(empty))
}

fn spinner_frame(started: Instant) -> char {
    const FRAMES: [char; 4] = ['|', '/', '-', '\\'];
    let idx = ((started.elapsed().as_millis() / 200) as usize) % FRAMES.len();
    FRAMES[idx]
}

fn confirm_flash_tui(
    image: Option<&Path>,
    selector: &TargetSelector,
    max_parallel: Option<u8>,
) -> anyhow::Result<bool> {
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    enable_raw_mode()?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let selector_label = match selector {
        TargetSelector::All => "all discovered devices".to_string(),
        TargetSelector::DeviceIds { ids } => format!("{} selected device(s)", ids.len()),
        TargetSelector::Labels { labels } => format!("{} label selector(s)", labels.len()),
    };

    let result = loop {
        terminal.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(3),
                    Constraint::Length(3),
                ])
                .split(frame.area());

            let title = Paragraph::new(Line::from(vec![Span::styled(
                "PiFlasher Confirmation",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )]))
            .block(Block::default().borders(Borders::ALL));
            frame.render_widget(title, chunks[0]);

            let body = Paragraph::new(vec![
                Line::from(format!(
                    "image: {}",
                    image
                        .map(|v| v.display().to_string())
                        .unwrap_or_else(|| DEFAULT_IMAGE_PATH.to_string())
                )),
                Line::from(format!("targets: {selector_label}")),
                Line::from(format!("max_parallel: {:?}", max_parallel)),
                Line::from(""),
                Line::from("Press 'y' to start flashing, 'n' or Esc to cancel."),
            ])
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title("Preflight"));
            frame.render_widget(body, chunks[1]);

            let footer =
                Paragraph::new("Default image path is ./rpi.img.xz unless --image is provided")
                    .block(Block::default().borders(Borders::ALL));
            frame.render_widget(footer, chunks[2]);
        })?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => break true,
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => break false,
                _ => {}
            }
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(result)
}

fn select_devices_tui(
    manager: &dyn DeviceManager,
    image_path: Option<&Path>,
) -> anyhow::Result<Option<Vec<String>>> {
    let mut devices = manager.list_devices()?;
    let mut selected_ids: HashSet<String> = devices
        .iter()
        .filter(|d| is_selectable_device(d))
        .map(|d| d.id.clone())
        .collect();
    let mut user_modified = false;
    let mut last_scan_error: Option<String> = None;

    let rescan_interval = Duration::from_secs(10);
    let mut last_rescan = Instant::now();
    let mut state = ListState::default();
    state.select(if devices.is_empty() { None } else { Some(0) });

    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    enable_raw_mode()?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = loop {
        let selectable_count = devices.iter().filter(|d| is_selectable_device(d)).count();
        let selected_count = devices
            .iter()
            .filter(|d| selected_ids.contains(&d.id))
            .count();

        terminal.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(8),
                    Constraint::Length(5),
                ])
                .split(frame.area());

            let title = Paragraph::new(Line::from(vec![Span::styled(
                "Select MicroSD Target Drives",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )]))
            .block(Block::default().borders(Borders::ALL));
            frame.render_widget(title, chunks[0]);

            let items = devices
                .iter()
                .map(|d| {
                    let check = if selected_ids.contains(&d.id) {
                        "[x]"
                    } else {
                        "[ ]"
                    };
                    let safety = if is_selectable_device(d) {
                        ""
                    } else {
                        " (blocked)"
                    };
                    let reasons = if d.ineligible_reasons.is_empty() {
                        String::new()
                    } else {
                        format!(" reasons={}", d.ineligible_reasons.join(","))
                    };
                    let line = format!(
                        "{check} {}  {}  {} {}  {}{}{}",
                        d.id,
                        human_bytes(d.capacity_bytes),
                        d.vendor,
                        d.product,
                        d.path,
                        safety,
                        reasons
                    );
                    ListItem::new(line)
                })
                .collect::<Vec<_>>();

            let list = List::new(if items.is_empty() {
                vec![ListItem::new("No drives detected. Waiting for scan...")]
            } else {
                items
            })
                .block(Block::default().borders(Borders::ALL).title("Drives"))
                .highlight_style(Style::default().bg(Color::Blue).fg(Color::White));
            frame.render_stateful_widget(list, chunks[1], &mut state);

            let next_scan_in = if last_rescan.elapsed() >= rescan_interval {
                0
            } else {
                (rescan_interval - last_rescan.elapsed()).as_secs()
            };
            let scan_line = if let Some(err) = &last_scan_error {
                format!(
                    "Auto scan every 10s (next in {next_scan_in}s). Last scan error: {err}"
                )
            } else {
                format!("Auto scan every 10s (next in {next_scan_in}s)")
            };
            let footer = Paragraph::new(vec![
                Line::from(format!(
                    "Image: {}",
                    image_path
                        .map(|v| v.display().to_string())
                        .unwrap_or_else(|| DEFAULT_IMAGE_PATH.to_string())
                )),
                Line::from(format!(
                    "Selected drives: {selected_count} / selectable: {selectable_count}"
                )),
                Line::from(scan_line),
                Line::from(
                    "Controls: Up/Down move, Space toggle, a select all, c clear, Enter continue, q cancel",
                ),
            ])
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL));
            frame.render_widget(footer, chunks[2]);
        })?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        if !devices.is_empty() {
                            let current = state.selected().unwrap_or(0);
                            let next = current.saturating_sub(1);
                            state.select(Some(next));
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if !devices.is_empty() {
                            let current = state.selected().unwrap_or(0);
                            let next = (current + 1).min(devices.len().saturating_sub(1));
                            state.select(Some(next));
                        }
                    }
                    KeyCode::Char(' ') => {
                        if let Some(current) = state.selected() {
                            if let Some(device) = devices.get(current) {
                                if is_selectable_device(device) {
                                    if selected_ids.contains(&device.id) {
                                        selected_ids.remove(&device.id);
                                    } else {
                                        selected_ids.insert(device.id.clone());
                                    }
                                    user_modified = true;
                                }
                            }
                        }
                    }
                    KeyCode::Char('a') | KeyCode::Char('A') => {
                        selected_ids = devices
                            .iter()
                            .filter(|d| is_selectable_device(d))
                            .map(|d| d.id.clone())
                            .collect();
                        user_modified = true;
                    }
                    KeyCode::Char('c') | KeyCode::Char('C') => {
                        selected_ids.clear();
                        user_modified = true;
                    }
                    KeyCode::Enter => {
                        let ids = devices
                            .iter()
                            .filter(|d| selected_ids.contains(&d.id))
                            .map(|d| d.id.clone())
                            .collect::<Vec<_>>();
                        if !ids.is_empty() {
                            break Some(ids);
                        }
                    }
                    KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => break None,
                    _ => {}
                }
            }
        }

        if last_rescan.elapsed() >= rescan_interval {
            let previous_focused_id = state
                .selected()
                .and_then(|idx| devices.get(idx))
                .map(|d| d.id.clone());

            match manager.list_devices() {
                Ok(fresh_devices) => {
                    devices = fresh_devices;
                    last_scan_error = None;

                    let selectable_ids = devices
                        .iter()
                        .filter(|d| is_selectable_device(d))
                        .map(|d| d.id.clone())
                        .collect::<HashSet<_>>();

                    selected_ids.retain(|id| selectable_ids.contains(id));
                    if !user_modified {
                        selected_ids = selectable_ids;
                    }

                    if devices.is_empty() {
                        state.select(None);
                    } else if let Some(prev) = previous_focused_id {
                        let idx = devices
                            .iter()
                            .position(|d| d.id == prev)
                            .unwrap_or_else(|| {
                                state
                                    .selected()
                                    .unwrap_or(0)
                                    .min(devices.len().saturating_sub(1))
                            });
                        state.select(Some(idx));
                    } else {
                        state.select(Some(0));
                    }
                }
                Err(err) => {
                    last_scan_error = Some(err.to_string());
                }
            }

            last_rescan = Instant::now();
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(result)
}

fn is_selectable_device(device: &DeviceInfo) -> bool {
    device.eligible
        && device.removable
        && !device.is_system_disk
        && !matches!(
            device.bus.to_lowercase().as_str(),
            "sata" | "nvme" | "pci" | "pcie"
        )
}

fn human_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;

    let b = bytes as f64;
    if b >= GIB {
        format!("{:.1} GiB", b / GIB)
    } else if b >= MIB {
        format!("{:.1} MiB", b / MIB)
    } else if b >= KIB {
        format!("{:.1} KiB", b / KIB)
    } else {
        format!("{} B", bytes)
    }
}

fn map_error_to_exit(code: ErrorCode) -> i32 {
    match code {
        ErrorCode::PolicyDeny => 20,
        ErrorCode::AgentUnavailable => 30,
        ErrorCode::ImagePreparation => 40,
        _ => 50,
    }
}

fn exit_code_for_report(report: &piflasher_protocol::RunReport) -> i32 {
    if report.summary.failed == 0 {
        return 0;
    }
    if report.summary.success > 0 {
        10
    } else {
        20
    }
}

#[cfg(target_os = "macos")]
fn default_manager() -> anyhow::Result<Arc<dyn DeviceManager>> {
    Ok(piflasher_platform_macos::default_manager()?)
}

#[cfg(target_os = "windows")]
fn default_manager() -> anyhow::Result<Arc<dyn DeviceManager>> {
    Ok(piflasher_platform_windows::default_manager()?)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn default_manager() -> anyhow::Result<Arc<dyn DeviceManager>> {
    Ok(piflasher_platform_macos::default_manager()?)
}

#[cfg(target_os = "macos")]
fn default_backend_description() -> &'static str {
    piflasher_platform_macos::backend_description()
}

#[cfg(target_os = "windows")]
fn default_backend_description() -> &'static str {
    piflasher_platform_windows::backend_description()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn default_backend_description() -> &'static str {
    piflasher_platform_macos::backend_description()
}

fn init_tracing() {
    let fmt = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(true)
        .without_time();
    let _ = fmt.try_init();
}
