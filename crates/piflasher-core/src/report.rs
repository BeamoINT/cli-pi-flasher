use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};
use piflasher_protocol::RunReport;

use crate::paths::reports_root;
use crate::CoreResult;

pub fn report_paths_for_job(root: &Path, report: &RunReport) -> (PathBuf, PathBuf) {
    let ts = report
        .started_at
        .to_rfc3339_opts(SecondsFormat::Secs, true)
        .replace(':', "");
    let name = format!("{}_{}", ts, report.job_id);
    (
        reports_root(root).join(format!("{name}.json")),
        reports_root(root).join(format!("{name}.txt")),
    )
}

pub fn persist_report(root: &Path, report: &RunReport) -> CoreResult<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(reports_root(root))?;
    let (json_path, summary_path) = report_paths_for_job(root, report);

    let json = serde_json::to_vec_pretty(report)?;
    std::fs::write(&json_path, json)?;

    let summary = build_summary(report);
    std::fs::write(&summary_path, summary.as_bytes())?;

    Ok((json_path, summary_path))
}

pub fn load_report(path: &Path) -> CoreResult<RunReport> {
    let raw = std::fs::read(path)?;
    let report = serde_json::from_slice(&raw)?;
    Ok(report)
}

fn build_summary(report: &RunReport) -> String {
    let mut out = String::new();
    out.push_str("PiFlasher Run Summary\n");
    out.push_str("====================\n");
    out.push_str(&format!("Job ID: {}\n", report.job_id));
    out.push_str(&format!("Started: {}\n", report.started_at));
    out.push_str(&format!("Ended: {}\n", report.ended_at));
    out.push_str(&format!("Image: {}\n", report.image.path));
    out.push_str(&format!("Image bytes: {}\n", report.image.bytes));
    out.push_str(&format!("Image blake3: {}\n\n", report.image.blake3));

    out.push_str("Targets\n");
    out.push_str("-------\n");
    for target in &report.targets {
        out.push_str(&format!(
            "{}: {:?} (bytes_written={}, hash_match={}, layout_check={})",
            target.device_id,
            target.status,
            target.bytes_written,
            target.hash_match,
            target.layout_check
        ));
        if let Some(code) = target.error_code {
            out.push_str(&format!(" [{}]", code.as_str()));
        }
        if let Some(msg) = &target.error_message {
            out.push_str(&format!(" - {}", msg));
        }
        out.push('\n');
    }

    out.push_str("\nSummary\n");
    out.push_str("-------\n");
    out.push_str(&format!(
        "success={} failed={} skipped={} duration_secs={:.3}\n",
        report.summary.success,
        report.summary.failed,
        report.summary.skipped,
        report.summary.duration_secs
    ));
    out.push_str(&format!("generated_at={}\n", Utc::now()));
    out
}
