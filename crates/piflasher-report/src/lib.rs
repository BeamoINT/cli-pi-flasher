use piflasher_protocol::RunReport;

pub fn render_human_summary(report: &RunReport) -> String {
    let mut out = String::new();
    out.push_str("PiFlasher Report\n");
    out.push_str("==============\n");
    out.push_str(&format!("Job: {}\n", report.job_id));
    out.push_str(&format!("Started: {}\n", report.started_at));
    out.push_str(&format!("Ended: {}\n", report.ended_at));
    out.push_str(&format!("Image: {}\n", report.image.path));
    out.push_str(&format!("Image bytes: {}\n", report.image.bytes));
    out.push_str(&format!("blake3: {}\n\n", report.image.blake3));

    out.push_str("Targets\n");
    out.push_str("-------\n");
    for t in &report.targets {
        let mut line = format!(
            "{} | status={:?} write={:.2}s verify={:.2}s hash_match={} layout_check={}",
            t.device_id, t.status, t.write_secs, t.verify_secs, t.hash_match, t.layout_check
        );
        if let Some(code) = t.error_code {
            line.push_str(&format!(" code={}", code.as_str()));
        }
        if let Some(msg) = &t.error_message {
            line.push_str(&format!(" msg={}", msg));
        }
        if !t.warnings.is_empty() {
            line.push_str(&format!(" warnings={}", t.warnings.join(" | ")));
        }
        out.push_str(&line);
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

    out
}

pub fn parse_report_json(bytes: &[u8]) -> Result<RunReport, serde_json::Error> {
    serde_json::from_slice(bytes)
}
