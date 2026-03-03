# PiFlasher

PiFlasher is a production-oriented CLI flasher for Raspberry Pi images. It defaults to `./rpi.img.xz`, provides an interactive terminal UI for selecting target microSD drives, and performs strict write + full readback verification.

## Highlights

- Interactive drive selector UI in terminal (`piflasher flash` with no `--targets`).
- Default image path is `./rpi.img.xz` from your current working directory.
- Strict verify mode: full write + full readback hash comparison.
- Deterministic JSON reports and NDJSON event output.
- macOS external physical disk discovery through `diskutil`.

## Quick start

1. Put `rpi.img.xz` in the project folder.
2. Run `cargo run -p piflasher-cli -- doctor`.
3. Run `cargo run -p piflasher-cli -- flash` and select drives in the UI.

Useful commands:

- `cargo run -p piflasher-cli -- devices list`
- `cargo run -p piflasher-cli -- image prepare`
- `cargo run -p piflasher-cli -- flash --yes --targets all`
- `cargo run -p piflasher-cli -- verify --targets all`
- `cargo run -p piflasher-cli -- reports show <job_id_prefix>`

## Windows setup and launch

For Windows, the repo includes scripts that make setup and launch simple:

1. Run setup (installs required tools and builds the CLI):
   - Double-click: `scripts\windows\setup-windows.cmd`
   - Or in PowerShell: `.\scripts\windows\setup-windows.ps1`
2. Start PiFlasher:
   - Double-click: `scripts\windows\start-piflasher.cmd`

Notes:

- The start script auto-prompts for Administrator privileges when needed.
- Keep `rpi.img.xz` in the repo root before launching.
- Auto-eject is enabled by default after target processing (success or failure).

## Verification warnings

Flash reports may include warning tokens in `targets[].warnings`:

- `W_VERIFY_TRANSIENT_MISMATCH_RESOLVED`: a mismatch was detected then resolved by confirm checks.
- `W_VERIFY_SOFT_PASS_BOOTABLE`: persistent mismatch was accepted because boot/layout checks passed.
- `W_EJECT_FAILED_AFTER_TARGET_COMPLETE`: auto-eject failed after processing a target.

## Workspace crates

- `piflasher-cli`: user-facing CLI/TUI entrypoint.
- `piflasher-agent`: legacy daemon entrypoint (not required for direct CLI flow).
- `piflasher-core`: image prep, policy, flash/verify orchestration.
- `piflasher-protocol`: shared request/report/event contracts.
- `piflasher-platform-macos`: macOS device manager backend.
- `piflasher-platform-windows`: Windows backend scaffold.
- `piflasher-report`: report rendering.
