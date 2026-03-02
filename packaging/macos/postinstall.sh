#!/bin/sh
set -eu

APP_ROOT="/Library/Application Support/PiFlasher"
mkdir -p "$APP_ROOT/image_cache" "$APP_ROOT/reports" "$APP_ROOT/logs"
chown -R root:wheel "$APP_ROOT"
chmod -R 755 "$APP_ROOT"

install -m 644 "$(dirname "$0")/com.piflasher.agent.plist" "/Library/LaunchDaemons/com.piflasher.agent.plist"
launchctl bootstrap system /Library/LaunchDaemons/com.piflasher.agent.plist || true
launchctl enable system/com.piflasher.agent || true
launchctl kickstart -k system/com.piflasher.agent || true
