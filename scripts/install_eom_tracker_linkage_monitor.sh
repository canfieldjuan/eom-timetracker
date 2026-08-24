#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(dirname -- "$script_dir")"
bin_dir="${HOME}/.local/bin"
unit_dir="${HOME}/.config/systemd/user"

install -D -m 0755 "$script_dir/eom_tracker_linkage_monitor.py" \
  "$bin_dir/eom-tracker-linkage-monitor.py"
install -D -m 0644 "$repo_dir/config/eom-tracker-linkage-monitor.service" \
  "$unit_dir/eom-tracker-linkage-monitor.service"
install -D -m 0644 "$repo_dir/config/eom-tracker-linkage-monitor-test.service" \
  "$unit_dir/eom-tracker-linkage-monitor-test.service"
install -D -m 0644 "$repo_dir/config/eom-tracker-linkage-monitor.timer" \
  "$unit_dir/eom-tracker-linkage-monitor.timer"

printf '%s\n' "Installed monitor files. Create ~/.config/eom-tracker-linkage-monitor.env with mode 0600, then run:"
printf '%s\n' "  systemctl --user daemon-reload"
printf '%s\n' "  systemctl --user start eom-tracker-linkage-monitor-test.service"
printf '%s\n' "  systemctl --user enable --now eom-tracker-linkage-monitor.timer"
