.PHONY: install uninstall purge update reinstall

install:
	./install.sh

uninstall:
	systemctl --user disable --now firewall-gui-update.timer 2>/dev/null || true
	rm -f "$(HOME)/.config/systemd/user/firewall-gui-update.timer"
	rm -f "$(HOME)/.config/systemd/user/firewall-gui-update.service"
	systemctl --user daemon-reload 2>/dev/null || true
	rm -f "$(HOME)/.local/bin/firewall-gui"
	rm -f "$(HOME)/.local/share/applications/org.jrf.FirewallGui.desktop"
	rm -f "$(HOME)/.local/share/icons/hicolor/scalable/apps/org.jrf.FirewallGui.svg"
	rm -rf "$(HOME)/.local/share/firewall-gui"
	@# Best-effort: the hardening helper is the one root-owned piece, and it is
	@# optional at install time, so a plain unprivileged uninstall must not fail
	@# or start prompting for a password just because it was never installed.
	@if [ -e /usr/libexec/firewall-gui-helper ] || [ -e /usr/share/polkit-1/actions/org.jrf.FirewallGui.policy ]; then \
		echo "Removing the system hardening helper (needs sudo):"; \
		sudo rm -f /usr/libexec/firewall-gui-helper \
			/usr/share/polkit-1/actions/org.jrf.FirewallGui.policy || \
		echo "  warning: couldn't remove it; run: sudo rm -f /usr/libexec/firewall-gui-helper /usr/share/polkit-1/actions/org.jrf.FirewallGui.policy" >&2; \
	fi
	command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$(HOME)/.local/share/applications" || true

# Full removal, including a persistent clone from a curl-bootstrapped install
# (~/.local/share/firewall-gui-src). Not part of `uninstall` since that clone
# may be a dev checkout the user wants to keep.
purge: uninstall
	rm -rf "$(HOME)/.local/share/firewall-gui-src"

# Manually trigger an update check right now instead of waiting for the timer.
update:
	systemctl --user start firewall-gui-update.service
	journalctl --user -u firewall-gui-update.service -n 20 --no-pager

reinstall: uninstall install
