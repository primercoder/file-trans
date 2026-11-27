#!/usr/bin/env bash
# Adds KDE Dolphin and Nautilus "Send with Kite" entries to a built .deb.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEB="${1:?usage: add_desktop_integration.sh <deb>}"
WORK="$(mktemp -d /tmp/kite-deb.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

dpkg-deb -R "$DEB" "$WORK/root"
install -D -m 644 "$ROOT/packaging/linux/kio/kite-send.desktop" \
  "$WORK/root/usr/share/kio/servicemenus/kite-send.desktop"
install -D -m 755 "$ROOT/packaging/linux/nautilus/send-with-kite" \
  "$WORK/root/usr/share/kite/send-with-kite"
install -d "$WORK/root/usr/share/doc/kite"
cat > "$WORK/root/usr/share/doc/kite/file-manager.md" <<'DOC'
# File manager integration

KDE Dolphin: the "Send with Kite" entry is installed system-wide.

GNOME Files (Nautilus): copy the helper into your scripts folder once:

    mkdir -p ~/.local/share/nautilus/scripts
    cp /usr/share/kite/send-with-kite ~/.local/share/nautilus/scripts/"Send with Kite"
    chmod +x ~/.local/share/nautilus/scripts/"Send with Kite"

Then right-click a file -> Scripts -> Send with Kite.
DOC
dpkg-deb --build --root-owner-group "$WORK/root" "$DEB" >/dev/null
echo "desktop integration added to $DEB"
