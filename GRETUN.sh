#!/bin/bash
set -uo pipefail

CONF_FILE="/etc/gre-tunnel.conf"
INSTALL_BIN="/usr/local/bin/gre.sh"
SERVICE_UNIT="/etc/systemd/system/gre-tunnel.service"
WATCHDOG_SERVICE="/etc/systemd/system/gre-tunnel-watchdog.service"
WATCHDOG_TIMER="/etc/systemd/system/gre-tunnel-watchdog.timer"

ensure_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
  fi
}

detect_local_public_ip() {
  local ip=""
  for _ in {1..15}; do
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
    if [ -z "$ip" ]; then
      ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    [ -n "$ip" ] && break
    sleep 2
  done
  echo "$ip"
}

save_config() {
  cat > "$CONF_FILE" <<EOF
ROLE="$ROLE"
LOCAL_PUBLIC_IP="$LOCAL_PUBLIC_IP"
REMOTE_PUBLIC_IP="$REMOTE_PUBLIC_IP"
LOCAL_GRE_IP="$LOCAL_GRE_IP"
REMOTE_GRE_IP="$REMOTE_GRE_IP"
EOF
  chmod 600 "$CONF_FILE"
  echo "[✓] Saved configuration to $CONF_FILE"
}

load_config() {
  if [ -f "$CONF_FILE" ]; then
    # shellcheck disable=SC1090
    source "$CONF_FILE"
    return 0
  fi
  return 1
}

create_tunnel() {
  local interactive=${1:-0}
  if [ "$interactive" -eq 1 ]; then
    clear
  fi

  # Wait for network on boot when running non-interactively
  if [ "$interactive" -eq 0 ]; then
    for _ in {1..15}; do
      ip -4 route show default 2>/dev/null | grep -q . && break
      sleep 2
    done
  fi

  LOCAL_PUBLIC_IP="${LOCAL_PUBLIC_IP:-$(detect_local_public_ip)}"
  if [ -z "$LOCAL_PUBLIC_IP" ]; then
    echo "Failed to detect local public IPv4" >&2
    return 1
  fi

  if [ "$ROLE" == "1" ]; then
    SERVER_ROLE="IRAN"
    LOCAL_GRE_IP="10.10.10.1/30"
    REMOTE_GRE_IP="10.10.10.2"
  else
    SERVER_ROLE="kharej"
    LOCAL_GRE_IP="10.10.10.2/30"
    REMOTE_GRE_IP="10.10.10.1"
  fi

  echo "[*] Server role: $SERVER_ROLE"

  modprobe ip_gre 2>/dev/null || true
  echo "ip_gre" > /etc/modules-load.d/gre-tunnel.conf 2>/dev/null || true

  # Remove any existing gre1
  ip link set gre1 down 2>/dev/null || true
  ip tunnel del gre1 2>/dev/null || true

  ip tunnel add gre1 mode gre local "$LOCAL_PUBLIC_IP" remote "$REMOTE_PUBLIC_IP" ttl 255
  ip addr add "$LOCAL_GRE_IP" dev gre1
  ip link set gre1 mtu 1390
  ip link set gre1 up

  if ! ip link show gre1 >/dev/null 2>&1; then
    echo "GRE interface creation failed" >&2
    return 1
  fi

  echo 1 > /proc/sys/net/ipv4/ip_forward || true
  if [ -f /etc/sysctl.conf ]; then
    if grep -q '^#\?net.ipv4.ip_forward=' /etc/sysctl.conf; then
      sed -i 's/^#\?net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf || true
    else
      echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf || true
    fi
    sysctl -p >/dev/null 2>&1 || true
  fi

  # Allow GRE protocol and clamp MSS in iptables
  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p gre -j ACCEPT 2>/dev/null || iptables -A INPUT -p gre -j ACCEPT
    iptables -C OUTPUT -p gre -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p gre -j ACCEPT
    iptables -t mangle -C FORWARD -o gre1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1350 2>/dev/null || \
      iptables -t mangle -A FORWARD -o gre1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1350
  fi

  echo "[✓] GRE tunnel created as gre1"
  echo "Local GRE IP: $LOCAL_GRE_IP"
  echo "Remote GRE IP: $REMOTE_GRE_IP"

  # Automatically save configuration and install persistent service on interactive setup
  if [ "$interactive" -eq 1 ]; then
    save_config
    echo "[*] Installing persistent boot service and watchdog..."
    install_service || echo "Warning: Failed to install systemd service."
  fi

  return 0
}

menu_config_tunnel() {
  clear
  echo
  echo "Configure GRE Tunnel"
  echo "1) Iran Server"
  echo "2) kharej Server"
  echo
  read -rp "Select server type [1-2]: " ROLE
  if [[ "$ROLE" != "1" && "$ROLE" != "2" ]]; then
    echo "Invalid selection"
    return
  fi

  LOCAL_PUBLIC_IP="$(detect_local_public_ip)"
  echo "Local Public IP detected: $LOCAL_PUBLIC_IP"
  read -rp "Confirm or enter Local Public IPv4 [$LOCAL_PUBLIC_IP]: " INPUT_LOCAL_IP
  LOCAL_PUBLIC_IP="${INPUT_LOCAL_IP:-$LOCAL_PUBLIC_IP}"

  read -rp "Enter REMOTE server Public IPv4: " REMOTE_PUBLIC_IP
  if [ -z "$REMOTE_PUBLIC_IP" ]; then
    echo "Remote IP cannot be empty"
    return
  fi

  create_tunnel 1 || echo "create_tunnel failed"
}

status_check() {
  clear
  echo
  echo "GRE Tunnel Status"
  if ip link show gre1 >/dev/null 2>&1; then
    echo "gre1: exists and is $(ip link show gre1 | awk -F': ' 'NR==1{print $2}')"
    REMOTE_PUBLIC_OF_TUN=$(ip tunnel show gre1 2>/dev/null | awk -F'remote ' '{print $2}' | awk '{print $1}') || true
    if [ -n "$REMOTE_PUBLIC_OF_TUN" ]; then
      echo "Tunnel remote public IP: $REMOTE_PUBLIC_OF_TUN"
      echo "Pinging remote public IP (1 try)..."
      PING_PUBLIC_OUT=$(ping -c 1 -W 1 "$REMOTE_PUBLIC_OF_TUN" 2>&1) || true
      echo "$PING_PUBLIC_OUT"
      if echo "$PING_PUBLIC_OUT" | grep -qE '1 received|1 packets received|bytes from'; then
        echo "Remote public is reachable"
      else
        echo "Remote public is NOT reachable"
      fi
    fi

    if load_config && [ -n "${REMOTE_GRE_IP:-}" ]; then
      echo "Pinging remote GRE inner IP $REMOTE_GRE_IP (4 tries)..."
      PING_INNER_OUT=$(ping -c 4 -W 2 "$REMOTE_GRE_IP" 2>&1) || true
      echo "$PING_INNER_OUT"
      if echo "$PING_INNER_OUT" | grep -qE '([1-9]) received|([1-9]) packets received|bytes from'; then
        echo "GRE inner tunnel is UP ✅"
      else
        echo "GRE inner tunnel seems DOWN ❌"
      fi
    fi
  else
    echo "gre1 interface not found"
  fi
  echo
  echo "Systemd Service Status:"
  systemctl is-active gre-tunnel.service 2>/dev/null || echo "inactive"
}

remove_tun() {
  clear
  echo
  echo "Removing GRE/GRETAP/ERSPAN interfaces..."
  mapfile -t tunifs < <(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E '^(gre|gretap|erspan)' || true)

  for ifc in "${tunifs[@]:-}"; do
    [ -z "$ifc" ] && continue
    echo "Removing tunnel/interface: $ifc"
    ip link set dev "$ifc" down 2>/dev/null || true
    ip tunnel del "$ifc" 2>/dev/null || ip link delete "$ifc" 2>/dev/null || true
  done

  uninstall_service
  rm -f "$CONF_FILE" /etc/modules-load.d/gre-tunnel.conf
  echo "[✓] Tunnel, config, and persistent service completely removed."
}

write_standalone_runner() {
  mkdir -p "$(dirname "$INSTALL_BIN")"
  if [ -f "$0" ] && [[ "$0" != /dev/fd/* ]] && [[ "$0" != /proc/* ]]; then
    cp -f "$0" "$INSTALL_BIN"
  else
    cat > "$INSTALL_BIN" <<'RUNNER_EOF'
#!/bin/bash
CONF_FILE="/etc/gre-tunnel.conf"
[ -f "$CONF_FILE" ] || exit 1
source "$CONF_FILE"

for _ in {1..15}; do
  ip -4 route show default 2>/dev/null | grep -q . && break
  sleep 2
done

modprobe ip_gre 2>/dev/null || true

if [[ "${1:-}" == "--watchdog-check" ]]; then
  if ip link show gre1 >/dev/null 2>&1 && ping -c 2 -W 2 "$REMOTE_GRE_IP" >/dev/null 2>&1; then
    exit 0
  fi
fi

ip link set gre1 down 2>/dev/null || true
ip tunnel del gre1 2>/dev/null || true
ip tunnel add gre1 mode gre local "$LOCAL_PUBLIC_IP" remote "$REMOTE_PUBLIC_IP" ttl 255
ip addr add "$LOCAL_GRE_IP" dev gre1
ip link set gre1 mtu 1390
ip link set gre1 up
echo 1 > /proc/sys/net/ipv4/ip_forward || true
if command -v iptables >/dev/null 2>&1; then
  iptables -C INPUT -p gre -j ACCEPT 2>/dev/null || iptables -A INPUT -p gre -j ACCEPT
  iptables -C OUTPUT -p gre -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p gre -j ACCEPT
  iptables -t mangle -C FORWARD -o gre1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1350 2>/dev/null || \
    iptables -t mangle -A FORWARD -o gre1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1350
fi
RUNNER_EOF
  fi
  chmod 755 "$INSTALL_BIN"
}

install_service() {
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not available on this system; cannot install service." >&2
    return 1
  fi

  write_standalone_runner

  cat > "$SERVICE_UNIT" <<EOF
[Unit]
Description=GRE Tunnel Persistent Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $INSTALL_BIN --service start
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  cat > "$WATCHDOG_SERVICE" <<EOF
[Unit]
Description=GRE Tunnel Self-Healing Watchdog
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $INSTALL_BIN --watchdog-check
EOF

  cat > "$WATCHDOG_TIMER" <<EOF
[Unit]
Description=Run GRE Tunnel Watchdog every 30s

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now gre-tunnel.service
  systemctl enable --now gre-tunnel-watchdog.timer
  echo "[✓] Persistent service and watchdog installed & enabled."
}

uninstall_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now gre-tunnel-watchdog.timer 2>/dev/null || true
    systemctl disable --now gre-tunnel.service 2>/dev/null || true
    rm -f "$SERVICE_UNIT" "$WATCHDOG_SERVICE" "$WATCHDOG_TIMER"
    systemctl daemon-reload
  fi
  rm -f "$INSTALL_BIN"
}

service_start() {
  if load_config; then
    echo "Starting tunnel from saved config..."
    create_tunnel 0
  else
    echo "No saved configuration at $CONF_FILE. Service cannot start." >&2
    return 1
  fi
}

watchdog_check() {
  load_config || return 0
  if ! ip link show gre1 >/dev/null 2>&1 || ! ping -c 2 -W 2 "$REMOTE_GRE_IP" >/dev/null 2>&1; then
    echo "Watchdog detected tunnel down; recreating..."
    create_tunnel 0
  fi
}

show_menu() {
  clear
  echo "==============================="
  echo " ++ GRE Tunnel Management ++"
  echo "==============================="
  echo
  echo "1) config tunnel (Auto-Persistent)"
  echo "2) status"
  echo "3) remove tun"
  echo "0) Exit"
  echo
  read -rp "Choose an option [0-3]: " CHOICE
  case "$CHOICE" in
    1) menu_config_tunnel ; read -rp "Press Enter to continue..." _ ;;
    2) status_check ; read -rp "Press Enter to continue..." _ ;;
    3) remove_tun ; read -rp "Press Enter to continue..." _ ;;
    0) echo "Bye"; exit 0 ;;
    *) echo "Invalid option"; sleep 1 ;;
  esac
}

if [[ "${1:-}" == "--service" && "${2:-}" == "start" ]]; then
  ensure_root
  service_start
  exit $?
fi

if [[ "${1:-}" == "--watchdog-check" ]]; then
  ensure_root
  watchdog_check
  exit $?
fi

ensure_root
while true; do
  show_menu
done
