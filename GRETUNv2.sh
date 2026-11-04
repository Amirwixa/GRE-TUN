#!/bin/bash
set -uo pipefail

# ============================================================
# GRE Tunnel Manager v2 (Final Persistent Edition)
#   - GRE tunnel with native kernel IPsec (ESP/AES-GCM) encryption
#   - Kernel network stack optimization (BBR + cake + buffer tuning)
#   - Optional NAT Port Forwarding (persistent across reboots)
#   - Automatic MTU/MSS clamping
#   - Guaranteed boot persistence + Self-healing watchdog (systemd timer)
#   - Works reliably even when executed via bash <(curl ...)
# ============================================================

CONF_FILE="/etc/gre-tunnel.conf"
PORTS_FILE="/etc/gre-tunnel-ports.conf"
INSTALL_BIN="/usr/local/bin/gre.sh"
SERVICE_UNIT="/etc/systemd/system/gre-tunnel.service"
WATCHDOG_SERVICE="/etc/systemd/system/gre-tunnel-watchdog.service"
WATCHDOG_TIMER="/etc/systemd/system/gre-tunnel-watchdog.timer"
SYSCTL_FILE="/etc/sysctl.d/99-gre-tunnel.conf"
MODULES_FILE="/etc/modules-load.d/gre-tunnel.conf"
TUN_IF="gre1"
LOG_TAG="gre-tunnel"

GRE_SPI_A="0x1000"
GRE_SPI_B="0x1001"

# ---------------- logging ----------------
log() {
  local level="$1"; shift
  logger -t "$LOG_TAG" -p "user.${level}" -- "$*" 2>/dev/null || true
  echo "[$level] $*"
}

ensure_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
  fi
}

require_bin() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing required binary: $1" >&2; exit 1; }
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

# ---------------- config persistence ----------------
save_config() {
  {
    printf 'ROLE=%q\n' "${ROLE:-1}"
    printf 'LOCAL_PUBLIC_IP=%q\n' "${LOCAL_PUBLIC_IP:-}"
    printf 'REMOTE_PUBLIC_IP=%q\n' "${REMOTE_PUBLIC_IP:-}"
    printf 'LOCAL_GRE_IP=%q\n' "${LOCAL_GRE_IP:-}"
    printf 'REMOTE_GRE_IP=%q\n' "${REMOTE_GRE_IP:-}"
    printf 'TUN_MTU=%q\n' "${TUN_MTU:-1400}"
    printf 'ENCRYPT_ENABLE=%q\n' "${ENCRYPT_ENABLE:-0}"
    printf 'PSK=%q\n' "${PSK:-}"
    printf 'GRE_KEY=%q\n' "${GRE_KEY:-0}"
    printf 'FORWARD_PORTS=%q\n' "${FORWARD_PORTS:-}"
  } > "$CONF_FILE"
  chmod 600 "$CONF_FILE"
  log info "Configuration saved to $CONF_FILE"
}

load_config() {
  if [ -f "$CONF_FILE" ]; then
    # shellcheck disable=SC1090
    source "$CONF_FILE"
    return 0
  fi
  return 1
}

# ---------------- kernel optimization ----------------
kernel_optimize() {
  log info "Applying kernel network optimizations (BBR + cake + buffer tuning)"

  modprobe ip_gre 2>/dev/null || true
  modprobe tcp_bbr 2>/dev/null || true
  modprobe sch_cake 2>/dev/null || true

  cat > "$MODULES_FILE" 2>/dev/null <<'EOF' || true
ip_gre
tcp_bbr
sch_cake
EOF

  cat > "$SYSCTL_FILE" <<'EOF'
# --- GRE tunnel performance tuning ---
net.core.default_qdisc = cake
net.ipv4.tcp_congestion_control = bbr

# Larger buffers for high-latency / cross-border links
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 4194304
net.core.wmem_default = 4194304
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.netdev_max_backlog = 32768
net.core.somaxconn = 8192

# PMTUD is unreliable across GRE/IPsec, let TCP probe actively
net.ipv4.tcp_mtu_probing = 2
net.ipv4.tcp_base_mss = 1024

# Reduce latency for interactive-ish traffic sharing the tunnel
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0

# GRE endpoints commonly see asymmetric routing; loosen strict RPF
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2

net.ipv4.ip_forward = 1

# Keepalive tuning so dead peers are detected quickly
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
EOF

  sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || sysctl --system >/dev/null 2>&1 || true
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
}

tune_offloads() {
  local phys_if=""
  phys_if=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' || true)
  if [ -n "$phys_if" ] && command -v ethtool >/dev/null 2>&1; then
    ethtool -K "$phys_if" gro on gso on tso on 2>/dev/null || true
    log info "Offloads (gro/gso/tso) enabled on $phys_if"
  fi
}

# ---------------- IPsec (native kernel xfrm) ----------------
derive_key() {
  printf '%s|%s' "$1" "$PSK" | sha512sum | cut -c1-40
}

setup_ipsec() {
  [ "${ENCRYPT_ENABLE:-0}" -eq 1 ] || { log info "Encryption disabled, skipping IPsec setup"; return 0; }
  [ -n "${PSK:-}" ] || { log err "ENCRYPT_ENABLE=1 but PSK is empty"; return 1; }

  require_bin ip
  modprobe esp4 2>/dev/null || true
  modprobe xfrm_user 2>/dev/null || true

  teardown_ipsec

  local key_a key_b spi_out spi_in key_out key_in
  key_a=$(derive_key "A")
  key_b=$(derive_key "B")

  if [ "$ROLE" == "1" ]; then
    spi_out="$GRE_SPI_A"; key_out="$key_a"
    spi_in="$GRE_SPI_B";  key_in="$key_b"
  else
    spi_out="$GRE_SPI_B"; key_out="$key_b"
    spi_in="$GRE_SPI_A";  key_in="$key_a"
  fi

  ip xfrm state add src "$LOCAL_PUBLIC_IP" dst "$REMOTE_PUBLIC_IP" proto esp spi "$spi_out" \
    aead 'rfc4106(gcm(aes))' "0x${key_out}" 128 mode transport

  ip xfrm state add src "$REMOTE_PUBLIC_IP" dst "$LOCAL_PUBLIC_IP" proto esp spi "$spi_in" \
    aead 'rfc4106(gcm(aes))' "0x${key_in}" 128 mode transport

  ip xfrm policy add src "$LOCAL_PUBLIC_IP" dst "$REMOTE_PUBLIC_IP" dir out proto gre \
    tmpl src "$LOCAL_PUBLIC_IP" dst "$REMOTE_PUBLIC_IP" proto esp mode transport

  ip xfrm policy add src "$REMOTE_PUBLIC_IP" dst "$LOCAL_PUBLIC_IP" dir in proto gre \
    tmpl src "$REMOTE_PUBLIC_IP" dst "$LOCAL_PUBLIC_IP" proto esp mode transport

  log info "IPsec ESP (AES-GCM-128, kernel xfrm) established for GRE traffic"
}

teardown_ipsec() {
  ip xfrm state deleteall 2>/dev/null || true
  ip xfrm policy deleteall 2>/dev/null || true
}

# ---------------- Firewall & NAT Port Forwarding ----------------
apply_mss_clamp() {
  local mss=$(( TUN_MTU - 40 ))
  if command -v iptables >/dev/null 2>&1; then
    iptables -t mangle -D FORWARD -o "$TUN_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss" 2>/dev/null || true
    iptables -t mangle -A FORWARD -o "$TUN_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
    iptables -t mangle -D FORWARD -i "$TUN_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss" 2>/dev/null || true
    iptables -t mangle -A FORWARD -i "$TUN_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
    log info "MSS clamped to $mss on $TUN_IF (MTU=$TUN_MTU)"
  fi
}

apply_port_forwarding() {
  [ -z "${FORWARD_PORTS:-}" ] && return 0
  command -v iptables >/dev/null 2>&1 || return 0

  # Ensure FORWARD chain permits tunnel traffic
  iptables -C FORWARD -i "$TUN_IF" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$TUN_IF" -j ACCEPT
  iptables -C FORWARD -o "$TUN_IF" -j ACCEPT 2>/dev/null || iptables -A FORWARD -o "$TUN_IF" -j ACCEPT

  # Masquerade traffic going into tunnel towards remote GRE IP
  iptables -t nat -C POSTROUTING -o "$TUN_IF" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "$TUN_IF" -j MASQUERADE

  IFS=',' read -ra PORT_LIST <<< "$FORWARD_PORTS"
  for p in "${PORT_LIST[@]}"; do
    p=$(echo "$p" | tr -d ' ')
    [ -z "$p" ] && continue
    # Support single port (e.g. 443) or range (e.g. 2000:2050 or 2000-2050)
    local ipt_port="${p//-/:}"
    local dnat_target="$REMOTE_GRE_IP"
    if [[ "$p" != *":"* && "$p" != *"-"* ]]; then
      dnat_target="${REMOTE_GRE_IP}:${p}"
    fi

    iptables -t nat -C PREROUTING -p tcp -d "$LOCAL_PUBLIC_IP" --dport "$ipt_port" -j DNAT --to-destination "$dnat_target" 2>/dev/null || \
      iptables -t nat -A PREROUTING -p tcp -d "$LOCAL_PUBLIC_IP" --dport "$ipt_port" -j DNAT --to-destination "$dnat_target"
    iptables -t nat -C PREROUTING -p udp -d "$LOCAL_PUBLIC_IP" --dport "$ipt_port" -j DNAT --to-destination "$dnat_target" 2>/dev/null || \
      iptables -t nat -A PREROUTING -p udp -d "$LOCAL_PUBLIC_IP" --dport "$ipt_port" -j DNAT --to-destination "$dnat_target"
  done
  log info "Applied persistent NAT port forwarding for ports: $FORWARD_PORTS -> $REMOTE_GRE_IP"
}

# ---------------- tunnel lifecycle ----------------
create_tunnel() {
  local interactive=${1:-0}
  [ "$interactive" -eq 1 ] && clear

  # Wait for network stack readiness during boot
  if [ "$interactive" -eq 0 ]; then
    for _ in {1..15}; do
      ip -4 route show default 2>/dev/null | grep -q . && break
      sleep 2
    done
  fi

  LOCAL_PUBLIC_IP="${LOCAL_PUBLIC_IP:-$(detect_local_public_ip)}"
  if [ -z "$LOCAL_PUBLIC_IP" ]; then
    log err "Failed to detect local public IPv4"
    return 1
  fi

  TUN_MTU="${TUN_MTU:-1400}"

  if [ "$ROLE" == "1" ]; then
    SERVER_ROLE="IRAN"
    LOCAL_GRE_IP="10.10.10.1/30"
    REMOTE_GRE_IP="10.10.10.2"
  else
    SERVER_ROLE="kharej"
    LOCAL_GRE_IP="10.10.10.2/30"
    REMOTE_GRE_IP="10.10.10.1"
  fi

  log info "Server role: $SERVER_ROLE"

  modprobe ip_gre 2>/dev/null || true

  ip link set "$TUN_IF" down 2>/dev/null || true
  ip tunnel del "$TUN_IF" 2>/dev/null || true

  local key_opt=""
  [ "${GRE_KEY:-0}" != "0" ] && [ -n "${GRE_KEY:-}" ] && key_opt="key ${GRE_KEY}"

  # shellcheck disable=SC2086
  ip tunnel add "$TUN_IF" mode gre local "$LOCAL_PUBLIC_IP" remote "$REMOTE_PUBLIC_IP" ttl 255 $key_opt
  ip addr add "$LOCAL_GRE_IP" dev "$TUN_IF"
  ip link set "$TUN_IF" mtu "$TUN_MTU"
  ip link set "$TUN_IF" up

  if ! ip link show "$TUN_IF" >/dev/null 2>&1; then
    log err "GRE interface creation failed"
    return 1
  fi

  kernel_optimize
  tune_offloads
  apply_mss_clamp

  if [ "${ENCRYPT_ENABLE:-0}" -eq 1 ]; then
    setup_ipsec || log warning "IPsec setup failed, tunnel is running UNENCRYPTED"
  else
    teardown_ipsec
  fi

  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p gre -j ACCEPT 2>/dev/null || iptables -A INPUT -p gre -j ACCEPT
    iptables -C OUTPUT -p gre -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p gre -j ACCEPT
    if [ "${ENCRYPT_ENABLE:-0}" -eq 1 ]; then
      iptables -C INPUT -p esp -j ACCEPT 2>/dev/null || iptables -A INPUT -p esp -j ACCEPT
      iptables -C OUTPUT -p esp -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p esp -j ACCEPT
    fi
  fi

  apply_port_forwarding

  log info "GRE tunnel up: $TUN_IF, local=$LOCAL_GRE_IP remote=$REMOTE_GRE_IP mtu=$TUN_MTU encrypt=${ENCRYPT_ENABLE:-0}"

  # Always persist configuration & install boot service + watchdog automatically
  if [ "$interactive" -eq 1 ]; then
    save_config
    echo "[*] Installing persistent systemd service + self-healing watchdog..."
    install_service || echo "Failed to install service."
    install_watchdog || echo "Failed to install watchdog."
    echo "[✓] Tunnel is now 100% persistent across reboots!"
  fi

  return 0
}

menu_config_tunnel() {
  clear
  echo "Configure GRE Tunnel (Auto-Persistent)"
  echo "1) Iran Server"
  echo "2) kharej Server"
  read -rp "Select server type [1-2]: " ROLE
  if [[ "$ROLE" != "1" && "$ROLE" != "2" ]]; then
    echo "Invalid selection"; return
  fi

  LOCAL_PUBLIC_IP="$(detect_local_public_ip)"
  echo "Local Public IP detected: $LOCAL_PUBLIC_IP"
  read -rp "Confirm or enter Local Public IPv4 [$LOCAL_PUBLIC_IP]: " INPUT_LOCAL_IP
  LOCAL_PUBLIC_IP="${INPUT_LOCAL_IP:-$LOCAL_PUBLIC_IP}"

  read -rp "Enter REMOTE server Public IPv4: " REMOTE_PUBLIC_IP
  [ -n "$REMOTE_PUBLIC_IP" ] || { echo "Remote IP cannot be empty"; return; }

  read -rp "Tunnel MTU [1400]: " TUN_MTU_IN
  TUN_MTU="${TUN_MTU_IN:-1400}"

  read -rp "Enable encryption (IPsec ESP/AES-GCM)? [Y/n]: " enc
  case "$enc" in
    [Nn]*) ENCRYPT_ENABLE=0; PSK="" ;;
    *)
      ENCRYPT_ENABLE=1
      read -rsp "Enter shared PSK (same on both servers): " PSK
      echo
      if [ -z "$PSK" ]; then
        echo "PSK cannot be empty when encryption is enabled."; return
      fi
      ;;
  esac

  read -rp "Optional GRE key (0 = none, must match on both sides) [0]: " GRE_KEY_IN
  GRE_KEY="${GRE_KEY_IN:-0}"

  FORWARD_PORTS=""
  if [ "$ROLE" == "1" ]; then
    read -rp "Optional ports to forward from Iran to Kharej (comma-separated, e.g. 443,8443,2053 or Enter to skip): " FORWARD_PORTS
  fi

  create_tunnel 1 || echo "create_tunnel failed"
}

menu_add_ports() {
  clear
  if ! load_config; then
    echo "Please configure the tunnel first (Option 1)."
    return
  fi
  echo "Current forwarded ports: ${FORWARD_PORTS:-None}"
  read -rp "Enter comma-separated ports to forward to $REMOTE_GRE_IP (e.g. 443,8080,2000-2010): " NEW_PORTS
  FORWARD_PORTS="$NEW_PORTS"
  save_config
  apply_port_forwarding
  echo "[✓] Ports updated and saved persistently."
}

status_check() {
  clear
  echo "GRE Tunnel Status"
  if ip link show "$TUN_IF" >/dev/null 2>&1; then
    echo "$TUN_IF: $(ip link show "$TUN_IF" | awk -F': ' 'NR==1{print $2}')"
    echo "Congestion control: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
    echo "Qdisc: $(tc qdisc show dev "$TUN_IF" 2>/dev/null | head -1)"

    REMOTE_PUBLIC_OF_TUN=$(ip tunnel show "$TUN_IF" 2>/dev/null | awk -F'remote ' '{print $2}' | awk '{print $1}') || true
    if [ -n "$REMOTE_PUBLIC_OF_TUN" ]; then
      echo "Tunnel remote public IP: $REMOTE_PUBLIC_OF_TUN"
      PING_PUBLIC_OUT=$(ping -c 1 -W 1 "$REMOTE_PUBLIC_OF_TUN" 2>&1) || true
      echo "$PING_PUBLIC_OUT"
    fi

    if load_config && [ -n "${REMOTE_GRE_IP:-}" ]; then
      echo "Pinging remote GRE inner IP $REMOTE_GRE_IP (4 tries)..."
      PING_INNER_OUT=$(ping -c 4 -W 2 "$REMOTE_GRE_IP" 2>&1) || true
      echo "$PING_INNER_OUT"
      if echo "$PING_INNER_OUT" | grep -qE '([1-9]) received|bytes from'; then
        echo "GRE inner tunnel is UP ✅"
      else
        echo "GRE inner tunnel seems DOWN ❌"
      fi
    fi

    if [ "${ENCRYPT_ENABLE:-0}" -eq 1 ]; then
      echo "--- IPsec state ---"
      ip -s xfrm state 2>/dev/null | head -20
    fi
  else
    echo "$TUN_IF interface not found"
  fi
  echo "--- Systemd Persistence Status ---"
  echo "Main Service: $(systemctl is-active gre-tunnel.service 2>/dev/null || echo inactive)"
  echo "Watchdog Timer: $(systemctl is-active gre-tunnel-watchdog.timer 2>/dev/null || echo inactive)"
}

remove_tun() {
  clear
  echo "Removing GRE/GRETAP/ERSPAN interfaces, IPsec state, and services..."
  teardown_ipsec

  mapfile -t tunifs < <(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E '^(gre|gretap|erspan)' || true)

  for ifc in "${tunifs[@]:-}"; do
    [ -z "$ifc" ] && continue
    ip link set dev "$ifc" down 2>/dev/null || true
    ip tunnel del "$ifc" 2>/dev/null || ip link delete "$ifc" 2>/dev/null || true
    echo "- $ifc removed"
  done

  uninstall_watchdog
  uninstall_service
  rm -f "$CONF_FILE" "$SYSCTL_FILE" "$MODULES_FILE"
  echo "[✓] Tunnel, configuration, and systemd services completely removed."
}

# ---------------- Self-contained binary installer ----------------
install_runner_script() {
  mkdir -p "$(dirname "$INSTALL_BIN")"
  # If executed from a normal file on disk, copy it; if run via bash <(curl ...), reconstruct from current bash functions
  if [ -f "$0" ] && [[ "$0" != /dev/fd/* ]] && [[ "$0" != /proc/* ]]; then
    cp -f "$0" "$INSTALL_BIN"
  else
    {
      echo '#!/bin/bash'
      echo 'set -uo pipefail'
      echo 'CONF_FILE="/etc/gre-tunnel.conf"'
      echo 'PORTS_FILE="/etc/gre-tunnel-ports.conf"'
      echo 'INSTALL_BIN="/usr/local/bin/gre.sh"'
      echo 'SERVICE_UNIT="/etc/systemd/system/gre-tunnel.service"'
      echo 'WATCHDOG_SERVICE="/etc/systemd/system/gre-tunnel-watchdog.service"'
      echo 'WATCHDOG_TIMER="/etc/systemd/system/gre-tunnel-watchdog.timer"'
      echo 'SYSCTL_FILE="/etc/sysctl.d/99-gre-tunnel.conf"'
      echo 'MODULES_FILE="/etc/modules-load.d/gre-tunnel.conf"'
      echo 'TUN_IF="gre1"'
      echo 'LOG_TAG="gre-tunnel"'
      echo 'GRE_SPI_A="0x1000"'
      echo 'GRE_SPI_B="0x1001"'
      echo 'WATCHDOG_FAILS_FILE="/run/gre-tunnel-watchdog.fails"'
      echo 'WATCHDOG_MAX_FAILS=2'
      declare -f log ensure_root require_bin detect_local_public_ip save_config load_config \
        kernel_optimize tune_offloads derive_key setup_ipsec teardown_ipsec apply_mss_clamp \
        apply_port_forwarding create_tunnel service_start watchdog_check
      cat <<'ENTRY_EOF'
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
ENTRY_EOF
    } > "$INSTALL_BIN"
  fi
  chmod 755 "$INSTALL_BIN"
}

# ---------------- systemd: main service ----------------
install_service() {
  command -v systemctl >/dev/null 2>&1 || { echo "systemctl not available" >&2; return 1; }

  install_runner_script

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

  systemctl daemon-reload
  systemctl enable --now gre-tunnel.service
  log info "gre-tunnel.service installed and started"
}

uninstall_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now gre-tunnel.service 2>/dev/null || true
    rm -f "$SERVICE_UNIT"
    systemctl daemon-reload
  fi
  rm -f "$INSTALL_BIN"
  log info "gre-tunnel.service uninstalled"
}

service_start() {
  if load_config; then
    log info "Starting tunnel from saved config..."
    create_tunnel 0
  else
    log err "No saved configuration at $CONF_FILE. Service cannot start."
    return 1
  fi
}

# ---------------- systemd: watchdog (self-healing) ----------------
install_watchdog() {
  command -v systemctl >/dev/null 2>&1 || { echo "systemctl not available" >&2; return 1; }

  install_runner_script

  cat > "$WATCHDOG_SERVICE" <<EOF
[Unit]
Description=GRE Tunnel Watchdog Check
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $INSTALL_BIN --watchdog-check
EOF

  cat > "$WATCHDOG_TIMER" <<EOF
[Unit]
Description=Run GRE Tunnel Watchdog every 15s

[Timer]
OnBootSec=25s
OnCalendar=*:*:0/15
AccuracySec=1s

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now gre-tunnel-watchdog.timer
  log info "gre-tunnel-watchdog.timer installed (checks every 15s)"
}

uninstall_watchdog() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now gre-tunnel-watchdog.timer 2>/dev/null || true
    rm -f "$WATCHDOG_SERVICE" "$WATCHDOG_TIMER"
    systemctl daemon-reload
  fi
  log info "Watchdog uninstalled"
}

WATCHDOG_FAILS_FILE="/run/gre-tunnel-watchdog.fails"
WATCHDOG_MAX_FAILS=2

watchdog_check() {
  load_config || { log err "watchdog: no config, skipping"; return 0; }

  local fails=0
  [ -f "$WATCHDOG_FAILS_FILE" ] && fails=$(cat "$WATCHDOG_FAILS_FILE" 2>/dev/null || echo 0)

  if ! ip link show "$TUN_IF" >/dev/null 2>&1 || ! ping -c 2 -W 2 "$REMOTE_GRE_IP" >/dev/null 2>&1; then
    fails=$((fails + 1))
    echo "$fails" > "$WATCHDOG_FAILS_FILE"
    log warning "watchdog: tunnel check failed ($fails/$WATCHDOG_MAX_FAILS)"
    if [ "$fails" -ge "$WATCHDOG_MAX_FAILS" ]; then
      log warning "watchdog: rebuilding tunnel after $fails consecutive failures"
      create_tunnel 0 && echo 0 > "$WATCHDOG_FAILS_FILE"
    fi
  else
    [ "$fails" -ne 0 ] && log info "watchdog: tunnel recovered"
    echo 0 > "$WATCHDOG_FAILS_FILE"
  fi
}

# ---------------- menu ----------------
show_menu() {
  clear
  echo "=========================================="
  echo " ++ GRE Tunnel Management v2 (Final) ++"
  echo "=========================================="
  echo "1) Configure Tunnel (Auto-Persistent)"
  echo "2) Tunnel & Service Status"
  echo "3) Configure NAT Port Forwarding (Iran)"
  echo "4) Reinstall/Refresh Watchdog & Service"
  echo "5) Remove Tunnel & Services"
  echo "0) Exit"
  read -rp "Choose an option [0-5]: " CHOICE
  case "$CHOICE" in
    1) menu_config_tunnel ; read -rp "Press Enter to continue..." _ ;;
    2) load_config >/dev/null 2>&1 || true; status_check ; read -rp "Press Enter to continue..." _ ;;
    3) menu_add_ports ; read -rp "Press Enter to continue..." _ ;;
    4) install_service; install_watchdog ; read -rp "Press Enter to continue..." _ ;;
    5) load_config >/dev/null 2>&1 || true; remove_tun ; read -rp "Press Enter to continue..." _ ;;
    0) echo "Bye"; exit 0 ;;
    *) echo "Invalid option"; sleep 1 ;;
  esac
}

### Script entry
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
