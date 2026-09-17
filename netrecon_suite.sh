#!/usr/bin/env bash
# netrecon_suite.sh — Network Recon & Diagnostic Toolkit (single file, v1.1)
# All 4 modules + FINAL_REPORT + self-tests + --gen-files (spawns GitHub repo files)
# USAGE: ./netrecon_suite.sh [target] | --gen-files | -h
# AUTHORIZED USE ONLY — targets you own or have written permission to test.
set -Eeuo pipefail; IFS=$'\n\t'; export LC_ALL=C; umask 027

SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"; VERSION="1.1.0"
RUN_STAMP="$(date +%Y%m%d_%H%M%S)"; RUN_START_EPOCH="$(date +%s)"
CUSTOM_ROOT=""; IFACE=""; ZOMBIE=""; FORCE_LOCAL=0; MODULES_SPEC=""; TIMEOUT_SET=0
LOCAL_CIDR=""; FAST_MODE=0; EVASIVE=0
OUT_ROOT=""; OUTDIR=""; DIR_M1=""; DIR_M2=""; DIR_M3=""; DIR_M4=""
LOGFILE=""; REPORT=""; README_MD=""
TARGET_RAW=""; TARGET_TYPE="unknown"; TARGET_IP=""; TARGET_LABEL=""; MODULES=()
REPORT_FINALIZED=0; RUN_TOOL_LAST_RC=0; PICKED_TOOL=""
M2_CIDR=""; M3_ALIVE=0; M3_OPEN_PORT=""; M4_TLS_OPEN=0; M4_SMB_OPEN=0; M4_V6_ADDR=""
HINT_DEB="sudo apt update && sudo apt install -y dnsutils whois traceroute mtr-tiny nmap masscan zmap hping3 arp-scan netdiscover fping tcpdump tshark iftop nethogs iperf3 ethtool sslscan testssl.sh whatweb wafw00f nikto enum4linux snmp geoip-bin lsof net-tools curl"
HINT_ARCH="sudo pacman -S --needed bind-tools whois traceroute mtr nmap masscan zmap hping3 arp-scan netdiscover fping tcpdump wireshark-cli iftop nethogs iperf3 ethtool sslscan testssl whatweb wafw00f nikto enum4linux snmp geoip lsof net-tools curl"

# ======================= USER-CONFIGURABLE DEFAULTS (edit freely) ============
QUIET_MODE=1            # 1=quiet console (--verbose to change)
AUTO_CONFIRM=1          # 1=never prompt (--ask to change)
DEFAULT_TIMEOUT=60      # per-tool seconds (--timeout N)
DEFAULT_TIMEOUT_FAST=15
DEFAULT_KILL_GRACE=5
PING_PROFILE_COUNT=20; PING_PROFILE_INTERVAL=0.2
PING_JITTER_COUNT=100; PING_JITTER_INTERVAL=0.05
PING6_COUNT=20
MTR_REPORT_CYCLES=10; MTR_PERF_CYCLES=50
TCPDUMP_PKT_COUNT=500; TCPDUMP_PKT_COUNT_FAST=100
MASSCAN_RATE=1000; NMAP_TOP_UDP_PORTS=100
IPERF3_DURATION=10; IFTOP_SNAPSHOT_SECS=20; NETHOGS_CYCLES=5
HPING_PROBE_COUNT=5; M2_MAX_SWEEP_HOSTS=1024
TOOL_CHAIN_DNS=(dig host nslookup getent)
TOOL_CHAIN_REVERSE=(dig host nslookup)
TOOL_CHAIN_TRACEROUTE=(traceroute tracepath)
TOOL_CHAIN_NETCAT=(ncat nc builtin)
TOOL_CHAIN_HOSTSWEEP=(fping nmap ping)
TOOL_CHAIN_SOCKETS=(ss netstat lsof)
TOOL_CHAIN_INTERFACES=(ip ifconfig)
TOOL_CHAIN_ARPCACHE=(ip arp)
TOOL_CHAIN_TLS=(openssl curl)
TOOL_CHAIN_GEOIP=(geoiplookup curl)
ONLINE_FALLBACK_GEOIP=1
MACVENDOR_API_PAUSE_SECS=1; MACVENDOR_API_MAX=50
TIMEOUT_SECS="$DEFAULT_TIMEOUT"

# ======================= COLORS / FORMAT =====================================
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_RED=$'\033[1;31m'; C_GREEN=$'\033[1;32m'; C_YELLOW=$'\033[1;33m'
    C_BLUE=$'\033[1;34m'; C_MAGENTA=$'\033[1;35m'; C_CYAN=$'\033[1;36m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""
    C_BLUE=""; C_MAGENTA=""; C_CYAN=""
fi
hr_plain() { printf '%*s\n' "${2:-78}" '' | tr ' ' "${1:-=}"; }
print_section() { local id="${1:?print_section}" title="${2:?print_section}"
    local IFS=' '
    log "EXEC" ""
    log "EXEC" "=============================================================================="
    log "EXEC" "  SECTION ${id} — ${title}"
    log "EXEC" "=============================================================================="
}

# ======================= SMALL UTILITIES =====================================
ts()         { date '+%Y-%m-%dT%H:%M:%S%z'; }
now_epoch()  { date +%s; }
elapsed()    { local d=$(( ${2:?elapsed} - ${1:?elapsed} )); (( d < 0 )) && d=0
    if (( d < 60 )); then printf '%ds' "$d"
    elif (( d < 3600 )); then printf '%dm%02ds' $(( d/60 )) $(( d%60 ))
    else printf '%dh%02dm%02ds' $(( d/3600 )) $(( (d%3600)/60 )) $(( d%60 )); fi; }
sanitize_dirname() { local c; c="$(printf '%s' "${1:-unknown}" | tr -c 'A-Za-z0-9._-' '_')"
    c="${c#${c%%[!_]*}}"; c="${c%${c##*[!_]}}"; c="${c:0:64}"
    [[ -z "$c" ]] && c="unknown_target"; printf '%s' "$c"; }
die() { local code="${1:?die}"; shift; local IFS=' '; log "ERROR" "$*"; exit "$code"; }
confirm_action() { local prompt="${1:?confirm}"
    if [[ "${AUTO_CONFIRM}" -eq 1 ]]; then log "DEBUG" "gate auto-passed: ${prompt}"; return 0; fi
    [[ -t 0 ]] || { log "WARN" "non-interactive → skipped: ${prompt}"; return 1; }
    local reply=""; read -r -p "Confirm? [y/N]: " reply || return 1
    [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]; }

# ======================= LOGGING & EXECUTION CORE ============================
has() { local tool="${1:?has}";
    local flag="HAS_$(printf '%s' "$tool" | tr -c 'A-Za-z0-9' '_')"
    [[ -n "${!flag:-}" ]] && { [[ "${!flag}" == "1" ]]; return; }
    if command -v "$tool" > /dev/null 2>&1; then printf -v "$flag" '%s' "1"; return 0; fi
    printf -v "$flag" '%s' "0"; return 1; }
pick_tool() { local purpose="${1:?pick}"; shift; local t
    for t in "$@"; do
        if [[ "$t" == "builtin" ]]; then PICKED_TOOL="builtin"; return 0; fi
        if has "$t"; then PICKED_TOOL="$t"; return 0; fi
    done; PICKED_TOOL=""; return 1; }
log() { local level="${1:-INFO}"; shift; local IFS=' '; local msg="$*"
    [[ "$level" == "DEBUG" && "${QUIET_MODE}" -eq 1 ]] && return 0
    local now color show=1; now="$(date '+%H:%M:%S')"
    case "$level" in OK)color="$C_GREEN";; WARN|SKIP)color="$C_YELLOW";; ERROR)color="$C_RED";;
        EXEC)color="$C_CYAN";; DEBUG)color="$C_DIM";; FINAL)color="$C_BOLD$C_CYAN";; *)color="$C_BLUE";; esac
    if [[ "${QUIET_MODE}" -eq 1 ]]; then case "$level" in ERROR|WARN|FINAL);; *) show=0;; esac; fi
    (( show )) && printf '%s[%s] [%-5s]%s %s\n' "$color" "$now" "$level" "$C_RESET" "$msg"
    [[ -n "${LOGFILE:-}" ]] && printf '[%s] [%s] %s\n' "$(ts)" "$level" "$msg" >> "$LOGFILE"; return 0; }
log_tool() { local tool="${1:?log_tool}" status="${2:?log_tool}" dur="${3:-0}" detail="${4:-}"
    local line="TOOL: ${tool} | STATUS: ${status} | dur=${dur}s"
    [[ -n "$detail" ]] && line+=" | ${detail}"
    [[ -n "${LOGFILE:-}" ]] && printf '[%s] %s\n' "$(ts)" "$line" >> "$LOGFILE"
    if [[ "${QUIET_MODE}" -eq 1 && "$status" == "RUNNING" ]]; then return 0; fi
    local color; case "$status" in OK)color="$C_GREEN";; RUNNING)color="$C_CYAN";;
        TIMEOUT)color="$C_MAGENTA";; ERROR)color="$C_RED";; *)color="$C_YELLOW";; esac
    printf '  %s[%-8s]%s %-22s (%ss)%s%s\n' "$color" "$status" "$C_RESET" "$tool" "$dur" \
        "${detail:+ — }" "${detail:-}"; return 0; }
tool_skip() { log_tool "${1:?tool_skip}" "SKIPPED" 0 "${2:?tool_skip reason}"; }
# run_tool [--root] <label> <outfile> <timeout> -- <cmd...>  (always returns 0)
run_tool() {
    local want_root=0; [[ "${1:-}" == "--root" ]] && { want_root=1; shift; }
    local label="${1:?run_tool}" outfile="${2:?run_tool}" tsecs="${3:-$TIMEOUT_SECS}"; shift 3
    [[ "${1:-}" == "--" ]] || die 2 "run_tool('${label}'): missing '--' separator (script bug)"
    shift; local IFS=' '; local -a cmd=("$@")
    (( ${#cmd[@]} > 0 )) || die 2 "run_tool('${label}'): empty command (script bug)"
    (( tsecs <= 0 )) && tsecs="$TIMEOUT_SECS"
    if ! has "${cmd[0]}"; then RUN_TOOL_LAST_RC=0
        log_tool "$label" "SKIPPED" 0 "not installed — fallback chain may cover this"; return 0; fi
    if [[ "$want_root" -eq 1 && "$EUID" -ne 0 ]]; then RUN_TOOL_LAST_RC=0
        log_tool "$label" "SKIPPED" 0 "requires root — re-run with sudo"; return 0; fi
    : >> "$outfile" 2> /dev/null || die 1 "run_tool('${label}'): cannot write '${outfile}' — check permissions"
    { printf '\n'; hr_plain "="; printf '### TOOL: %s | %s\n### CMD: %s\n### TIMEOUT: %ss\n' \
        "$label" "$(ts)" "$*" "$tsecs"; } >> "$outfile"
    log_tool "$label" "RUNNING" 0 "timeout=${tsecs}s"
    local start end rc status detail; start="$(now_epoch)"
    set +e
    if [[ "${QUIET_MODE}" -eq 0 ]]; then
        timeout -k "$DEFAULT_KILL_GRACE" "$tsecs" "$@" 2>&1 | tee -a "$outfile"; rc=${PIPESTATUS[0]}
    else
        timeout -k "$DEFAULT_KILL_GRACE" "$tsecs" "$@" >> "$outfile" 2>&1; rc=$?
    fi
    set -e; end="$(now_epoch)"; local dur=$(( end - start )); RUN_TOOL_LAST_RC="$rc"
    case "$rc" in
        0)   status="OK"; detail="" ;;
        124) status="TIMEOUT"; detail="exceeded ${tsecs}s — raise via --timeout N" ;;
        126) status="ERROR"; detail="rc=126 not executable — check perms / run with sudo" ;;
        127) status="ERROR"; detail="rc=127 not found — reinstall the tool" ;;
        *)   status="ERROR"; detail="rc=${rc} — see tail of this output file" ;;
    esac
    { printf '### END: %s | STATUS: %s (rc=%s)\n' "$(ts)" "$status" "$rc"; hr_plain "="; } >> "$outfile"
    log_tool "$label" "$status" "$dur" "$detail"; return 0; }

# ======================= DEPENDENCY CHECKER ==================================
REQUIRED_CMDS=(timeout date tee stat find du grep awk sed tr ip curl)
OPTIONAL_TOOLS=("dig|dns" "nslookup|dns" "host|dns" "whois|dns" "traceroute|route"
 "tracepath|route" "mtr|route" "geoiplookup|geoip" "bgpq3|bgp" "bgpq4|bgp" "getent|dns"
 "dnsrecon|enum" "dnsenum|enum" "fierce|enum" "amass|enum" "subfinder|enum" "theHarvester|enum"
 "theharvester|enum" "arp-scan|l2" "arping|l2" "netdiscover|l2" "fping|l2" "iw|wifi"
 "iwlist|wifi" "ifconfig|legacy" "arp|legacy" "lsof|host" "netstat|legacy" "nmap|host"
 "ping|telemetry" "ping6|telemetry" "tcpdump|telemetry" "tshark|telemetry" "iftop|telemetry"
 "nethogs|telemetry" "iperf3|telemetry" "ethtool|telemetry" "nstat|telemetry" "ss|telemetry"
 "masscan|scan" "zmap|scan" "hping3|scan" "nc|netcat" "ncat|netcat" "socat|netcat"
 "openssl|tls" "sslscan|tls" "testssl.sh|tls" "testssl|tls" "whatweb|web" "wafw00f|web"
 "nikto|web" "enum4linux|smb" "enum4linux-ng|smb" "snmpwalk|snmp")
check_dependencies() {
    (( BASH_VERSINFO[0] >= 4 )) || die 3 "bash >= 4.0 required, found ${BASH_VERSION}"
    local -a missing=(); local cmd
    for cmd in "${REQUIRED_CMDS[@]}"; do command -v "$cmd" > /dev/null 2>&1 || missing+=("$cmd"); done
    if (( ${#missing[@]} > 0 )); then local list
        list="$(printf '%s\n' "${missing[@]}" | tr '\n' ' ')"
        die 3 "missing REQUIRED deps: ${list% } — install coreutils/iproute2/curl then re-run"; fi
    local entry tool cat
    for entry in "${OPTIONAL_TOOLS[@]}"; do IFS='|' read -r tool cat <<< "$entry"; has "$tool" || true; done
    log "OK" "required deps present + optional cache primed"; }
print_dep_report() { local entry tool cat avail=0 total=0; log "EXEC" "--- OPTIONAL TOOL AVAILABILITY ---"
    for entry in "${OPTIONAL_TOOLS[@]}"; do IFS='|' read -r tool cat <<< "$entry"; total=$((total+1))
        if has "$tool"; then avail=$((avail+1)); log "OK" "dep [$cat] ${tool}"
        else log "SKIP" "dep [$cat] ${tool} — MISSING (fallback/skip applies)"; fi; done
    log "INFO" "optional coverage: ${avail}/${total}"; }

# ======================= OUTPUT DIRS + PER-RUN README + SNAPSHOT =============
init_output_dirs() {
    local label; label="$(sanitize_dirname "${1:?init_output_dirs}")"; TARGET_LABEL="$label"
    local root="${CUSTOM_ROOT:-netrecon_results}"; OUT_ROOT="$root"
    local base="${root}/${label}_${RUN_STAMP}"
    local candidate="$base" n=1
    while [[ -e "$candidate" ]]; do n=$((n+1)); candidate="${base}_${n}"; done; OUTDIR="$candidate"
    mkdir -p "$OUTDIR" || die 1 "cannot create '${OUTDIR}' — check permissions or use -o /path"
    DIR_M1="$OUTDIR/01_dns_routing"; DIR_M2="$OUTDIR/02_local_l2"
    DIR_M3="$OUTDIR/03_remote_perf"; DIR_M4="$OUTDIR/04_blackbox"
    mkdir -p "$DIR_M1" "$DIR_M2" "$DIR_M3" "$DIR_M4" "$OUTDIR/logs" \
        || die 1 "cannot create module subdirs under '${OUTDIR}'"
    LOGFILE="$OUTDIR/logs/execution_log.txt"; REPORT="$OUTDIR/FINAL_REPORT.txt"; README_MD="$OUTDIR/README.md"
    : >> "$LOGFILE" || die 1 "cannot write ${LOGFILE}"; : >> "$REPORT" || die 1 "cannot write ${REPORT}"
    { hr_plain "="; printf '### NETRECON EXECUTION LOG | target=%s | %s | v%s\n' "$label" "$(ts)" "$VERSION"; hr_plain "="; } >> "$LOGFILE"
    { printf '### NETRECON FINAL REPORT (in progress) | target=%s | %s\n' "$label" "$(ts)"; } >> "$REPORT"
    write_run_readme; log "FINAL" "results directory: ${OUTDIR}"; }
write_run_readme() {
    { printf '# Run README — generated %s\n\n' "$(ts)"
      printf '## Live defaults for this run\n\n| Setting | Value |\n|---|---|\n'
      printf '| DEFAULT_TIMEOUT | %s |\n| fast timeout | %s |\n| ping profile | %s @ %s |\n' \
        "$DEFAULT_TIMEOUT" "$DEFAULT_TIMEOUT_FAST" "$PING_PROFILE_COUNT" "$PING_PROFILE_INTERVAL"
      printf '| jitter | %s @ %s |\n| mtr M1/M3 | %s/%s |\n| pcap cap | %s (fast %s) |\n' \
        "$PING_JITTER_COUNT" "$PING_JITTER_INTERVAL" "$MTR_REPORT_CYCLES" "$MTR_PERF_CYCLES" \
        "$TCPDUMP_PKT_COUNT" "$TCPDUMP_PKT_COUNT_FAST"
      printf '| masscan rate | %s |\n| sweep limit | %s hosts |\n' "$MASSCAN_RATE" "$M2_MAX_SWEEP_HOSTS"
      printf '\n## Effective toolchain (first available wins)\n\n| Job | Selected | Chain |\n|---|---|---|\n'
    } > "$README_MD"
    local row chain
    for row in "DNS:TOOL_CHAIN_DNS" "Reverse:TOOL_CHAIN_REVERSE" "Traceroute:TOOL_CHAIN_TRACEROUTE" \
               "Netcat:TOOL_CHAIN_NETCAT" "HostSweep:TOOL_CHAIN_HOSTSWEEP" "Sockets:TOOL_CHAIN_SOCKETS" \
               "Interfaces:TOOL_CHAIN_INTERFACES" "ARPCache:TOOL_CHAIN_ARPCACHE" "TLS:TOOL_CHAIN_TLS" \
               "GeoIP:TOOL_CHAIN_GEOIP"; do
        local name="${row%%:*}" var="${row##*:}"; local -a ch=(); eval 'ch=("${'"$var"'[@]}")'
        chain="${ch[*]}"
        if pick_tool "$name" "${ch[@]}"; then
            printf '| %s | **%s** | %s |\n' "$name" "$PICKED_TOOL" "$chain" >> "$README_MD"
        else
            printf '| %s | none | %s |\n' "$name" "$chain" >> "$README_MD"; fi
    done
    printf '\nInstall hints:\nDebian/Kali: %s\nArch: %s\n' "$HINT_DEB" "$HINT_ARCH" >> "$README_MD"
    log "OK" "run README → ${README_MD}"; }
snapshot_env() {
    { hr_plain "="; printf '### ENV SNAPSHOT %s (utc %s)\n' "$(ts)" "$(date -u '+%FT%TZ')"
      printf 'host: %s\nkernel: %s\nuser: %s\nbash: %s\n' "$(uname -n)" "$(uname -srmo)" "$(id)" "$BASH_VERSION"
      hr_plain "-"; local t line
      for t in nmap masscan zmap hping3 tcpdump tshark openssl curl dig whois; do
          if has "$t"; then line="$(timeout 5 "$t" --version 2>&1 | head -n1 || true)"
              printf '%-9s: %s\n' "$t" "${line:-n/a}"; else printf '%-9s: not installed\n' "$t"; fi
      done; hr_plain "="; } > "$OUTDIR/logs/env_snapshot.txt"
    log "OK" "env snapshot written"; }

# ======================= TARGET PARSER / DETECTOR ============================
RE_IPV4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
RE_DOMAIN='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
is_ipv4() { local s="${1:-}"; [[ "$s" =~ $RE_IPV4 ]] || return 1; local -a oct; IFS='.' read -r -a oct <<< "$s"
    local o; for o in "${oct[@]}"; do (( 10#$o > 255 )) && return 1; done; return 0; }
is_ipv6() { local s="${1:-}"; s="${s%%%*}"; [[ "$s" == *:* ]] || return 1
    [[ "$s" =~ ^[0-9a-fA-F:]+$ && "$s" =~ : ]] || return 1
    [[ "$s" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; }
is_cidr() { local s="${1:-}"; [[ "$s" == */* ]] || return 1
    local addr="${s%%/*}" pre="${s##*/}"; [[ "$pre" =~ ^[0-9]{1,3}$ ]] || return 1
    if is_ipv4 "$addr"; then (( 10#$pre <= 32 )); else is_ipv6 "$addr" && (( 10#$pre <= 128 )); fi; }
is_domain() { [[ "${1:-}" =~ $RE_DOMAIN ]]; }
is_private_v4() { is_ipv4 "$1" || return 1; local -a o; IFS='.' read -r -a o <<< "$1"
    local a=$((10#${o[0]})) b=$((10#${o[1]}))
    (( a==10 )) && return 0; (( a==172 && b>=16 && b<=31 )) && return 0
    (( a==192 && b==168 )) && return 0; (( a==127 )) && return 0; (( a==169 && b==254 )) && return 0; return 1; }
is_private_cidr() { is_cidr "$1" || return 1; local addr="${1%%/*}"; is_ipv4 "$addr" || return 0
    is_private_v4 "$addr"; }
pick_interface() {
    if [[ -n "$IFACE" ]]; then ip link show "$IFACE" > /dev/null 2>&1 && { log "OK" "iface: ${IFACE}"; return 0; }
        log "WARN" "iface '${IFACE}' not found — autodetecting"; IFACE=""; fi
    IFACE="$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')"
    if [[ -z "$IFACE" ]]; then log "WARN" "no default iface detected — try --iface <dev>"
    else log "INFO" "default interface: ${IFACE}"; fi; }
detect_target_type() {
    local t="${TARGET_RAW:?no target}"; local lower="${t,,}"
    if [[ "$lower" == "local" ]]; then TARGET_TYPE="local"; log "OK" "type: local"; return 0; fi
    if is_cidr "$t"; then TARGET_TYPE="cidr"
    elif is_ipv4 "$t"; then TARGET_TYPE="ipv4"
    elif is_ipv6 "$t"; then TARGET_TYPE="ipv6"
    elif is_domain "$t"; then TARGET_TYPE="domain"
    else die 2 "unrecognized target '${t}' — expected IP, domain, CIDR, or 'local'"; fi
    log "OK" "type: ${TARGET_TYPE} (${t})"; }
resolve_target() {
    case "$TARGET_TYPE" in
        ipv4|ipv6|cidr) TARGET_IP="$TARGET_RAW"; return 0 ;;
        local) TARGET_IP=""; return 0 ;; esac
    if ! pick_tool "dns" "${TOOL_CHAIN_DNS[@]}"; then
        log "WARN" "no DNS tool — using hostname directly"; TARGET_IP=""; return 0; fi
    local ip=""
    case "$PICKED_TOOL" in
        dig)     ip="$(dig +short A "$TARGET_RAW" 2>/dev/null | grep -E '^[0-9]+\.' | head -n1 || true)" ;;
        host)    ip="$(host -t A "$TARGET_RAW" 2>/dev/null | awk '/has address/{print $NF;exit}' || true)" ;;
        nslookup) ip="$(nslookup "$TARGET_RAW" 2>/dev/null | awk '/^Address/{print $2;exit}' | grep -E '^[0-9]+\.' || true)" ;;
        getent)  ip="$(getent ahostsv4 "$TARGET_RAW" 2>/dev/null | awk '{print $1;exit}' || true)" ;;
    esac
    if [[ -n "$ip" ]] && is_ipv4 "$ip"; then TARGET_IP="$ip"; log "OK" "resolved ${TARGET_RAW} → ${TARGET_IP}"
    else TARGET_IP=""; log "WARN" "could not resolve ${TARGET_RAW} — using hostname directly"; fi; }
derive_local_subnet() {
    if [[ -z "$IFACE" ]]; then LOCAL_CIDR=""; log "WARN" "no iface — M2 sweeps limited"; return 0; fi
    LOCAL_CIDR="$(ip -o -4 addr show dev "$IFACE" scope global 2>/dev/null | awk '{print $4;exit}' || true)"
    if [[ -n "$LOCAL_CIDR" ]] && is_cidr "$LOCAL_CIDR"; then
        log "OK" "local subnet: ${LOCAL_CIDR} (${IFACE})"
    else LOCAL_CIDR=""; log "WARN" "no global IPv4 on ${IFACE} — M2 sweeps limited"; fi; }

# ======================= FLAG EFFECTS ========================================
apply_fast_mode() {
    if [[ "$FAST_MODE" -eq 1 ]]; then
        if [[ "$TIMEOUT_SET" -eq 0 ]]; then TIMEOUT_SECS="$DEFAULT_TIMEOUT_FAST"; fi
        log "INFO" "--fast: timeout=${TIMEOUT_SECS}s, heavy ops trimmed/skipped by modules"; fi
    if [[ "$EVASIVE" -eq 1 ]]; then
        log "INFO" "--evasive: nmap -f --data-length 24, hping3 -d 24 on general probes"; fi
    if [[ -n "$ZOMBIE" ]]; then
        if is_ipv4 "$ZOMBIE"; then log "INFO" "zombie: ${ZOMBIE}"
        else log "WARN" "bad --zombie '${ZOMBIE}' — idle scan disabled"; ZOMBIE=""; fi; fi; }
build_evasive_nmap()  { [[ "$EVASIVE" -eq 1 ]] && printf '%s' "-f --data-length 24"; return 0; }
build_evasive_hping() { [[ "$EVASIVE" -eq 1 ]] && printf '%s' "-d 24"; return 0; }

# ======================= MODULE 1 — DNS & ROUTING ============================
m1_eligible() { case "$TARGET_TYPE" in domain) return 0;; ipv4) is_private_v4 "$TARGET_RAW" && return 1; return 0;;
    ipv6) return 0;; *) return 1;; esac; }
m1_dns_records() { local f="$DIR_M1/dns_records_full.txt"; print_section "1.1" "DNS RECORD SUITE"
    if [[ "$TARGET_TYPE" != "domain" ]]; then tool_skip "dns_records" "domains only (target: ${TARGET_TYPE})"; return 0; fi
    if has dig; then run_tool "dig_records" "$f" "$TIMEOUT_SECS" -- dig +noall +answer +comments \
        "$TARGET_RAW" A "$TARGET_RAW" AAAA "$TARGET_RAW" MX "$TARGET_RAW" NS "$TARGET_RAW" TXT "$TARGET_RAW" SOA "$TARGET_RAW" CNAME
    elif has host; then run_tool "host_dump" "$f" "$TIMEOUT_SECS" -- host -a "$TARGET_RAW"
    else tool_skip "dns_records" "dig+host missing — install dnsutils"; fi
    has nslookup && run_tool "nslookup" "$f" "$TIMEOUT_SECS" -- nslookup "$TARGET_RAW"; return 0; }
m1_dns_reverse() { local f="$DIR_M1/dns_reverse.txt"; print_section "1.2" "REVERSE DNS"
    [[ "$TARGET_TYPE" == "local" || "$TARGET_TYPE" == "cidr" ]] && { tool_skip "dns_reverse" "n/a for ${TARGET_TYPE}"; return 0; }
    [[ -z "$TARGET_IP" ]] && { tool_skip "dns_reverse" "no resolved IP"; return 0; }
    if has dig; then run_tool "dig_reverse" "$f" 20 -- dig +short -x "$TARGET_IP"
    elif has host; then run_tool "host_reverse" "$f" 20 -- host "$TARGET_IP"
    else tool_skip "dns_reverse" "no reverse tool"; fi; return 0; }
m1_dnssec() { local f="$DIR_M1/dns_dnssec.txt"; print_section "1.3" "DNSSEC"
    if [[ "$TARGET_TYPE" != "domain" ]]; then tool_skip "dnssec" "domains only"; return 0; fi
    has dig || { tool_skip "dnssec" "dig not installed"; return 0; }
    run_tool "dig_dnssec" "$f" "$TIMEOUT_SECS" -- dig +dnssec +multi "$TARGET_RAW" A; return 0; }
m1_axfr() { local f="$DIR_M1/dns_axfr_attempt.txt"; print_section "1.4" "AXFR ATTEMPT"
    if [[ "$TARGET_TYPE" != "domain" ]]; then tool_skip "axfr" "domains only"; return 0; fi
    has dig || { tool_skip "axfr" "dig not installed"; return 0; }
    local -a ns=(); local n
    while IFS= read -r n; do n="${n%.}"; [[ -n "$n" ]] && ns+=("$n"); done \
        < <(timeout 15 dig +short NS "$TARGET_RAW" 2>/dev/null || true)
    (( ${#ns[@]} == 0 )) && ns=("$TARGET_RAW")
    for n in "${ns[@]}"; do run_tool "axfr@${n}" "$f" "$TIMEOUT_SECS" -- dig AXFR "$TARGET_RAW" "@${n}"; done
    return 0; }
m1_whois() { local ff="$DIR_M1/whois_full.txt" fs="$DIR_M1/whois_summary.txt"; print_section "1.5" "WHOIS"
    m1_eligible || { tool_skip "whois" "n/a for ${TARGET_TYPE}"; return 0; }
    has whois || { tool_skip "whois" "whois not installed"; return 0; }
    run_tool "whois" "$ff" "$TIMEOUT_SECS" -- whois "$TARGET_RAW"
    { printf '\n### WHOIS KEY FIELDS\n'; grep -aiE 'registrar:|creation date|expir|expiry|name server:|dnssec:' \
        "$ff" 2>/dev/null | head -n 30 || true; } >> "$fs"
    log "OK" "whois summary written"; return 0; }
m1_paths() { print_section "1.6" "PATH DISCOVERY"
    [[ "$TARGET_TYPE" == "local" || "$TARGET_TYPE" == "cidr" ]] && { tool_skip "paths" "n/a for ${TARGET_TYPE}"; return 0; }
    local dest="${TARGET_IP:-$TARGET_RAW}" tmo=$(( TIMEOUT_SECS*2 ))
    if has traceroute; then
        run_tool "traceroute_icmp" "$DIR_M1/traceroute_icmp.txt" "$tmo" -- traceroute -n -w 2 -q 1 -m 20 "$dest"
        if [[ "$FAST_MODE" -eq 1 ]]; then tool_skip "traceroute_tcp" "fast mode"; tool_skip "traceroute_udp" "fast mode"
        else run_tool --root "traceroute_tcp" "$DIR_M1/traceroute_tcp.txt" "$tmo" -- traceroute -T -n -w 2 -q 1 -m 20 "$dest"
             run_tool --root "traceroute_udp" "$DIR_M1/traceroute_udp.txt" "$tmo" -- traceroute -U -n -w 2 -q 1 -m 20 "$dest"; fi
    else tool_skip "traceroute" "traceroute not installed"; fi
    has tracepath && run_tool "tracepath_mtu" "$DIR_M1/tracepath_mtu.txt" "$tmo" -- tracepath -n "$dest"
    return 0; }
m1_mtr() { local f="$DIR_M1/mtr_report.txt"; print_section "1.7" "MTR"
    [[ "$TARGET_TYPE" == "local" || "$TARGET_TYPE" == "cidr" ]] && { tool_skip "mtr" "n/a"; return 0; }
    has mtr || { tool_skip "mtr" "mtr not installed"; return 0; }
    local cyc="$MTR_REPORT_CYCLES"; [[ "$FAST_MODE" -eq 1 ]] && cyc=3
    run_tool --root "mtr_report" "$f" $(( TIMEOUT_SECS*2 )) -- mtr --report --wide -z -c "$cyc" "${TARGET_IP:-$TARGET_RAW}"
    return 0; }
m1_asn() { local f="$DIR_M1/asn_bgp_info.txt"; print_section "1.8" "ASN/BGP"
    [[ "$TARGET_TYPE" == "local" ]] && { tool_skip "asn" "n/a local"; return 0; }
    [[ -z "$TARGET_IP" ]] && { tool_skip "asn" "no resolved IP"; return 0; }
    has whois || { tool_skip "asn" "whois not installed"; return 0; }
    run_tool "asn_cymru" "$f" 30 -- whois -h whois.cymru.com " -v ${TARGET_IP}"
    local asn; asn="$(grep -aE '^[0-9]+[[:space:]]*\|' "$f" 2>/dev/null | head -n1 | cut -d'|' -f1 | tr -d '[:space:]' || true)"
    if [[ -n "$asn" ]]; then log "INFO" "origin ASN: AS${asn}"
        if has bgpq3; then run_tool "bgpq3" "$f" "$TIMEOUT_SECS" -- bgpq3 -l "net_AS${asn}" "AS${asn}"
        elif has bgpq4; then run_tool "bgpq4" "$f" "$TIMEOUT_SECS" -- bgpq4 -l "net_AS${asn}" "AS${asn}"; fi
    else log "INFO" "no ASN extracted"; fi; return 0; }
m1_geoip() { local f="$DIR_M1/geoip_result.txt"; print_section "1.9" "GEOIP"
    [[ "$TARGET_TYPE" == "local" ]] && { tool_skip "geoip" "n/a local"; return 0; }
    if has geoiplookup; then run_tool "geoiplookup" "$f" 20 -- geoiplookup "${TARGET_IP:-$TARGET_RAW}"
    else tool_skip "geoiplookup" "geoip-bin not installed"; fi
    if [[ -n "$TARGET_IP" && "$ONLINE_FALLBACK_GEOIP" -eq 1 ]] && has curl; then
        run_tool "geoip_online" "$f" 20 -- curl -fsS "http://ip-api.com/line/${TARGET_IP}?fields=status,country,regionName,city,isp,org,as,reverse"
    fi; return 0; }
m1_subdomains() { local f="$DIR_M1/subdomain_enum.txt"; print_section "1.10" "SUBDOMAIN ENUM"
    if [[ "$TARGET_TYPE" != "domain" ]]; then tool_skip "subdomains" "domains only"; return 0; fi
    local t3=$(( TIMEOUT_SECS*3 )) ran=0
    if has subfinder; then run_tool "subfinder" "$f" "$t3" -- subfinder -d "$TARGET_RAW"; ran=1
    else tool_skip "subfinder" "not installed"; fi
    if [[ "$FAST_MODE" -eq 1 ]]; then tool_skip "amass" "fast mode"
    elif has amass; then run_tool "amass" "$f" "$t3" -- amass enum -d "$TARGET_RAW"; ran=1
    else tool_skip "amass" "not installed"; fi
    has dnsrecon && { run_tool "dnsrecon" "$f" "$t3" -- dnsrecon -d "$TARGET_RAW" -t std; ran=1; } || tool_skip "dnsrecon" "not installed"
    if [[ "$FAST_MODE" -eq 1 ]]; then tool_skip "dnsenum" "fast mode"
    elif has dnsenum; then run_tool "dnsenum" "$f" "$t3" -- dnsenum "$TARGET_RAW"; ran=1
    else tool_skip "dnsenum" "not installed"; fi
    has fierce && { run_tool "fierce" "$f" "$t3" -- fierce --domain "$TARGET_RAW"; ran=1; } || tool_skip "fierce" "not installed"
    (( ran == 0 )) && log "INFO" "no subdomain tools available"; return 0; }
write_mod_summary() { # $1=dir $2=title $3=logfile_start_line
    local dir="$1" title="$2" start="$3" f="$1/summary.txt"
    { hr_plain "="; printf '### %s | %s\n' "$title" "$(ts)"; hr_plain "-"
      printf 'files:\n'; local x
      while IFS= read -r x; do [[ -e "$x" ]] || continue
          printf '  %-28s %8s bytes\n' "$(basename "$x")" "$(stat -c%s "$x" 2>/dev/null || echo 0)"
      done < <(find "$dir" -maxdepth 1 -type f ! -name 'summary.txt' | sort)
      hr_plain "-"; printf 'tool outcomes:\n'
      tail -n +"$(( start + 1 ))" "$LOGFILE" 2>/dev/null | grep 'TOOL:' || printf '  (none)\n'
      hr_plain "="; } > "$f"; log "FINAL" "summary → $(basename "$dir")/summary.txt"; }
recon_dns_routing() { print_section "1" "DNS & ROUTING INTELLIGENCE"
    local s; s="$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)"
    m1_dns_records; m1_dns_reverse; m1_dnssec; m1_axfr; m1_whois; m1_paths; m1_mtr; m1_asn; m1_geoip; m1_subdomains
    write_mod_summary "$DIR_M1" "MODULE 1 — DNS & ROUTING" "$s"; }

# ======================= MODULE 2 — LOCAL L2 =================================
m2_sweeps_ok() { [[ -n "$M2_CIDR" ]] && is_cidr "$M2_CIDR" || return 1
    local a="${M2_CIDR%%/*}" p="${M2_CIDR##*/}"; is_ipv4 "$a" || return 1
    (( 10#$p < 32 )) || return 1; (( (1 << (32 - 10#$p)) <= M2_MAX_SWEEP_HOSTS )); }
m2_inventory() { print_section "2.1" "HOST-LOCAL INVENTORY"
    if pick_tool "ifaces" "${TOOL_CHAIN_INTERFACES[@]}"; then
        [[ "$PICKED_TOOL" == "ip" ]] && run_tool "ip_addr" "$DIR_M2/interfaces.txt" "$TIMEOUT_SECS" -- ip addr show \
            || run_tool "ifconfig" "$DIR_M2/interfaces.txt" "$TIMEOUT_SECS" -- ifconfig -a
    fi
    run_tool "ip_route" "$DIR_M2/routing_table.txt" "$TIMEOUT_SECS" -- ip route show
    run_tool "ip_route_all" "$DIR_M2/routing_table.txt" "$TIMEOUT_SECS" -- ip route show table all
    if pick_tool "arpcache" "${TOOL_CHAIN_ARPCACHE[@]}"; then
        [[ "$PICKED_TOOL" == "ip" ]] && run_tool "ip_neigh" "$DIR_M2/arp_cache.txt" "$TIMEOUT_SECS" -- ip -4 neigh show \
            || run_tool "arp_a" "$DIR_M2/arp_cache.txt" "$TIMEOUT_SECS" -- arp -an; fi
    if pick_tool "sockets" "${TOOL_CHAIN_SOCKETS[@]}"; then
        case "$PICKED_TOOL" in
            ss)      run_tool "ss_tulnp" "$DIR_M2/listening_sockets.txt" "$TIMEOUT_SECS" -- ss -tulnp ;;
            netstat) run_tool "netstat" "$DIR_M2/listening_sockets.txt" "$TIMEOUT_SECS" -- netstat -tulnp ;;
            lsof)    run_tool "lsof_listen" "$DIR_M2/listening_sockets.txt" "$TIMEOUT_SECS" -- lsof -i -P -n -sTCP:LISTEN ;;
        esac; fi
    has lsof && run_tool "lsof_procs" "$DIR_M2/open_processes_network.txt" "$TIMEOUT_SECS" -- lsof -i -P -n \
        || tool_skip "lsof" "not installed"; return 0; }
m2_sweeps() { print_section "2.2" "SWEEP TARGET"; M2_CIDR=""
    if [[ "$TARGET_TYPE" == "cidr" ]]; then M2_CIDR="$TARGET_RAW"
    else [[ -z "$LOCAL_CIDR" && -n "$IFACE" ]] && \
        LOCAL_CIDR="$(ip -o -4 addr show dev "$IFACE" scope global 2>/dev/null | awk '{print $4;exit}' || true)"
        [[ -n "$LOCAL_CIDR" ]] && M2_CIDR="$LOCAL_CIDR"; fi
    if [[ -n "$M2_CIDR" ]]; then log "OK" "sweep CIDR: ${M2_CIDR}"
    else log "WARN" "no sweep CIDR — sweeps will skip, inventories ran"; fi
    print_section "2.3" "DISCOVERY SWEEPS"
    if ! m2_sweeps_ok; then
        tool_skip "fping" "no CIDR or > M2_MAX_SWEEP_HOSTS=${M2_MAX_SWEEP_HOSTS}"
        tool_skip "nmap_sweep" "no CIDR or too large"; tool_skip "arp_scan" "no CIDR or too large"
        tool_skip "netdiscover" "no CIDR or too large"; return 0; fi
    local t2=$(( TIMEOUT_SECS*2 ))
    if has fping; then run_tool "fping" "$DIR_M2/fping_sweep.txt" "$t2" -- fping -asg "$M2_CIDR"
        [[ "$RUN_TOOL_LAST_RC" -ne 0 ]] && log "INFO" "fping rc=$RUN_TOOL_LAST_RC (1=some hosts down, normal)"
    else tool_skip "fping" "not installed"; fi
    if has nmap; then
        run_tool "nmap_sn" "$DIR_M2/nmap_ping_sweep.txt" "$t2" -- nmap -sn "$M2_CIDR"
        [[ "$FAST_MODE" -eq 1 ]] && tool_skip "nmap_eth" "fast mode" \
            || run_tool --root "nmap_eth" "$DIR_M2/nmap_eth_discovery.txt" "$t2" -- nmap -sn --send-eth "$M2_CIDR"
    else tool_skip "nmap_sweep" "not installed"; fi
    if [[ "$FAST_MODE" -eq 1 ]]; then tool_skip "netdiscover" "fast mode"
    elif has netdiscover && (( EUID == 0 )); then
        printf '### netdiscover TIMEOUT = sweep done, listener killed (by design)\n' >> "$DIR_M2/netdiscover_results.txt"
        run_tool --root "netdiscover" "$DIR_M2/netdiscover_results.txt" "$t2" -- netdiscover -r "$M2_CIDR" -f
    else tool_skip "netdiscover" "not installed or not root"; fi
    return 0; }
m2_arpscan() { local f="$DIR_M2/arp_scan_results.txt"; print_section "2.4" "ARP-SCAN"
    has arp-scan || { tool_skip "arp_scan" "not installed"; return 0; }
    (( EUID == 0 )) || { tool_skip "arp_scan" "requires root"; return 0; }
    local t2=$(( TIMEOUT_SECS*2 ))
    if [[ -n "$M2_CIDR" ]] && m2_sweeps_ok; then
        [[ -n "$IFACE" ]] && run_tool --root "arp_scan" "$f" "$t2" -- arp-scan -I "$IFACE" --retry=3 "$M2_CIDR" \
            || run_tool --root "arp_scan" "$f" "$t2" -- arp-scan --retry=3 "$M2_CIDR"
    else run_tool --root "arp_scan" "$f" "$t2" -- arp-scan --localnet --retry=3; fi
    return 0; }
m2_arping() { local f="$DIR_M2/arping_live_hosts.txt"; print_section "2.5" "ARPING DISCOVERED HOSTS"
    has arping || { tool_skip "arping" "not installed"; return 0; }
    (( EUID == 0 )) || { tool_skip "arping" "requires root"; return 0; }
    local -a srcs=() s
    for s in "$DIR_M2/arp_cache.txt" "$DIR_M2/fping_sweep.txt" "$DIR_M2/nmap_ping_sweep.txt" \
             "$DIR_M2/nmap_eth_discovery.txt" "$DIR_M2/arp_scan_results.txt"; do [[ -f "$s" ]] && srcs+=("$s"); done
    local -a cands=(); local ip
    if (( ${#srcs[@]} > 0 )); then
        while IFS= read -r ip; do is_ipv4 "$ip" && cands+=("$ip"); done \
            < <(grep -hoE '([0-9]{1,3}\.){3}[0-9]{1,3}' "${srcs[@]}" 2>/dev/null | sort -u | head -n 254); fi
    (( ${#cands[@]} == 0 )) && { tool_skip "arping" "no discovered hosts to probe"; return 0; }
    printf '### arping %s discovered hosts (cap 254)\n' "${#cands[@]}" >> "$f"
    run_tool --root "arping" "$f" $(( TIMEOUT_SECS*3 )) -- env HOSTS="${cands[*]}" IFACE="$IFACE" bash -c '
        IFS=" " read -r -a hs <<< "$HOSTS"
        for ip in "${hs[@]}"; do
            I=""; [ -n "$IFACE" ] && I="-I $IFACE"
            timeout 2 arping $I -c 1 -w 1 "$ip" > /dev/null 2>&1 && echo "ALIVE: ${ip}"
        done'
    return 0; }
m2_macmap() { local f="$DIR_M2/mac_vendor_map.txt"; print_section "2.6" "MAC VENDOR MAP"
    local -a srcs=() s
    for s in "$DIR_M2/arp_cache.txt" "$DIR_M2/arp_scan_results.txt" "$DIR_M2/netdiscover_results.txt" \
             "$DIR_M2/nmap_ping_sweep.txt" "$DIR_M2/nmap_eth_discovery.txt"; do [[ -f "$s" ]] && srcs+=("$s"); done
    local -a macs=()
    if (( ${#srcs[@]} > 0 )); then
        while IFS= read -r m; do [[ -n "$m" ]] && macs+=("$(printf '%s' "$m" | tr '[:lower:]' '[:upper:]')"); done \
            < <(grep -hoE '([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}' "${srcs[@]}" 2>/dev/null | sort -u); fi
    printf '### %s unique MAC(s)\n' "${#macs[@]}" >> "$f"
    (( ${#macs[@]} == 0 )) && { tool_skip "mac_map" "no MACs discovered"; return 0; }
    local db="" d; for d in /usr/share/nmap/nmap-mac-prefixes /usr/share/nmap/nmap-mac-prefixes.txt; do
        [[ -f "$d" ]] && { db="$d"; break; }; done
    local -a unres=(); local mac oui v
    if [[ -n "$db" ]]; then
        for mac in "${macs[@]}"; do oui="${mac:0:8}"
            v="$(grep -ai "^${oui} " "$db" 2>/dev/null | head -n1 | cut -d' ' -f2- || true)"
            [[ -n "$v" ]] && printf '%s  %s  [offline]\n' "$mac" "$v" >> "$f" \
                || { printf '%s  (unknown offline)\n' "$mac" >> "$f"; unres+=("$oui"); }
        done
    else for mac in "${macs[@]}"; do unres+=("${mac:0:8}"); printf '%s  (no offline db)\n' "$mac" >> "$f"; done; fi
    (( ${#unres[@]} == 0 )) && { log "OK" "all MACs resolved offline"; return 0; }
    [[ "$MACVENDOR_API_MAX" -eq 0 ]] && { tool_skip "mac_online" "disabled via MACVENDOR_API_MAX=0"; return 0; }
    has curl || { tool_skip "mac_online" "curl missing"; return 0; }
    local -a uniq=(); local o u seen
    for o in "${unres[@]}"; do seen=0
        for u in "${uniq[@]:-}"; do [[ "$u" == "$o" ]] && { seen=1; break; }; done
        (( seen == 0 )) && uniq+=("$o"); done
    local budget="$MACVENDOR_API_MAX"; (( ${#uniq[@]} < budget )) && budget="${#uniq[@]}"
    run_tool "mac_online" "$f" $(( budget*MACVENDOR_API_PAUSE_SECS+30 )) -- env \
        LIST="${uniq[*]}" PAUSE="$MACVENDOR_API_PAUSE_SECS" MAX="$budget" bash -c '
        IFS=" " read -r -a arr <<< "$LIST"; n=0
        for oui in "${arr[@]}"; do
            [ "$n" -ge "$MAX" ] && break
            v="$(timeout 10 curl -fsS "https://api.macvendors.com/${oui}" 2>/dev/null || true)"
            [ -n "$v" ] && printf "%s  %s  [online]\n" "$oui" "$v" || printf "%s  (lookup failed)\n" "$oui"
            n=$((n+1)); [ "$n" -lt "$MAX" ] && sleep "$PAUSE"
        done'; return 0; }
m2_wireless() { local f="$DIR_M2/wireless_discovery.txt"; print_section "2.7" "WIRELESS"
    if has iw; then run_tool "iw_dev" "$f" "$TIMEOUT_SECS" -- iw dev
        local w; w="$(grep -oE 'Interface [a-zA-Z0-9]+' "$f" 2>/dev/null | head -n1 | awk '{print $2}' || true)"
        if [[ -n "$w" ]]; then
            if has iwlist; then (( EUID == 0 )) && run_tool --root "iwlist" "$f" 45 -- iwlist "$w" scanning \
                || tool_skip "iwlist" "requires root"
            else tool_skip "iwlist" "not installed"; fi
        else log "INFO" "no wireless interface"; printf '(no wlan iface)\n' >> "$f"; fi
    else tool_skip "wireless" "iw/iwlist not installed"; fi; return 0; }
recon_local_l2() { print_section "2" "LOCAL L2 DISCOVERY"
    local s; s="$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)"
    m2_inventory; m2_sweeps; m2_arpscan; m2_arping; m2_macmap; m2_wireless
    write_mod_summary "$DIR_M2" "MODULE 2 — LOCAL L2" "$s"; }

# ======================= MODULE 3 — REMOTE PERF ==============================
m3_liveness() { local f="$DIR_M3/ping_latency_profile.txt"; print_section "3.0" "LIVENESS"; M3_ALIVE=0
    if has ping; then run_tool "liveness_ping" "$f" 20 -- ping -c 3 -W 2 "${TARGET_IP:-$TARGET_RAW}"
        [[ "$RUN_TOOL_LAST_RC" -eq 0 ]] && M3_ALIVE=1; fi
    if [[ "$M3_ALIVE" -eq 0 ]] && has curl; then
        run_tool "liveness_http" "$f" 20 -- curl -sS -o /dev/null --connect-timeout 5 --max-time 10 "http://${TARGET_RAW}/"
        [[ "$RUN_TOOL_LAST_RC" -eq 0 ]] && M3_ALIVE=1; fi
    (( M3_ALIVE == 1 )) && log "OK" "target LIVE" \
        || log "WARN" "target UNREACHABLE — continuing (100%% loss is data too)"
    return 0; }
m3_pingstats() { local f="${1:?pingstats}" label="${2:?pingstats}"
    local -a times=() ; local t
    while IFS= read -r t; do times+=("$t"); done \
        < <(grep -oE 'time=[0-9]+\.?[0-9]*' "$f" 2>/dev/null | cut -d= -f2 || true)
    { hr_plain "-"; printf '### %s parsed stats\n' "$label"
      if (( ${#times[@]} > 0 )); then
          printf '%s\n' "${times[@]}" | awk '{n++;s+=$1;ss+=$1*$1;if(min==""||$1<min)min=$1;if($1>max)max=$1}
              END{if(!n){print "no samples";exit}a=s/n;v=ss/n-a*a;v<0&&v=0
              printf "samples=%d min=%.3f avg=%.3f max=%.3f jitter=%.3f ms\n",n,min,a,max,sqrt(v)}'
      else printf 'no samples (unreachable?)\n'; fi
      grep -aE 'packet loss|rtt |round-trip' "$f" 2>/dev/null || true; } >> "$f"; return 0; }
m3_pings() { print_section "3.1" "PING PROFILES"
    local f1="$DIR_M3/ping_latency_profile.txt" f2="$DIR_M3/ping_jitter_analysis.txt"
    run_tool "ping_profile" "$f1" 30 -- ping -c "$PING_PROFILE_COUNT" -i "$PING_PROFILE_INTERVAL" "${TARGET_IP:-$TARGET_RAW}"
    m3_pingstats "$f1" "latency"
    if [[ "$FAST_MODE" -eq 1 ]]; then tool_skip "jitter" "fast mode"; return 0; fi
    if [[ "$PING_JITTER_INTERVAL" < "0.2" ]]; then
        if (( EUID == 0 )); then
            run_tool --root "jitter" "$f2" 45 -- ping -c "$PING_JITTER_COUNT" -i "$PING_JITTER_INTERVAL" "${TARGET_IP:-$TARGET_RAW}"
        else log "WARN" "jitter -i 0.05 needs root — substituting 0.25s"
            run_tool "jitter" "$f2" 60 -- ping -c "$PING_JITTER_COUNT" -i 0.25 "${TARGET_IP:-$TARGET_RAW}"; fi
    else run_tool "jitter" "$f2" 60 -- ping -c "$PING_JITTER_COUNT" -i "$PING_JITTER_INTERVAL" "${TARGET_IP:-$TARGET_RAW}"; fi
    m3_pingstats "$f2" "jitter"
    local f6="$DIR_M3/ping6_ipv6_latency.txt" v6=""
    if is_ipv6 "$TARGET_RAW"; then v6="$TARGET_RAW"
    elif has dig; then v6="$(timeout 10 dig +short AAAA "$TARGET_RAW" 2>/dev/null | head -n1 || true)"; fi
    if [[ -n "$v6" ]] && is_ipv6 "$v6"; then
        has ping6 && run_tool "ping6" "$f6" 40 -- ping6 -c "$PING6_COUNT" "$v6" \
            || run_tool "ping6" "$f6" 40 -- ping -6 -c "$PING6_COUNT" "$v6"
        m3_pingstats "$f6" "ipv6"
    else tool_skip "ping6" "no IPv6 address"; fi
    return 0; }
m3_mtr_as() { print_section "3.2" "MTR PERF + AS PATH"
    [[ "$TARGET_TYPE" == "local" || "$TARGET_TYPE" == "cidr" ]] && { tool_skip "mtr_perf" "n/a"; tool_skip "traceroute_as" "n/a"; return 0; }
    local dest="${TARGET_IP:-$TARGET_RAW}"
    if has mtr; then local cyc="$MTR_PERF_CYCLES"; [[ "$FAST_MODE" -eq 1 ]] && cyc=10
        run_tool --root "mtr_perf" "$DIR_M3/mtr_perf_report.txt" $(( cyc*2+30 )) -- mtr --report --wide -z -c "$cyc" "$dest"
    else tool_skip "mtr_perf" "not installed"; fi
    if has traceroute; then
        run_tool "traceroute_as" "$DIR_M3/traceroute_as_path.txt" $(( TIMEOUT_SECS*2 )) -- traceroute -n -A -w 2 -q 1 -m 20 "$dest"
    else tool_skip "traceroute_as" "not installed"; fi
    return 0; }
m3_tcp() { print_section "3.3" "TCP STATE + SOCKETS + RETRANS"
    run_tool "ss_s" "$DIR_M3/socket_summary.txt" "$TIMEOUT_SECS" -- ss -s 2>/dev/null || true
    if has nstat; then run_tool "retrans" "$DIR_M3/tcp_retrans_counters.txt" "$TIMEOUT_SECS" -- bash -c \
        'nstat -az | grep -iE "retrans|reset" || echo "(no retrans counters)"'
    else tool_skip "retrans" "nstat not installed"; fi
    M3_OPEN_PORT=""
    local h="${TARGET_IP:-$TARGET_RAW}" p
    for p in 443 80 22; do timeout 3 bash -c "exec 3<>/dev/tcp/${h}/${p}" 2>/dev/null && { M3_OPEN_PORT="$p"; break; }; done
    if [[ -z "$TARGET_IP" || -z "$M3_OPEN_PORT" ]]; then
        tool_skip "ss_ti" "needs resolved IP + open port (443/80/22 probed)"; return 0; fi
    local port="$M3_OPEN_PORT";
    local url="http://${TARGET_IP}:${port}/"
    [[ "$port" == "443" ]] && url="https://${TARGET_IP}/"
    bash -c 'exec 3<>/dev/tcp/$1/$2 2>/dev/null||true
        for i in 1 2 3 4; do curl -sk -o /dev/null --max-time 3 "$3" 2>/dev/null; sleep 1; done' \
        _ "$TARGET_IP" "$port" "$url" &
    local hp=$!; sleep 1
    run_tool "ss_ti" "$DIR_M3/tcp_connection_state.txt" "$TIMEOUT_SECS" -- ss -ti dst "$TARGET_IP"
    sleep 2; run_tool "ss_tin" "$DIR_M3/tcp_connection_state.txt" "$TIMEOUT_SECS" -- ss -tin dst "$TARGET_IP"
    kill "$hp" 2>/dev/null || true; wait "$hp" 2>/dev/null || true
    return 0; }
m3_iperf_curl() { print_section "3.4" "IPERF3 + CURL TIMING"
    if has iperf3; then
        printf '### NOTE: needs an iperf3 SERVER on target — ERROR usually = none running\n' >> "$DIR_M3/iperf3_throughput.txt"
        run_tool "iperf3" "$DIR_M3/iperf3_throughput.txt" $(( IPERF3_DURATION+20 )) -- iperf3 -c "${TARGET_IP:-$TARGET_RAW}" -t "$IPERF3_DURATION"
    else tool_skip "iperf3" "not installed"; fi
    local scheme="https"; [[ "$M3_OPEN_PORT" == "80" ]] && scheme="http"
    # shellcheck disable=SC2016
    local w='dns=%{time_namelookup}s connect=%{time_connect}s tls=%{time_appconnect}s ttfb=%{time_starttransfer}s total=%{time_total}s code=%{http_code} ip=%{remote_ip}\n'
    run_tool "curl_timing" "$DIR_M3/curl_timing_breakdown.txt" 30 -- \
        curl -sS -o /dev/null --connect-timeout 8 --max-time 25 -w "$w" "${scheme}://${TARGET_RAW}/"
    return 0; }
m3_capture() { print_section "3.5" "PCAP + TSHARK + BW"
    if ! has tcpdump; then tool_skip "pcap" "tcpdump not installed"
    elif (( EUID != 0 )); then tool_skip "pcap" "requires root"
    elif [[ -z "$TARGET_IP" ]]; then tool_skip "pcap" "no resolved IP"
    else
        local pkts="$TCPDUMP_PKT_COUNT"; [[ "$FAST_MODE" -eq 1 ]] && pkts="$TCPDUMP_PKT_COUNT_FAST"
        printf '### pcap TIMEOUT = cap not reached; tcpdump flushes on SIGTERM — capture valid\n' >> "$DIR_M3/packet_capture_log.txt"
        run_tool --root "pcap" "$DIR_M3/packet_capture_log.txt" 90 -- \
            tcpdump -i any -c "$pkts" -w "$DIR_M3/packet_capture.pcap" host "$TARGET_IP"
        [[ -s "$DIR_M3/packet_capture.pcap" ]] \
            && log "OK" "pcap: $(stat -c%s "$DIR_M3/packet_capture.pcap") bytes" \
            || log "WARN" "pcap empty — target silent"
    fi
    if has tshark && [[ -s "$DIR_M3/packet_capture.pcap" ]]; then
        run_tool "tshark" "$DIR_M3/tshark_flow_stats.txt" 60 -- tshark -r "$DIR_M3/packet_capture.pcap" -q -z io,stat,1
    else tool_skip "tshark" "not installed or no pcap"; fi
    if has iftop && (( EUID == 0 )) && [[ -n "$IFACE" && -n "$TARGET_IP" ]]; then
        run_tool --root "iftop" "$DIR_M3/iftop_snapshot.txt" $(( IFTOP_SNAPSHOT_SECS+15 )) -- \
            iftop -t -s "$IFTOP_SNAPSHOT_SECS" -n -N -i "$IFACE" -f "host ${TARGET_IP}"
    else tool_skip "iftop" "not installed / not root / no iface+IP"; fi
    if has nethogs && (( EUID == 0 )); then
        printf '### nethogs = per-PROCESS host-wide (cannot filter by peer)\n' >> "$DIR_M3/nethogs_process_bw.txt"
        run_tool --root "nethogs" "$DIR_M3/nethogs_process_bw.txt" $(( NETHOGS_CYCLES*2+15 )) -- nethogs -t -c "$NETHOGS_CYCLES"
    else tool_skip "nethogs" "not installed or not root"; fi
    return 0; }
m3_nic() { print_section "3.6" "NIC + QDISC"
    if has ethtool && [[ -n "$IFACE" ]]; then
        run_tool "ethtool" "$DIR_M3/ethtool_nic_stats.txt" "$TIMEOUT_SECS" -- ethtool "$IFACE"
        run_tool "ethtool_S" "$DIR_M3/ethtool_nic_stats.txt" "$TIMEOUT_SECS" -- ethtool -S "$IFACE"
    else tool_skip "ethtool" "not installed or no iface"; fi
    run_tool "tc_qdisc" "$DIR_M3/tc_qdisc_stats.txt" "$TIMEOUT_SECS" -- tc -s qdisc show
    [[ -n "$IFACE" ]] && run_tool "tc_class" "$DIR_M3/tc_qdisc_stats.txt" "$TIMEOUT_SECS" -- tc -s class show dev "$IFACE"
    return 0; }
recon_remote_perf() { print_section "3" "REMOTE PERFORMANCE"
    if [[ "$TARGET_TYPE" == "local" || "$TARGET_TYPE" == "cidr" ]]; then
        tool_skip "module3" "needs single remote host (got ${TARGET_TYPE})"; return 0; fi
    local s; s="$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)"
    m3_liveness; m3_pings; m3_mtr_as; m3_tcp; m3_iperf_curl; m3_capture; m3_nic
    write_mod_summary "$DIR_M3" "MODULE 3 — REMOTE PERF" "$s"; }

# ======================= MODULE 4 — BLACK-BOX ================================
m4_host() { case "$TARGET_TYPE" in domain|ipv4|ipv6) return 0;; *) return 1;; esac; }
m4_probe() { timeout 3 bash -c "exec 3<>/dev/tcp/${1}/${2}" 2>/dev/null; }
m4_pre() { print_section "4.0" "PRE-PROBES (443/445/139/AAAA)"
    if ! m4_host; then tool_skip "preprobes" "CIDR target — host-only probes skip"; return 0; fi
    local h="${TARGET_IP:-$TARGET_RAW}"
    if m4_probe "$h" 443; then M4_TLS_OPEN=1; log_tool "preprobe_tls" "OK" 0 "443 open — TLS family runs"
    else M4_TLS_OPEN=0; log_tool "preprobe_tls" "SKIPPED" 0 "443 closed — TLS family skips"; fi
    if m4_probe "$h" 445 || m4_probe "$h" 139; then M4_SMB_OPEN=1; log_tool "preprobe_smb" "OK" 0 "SMB open"
    else M4_SMB_OPEN=0; log_tool "preprobe_smb" "SKIPPED" 0 "445/139 closed — enum4linux skips"; fi
    M4_V6_ADDR=""
    if is_ipv6 "$TARGET_RAW"; then M4_V6_ADDR="$TARGET_RAW"
    elif has dig; then local a; a="$(timeout 10 dig +short AAAA "$TARGET_RAW" 2>/dev/null | head -n1 || true)"
        [[ -n "$a" ]] && is_ipv6 "$a" && M4_V6_ADDR="$a"; fi
    [[ -n "$M4_V6_ADDR" ]] && log_tool "preprobe_aaaa" "OK" 0 "v6: ${M4_V6_ADDR}" \
        || log_tool "preprobe_aaaa" "SKIPPED" 0 "no IPv6"; return 0; }
m4_nmap_family() { print_section "4.1" "NMAP FAMILY"
    if ! m4_host; then
        for t in nmap_full nmap_udp nmap_conn nmap_stealth nmap_ack nmap_idle nmap_evasive nmap_v6; do
            tool_skip "$t" "host-only (target: ${TARGET_TYPE})"; done; return 0; fi
    has nmap || { for t in nmap_full nmap_udp nmap_conn nmap_stealth nmap_ack nmap_idle nmap_evasive nmap_v6; do
        tool_skip "$t" "nmap not installed"; done; return 0; }
    local h="${TARGET_IP:-$TARGET_RAW}"
    if [[ "$FAST_MODE" -eq 1 ]]; then
        confirm_action "nmap audit (top-1000) vs ${h}" \
            || { tool_skip "nmap_full" "declined"; }
        local ev; ev="$(build_evasive_nmap)"; local -a eva=(); [[ -n "$ev" ]] && eva=($ev)
        run_tool --root "nmap_full" "$DIR_M4/nmap_full_tcp.txt" $(( TIMEOUT_SECS*10 )) -- \
            nmap -sS -sV -O -A --script vuln --top-ports 1000 "${eva[@]}" "$h"
    else
        confirm_action "nmap FULL -p- audit vs ${h} — LOUD, up to 10min" \
            || { tool_skip "nmap_full" "declined"; }
        local ev; ev="$(build_evasive_nmap)"; local -a eva=(); [[ -n "$ev" ]] && eva=($ev)
        run_tool --root "nmap_full" "$DIR_M4/nmap_full_tcp.txt" $(( TIMEOUT_SECS*10 )) -- \
            nmap -sS -sV -O -A --script vuln -p- "${eva[@]}" "$h"
    fi
    run_tool --root "nmap_udp" "$DIR_M4/nmap_top_udp.txt" $(( TIMEOUT_SECS*4 )) -- nmap -sU --top-ports "$NMAP_TOP_UDP_PORTS" "$h"
    run_tool "nmap_conn" "$DIR_M4/nmap_connect_scan.txt" $(( TIMEOUT_SECS*3 )) -- nmap -sT -Pn "$h"
    run_tool --root "nmap_stealth" "$DIR_M4/nmap_stealth_scans.txt" $(( TIMEOUT_SECS*3 )) -- bash -c \
        "echo '=== FIN ==='; nmap -sF '${h}'; echo '=== XMAS ==='; nmap -sX '${h}'; echo '=== NULL ==='; nmap -sN '${h}'"
    run_tool --root "nmap_ack" "$DIR_M4/nmap_ack_firewall.txt" $(( TIMEOUT_SECS*2 )) -- nmap -sA "$h"
    if [[ -z "$ZOMBIE" ]]; then tool_skip "nmap_idle" "no --zombie given"
    else run_tool --root "nmap_idle" "$DIR_M4/nmap_idle_scan.txt" $(( TIMEOUT_SECS*4 )) -- nmap -sI "$ZOMBIE" "$h"; fi
    if [[ "$FAST_MODE" -eq 1 ]]; then tool_skip "nmap_evasive" "fast mode"
    elif confirm_action "nmap EVASIVE (-T2 fragmented+decoys) vs ${h}" \
        || tool_skip "nmap_evasive" "declined"; then
        run_tool --root "nmap_evasive" "$DIR_M4/nmap_evasive_scan.txt" $(( TIMEOUT_SECS*3 )) -- \
            nmap -f -T2 --data-length 24 -D RND:5 "$h"; fi
    [[ -n "$M4_V6_ADDR" ]] && run_tool "nmap_v6" "$DIR_M4/nmap_ipv6_scan.txt" $(( TIMEOUT_SECS*3 )) -- nmap -6 "$M4_V6_ADDR" \
        || tool_skip "nmap_v6" "no IPv6 endpoint"
    return 0; }
m4_masscan_zmap() { print_section "4.2" "MASSCAN + ZMAP"
    if [[ "$FAST_MODE" -eq 1 ]]; then tool_skip "masscan" "fast mode"; else
        has masscan || tool_skip "masscan" "not installed"
        (( EUID == 0 )) || tool_skip "masscan" "requires root"
        if has masscan && (( EUID == 0 )); then
            local tgt
            if [[ "$TARGET_TYPE" == "cidr" ]]; then
                local a="${TARGET_RAW%%/*}" p="${TARGET_RAW##*/}"
                if is_ipv4 "$a" && (( 10#$p < 32 )) && (( (1 << (32-10#$p)) <= M2_MAX_SWEEP_HOSTS )); then tgt="$TARGET_RAW"
                else tgt=""; tool_skip "masscan" "range too large (guard)"; fi
            else m4_host && tgt="${TARGET_IP:-$TARGET_RAW}" || tgt=""; fi
            if [[ -n "$tgt" ]] && confirm_action "MASSCAN 1-65535 @${MASSCAN_RATE}pps vs ${tgt}"; then
                run_tool --root "masscan" "$DIR_M4/masscan_port_sweep.txt" $(( TIMEOUT_SECS*5 )) -- \
                    masscan -p1-65535 --rate="$MASSCAN_RATE" "$tgt"
            elif [[ -n "$tgt" ]]; then tool_skip "masscan" "declined"; fi
        fi
    fi
    has zmap || tool_skip "zmap" "not installed"
    (( EUID == 0 )) || tool_skip "zmap" "requires root"
    if has zmap && (( EUID == 0 )); then
        local tgt; if [[ "$TARGET_TYPE" == "cidr" ]]; then
            local a="${TARGET_RAW%%/*}" p="${TARGET_RAW##*/}"
            is_ipv4 "$a" && (( 10#$p < 32 )) && (( (1 << (32-10#$p)) <= M2_MAX_SWEEP_HOSTS )) && tgt="$TARGET_RAW" || tgt=""
        else m4_host && tgt="${TARGET_IP:-$TARGET_RAW}/32" || tgt=""; fi
        if [[ -n "$tgt" ]] && confirm_action "zmap :80 vs ${tgt}"; then
            run_tool --root "zmap" "$DIR_M4/zmap_probe.txt" $(( TIMEOUT_SECS*3 )) -- zmap -p 80 "$tgt"
        elif [[ -n "$tgt" ]]; then tool_skip "zmap" "declined"; fi
    fi
    return 0; }
m4_hping() { print_section "4.3" "HPING3 PROBES"
    if ! has hping3; then for t in hping_syn hping_scan hping_icmp hping_listen; do tool_skip "$t" "hping3 not installed"; done; return 0; fi
    if ! m4_host; then for t in hping_syn hping_scan hping_icmp; do tool_skip "$t" "host-only"; done; else
        local h="${TARGET_IP:-$TARGET_RAW}" ev; ev="$(build_evasive_hping)"; local -a eva=(); [[ -n "$ev" ]] && eva=($ev)
        run_tool --root "hping_syn" "$DIR_M4/hping3_syn_probe.txt" $(( TIMEOUT_SECS*2 )) -- hping3 -S -p 80 -c "$HPING_PROBE_COUNT" "${eva[@]}" "$h"
        run_tool --root "hping_scan" "$DIR_M4/hping3_port_scan.txt" $(( TIMEOUT_SECS*4 )) -- hping3 --scan 1-1000 -S "${eva[@]}" "$h"
        run_tool --root "hping_icmp" "$DIR_M4/hping3_icmp_fingerprint.txt" $(( TIMEOUT_SECS*2 )) -- hping3 -1 -c 3 "$h"
    fi
    if (( EUID == 0 )) && [[ -n "$IFACE" ]]; then
        printf '### passive listener — TIMEOUT = designed stop\n' >> "$DIR_M4/hping3_passive_listen.txt"
        run_tool --root "hping_listen" "$DIR_M4/hping3_passive_listen.txt" "$TIMEOUT_SECS" -- hping3 --listen signature -I "$IFACE"
    else tool_skip "hping_listen" "needs root + iface"; fi
    return 0; }
m4_banners() { print_section "4.4" "BANNER GRABS"
    if ! m4_host; then tool_skip "banners" "host-only"; return 0; fi
    pick_tool "netcat" "${TOOL_CHAIN_NETCAT[@]}" || { tool_skip "banners" "no netcat chain"; return 0; }
    local ncx="$PICKED_TOOL" h="${TARGET_IP:-$TARGET_RAW}" t2=$(( TIMEOUT_SECS*2 )) payload
    payload="HEAD / HTTP/1.0\r\nHost: ${h}\r\nUser-Agent: netrecon\r\n\r\n"
    run_tool "banner_http" "$DIR_M4/nc_banner_http.txt" "$t2" -- env NCX="$ncx" HOST="$h" PORT=80 PAYLOAD="$payload" RWAIT=6 bash -c '
        if [ "$NCX" = "builtin" ]; then
            exec 3<>"/dev/tcp/${HOST}/${PORT}" 2>/dev/null || { echo "[connect failed]"; exit 3; }
            printf "%b" "$PAYLOAD" >&3; timeout "$RWAIT" head -c 4096 <&3 2>/dev/null
        else printf "%b" "$PAYLOAD" | timeout $(( RWAIT+4 )) "$NCX" -w "$RWAIT" "$HOST" "$PORT" 2>/dev/null; fi'
    payload="EHLO netrecon.local\r\n"
    run_tool "banner_smtp" "$DIR_M4/nc_banner_smtp.txt" "$t2" -- env NCX="$ncx" HOST="$h" PORT=25 PAYLOAD="$payload" RWAIT=6 bash -c '
        if [ "$NCX" = "builtin" ]; then
            exec 3<>"/dev/tcp/${HOST}/${PORT}" 2>/dev/null || { echo "[connect failed]"; exit 3; }
            printf "%b" "$PAYLOAD" >&3; timeout "$RWAIT" head -c 4096 <&3 2>/dev/null
        else printf "%b" "$PAYLOAD" | timeout $(( RWAIT+4 )) "$NCX" -w "$RWAIT" "$HOST" "$PORT" 2>/dev/null; fi'
    run_tool "banner_ftp" "$DIR_M4/nc_banner_ftp.txt" "$t2" -- env NCX="$ncx" HOST="$h" PORT=21 RWAIT=6 bash -c '
        if [ "$NCX" = "builtin" ]; then
            exec 3<>"/dev/tcp/${HOST}/${PORT}" 2>/dev/null || { echo "[connect failed]"; exit 3; }
            timeout "$RWAIT" head -c 4096 <&3 2>/dev/null
        else timeout "$RWAIT" "$NCX" -w "$RWAIT" "$HOST" "$PORT" </dev/null 2>/dev/null; fi'
    run_tool "banner_ssh" "$DIR_M4/nc_banner_ssh.txt" "$t2" -- env NCX="$ncx" HOST="$h" PORT=22 RWAIT=6 bash -c '
        if [ "$NCX" = "builtin" ]; then
            exec 3<>"/dev/tcp/${HOST}/${PORT}" 2>/dev/null || { echo "[connect failed]"; exit 3; }
            timeout "$RWAIT" head -c 4096 <&3 2>/dev/null
        else timeout "$RWAIT" "$NCX" -w "$RWAIT" "$HOST" "$PORT" </dev/null 2>/dev/null; fi'
    return 0; }
m4_tls_web() { print_section "4.5" "TLS + WEB"
    local h="${TARGET_IP:-$TARGET_RAW}" scheme="http"
    [[ "$M4_TLS_OPEN" -eq 1 ]] && scheme="https"
    if [[ "$M4_TLS_OPEN" -eq 0 ]]; then
        tool_skip "openssl_tls" "443 closed (pre-probe)"; tool_skip "sslscan" "443 closed"
        tool_skip "testssl" "443 closed"
    else
        local conn="$h:443"; is_ipv6 "$h" && conn="[${h}]:443"
        if has openssl; then
            run_tool "openssl_tls" "$DIR_M4/openssl_tls_cert.txt" $(( TIMEOUT_SECS*2 )) -- \
                bash -c "openssl s_client -connect '${conn}' -servername '${h}' </dev/null 2>&1"
        else tool_skip "openssl_tls" "not installed"; fi
        has sslscan && run_tool "sslscan" "$DIR_M4/sslscan_ciphers.txt" $(( TIMEOUT_SECS*2 )) -- sslscan "$conn" \
            || tool_skip "sslscan" "not installed"
        if has testssl.sh; then run_tool "testssl" "$DIR_M4/testssl_full_audit.txt" $(( TIMEOUT_SECS*4 )) -- testssl.sh "$conn"
        elif has testssl; then run_tool "testssl" "$DIR_M4/testssl_full_audit.txt" $(( TIMEOUT_SECS*4 )) -- testssl "$conn"
        else tool_skip "testssl" "not installed"; fi
    fi
    m4_host || { tool_skip "web_family" "host-only"; return 0; }
    has curl && run_tool "curl_headers" "$DIR_M4/curl_http_headers.txt" 30 -- \
        curl -sSkI --connect-timeout 8 --max-time 20 "${scheme}://${h}/" \
        || tool_skip "curl_headers" "curl missing"
    if has whatweb; then run_tool "whatweb" "$DIR_M4/whatweb_tech.txt" $(( TIMEOUT_SECS*2 )) -- whatweb "${scheme}://${h}"
    else tool_skip "whatweb" "not installed"; fi
    if has wafw00f; then run_tool "wafw00f" "$DIR_M4/wafw00f_detection.txt" $(( TIMEOUT_SECS*2 )) -- wafw00f "${scheme}://${h}"
    else tool_skip "wafw00f" "not installed"; fi
    if ! has nikto; then tool_skip "nikto" "not installed"
    elif confirm_action "NIKTO scan vs ${scheme}://${h} — very loud"; then
        run_tool "nikto" "$DIR_M4/nikto_vuln_scan.txt" $(( TIMEOUT_SECS*3 )) -- nikto -h "${scheme}://${h}"
    else tool_skip "nikto" "declined"; fi
    return 0; }
m4_smb_snmp() { print_section "4.6" "SMB + SNMP"
    if [[ "$M4_SMB_OPEN" -eq 0 ]]; then tool_skip "enum4linux" "445/139 closed (pre-probe)"
    elif has enum4linux; then
        run_tool "enum4linux" "$DIR_M4/enum4linux_smb.txt" $(( TIMEOUT_SECS*3 )) -- enum4linux -a "${TARGET_IP:-$TARGET_RAW}"
    elif has enum4linux-ng; then
        run_tool "enum4linux_ng" "$DIR_M4/enum4linux_smb.txt" $(( TIMEOUT_SECS*3 )) -- enum4linux-ng -A "${TARGET_IP:-$TARGET_RAW}"
    else tool_skip "enum4linux" "not installed"; fi
    if ! m4_host; then tool_skip "snmpwalk" "host-only"
    elif ! has snmpwalk; then tool_skip "snmpwalk" "not installed"
    else run_tool "snmpwalk" "$DIR_M4/snmp_default_community.txt" 20 -- snmpwalk -v2c -c public -t 2 -r 1 "${TARGET_IP:-$TARGET_RAW}"; fi
    return 0; }
recon_blackbox() { print_section "4" "BLACK-BOX AUDIT"
    if [[ "$TARGET_TYPE" == "local" ]]; then tool_skip "module4" "local mode — no remote host"; return 0; fi
    local s; s="$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)"
    m4_pre; m4_nmap_family; m4_masscan_zmap; m4_hping; m4_banners; m4_tls_web; m4_smb_snmp
    write_mod_summary "$DIR_M4" "MODULE 4 — BLACK-BOX" "$s"; }

# ======================= FINAL REPORT ========================================
declare -A MOD_TITLES=([1]="DNS & ROUTING" [2]="LOCAL L2" [3]="REMOTE PERF" [4]="BLACK-BOX")
rep_stats() { [[ -f "$LOGFILE" ]] || return 0
    awk '/SECTION/{if(match($0,/SECTION [0-9]+/))mod=substr($0,RSTART+8,RLENGTH-8)+0;next}
        /STATUS: RUNNING/{next}
        /TOOL: .* \| STATUS: /{if(match($0,/STATUS: [A-Z]+/)){st=substr($0,RSTART+8,RLENGTH-8)
            c[mod SUBSEP st]++; t[st]++; tot++}}
        END{for(k in c){split(k,p,SUBSEP);printf "MOD %d %s %d\n",p[1],p[2],c[k]}
            printf "OVERALL"; n=split("OK SKIPPED TIMEOUT ERROR",o," ")
            for(i=1;i<=n;i++)printf " %s=%d",o[i],t[o[i]]+0; printf " total=%d\n",tot+0}' \
        "$LOGFILE" 2>/dev/null; }
rep_evidence() { local label="${1:?}" file="${2:?}" pat="${3:?}" max="${4:-8}"
    [[ -f "$file" ]] || return 0
    local hits; hits="$(grep -aiE "$pat" "$file" 2>/dev/null | grep -avE '^###|^====|^----|^\[' | head -n "$max" || true)"
    [[ -z "$hits" ]] && return 0
    printf '  %s:\n' "$label" >> "$REPORT"; local l
    while IFS= read -r l; do [[ -n "$l" ]] && printf '    %s\n' "$l" >> "$REPORT"; done <<< "$hits"; }
generate_final_report() {
    print_section "R" "FINAL REPORT"; log "INFO" "generating FINAL_REPORT.txt..."
    local dur="n/a"; [[ "${RUN_START_EPOCH:-0}" -gt 0 ]] && dur="$(elapsed "$RUN_START_EPOCH" "$(now_epoch)")"
    declare -A MC=(); local overall="(none)" r
    while IFS= read -r r; do
        if [[ "$r" == OVERALL* ]]; then overall="${r#OVERALL }"; continue; fi
        local _tag mod st cnt; read -r _tag mod st cnt <<< "$r" || true
        [[ -n "${st:-}" ]] && MC["${mod}|${st}"]="$cnt"
    done < <(rep_stats)
    local cov=0 tot=0 e t c
    for e in "${OPTIONAL_TOOLS[@]}"; do IFS='|' read -r t c <<< "$e"; tot=$((tot+1)); has "$t" && cov=$((cov+1)); done
    { hr_plain "="; printf '### NETRECON FINAL REPORT — COMPLETE | %s\n' "$(ts)"; hr_plain "="
      printf 'RUN CONTEXT\n  target: %s (%s) → %s\n  iface: %s | subnet: %s\n' \
        "$TARGET_RAW" "$TARGET_TYPE" "${TARGET_IP:-hostname-mode}" "${IFACE:-none}" "${LOCAL_CIDR:-n/a}"
      printf '  modules: [%s] | timeout: %ss | fast=%s evasive=%s\n  version: %s | duration: %s\n' \
        "${MODULES[*]}" "$TIMEOUT_SECS" "$FAST_MODE" "$EVASIVE" "$VERSION" "$dur"
      hr_plain "-"; printf 'EXECUTION OVERVIEW\n  outcomes: %s\n  tool coverage: %d/%d\n' "$overall" "$cov" "$tot"
      hr_plain "-"; printf 'MODULE BREAKDOWN\n'
    } >> "$REPORT"
    local mod mdir
    for mod in "${MODULES[@]}"; do
        case "$mod" in 1)mdir="$DIR_M1";; 2)mdir="$DIR_M2";; 3)mdir="$DIR_M3";; 4)mdir="$DIR_M4";; *)continue;; esac
        { printf -- '--- MODULE %s: %s ---\n' "$mod" "${MOD_TITLES[$mod]:-?}"
          printf '  OK=%s SKIP=%s TIMEOUT=%s ERROR=%s\n' \
            "${MC[${mod}|OK]:-0}" "${MC[${mod}|SKIPPED]:-0}" "${MC[${mod}|TIMEOUT]:-0}" "${MC[${mod}|ERROR]:-0}"
          printf '  files:\n'; } >> "$REPORT"
        local x; while IFS= read -r x; do [[ -e "$x" ]] && printf '    %-28s %8s bytes\n' \
            "$(basename "$x")" "$(stat -c%s "$x" 2>/dev/null || echo 0)"; done \
            < <(find "$mdir" -maxdepth 1 -type f ! -name 'summary.txt' | sort)
    done
    { hr_plain "-"; printf 'KEY FINDINGS\n'; } >> "$REPORT"
    local before; before="$(wc -l < "$REPORT")"
    rep_evidence "ASN"            "$DIR_M1/asn_bgp_info.txt"   '^[0-9]+[[:space:]]*\|' 3
    rep_evidence "GeoIP country"  "$DIR_M1/geoip_result.txt"   'GeoIP Country|country' 3
    rep_evidence "Whois expiry"   "$DIR_M1/whois_full.txt"     '(expir|expiry)' 4
    rep_evidence "ARP-live hosts" "$DIR_M2/arping_live_hosts.txt" 'ALIVE' 15
    rep_evidence "arp-scan MACs"  "$DIR_M2/arp_scan_results.txt" '([0-9A-Fa-f]{2}:){5}' 15
    rep_evidence "fping alive"    "$DIR_M2/fping_sweep.txt"    'is alive' 15
    rep_evidence "Latency stats"  "$DIR_M3/ping_latency_profile.txt" '^samples=' 3
    rep_evidence "Jitter stats"   "$DIR_M3/ping_jitter_analysis.txt" '^samples=' 3
    rep_evidence "MTR hops"       "$DIR_M3/mtr_perf_report.txt" 'HOST:' 10
    rep_evidence "TCP RTT"        "$DIR_M3/tcp_connection_state.txt" 'rtt:' 6
    rep_evidence "Retrans"        "$DIR_M3/tcp_retrans_counters.txt" 'retrans' 6
    rep_evidence "Open TCP"       "$DIR_M4/nmap_full_tcp.txt"  '^[0-9]+/tcp[[:space:]]+open' 20
    rep_evidence "Open UDP"       "$DIR_M4/nmap_top_udp.txt"   '^[0-9]+/udp[[:space:]]+open' 15
    rep_evidence "SSH banner"     "$DIR_M4/nc_banner_ssh.txt"  'SSH-' 3
    rep_evidence "HTTP server"    "$DIR_M4/nc_banner_http.txt" '^HTTP/|[Ss]erver:' 4
    rep_evidence "TLS verify"     "$DIR_M4/openssl_tls_cert.txt" 'Verify return code|Cipher is' 4
    rep_evidence "testssl hits"   "$DIR_M4/testssl_full_audit.txt" 'VULNERABLE|NOT ok|WARN' 10
    rep_evidence "WAF verdict"    "$DIR_M4/wafw00f_detection.txt" 'WAF' 4
    rep_evidence "masscan ports"  "$DIR_M4/masscan_port_sweep.txt" 'Discovered open port' 20
    rep_evidence "Nikto hits"     "$DIR_M4/nikto_vuln_scan.txt" '^\+ ' 12
    (( $(wc -l < "$REPORT") <= before )) && printf '  (no evidence extracted — check module files)\n' >> "$REPORT"
    { hr_plain "-"; printf 'FILES\n'; find "$OUTDIR" -type f ! -path "$REPORT" -exec stat -c '%10s %n' {} + 2>/dev/null \
        | sort -k2 | sed 's/^/  /'; printf '  TOTAL: %s bytes\n' "$(du -sb "$OUTDIR" 2>/dev/null | cut -f1 || echo '?')"
      hr_plain "="; printf 'AUTHORIZED USE ONLY — keep this + execution_log.txt as your activity record.\n'; hr_plain "="
    } >> "$REPORT"
    REPORT_FINALIZED=1; log "FINAL" "FINAL_REPORT.txt written — ${overall}"; }

# ======================= ORCHESTRATOR ========================================
usage() {
    cat <<USAGE_EOF
 ${SCRIPT_NAME} v${VERSION} — network recon & diagnostic toolkit
AUTHORIZED USE ONLY: only scan systems you own or have permission to test.

USAGE
  ./${SCRIPT_NAME} [target] [options]     # target: IP | domain | CIDR | local
  ./${SCRIPT_NAME}                        # asks ONLY for a target, then runs all
  ./${SCRIPT_NAME} --gen-files            # writes README/DISCLAIMER/LICENSE/requirements/.gitignore

OPTIONS
  -m, --modules LIST   only these modules, e.g. -m 1,3     --fast    trim heavy ops
  -o, --outdir PATH    custom results root                 --evasive nmap/hping evasion flags
      --timeout N      per-tool seconds (default ${DEFAULT_TIMEOUT})
      --iface DEV      bind L2 tools                       --zombie IP  nmap idle scan
      --local          force-add Module 2                  --ask        enable confirm prompts
  -v, --verbose        full console narration              -h help  -V version

MODULES  1=DNS/routing  2=local L2  3=remote perf  4=black-box (auto-selected by target)

LIVE DEFAULTS (edit block at top of script): timeout=${DEFAULT_TIMEOUT}s fast=${DEFAULT_TIMEOUT_FAST}s
  ping=${PING_PROFILE_COUNT}@${PING_PROFILE_INTERVAL}s jitter=${PING_JITTER_COUNT}@${PING_JITTER_INTERVAL}s
  mtr=${MTR_REPORT_CYCLES}/${MTR_PERF_CYCLES} pcap=${TCPDUMP_PKT_COUNT} masscan=${MASSCAN_RATE}pps sweep≤${M2_MAX_SWEEP_HOSTS}

EXIT CODES  0 ok  1 tool errors  2 usage  3 missing deps  130 interrupted
USAGE_EOF
}
parse_args() {
    local -a pos=(); local need=""
    while (( $# > 0 )); do
        if [[ -n "$need" ]]; then
            case "$need" in
                modules) MODULES_SPEC="$1" ;; outdir) CUSTOM_ROOT="$1" ;;
                timeout) [[ "$1" =~ ^[0-9]+$ ]] || die 2 "--timeout needs an integer"
                    TIMEOUT_SECS="$1"; TIMEOUT_SET=1 ;;
                iface) IFACE="$1" ;; zombie) ZOMBIE="$1" ;;
            esac; need=""; shift; continue; fi
        case "$1" in
            -m|--modules) [[ -n "${2:-}" ]] || die 2 "-m needs a value"; need="modules" ;;
            -o|--outdir)  [[ -n "${2:-}" ]] || die 2 "-o needs a path"; need="outdir" ;;
            --timeout)    [[ -n "${2:-}" ]] || die 2 "--timeout needs N"; need="timeout" ;;
            --iface)      [[ -n "${2:-}" ]] || die 2 "--iface needs dev"; need="iface" ;;
            --zombie)     [[ -n "${2:-}" ]] || die 2 "--zombie needs IP"; need="zombie" ;;
            --fast) FAST_MODE=1 ;; --evasive) EVASIVE=1 ;; --local) FORCE_LOCAL=1 ;;
            --ask) AUTO_CONFIRM=0 ;; -y|--yes) AUTO_CONFIRM=1 ;; -v|--verbose) QUIET_MODE=0 ;;
            --gen-files) gen_repo_files; exit 0 ;;
            -h|--help) usage; exit 0 ;;
            -V|--version) printf '%s v%s\n' "$SCRIPT_NAME" "$VERSION"; exit 0 ;;
            --) shift; while (($#)); do pos+=("$1"); shift; done; break ;;
            -*) die 2 "unknown option '$1' — try --help" ;;
            *) pos+=("$1") ;;
        esac; shift; done
    [[ -n "$need" ]] && die 2 "option '--${need}' missing its value"
    (( ${#pos[@]} <= 1 )) || die 2 "multiple targets given — pass exactly ONE"
    (( ${#pos[@]} == 1 )) && TARGET_RAW="${pos[0]}"; return 0; }
prompt_target() {
    [[ -t 0 ]] || die 2 "no target + non-interactive stdin — run: ${SCRIPT_NAME} <target>"
    local reply="" a
    for a in 1 2 3; do
        printf 'Target (IP / domain / CIDR / "local"): '
        IFS= read -r -e reply || die 2 "input closed — run: ${SCRIPT_NAME} <target>"
        reply="${reply#"${reply%%[![:space:]]*}"}"; reply="${reply%"${reply##*[![:space:]]}"}"
        [[ -n "$reply" ]] && { TARGET_RAW="$reply"; return 0; }
        printf 'empty — try again (%d/3)\n' "$a"
    done; die 2 "no target after 3 attempts"; }
normalize_modules() { local spec="${1:?}" p e dup; local -a parts out=()
    IFS=',' read -r -a parts <<< "$spec"
    for p in "${parts[@]}"; do [[ "$p" =~ ^[1-4]$ ]] || die 2 "bad module '${p}' in -m (use 1-4)"
        dup=0; for e in "${out[@]:-}"; do [[ "$e" == "$p" ]] && { dup=1; break; }; done
        (( dup == 0 )) && out+=("$p"); done
    (( ${#out[@]} > 0 )) || die 2 "-m '${spec}' empty"
    MODULES=("${out[@]}"); }
sort_modules() { local -a s=(); local n m
    for n in 1 2 3 4; do for m in ${MODULES[@]+"${MODULES[@]}"}; do
        [[ "$m" == "$n" ]] && { s+=("$n"); break; }; done; done; MODULES=("${s[@]}"); }
add_module() { local w="${1:?}" m
    for m in ${MODULES[@]+"${MODULES[@]}"}; do [[ "$m" == "$w" ]] && return 0; done
    MODULES+=("$w"); }
select_modules() {
    if [[ -n "$MODULES_SPEC" ]]; then normalize_modules "$MODULES_SPEC"; sort_modules
        log "INFO" "modules (-m): [${MODULES[*]}]"; return 0; fi
    case "$TARGET_TYPE" in
        local) MODULES=(2) ;;
        cidr)  if is_private_cidr "$TARGET_RAW"; then MODULES=(2)
               else MODULES=(4); log "WARN" "PUBLIC CIDR → module 4 only — internet scanning is illegal without ownership"; fi ;;
        domain) MODULES=(1 3 4) ;;
        ipv4)  if is_private_v4 "$TARGET_RAW"; then MODULES=(3 4); else MODULES=(1 3 4); fi ;;
        ipv6)  MODULES=(3 4) ;;
        *) die 2 "no modules for '${TARGET_TYPE}' (bug)" ;;
    esac
    [[ "$FORCE_LOCAL" -eq 1 ]] && { add_module 2; log "INFO" "--local: module 2 added"; }
    sort_modules; log "INFO" "modules: [${MODULES[*]}]"; }
run_modules() { local m
    for m in ${MODULES[@]+"${MODULES[@]}"}; do
        case "$m" in
            1) recon_dns_routing ;; 2) recon_local_l2 ;; 3) recon_remote_perf ;; 4) recon_blackbox ;;
        esac; done; }
main() {
    parse_args "$@"
    printf '%s[*]%s NETRECON v%s — AUTHORIZED USE ONLY (use -v for full narration)\n' \
        "$C_YELLOW" "$C_RESET" "$VERSION"
    check_dependencies
    [[ -z "$TARGET_RAW" ]] && prompt_target
    detect_target_type; pick_interface; apply_fast_mode; resolve_target
    [[ "$TARGET_TYPE" == "local" ]] && derive_local_subnet
    select_modules; init_output_dirs "$TARGET_RAW"; snapshot_env; print_dep_report
    run_modules
    generate_final_report
    log "FINAL" "run complete: ${OUTDIR}"; }

# ======================= TRAPS ===============================================
on_err() { local rc=$?; local src="${BASH_SOURCE[1]:-?}" ln="${BASH_LINENO[0]:-?}"
    log "ERROR" "unhandled rc=${rc} at ${src##*/}:${ln}: ${BASH_COMMAND:-?}"
    log "ERROR" "remedy: check execution_log.txt last TOOL block; re-run with -v"; exit "$rc"; }
on_int() { local -a pids=(); mapfile -t pids < <(jobs -p); local p
    for p in "${pids[@]:-}"; do [[ -n "$p" ]] && kill -TERM "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    log "WARN" "interrupted — partial results in: ${OUTDIR:-none}"; exit 130; }
on_exit() { local rc=$?
    if [[ "${REPORT_FINALIZED}" -eq 0 && -n "${REPORT:-}" && -d "${OUTDIR:-}" ]]; then
        { hr_plain "="; printf '### REPORT STATUS: INCOMPLETE — run ended early (rc=%s) at %s\n' "$rc" "$(ts)"
          printf '### partial results preserved — see logs/execution_log.txt\n'; hr_plain "="; } \
            >> "$REPORT" 2>/dev/null || true; fi; }
trap on_err ERR; trap on_int INT TERM; trap on_exit EXIT

# ======================= --gen-files (GitHub repo spawner) ===================
gen_repo_files() {
    local f
    for f in README.md DISCLAIMER.md LICENSE requirements.txt .gitignore; do
        [[ -e "$f" ]] && printf '  [skip] %s exists\n' "$f"; done
    [[ -e README.md ]] || { cat > README.md <<'NR1'
# netrecon_suite

A big bash script I wrote because I got tired of typing the same 30 network
commands every time I sat down to look at a box.

You give it a target — an IP, a domain, a subnet, or just the word "local" —
and it asks you literally one question, then runs the whole toolbox for you:
DNS records, whois, traceroutes, ARP scans, ping tests, nmap, banner grabs,
TLS checks, packet captures... all of it. Everything lands in a timestamped
folder so you can actually find your results later.

## The deal

**Only run this against stuff you own or have permission to test.**
Seriously. Read DISCLAIMER.md first.

## Quick start

    git clone https://github.com/YOURNAME/netrecon-suite.git
    cd netrecon-suite
    chmod +x netrecon_suite.sh
    ./netrecon_suite.sh

It asks for a target, you type one, walk away, come back to organized results
plus a FINAL_REPORT.txt.

## What it does

Four modules, auto-picked by target type:

- Module 1 — DNS & routing: dig, whois, traceroutes, mtr, ASN, geoip, subdomains
- Module 2 — local network: arp-scan, nmap sweeps, fping, MAC vendor lookup
- Module 3 — performance: ping/jitter profiles, live TCP stats, iperf3, pcap+tshark
- Module 4 — black-box: full nmap suite, masscan, zmap, hping3, banners, TLS, nikto

## Flags

    ./netrecon_suite.sh 8.8.8.8              # no questions
    ./netrecon_suite.sh example.com -m 1,3   # modules 1 and 3 only
    ./netrecon_suite.sh local --fast         # quick local sweep
    ./netrecon_suite.sh target --ask         # re-enable safety prompts

## Self-tests (safe, offline)

    NETRECON_STEP2_SELFTEST=1 bash netrecon_suite.sh
    NETRECON_STEP8_SELFTEST=1 bash netrecon_suite.sh

Tested on Kali, Ubuntu, Arch. bash 4+. Use sudo for the fun tools.
NR1
    printf '  [ok] README.md\n'; }
    [[ -e DISCLAIMER.md ]] || { cat > DISCLAIMER.md <<'NR2'
# Read this before you run anything

Short version: **don't point this at machines that aren't yours.**

This tool actively scans, probes and sends packets at targets. Done without
permission, that's a crime in most countries - actual charges, not a gray area.

By using this script you're saying:

1. You only run it against systems **you own**, or where the owner gave you
   **written permission** first.
2. You know the law where you live and you're staying inside it.
3. Whatever happens - targets going down, alarms going off, lawyers - that's
   on you. The MIT license says the same thing in fancier words.

Fair warnings: Module 4 is **loud** (nmap -p-, masscan at 1000pps, nikto -
every IDS logs all of it). Fragile devices have died to scans like these.
Keep FINAL_REPORT.txt and execution_log.txt as your paper trail.

Good uses: auditing your own stuff, labs, learning, authorized pentesting.
Bad uses: everything else.

If you have to ask "is this allowed?" - ask the owner first, or don't.
NR2
    printf '  [ok] DISCLAIMER.md\n'; }
    [[ -e LICENSE ]] || { cat > LICENSE <<'NR3'
MIT License

Copyright (c) 2025 YOUR NAME HERE

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
NR3
    printf '  [ok] LICENSE (add your name!)\n'; }
    [[ -e requirements.txt ]] || { cat > requirements.txt <<'NR4'
# Shopping list, not a real python file. Only the REQUIRED block is mandatory;
# the script skips everything else it can't find.

# REQUIRED
bash (4+), coreutils, iproute2, curl

# module 1
dnsutils whois traceroute mtr-tiny geoip-bin bgpq3(or bgpq4) jq
dnsrecon dnsenum fierce amass subfinder theharvester

# module 2
arp-scan arping netdiscover fping iw wireless-tools lsof net-tools nmap

# module 3
iputils-ping tcpdump tshark iftop nethogs iperf3 ethtool

# module 4
masscan zmap hping3 openbsd-netcat openssl sslscan testssl.sh
whatweb wafw00f nikto enum4linux snmp
NR4
    printf '  [ok] requirements.txt\n'; }
    [[ -e .gitignore ]] || { cat > .gitignore <<'NR5'
netrecon_results/
*.log
*.pcap
*.swp
.DS_Store
NR5
    printf '  [ok] .gitignore\n'; }
    printf '\nDone. Edit LICENSE (your name) + README clone URL, then upload to GitHub.\n'; }

# ======================= SELF-TESTS (offline, safe) ==========================
self_test_step2() {
    QUIET_MODE=0; check_dependencies; local pass=0 fail=0
    _t() { local name="$1" exp="$2"; shift 2; local rc=0; "$@" || rc=$?
        if [[ "$rc" -eq 0 && "$exp" == "y" || "$rc" -ne 0 && "$exp" == "n" ]]; then
            log "OK" "pass: $name"; pass=$((pass+1))
        else log "ERROR" "FAIL: $name (rc=$rc)"; fail=$((fail+1)); fi; }
    _t "ipv4 ok"        y is_ipv4 "8.8.8.8"
    _t "ipv4 lead-zero" y is_ipv4 "010.1.1.1"
    _t "ipv4 reject999" n is_ipv4 "999.1.1.1"
    _t "ipv6 ::1"       y is_ipv6 "::1"
    _t "ipv6 db8"       y is_ipv6 "2001:db8::1"
    _t "ipv6 garbage"   n is_ipv6 "gggg::1"
    _t "cidr ok"        y is_cidr "192.168.1.0/24"
    _t "cidr /33"       n is_cidr "10.0.0.0/33"
    _t "cidr noslash"   n is_cidr "10.0.0.0"
    _t "domain ok"      y is_domain "example.com"
    _t "domain bad"     n is_domain "localhost"
    _t "priv10"         y is_private_v4 "10.1.2.3"
    _t "priv172"        y is_private_v4 "172.20.1.1"
    _t "pub 8.8.8.8"    n is_private_v4 "8.8.8.8"
    _t "pub 172.32"     n is_private_v4 "172.32.1.1"
    local saved="$TARGET_RAW" tt
    for tt in "8.8.8.8:ipv4" "example.com:domain" "192.168.1.0/24:cidr" "local:local"; do
        TARGET_RAW="${tt%%:*}"; detect_target_type
        if [[ "$TARGET_TYPE" == "${tt##*:}" ]]; then log "OK" "detect ${tt%%:*}"; pass=$((pass+1))
        else log "ERROR" "FAIL detect ${tt}"; fail=$((fail+1)); fi; done
    TARGET_RAW="$saved"
    MODULES=(); normalize_modules "3,1,3"; sort_modules
    log "INFO" "RESULT: pass=${pass} fail=${fail}"
    (( fail > 0 )) && exit 1; log "FINAL" "SELF-TEST OK (offline)"; }
self_test_step8() {
    QUIET_MODE=0; check_dependencies; local pass=0 fail=0 out
    _c() { local n="$1" a="$2" e="$3"
        if [[ "$a" == "$e" ]]; then log "OK" "pass: $n"; pass=$((pass+1))
        else log "ERROR" "FAIL: $n (got '$a' want '$e')"; fail=$((fail+1)); fi; }
    EVASIVE=0; _c "ev_off_nmap"  "$(build_evasive_nmap)" ""
    _c "ev_off_hping" "$(build_evasive_hping)" ""
    EVASIVE=1; _c "ev_on_nmap"  "$(build_evasive_nmap)" "-f --data-length 24"
    _c "ev_on_hping" "$(build_evasive_hping)" "-d 24"; EVASIVE=0
    out="$( FAST_MODE=1 TIMEOUT_SET=0 apply_fast_mode; printf '%s' "$TIMEOUT_SECS" )"
    _c "fast_timeout" "$out" "$DEFAULT_TIMEOUT_FAST"
    out="$( FAST_MODE=1 TIMEOUT_SET=1 TIMEOUT_SECS=42 apply_fast_mode; printf '%s' "$TIMEOUT_SECS" )"
    _c "timeout_beats_fast" "$out" "42"
    out="$( ZOMBIE="999.1.1.1" apply_fast_mode; printf '%s' "$ZOMBIE" )"
    _c "zombie_bad" "$out" ""
    out="$( ZOMBIE="10.9.9.9" apply_fast_mode; printf '%s' "$ZOMBIE" )"
    _c "zombie_ok" "$out" "10.9.9.9"
    CUSTOM_ROOT=""; out="$( parse_args -o /tmp/x 1.2.3.4; printf '%s' "$CUSTOM_ROOT" )"
    _c "outdir_parse" "$out" "/tmp/x"
    log "INFO" "RESULT: pass=${pass} fail=${fail}"
    (( fail > 0 )) && exit 1; log "FINAL" "SELF-TEST OK (offline)"; }

# ======================= ENTRY POINT =========================================
if [[ "${NETRECON_STEP2_SELFTEST:-0}" == "1" ]]; then self_test_step2
elif [[ "${NETRECON_STEP8_SELFTEST:-0}" == "1" ]]; then self_test_step8
else main "$@"
fi
