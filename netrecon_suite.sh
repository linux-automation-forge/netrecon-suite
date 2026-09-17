#!/usr/bin/env bash
# =============================================================================
#  netrecon_suite.sh — Network Recon & Diagnostic Automated Toolkit
# =============================================================================
#  VERSION      : 1.0.0  (first stable release — SINGLE-FILE build)
#
#  EVERYTHING IS IN THIS ONE FILE:
#    - All 4 recon modules (DNS/routing, local L2, remote perf, black-box)
#    - Consolidated FINAL_REPORT generator
#    - Offline self-tests for debugging
#    - `--gen-files`  → writes README.md, DISCLAIMER.md, LICENSE,
#                       requirements.txt and .gitignore next to this script
#                       so one file can spawn the whole GitHub repo.
#
#  USER EXPERIENCE CONTRACT:
#    ./netrecon_suite.sh            → asks ONLY for a target, then runs
#                                     everything applicable, quietly.
#    ./netrecon_suite.sh <target>   → no questions at all.
#    Prompts are OFF by default (--ask to re-enable).
#    Quiet console by default (--verbose for full narration).
#
#  DEBUG / SELF-TESTS (env-gated, no traffic):
#    NETRECON_STEP2_SELFTEST=1 bash netrecon_suite.sh   # validators (~30 checks)
#    NETRECON_STEP8_SELFTEST=1 bash netrecon_suite.sh   # flag matrix (~12 checks)
#
#  AUTHORIZED USE ONLY. Run exclusively against systems you own or have
#  explicit written permission to test. Full legal text: --gen-files then
#  read DISCLAIMER.md (summary also embedded in gen_repo_files below).
# =============================================================================


# =============================================================================
# [A] HEADER & GLOBAL SAFETY
# =============================================================================

# Strict mode:
#   -e : exit on unhandled failure   -E : ERR trap inherits into functions
#   -u : error on unset variables    -o pipefail : any pipeline stage fails → fails
set -Eeuo pipefail

# Deterministic field splitting. Functions needing space-splitting declare
# a scoped `local IFS=' '` — see log(), run_tool().
IFS=$'\n\t'

# Predictable tool output parsing (some tools localize messages/dates)
export LC_ALL=C

# New files/dirs: owner rw, group r, world nothing
umask 027

# --- Runtime state (NOT user defaults — see block [B] for those) -------------
SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
VERSION="1.0.0"
RUN_STAMP="$(date +%Y%m%d_%H%M%S)"        # per-run timestamp; dir suffix
RUN_START_EPOCH="$(date +%s)"             # wall-clock start → report duration

CUSTOM_ROOT=""                             # -o override for output root
IFACE=""                                   # --iface network interface
ZOMBIE=""                                  # --zombie idle-scan host
FORCE_LOCAL=0                              # --local force Module 2 eligibility
MODULES_SPEC=""                            # raw -m list, e.g. "1,3"
TIMEOUT_SET=0                              # 1 = user passed --timeout explicitly
LOCAL_CIDR=""                              # derived from default iface ("local")
FAST_MODE=0                                # --fast
EVASIVE=0                                  # --evasive

OUT_ROOT_DEFAULT="netrecon_results"        # fallback if -o not supplied
OUT_ROOT=""                                # resolved root after init
OUTDIR=""                                  # run-specific results directory
DIR_M1="" ; DIR_M2="" ; DIR_M3="" ; DIR_M4=""
LOGFILE=""                                 # logs/execution_log.txt
REPORT=""                                  # FINAL_REPORT.txt
README_MD=""                               # per-run README.md

TARGET_RAW=""                              # target exactly as user typed
TARGET_TYPE="unknown"                      # local|domain|ipv4|ipv6|cidr
TARGET_IP=""                               # resolved IP (domains → A/AAAA)
TARGET_LABEL=""                            # sanitized directory label
MODULES=()                                 # selected module numbers (sorted)

REPORT_FINALIZED=0                         # EXIT trap writes INCOMPLETE if 0
RUN_TOOL_LAST_RC=0                         # rc of most recent run_tool call
PICKED_TOOL=""                             # set by pick_tool()
M2_CIDR=""                                 # Module 2 sweep CIDR (resolved)
M3_ALIVE=0                                 # Module 3 liveness verdict (0/1)
M3_OPEN_PORT=""                            # Module 3 first open TCP port (443/80/22)
M4_TLS_OPEN=0                              # Module 4: port 443 reachable (0/1)
M4_SMB_OPEN=0                              # Module 4: port 445/139 reachable (0/1)
M4_V6_ADDR=""                              # Module 4: resolved IPv6 address

# --- Install hints (embedded in dependency-failure messages) -----------------
HINT_DEBIAN="sudo apt update && sudo apt install -y dnsutils whois traceroute mtr-tiny nmap masscan zmap hping3 arp-scan netdiscover fping tcpdump tshark iftop nethogs iperf3 ethtool sslscan testssl.sh whatweb wafw00f nikto enum4linux snmp geoip-bin lsof net-tools curl"
HINT_ARCH="sudo pacman -S --needed bind-tools whois traceroute mtr nmap masscan zmap hping3 arp-scan netdiscover fping tcpdump wireshark-cli iftop nethogs iperf3 ethtool sslscan testssl whatweb wafw00f nikto enum4linux snmp geoip lsof net-tools curl"


# =============================================================================
# [B] ██  USER-CONFIGURABLE DEFAULTS  ██
# =============================================================================
#   ▶▶ THIS IS THE BLOCK TO EDIT ◀◀
#   Every value below is a SAFE, SENSIBLE DEFAULT. Change any of them here to
#   permanently customize the suite — no flags needed. Most are also
#   overridable per-run via CLI flags (documented in --help and in the
#   per-run README.md generated inside every results directory).
# =============================================================================

# --- Interaction behaviour -----------------------------------------------------
QUIET_MODE=1            # 1 = QUIET (default): console shows only the target
                        #     question, one status line per tool, warnings/
                        #     errors, and the results path. Everything else
                        #     goes to logs/execution_log.txt.   (CLI: --verbose)
AUTO_CONFIRM=1          # 1 = NEVER PROMPT (default): heavy-operation gates
                        #     auto-pass — after the target, the script asks
                        #     NOTHING and runs end-to-end.              (CLI: --ask)

# --- Per-tool execution limits --------------------------------------------------
DEFAULT_TIMEOUT=60        # seconds allowed per tool            (CLI: --timeout N)
DEFAULT_TIMEOUT_FAST=15   # timeout used in --fast mode
DEFAULT_KILL_GRACE=5      # seconds between timeout SIGTERM and SIGKILL

# --- Collection profiles (count/interval pairs; signal vs. speed) ----------------
PING_PROFILE_COUNT=20     ; PING_PROFILE_INTERVAL=0.2   # latency profile ping run
PING_JITTER_COUNT=100     ; PING_JITTER_INTERVAL=0.05   # high-frequency jitter run
PING6_COUNT=20                                          # IPv6 latency run
MTR_REPORT_CYCLES=10                                    # Module 1 path report
MTR_PERF_CYCLES=50                                      # Module 3 perf report
TCPDUMP_PKT_COUNT=500                                   # packets captured per pcap
TCPDUMP_PKT_COUNT_FAST=100                              # pcap size in --fast mode
MASSCAN_RATE=1000                                       # packets/sec for masscan
NMAP_TOP_UDP_PORTS=100                                  # UDP top-ports count
IPERF3_DURATION=10                                      # seconds per iperf3 test
IFTOP_SNAPSHOT_SECS=20                                  # iftop terminal snapshot
NETHOGS_CYCLES=5                                        # nethogs refresh cycles
HPING_PROBE_COUNT=5                                     # packets per hping3 probe
M2_MAX_SWEEP_HOSTS=1024                                 # max hosts in any sweep
                                                        # (Module 2 L2 sweeps AND
                                                        #  Module 4 range scans;
                                                        #  refuse larger ranges —
                                                        #  edit freely)

# --- Tool fallback chains ---------------------------------------------------------
# First AVAILABLE tool in each chain wins; later entries are automatic
# fallbacks so the suite still produces output on minimal systems.
# 'builtin' = pure-bash fallback (e.g. /dev/tcp client) — always present.
TOOL_CHAIN_DNS=(dig host nslookup getent)     # forward lookups
TOOL_CHAIN_REVERSE=(dig host nslookup)        # reverse/PTR lookups
TOOL_CHAIN_TRACEROUTE=(traceroute tracepath)  # path tracing
TOOL_CHAIN_NETCAT=(ncat nc builtin)           # banner grabs, port probes
TOOL_CHAIN_HOSTSWEEP=(fping nmap ping)        # subnet liveness sweeps
TOOL_CHAIN_SOCKETS=(ss netstat lsof)          # listening socket inventory
TOOL_CHAIN_INTERFACES=(ip ifconfig)           # interface inventory
TOOL_CHAIN_ARPCACHE=(ip arp)                  # ARP/neigh cache dump
TOOL_CHAIN_TLS=(openssl curl)                 # TLS cert/cipher inspection
TOOL_CHAIN_GEOIP=(geoiplookup curl)           # geolocation (curl → HTTP API)

# --- Online fallbacks & network etiquette ------------------------------------------
ONLINE_FALLBACK_GEOIP=1    # 1 = allow HTTP geoip query when geoiplookup missing
MACVENDOR_API_PAUSE_SECS=1 # delay between online MAC-vendor API calls (rate limit)
MACVENDOR_API_MAX=50       # max online vendor lookups per run (0 = unlimited)

# --- Derived values (do not edit; flags may adjust these at runtime) ---------------
TIMEOUT_SECS="$DEFAULT_TIMEOUT"


# =============================================================================
# [C] CONSTANTS & FORMATTING HELPERS
# =============================================================================

# --- Color constants: activate ONLY on a TTY with NO_COLOR unset -------------
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_RED=$'\033[1;31m'
    C_GREEN=$'\033[1;32m'
    C_YELLOW=$'\033[1;33m'
    C_BLUE=$'\033[1;34m'
    C_MAGENTA=$'\033[1;35m'
    C_CYAN=$'\033[1;36m'
else
    C_RESET="" ; C_BOLD="" ; C_DIM=""
    C_RED="" ; C_GREEN="" ; C_YELLOW="" ; C_BLUE="" ; C_MAGENTA="" ; C_CYAN=""
fi

# -----------------------------------------------------------------------------
# print_banner — identity + authorized-use notice (compact when quiet)
# -----------------------------------------------------------------------------
print_banner() {
    if [[ "${QUIET_MODE}" -eq 1 ]]; then
        printf '%s[*]%s NETRECON SUITE v%s — AUTHORIZED USE ONLY. Quiet mode (use --verbose for full narration).\n' \
            "$C_YELLOW" "$C_RESET" "$VERSION"
        return 0
    fi
    printf '%s' "$C_CYAN"
    printf '+==============================================================================+\n'
    printf '|  NETRECON SUITE v%-58s |\n' "$VERSION"
    printf '|  Network Recon & Diagnostic Automated Collection Toolkit                     |\n'
    printf '+==============================================================================+\n'
    printf '%s' "$C_RESET"
    printf '%s' "$C_YELLOW"
    printf '|  AUTHORIZED USE ONLY: run this tool ONLY against systems you own or         |\n'
    printf '|  have explicit written permission to test. Unauthorized scanning is         |\n'
    printf '|  illegal in most jurisdictions. You are responsible for compliance.         |\n'
    printf '+==============================================================================+\n'
    printf '%s\n' "$C_RESET"
}

# -----------------------------------------------------------------------------
# print_section — module/phase header. Console only when not quiet; the
#                 execution_log.txt ALWAYS records it.
# -----------------------------------------------------------------------------
print_section() {
    local id="${1:?print_section: section id required}"
    local title="${2:?print_section: title required}"
    local IFS=' '
    log "EXEC" ""
    log "EXEC" "=============================================================================="
    log "EXEC" "  SECTION ${id} — ${title}"
    log "EXEC" "=============================================================================="
}

# -----------------------------------------------------------------------------
# print_kv — aligned key/value console line for status panels (verbose use)
# -----------------------------------------------------------------------------
print_kv() {
    local key="${1:?print_kv: key required}"
    local val="${2:-}"
    printf '  %s%-24s%s %s\n' "$C_BOLD" "$key" "$C_RESET" "$val"
}

# -----------------------------------------------------------------------------
# hr — colored console rule.  hr_plain — raw rule SAFE for output files.
# -----------------------------------------------------------------------------
hr() {
    local ch="${1:--}"
    local width="${2:-78}"
    printf '%s%s%s\n' "$C_DIM" "$(printf '%*s' "$width" '' | tr ' ' "$ch")" "$C_RESET"
}
hr_plain() {
    local ch="${1:-=}"
    local width="${2:-78}"
    printf '%*s\n' "$width" '' | tr ' ' "$ch"
}


# =============================================================================
# [D] SMALL UTILITIES
# =============================================================================

# -----------------------------------------------------------------------------
# ts / now_epoch / elapsed — timestamping and duration arithmetic
# -----------------------------------------------------------------------------
ts() { date '+%Y-%m-%dT%H:%M:%S%z'; }
now_epoch() { date +%s; }
elapsed() {
    local start="${1:?elapsed: start epoch required}"
    local end="${2:?elapsed: end epoch required}"
    local d=$(( end - start ))
    if (( d < 0 )); then d=0 ; fi
    if (( d < 60 )); then
        printf '%ds' "$d"
    elif (( d < 3600 )); then
        printf '%dm%02ds' $(( d / 60 )) $(( d % 60 ))
    else
        printf '%dh%02dm%02ds' $(( d / 3600 )) $(( (d % 3600) / 60 )) $(( d % 60 ))
    fi
}

# -----------------------------------------------------------------------------
# sanitize_dirname — arbitrary target string → filesystem-safe label
# -----------------------------------------------------------------------------
sanitize_dirname() {
    local raw="${1:-unknown}"
    local clean
    clean="$(printf '%s' "$raw" | tr -c 'A-Za-z0-9._-' '_')"
    clean="${clean#${clean%%[!_]*}}"                 # trim leading underscores
    clean="${clean%${clean##*[!_]}}"                 # trim trailing underscores
    clean="${clean:0:64}"
    if [[ -z "$clean" ]]; then clean="unknown_target" ; fi
    printf '%s' "$clean"
}

# -----------------------------------------------------------------------------
# die — fatal exit. Message MUST state cause AND remedy.
# -----------------------------------------------------------------------------
die() {
    local code="${1:?die: exit code required}"
    shift
    local IFS=' '
    log "ERROR" "$*"
    exit "$code"
}

# -----------------------------------------------------------------------------
# require_root — hard gate for whole-run privileged operations
# -----------------------------------------------------------------------------
require_root() {
    if (( EUID != 0 )); then
        die 1 "this operation requires root (current EUID=${EUID}) — re-run with: sudo ./${SCRIPT_NAME} <args>"
    fi
}

# -----------------------------------------------------------------------------
# confirm_action — gate for dangerous operations.
#   DEFAULT (AUTO_CONFIRM=1): auto-passes, logs to file only — the user is
#   NEVER interrupted. With --ask: interactive y/N; non-interactive stdin
#   defaults to DENY (fail-safe).
# -----------------------------------------------------------------------------
confirm_action() {
    local prompt="${1:?confirm_action: prompt required}"
    if [[ "${AUTO_CONFIRM}" -eq 1 ]]; then
        log "DEBUG" "gate auto-passed (default: no prompts): ${prompt}"
        return 0
    fi
    if [[ ! -t 0 ]]; then
        log "WARN" "non-interactive session → action SKIPPED (re-run with default settings to auto-allow, or run interactively): ${prompt}"
        return 1
    fi
    local reply=""
    if ! read -r -p "$(printf '%sConfirm? [y/N]: ' "${prompt} ")" reply; then
        return 1
    fi
    [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}


# =============================================================================
# [E] LOGGING & EXECUTION CORE
# =============================================================================

# -----------------------------------------------------------------------------
# has — cached tool-availability query. "testssl.sh" → HAS_TESTSSL_SH.
# -----------------------------------------------------------------------------
has() {
    local tool="${1:?has: tool name required}"
    local flag="HAS_$(printf '%s' "$tool" | tr -c 'A-Za-z0-9' '_')"
    if [[ -n "${!flag:-}" ]]; then
        [[ "${!flag}" == "1" ]]
        return
    fi
    if command -v "$tool" > /dev/null 2>&1; then
        printf -v "$flag" '%s' "1"
        return 0
    fi
    printf -v "$flag" '%s' "0"
    return 1
}

# -----------------------------------------------------------------------------
# pick_tool — FALLBACK RESOLVER. Walks a tool chain; first available candidate
#             wins; 'builtin' entries always match. Sets PICKED_TOOL ("" none).
# -----------------------------------------------------------------------------
pick_tool() {
    local purpose="${1:?pick_tool: purpose label required}"
    shift
    local -a chain=("$@")
    if (( ${#chain[@]} == 0 )); then
        PICKED_TOOL=""
        return 1
    fi
    local t
    for t in "${chain[@]}"; do
        if [[ "$t" == "builtin" ]]; then
            PICKED_TOOL="builtin"
            log "DEBUG" "resolver [${purpose}]: using pure-bash fallback"
            return 0
        fi
        if has "$t"; then
            PICKED_TOOL="$t"
            log "DEBUG" "resolver [${purpose}]: selected '${t}'"
            return 0
        fi
    done
    PICKED_TOOL=""
    log "DEBUG" "resolver [${purpose}]: no candidate available in chain"
    return 1
}

# -----------------------------------------------------------------------------
# log — single channel for ALL human-readable events.
#       Console policy under QUIET_MODE=1 (the default):
#         shown    → ERROR, WARN, FINAL
#         file-only→ INFO, OK, SKIP, EXEC, DEBUG
#       execution_log.txt ALWAYS receives every line (full audit trail).
# -----------------------------------------------------------------------------
log() {
    local level="${1:-INFO}"
    shift
    local IFS=' '
    local msg="$*"

    if [[ "$level" == "DEBUG" && "${QUIET_MODE}" -eq 1 ]]; then
        return 0
    fi

    local now color to_console=1
    now="$(date '+%H:%M:%S')"
    case "$level" in
        OK)     color="$C_GREEN"   ;;
        WARN)   color="$C_YELLOW"  ;;
        ERROR)  color="$C_RED"     ;;
        SKIP)   color="$C_YELLOW"  ;;
        EXEC)   color="$C_CYAN"    ;;
        DEBUG)  color="$C_DIM"     ;;
        FINAL)  color="$C_BOLD$C_CYAN" ;;
        *)      color="$C_BLUE"    ;;
    esac

    if [[ "${QUIET_MODE}" -eq 1 ]]; then
        case "$level" in
            ERROR|WARN|FINAL) ;;
            *) to_console=0 ;;
        esac
    fi

    if [[ "$to_console" -eq 1 ]]; then
        printf '%s[%s] [%-5s]%s %s\n' "$color" "$now" "$level" "$C_RESET" "$msg"
    fi

    if [[ -n "${LOGFILE:-}" ]]; then
        printf '[%s] [%s] %s\n' "$(ts)" "$level" "$msg" >> "$LOGFILE"
    fi
}

# -----------------------------------------------------------------------------
# log_tool — the mandated per-tool audit line, exact contract:
#     TOOL: <name> | STATUS: RUNNING/OK/SKIPPED/TIMEOUT/ERROR | dur=Ns [| detail]
#   Quiet mode suppresses only the interim RUNNING line.
# -----------------------------------------------------------------------------
log_tool() {
    local tool="${1:?log_tool: tool label required}"
    local status="${2:?log_tool: status required}"
    local dur="${3:-0}"
    local detail="${4:-}"

    local line="TOOL: ${tool} | STATUS: ${status} | dur=${dur}s"
    if [[ -n "$detail" ]]; then
        line+=" | ${detail}"
    fi

    if [[ -n "${LOGFILE:-}" ]]; then
        printf '[%s] %s\n' "$(ts)" "$line" >> "$LOGFILE"
    fi

    if [[ "${QUIET_MODE}" -eq 1 && "$status" == "RUNNING" ]]; then
        return 0
    fi

    local color
    case "$status" in
        OK)       color="$C_GREEN"   ;;
        RUNNING)  color="$C_CYAN"    ;;
        TIMEOUT)  color="$C_MAGENTA" ;;
        ERROR)    color="$C_RED"     ;;
        *)        color="$C_YELLOW"  ;;
    esac
    printf '  %s[%-8s]%s %-24s (%ss)%s%s\n' \
        "$color" "$status" "$C_RESET" "$tool" "$dur" \
        "${detail:+ — }" "${detail:-}"
}

# -----------------------------------------------------------------------------
# tool_skip — clean SKIPPED audit line WITHOUT invoking run_tool.
# -----------------------------------------------------------------------------
tool_skip() {
    local label="${1:?tool_skip: label required}"
    local reason="${2:?tool_skip: reason required}"
    log_tool "$label" "SKIPPED" 0 "$reason"
}

# -----------------------------------------------------------------------------
# run_tool — UNIVERSAL EXECUTION WRAPPER. Every external tool call in every
#            module goes through this function. Contract:
#
#   run_tool [--root] <label> <outfile> <timeout_secs> -- <command...>
#
#   1. Binary missing              → log_tool SKIPPED, return 0
#   2. --root given, EUID != 0     → log_tool SKIPPED (requires root), return 0
#   3. Header block appended to outfile (target, exact argv, start time)
#   4. Run under `timeout -k $DEFAULT_KILL_GRACE <T>`; output ALWAYS appended
#      to outfile; streamed to console only when QUIET_MODE=0
#   5. rc classified: 0=OK, 124=TIMEOUT, 126/127=ERROR, other=ERROR
#   6. Footer block + final log_tool status line with duration
#
#   Returns : ALWAYS 0. Callers needing the raw rc read $RUN_TOOL_LAST_RC.
# -----------------------------------------------------------------------------
run_tool() {
    local want_root=0
    if [[ "${1:-}" == "--root" ]]; then
        want_root=1
        shift
    fi

    local label="${1:?run_tool: label required}"
    local outfile="${2:?run_tool: outfile required}"
    local tsecs="${3:-$TIMEOUT_SECS}"
    shift 3

    if [[ "${1:-}" != "--" ]]; then
        die 2 "run_tool('${label}'): expected '--' separator before command — script bug, report the failing section"
    fi
    shift

    local IFS=' '
    local -a cmd=("$@")
    if (( ${#cmd[@]} == 0 )); then
        die 2 "run_tool('${label}'): no command supplied after '--' — script bug, report the failing section"
    fi
    if (( tsecs <= 0 )); then tsecs="$TIMEOUT_SECS" ; fi

    if ! has "${cmd[0]}"; then
        RUN_TOOL_LAST_RC=0
        log_tool "$label" "SKIPPED" 0 "not installed — fallback chain may cover this; see README.md toolchain table"
        return 0
    fi

    if [[ "$want_root" -eq 1 && "$EUID" -ne 0 ]]; then
        RUN_TOOL_LAST_RC=0
        log_tool "$label" "SKIPPED" 0 "requires root — re-run with sudo for this tool"
        return 0
    fi

    if ! : >> "$outfile" 2> /dev/null; then
        die 1 "run_tool('${label}'): cannot write to '${outfile}' — check permissions on the results directory or pass -o /writable/path"
    fi

    {
        printf '\n'
        hr_plain "="
        printf '### TOOL   : %s\n' "$label"
        printf '### START  : %s\n' "$(ts)"
        printf '### CMD    : %s\n' "$*"
        printf '### TARGET : %s (%s)\n' "${TARGET_RAW:-n/a}" "${TARGET_TYPE:-unknown}"
        printf '### TIMEOUT: %ss\n' "$tsecs"
    } >> "$outfile"

    log_tool "$label" "RUNNING" 0 "timeout=${tsecs}s"
    local start end rc status detail
    start="$(now_epoch)"

    set +e
    if [[ "${QUIET_MODE}" -eq 0 ]]; then
        timeout -k "$DEFAULT_KILL_GRACE" "$tsecs" "$@" 2>&1 | tee -a "$outfile"
        rc=${PIPESTATUS[0]}
    else
        timeout -k "$DEFAULT_KILL_GRACE" "$tsecs" "$@" >> "$outfile" 2>&1
        rc=$?
    fi
    set -e

    end="$(now_epoch)"
    local dur=$(( end - start ))
    RUN_TOOL_LAST_RC="$rc"

    case "$rc" in
        0)
            status="OK" ; detail=""
            ;;
        124)
            status="TIMEOUT"
            detail="exceeded ${tsecs}s — raise via --timeout N or edit DEFAULT_TIMEOUT in the defaults block"
            ;;
        126)
            status="ERROR"
            detail="rc=126 permission denied — binary not executable; check perms or re-run with sudo"
            ;;
        127)
            status="ERROR"
            detail="rc=127 not found inside timeout — race vs dependency check; reinstall the tool"
            ;;
        *)
            status="ERROR"
            detail="rc=${rc} — inspect the tail of this output file for the tool's own error message"
            ;;
    esac

    {
        printf '### END    : %s\n' "$(ts)"
        printf '### STATUS : %s (rc=%s, dur=%ss)\n' "$status" "$rc" "$dur"
        hr_plain "="
    } >> "$outfile"

    log_tool "$label" "$status" "$dur" "$detail"
    return 0
}


# =============================================================================
# [F] DEPENDENCY CHECKER
# =============================================================================

REQUIRED_CMDS=(
    timeout date tee stat find du grep awk sed tr    # coreutils + text tools
    ip                                               # iproute2
    curl                                             # HTTP timing + GeoIP fallback
)

OPTIONAL_TOOLS=(
    "dig|dns"            "nslookup|dns"       "host|dns"
    "whois|dns"          "traceroute|route"   "tracepath|route"
    "mtr|route"          "geoiplookup|geoip"  "bgpq3|bgp"        "bgpq4|bgp"
    "getent|dns"
    "dnsrecon|enum"      "dnsenum|enum"       "fierce|enum"
    "amass|enum"         "subfinder|enum"     "theHarvester|enum"
    "theharvester|enum"
    "arp-scan|l2"        "arping|l2"          "netdiscover|l2"   "fping|l2"
    "iw|wifi"            "iwlist|wifi"
    "ifconfig|legacy"    "arp|legacy"
    "lsof|host"          "netstat|legacy"     "nmap|host"
    "ping|telemetry"     "ping6|telemetry"    "tcpdump|telemetry"
    "tshark|telemetry"   "iftop|telemetry"    "nethogs|telemetry"
    "bmon|telemetry"     "vnstat|telemetry"   "iperf3|telemetry"
    "nuttcp|telemetry"   "ethtool|telemetry"  "nstat|telemetry"  "ss|telemetry"
    "masscan|scan"       "zmap|scan"          "hping3|scan"
    "nc|netcat"          "ncat|netcat"        "socat|netcat"
    "openssl|tls"        "sslscan|tls"        "testssl.sh|tls"   "testssl|tls"
    "whatweb|web"        "wafw00f|web"        "nikto|web"
    "enum4linux|smb"     "enum4linux-ng|smb"  "snmpwalk|snmp"
)

# -----------------------------------------------------------------------------
# check_dependencies — hard gate. bash >= 4 + REQUIRED_CMDS; primes HAS_* cache.
# -----------------------------------------------------------------------------
check_dependencies() {
    if (( BASH_VERSINFO[0] < 4 )); then
        die 3 "bash >= 4.0 required, found ${BASH_VERSION} — try: bash ./${SCRIPT_NAME} or upgrade bash"
    fi

    local -a missing=()
    local cmd
    for cmd in "${REQUIRED_CMDS[@]}"; do
        if ! command -v "$cmd" > /dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done

    if (( ${#missing[@]} > 0 )); then
        local list
        list="$(printf '%s\n' "${missing[@]}" | tr '\n' ' ')"
        die 3 "missing REQUIRED dependencies: ${list% } — install coreutils/iproute2/curl for your distro (Debian/Kali: sudo apt install -y coreutils iproute2 curl | Arch: sudo pacman -S --needed coreutils iproute2 curl), then re-run"
    fi
    log "OK" "required dependencies present: ${#REQUIRED_CMDS[@]} commands + bash ${BASH_VERSION}"

    local entry tool cat
    for entry in "${OPTIONAL_TOOLS[@]}"; do
        IFS='|' read -r tool cat <<< "$entry"
        has "$tool" || true
    done
    log "DEBUG" "optional tool availability cache primed (${#OPTIONAL_TOOLS[@]} entries)"
}

# -----------------------------------------------------------------------------
# print_dep_report — per-tool availability table. File always; console only
#                    outside quiet mode.
# -----------------------------------------------------------------------------
print_dep_report() {
    local entry tool cat
    local avail=0 total=0
    log "EXEC" "--- OPTIONAL TOOL AVAILABILITY ---"
    for entry in "${OPTIONAL_TOOLS[@]}"; do
        IFS='|' read -r tool cat <<< "$entry"
        total=$(( total + 1 ))
        if has "$tool"; then
            avail=$(( avail + 1 ))
            log "OK"   "dep [$(printf '%-9s' "$cat")] ${tool}"
        else
            log "SKIP" "dep [$(printf '%-9s' "$cat")] ${tool} — MISSING (fallback chain or graceful skip applies)"
        fi
    done
    log "INFO" "optional tool coverage: ${avail}/${total} available"
}


# =============================================================================
# [G] OUTPUT DIRECTORIES + PER-RUN README + ENV SNAPSHOT
# =============================================================================

# -----------------------------------------------------------------------------
# init_output_dirs — per-run results tree. IDEMPOTENCY: never overwrite; a
#   _2/_3/... suffix is appended on collision.
# -----------------------------------------------------------------------------
init_output_dirs() {
    local label
    label="$(sanitize_dirname "${1:?init_output_dirs: target label required}")"
    TARGET_LABEL="$label"

    local root="${CUSTOM_ROOT:-$OUT_ROOT_DEFAULT}"
    OUT_ROOT="$root"

    local base="${root}/${label}_${RUN_STAMP}"
    local candidate="$base"
    local n=1
    while [[ -e "$candidate" ]]; do
        n=$(( n + 1 ))
        candidate="${base}_${n}"
    done
    OUTDIR="$candidate"

    if ! mkdir -p "$OUTDIR"; then
        die 1 "cannot create output directory '${OUTDIR}' — check permissions on '${root}' or pass a writable path via -o /your/path"
    fi

    DIR_M1="$OUTDIR/01_dns_routing"
    DIR_M2="$OUTDIR/02_local_l2"
    DIR_M3="$OUTDIR/03_remote_perf"
    DIR_M4="$OUTDIR/04_blackbox"
    if ! mkdir -p "$DIR_M1" "$DIR_M2" "$DIR_M3" "$DIR_M4" "$OUTDIR/logs"; then
        die 1 "cannot create module subdirectories under '${OUTDIR}' — check free space and permissions (df -h . ; ls -ld '${OUTDIR}')"
    fi

    LOGFILE="$OUTDIR/logs/execution_log.txt"
    REPORT="$OUTDIR/FINAL_REPORT.txt"
    README_MD="$OUTDIR/README.md"

    if ! : >> "$LOGFILE"; then
        die 1 "cannot write execution log '${LOGFILE}' — check directory permissions"
    fi
    if ! : >> "$REPORT"; then
        die 1 "cannot write report file '${REPORT}' — check directory permissions"
    fi

    {
        hr_plain "="
        printf '### NETRECON SUITE — EXECUTION LOG\n'
        printf '### run target : %s\n' "$label"
        printf '### started    : %s\n' "$(ts)"
        printf '### pid        : %s\n' "$$"
        printf '### suite ver  : %s\n' "$VERSION"
        printf '### mode       : quiet=%s auto-confirm=%s\n' "$QUIET_MODE" "$AUTO_CONFIRM"
        hr_plain "="
    } >> "$LOGFILE"

    {
        printf '### NETRECON SUITE — FINAL REPORT (in progress)\n'
        printf '### target  : %s\n' "$label"
        printf '### started : %s\n' "$(ts)"
    } >> "$REPORT"

    write_readme
    log "FINAL" "results directory: ${OUTDIR}"
}

# -----------------------------------------------------------------------------
# _readme_chain_row — one Markdown table row: purpose | selected | full chain.
# -----------------------------------------------------------------------------
_readme_chain_row() {
    local purpose="${1:?_readme_chain_row: purpose required}"
    shift
    local chain_str="$*"
    if pick_tool "$purpose" "$@"; then
        printf '| %s | **%s** | %s |\n' "$purpose" "$PICKED_TOOL" "$chain_str" >> "$README_MD"
    else
        printf '| %s | _none available_ | %s |\n' "$purpose" "$chain_str" >> "$README_MD"
    fi
}

# -----------------------------------------------------------------------------
# write_readme — generate OUTDIR/README.md: run behaviour, every configurable
#   default with live value + CLI override, effective toolchain, missing
#   optional tools, install hints.
# -----------------------------------------------------------------------------
write_readme() {
    {
        cat <<'EOF'
# netrecon_suite.sh — Run README

This file was generated automatically at the start of this run. It documents
exactly how THIS run is configured and which tools it will actually use.

## How this run behaves

| Behaviour | Value | Change it via |
|---|---|---|
| Quiet console | see below | `--verbose` for full narration |
| Confirmation prompts | see below | default = none; `--ask` to re-enable |

The script asks at most ONE question in its lifetime: the target (and only if
you did not supply one as an argument). Everything else is automatic.

## User-configurable defaults

Edit these in the **★ USER-CONFIGURABLE DEFAULTS ★** block at the top of
`netrecon_suite.sh` to change them permanently, or use the CLI flag per run.
Values below are the LIVE values for this run.

| Setting | Live value | Meaning | CLI override |
|---|---|---|---|
EOF
        local -a tun_doc=(
            "QUIET_MODE|1=quiet console, 0=full narration|--verbose"
            "AUTO_CONFIRM|1=never prompt, 0=ask before heavy scans|--ask"
            "DEFAULT_TIMEOUT|per-tool timeout in seconds|--timeout N"
            "DEFAULT_TIMEOUT_FAST|timeout used in --fast mode|--fast + --timeout N"
            "DEFAULT_KILL_GRACE|seconds between SIGTERM and SIGKILL after timeout|(edit block)"
            "PING_PROFILE_COUNT|packets in latency-profile ping run|(edit block)"
            "PING_PROFILE_INTERVAL|interval between profile pings (s)|(edit block)"
            "PING_JITTER_COUNT|packets in high-frequency jitter run|(edit block)"
            "PING_JITTER_INTERVAL|interval between jitter pings (s)|(edit block)"
            "PING6_COUNT|packets in IPv6 latency run|(edit block)"
            "MTR_REPORT_CYCLES|mtr cycles, Module 1 path report|(edit block)"
            "MTR_PERF_CYCLES|mtr cycles, Module 3 perf report|(edit block)"
            "TCPDUMP_PKT_COUNT|packets captured per pcap file|(edit block)"
            "TCPDUMP_PKT_COUNT_FAST|pcap packet cap in --fast mode|(edit block)"
            "MASSCAN_RATE|masscan packets per second|(edit block)"
            "NMAP_TOP_UDP_PORTS|nmap top-UDP port count|(edit block)"
            "IPERF3_DURATION|seconds per iperf3 throughput test|(edit block)"
            "IFTOP_SNAPSHOT_SECS|iftop terminal snapshot duration|(edit block)"
            "NETHOGS_CYCLES|nethogs per-process sampling cycles|(edit block)"
            "HPING_PROBE_COUNT|packets per hping3 probe|(edit block)"
            "M2_MAX_SWEEP_HOSTS|max hosts in any sweep/range scan (M2+M4)|(edit block)"
            "ONLINE_FALLBACK_GEOIP|allow HTTP geoip fallback (1/0)|(edit block)"
            "MACVENDOR_API_PAUSE_SECS|delay between online MAC vendor calls (s)|(edit block)"
            "MACVENDOR_API_MAX|max online MAC vendor lookups per run (0=∞)|(edit block)"
        )
        local entry key meaning flagov
        for entry in "${tun_doc[@]}"; do
            IFS='|' read -r key meaning flagov <<< "$entry"
            printf '| `%s` | `%s` | %s | %s |\n' "$key" "${!key}" "$meaning" "$flagov"
        done

        cat <<'EOF'

## Effective toolchain on this host

The suite never hard-requires optional tools. For each job it walks a
fallback chain (edit the `TOOL_CHAIN_*` arrays in the defaults block) and
uses the first available candidate. **Selected** = what THIS host will use.

| Job | Selected | Full chain |
|---|---|---|
EOF
    } > "$README_MD"

    _readme_chain_row "DNS lookup"          "${TOOL_CHAIN_DNS[@]}"
    _readme_chain_row "Reverse DNS"         "${TOOL_CHAIN_REVERSE[@]}"
    _readme_chain_row "Traceroute"          "${TOOL_CHAIN_TRACEROUTE[@]}"
    _readme_chain_row "Netcat/banner grab"  "${TOOL_CHAIN_NETCAT[@]}"
    _readme_chain_row "Host sweep"          "${TOOL_CHAIN_HOSTSWEEP[@]}"
    _readme_chain_row "Socket inventory"    "${TOOL_CHAIN_SOCKETS[@]}"
    _readme_chain_row "Interface inventory" "${TOOL_CHAIN_INTERFACES[@]}"
    _readme_chain_row "ARP cache"           "${TOOL_CHAIN_ARPCACHE[@]}"
    _readme_chain_row "TLS inspection"      "${TOOL_CHAIN_TLS[@]}"
    _readme_chain_row "GeoIP"               "${TOOL_CHAIN_GEOIP[@]}"

    {
        cat <<'EOF'

## Missing optional tools on this host

These are absent; related features degrade gracefully or use fallbacks.

EOF
        local entry tool cat any_missing=0
        for entry in "${OPTIONAL_TOOLS[@]}"; do
            IFS='|' read -r tool cat <<< "$entry"
            if ! has "$tool"; then
                printf -- '- `%s` (category: %s)\n' "$tool" "$cat"
                any_missing=1
            fi
        done
        if [[ "$any_missing" -eq 0 ]]; then
            printf 'None — full tool coverage on this host.\n'
        fi
        cat <<'EOF'

## Install missing tools

Debian/Kali: