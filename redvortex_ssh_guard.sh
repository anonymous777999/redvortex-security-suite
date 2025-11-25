#!/usr/bin/env bash
#===============================================================================
# RedVortex SSH Guard v4.1 - With Whitelist Management
#===============================================================================

set -uo pipefail

#---------------------------------------
# Configuration
#---------------------------------------
LOGFILE="/var/log/auth.log"
STATE_DIR="/var/lib/redvortex_guard"
LOCKFILE="/var/run/redvortex_guard.lock"
WHITELIST_FILE="/etc/redvortex_whitelist"

NFT_TABLE="redvortex_guard"
NFT_SET="banned"

FAIL_THRESHOLD=5
FAIL_WINDOW=300
BAN_DURATION=3600

USE_COLORS=true
DEBUG=false

#---------------------------------------
# Colors
#---------------------------------------
if [[ "$USE_COLORS" == "true" ]]; then
    RED='\e[91m'; GREEN='\e[92m'; YELLOW='\e[93m'
    BLUE='\e[94m'; CYAN='\e[96m'; RESET='\e[0m'; BOLD='\e[1m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; RESET=''; BOLD=''
fi

log_info()  { echo -e "${GREEN}[INFO]${RESET} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET} $1"; }
log_error() { echo -e "${RED}[ERROR]${RESET} $1"; }
log_ban()   { echo -e "${RED}${BOLD}[BANNED]${RESET} $1"; }
log_debug() { [[ "$DEBUG" == "true" ]] && echo -e "${CYAN}[DEBUG]${RESET} $1"; }

#---------------------------------------
# Root check
#---------------------------------------
if [[ $EUID -ne 0 ]]; then
    log_error "Must be run as root"
    exit 1
fi

#---------------------------------------
# Check dependencies
#---------------------------------------
for cmd in nft tail logger; do
    if ! command -v "$cmd" &>/dev/null; then
        log_error "Missing command: $cmd"
        exit 1
    fi
done

#---------------------------------------
# Setup directories
#---------------------------------------
mkdir -p "$STATE_DIR"
touch "$STATE_DIR/failures"
touch "$WHITELIST_FILE"

#---------------------------------------
# Whitelist Functions (NEW)
#---------------------------------------
whitelist_add() {
    local ip="$1"
    
    # Validate IP format
    if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_error "Invalid IP format: $ip"
        return 1
    fi
    
    # Check if already whitelisted
    if grep -qxF "$ip" "$WHITELIST_FILE" 2>/dev/null; then
        log_warn "$ip is already in whitelist"
    else
        echo "$ip" >> "$WHITELIST_FILE"
        log_info "Added $ip to whitelist"
    fi
    
    # If currently banned, unban immediately
    if is_banned "$ip"; then
        unban_ip "$ip"
        log_info "Removed $ip from ban list"
    fi
    
    # Clear any failure records
    clear_failures "$ip"
    log_info "Cleared failure history for $ip"
    
    echo -e "${GREEN}✓ $ip is now whitelisted and will never be banned${RESET}"
}

whitelist_remove() {
    local ip="$1"
    
    if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_error "Invalid IP format: $ip"
        return 1
    fi
    
    if grep -qxF "$ip" "$WHITELIST_FILE" 2>/dev/null; then
        grep -vxF "$ip" "$WHITELIST_FILE" > "$WHITELIST_FILE.tmp"
        mv "$WHITELIST_FILE.tmp" "$WHITELIST_FILE"
        log_info "Removed $ip from whitelist"
        echo -e "${YELLOW}⚠ $ip can now be banned if it misbehaves${RESET}"
    else
        log_warn "$ip is not in whitelist"
    fi
}

whitelist_show() {
    echo -e "${CYAN}╔════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║           WHITELISTED IPs              ║${RESET}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${RESET}"
    
    if [[ -s "$WHITELIST_FILE" ]]; then
        local count=1
        while read -r ip; do
            [[ -z "$ip" ]] && continue
            echo -e "  ${GREEN}$count.${RESET} $ip"
            ((count++))
        done < "$WHITELIST_FILE"
    else
        echo -e "  ${YELLOW}(empty)${RESET}"
    fi
    echo ""
}

is_whitelisted() {
    local ip="$1"
    [[ -f "$WHITELIST_FILE" ]] && grep -qxF "$ip" "$WHITELIST_FILE" 2>/dev/null
}

#---------------------------------------
# nftables Functions
#---------------------------------------
setup_firewall() {
    log_info "Configuring nftables firewall..."

    nft delete table inet "$NFT_TABLE" 2>/dev/null || true
    nft add table inet "$NFT_TABLE"
    nft add set inet "$NFT_TABLE" "$NFT_SET" '{ type ipv4_addr; flags timeout; }'
    nft add chain inet "$NFT_TABLE" guard '{ type filter hook input priority -400; policy accept; }'
    nft add rule inet "$NFT_TABLE" guard tcp dport 22 ip saddr "@$NFT_SET" counter drop comment \"RedVortex-Block\"

    log_info "Firewall configured successfully"
}

show_firewall_status() {
    echo -e "${CYAN}╔════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║         FIREWALL STATUS                ║${RESET}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${RESET}"
    nft list table inet "$NFT_TABLE" 2>/dev/null || echo "Table not found"
    echo ""
}

is_banned() {
    local ip="$1"
    nft list set inet "$NFT_TABLE" "$NFT_SET" 2>/dev/null | grep -qF "$ip"
}

ban_ip() {
    local ip="$1"
    local reason="$2"
    local duration="${3:-$BAN_DURATION}"

    if is_whitelisted "$ip"; then
        log_warn "Cannot ban whitelisted IP: $ip"
        return 0
    fi

    if is_banned "$ip"; then
        log_debug "Already banned: $ip"
        return 0
    fi

    if nft add element inet "$NFT_TABLE" "$NFT_SET" "{ $ip timeout ${duration}s }" 2>/dev/null; then
        log_ban "$ip - $reason (${duration}s)"
        logger -t redvortex "BANNED: $ip reason=$reason duration=${duration}s"
        return 0
    else
        log_error "Failed to ban $ip"
        return 1
    fi
}

unban_ip() {
    local ip="$1"
    
    if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_error "Invalid IP format: $ip"
        return 1
    fi
    
    if is_banned "$ip"; then
        nft delete element inet "$NFT_TABLE" "$NFT_SET" "{ $ip }" 2>/dev/null
        log_info "Unbanned: $ip"
        logger -t redvortex "UNBANNED: $ip"
    else
        log_warn "$ip is not currently banned"
    fi
    
    # Also clear failures
    clear_failures "$ip"
}

unban_all() {
    log_warn "Removing ALL bans..."
    nft flush set inet "$NFT_TABLE" "$NFT_SET" 2>/dev/null
    > "$STATE_DIR/failures"
    log_info "All IPs unbanned and failure history cleared"
}

list_banned() {
    echo -e "${CYAN}╔════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║            BANNED IPs                  ║${RESET}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${RESET}"
    
    local banned_ips=$(nft list set inet "$NFT_TABLE" "$NFT_SET" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
    
    if [[ -n "$banned_ips" ]]; then
        local count=1
        while read -r ip; do
            echo -e "  ${RED}$count.${RESET} $ip"
            ((count++))
        done <<< "$banned_ips"
    else
        echo -e "  ${GREEN}(none)${RESET}"
    fi
    echo ""
}

#---------------------------------------
# Failure Tracking
#---------------------------------------
FAIL_FILE="$STATE_DIR/failures"

record_failure() {
    local ip="$1"
    local now=$(date +%s)
    echo "$ip $now" >> "$FAIL_FILE"
}

count_failures() {
    local ip="$1"
    local now=$(date +%s)
    local cutoff=$((now - FAIL_WINDOW))
    local count=0

    [[ -f "$FAIL_FILE" ]] || { echo 0; return; }

    while read -r rec_ip rec_time; do
        if [[ "$rec_ip" == "$ip" ]] && (( rec_time >= cutoff )); then
            ((count++))
        fi
    done < "$FAIL_FILE"

    echo "$count"
}

clean_old_failures() {
    local now=$(date +%s)
    local cutoff=$((now - FAIL_WINDOW))
    local tmpfile="$FAIL_FILE.tmp"

    [[ -f "$FAIL_FILE" ]] || return

    > "$tmpfile"
    while read -r rec_ip rec_time; do
        if (( rec_time >= cutoff )); then
            echo "$rec_ip $rec_time" >> "$tmpfile"
        fi
    done < "$FAIL_FILE"

    mv "$tmpfile" "$FAIL_FILE"
}

clear_failures() {
    local ip="$1"
    [[ -f "$FAIL_FILE" ]] || return
    
    local tmpfile="$FAIL_FILE.tmp"
    grep -v "^$ip " "$FAIL_FILE" > "$tmpfile" 2>/dev/null || true
    mv "$tmpfile" "$FAIL_FILE"
}

#---------------------------------------
# Process Log Lines
#---------------------------------------
process_line() {
    local line="$1"

    # Failed password
    if [[ "$line" =~ Failed\ password\ for\ (invalid\ user\ )?([^[:space:]]+)\ from\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
        local user="${BASH_REMATCH[2]}"
        local ip="${BASH_REMATCH[3]}"

        is_banned "$ip" && return
        is_whitelisted "$ip" && { log_debug "Whitelisted: $ip"; return; }

        record_failure "$ip"
        local count=$(count_failures "$ip")

        echo -e "${RED}[FAIL]${RESET} $ip → $user ${YELLOW}($count/$FAIL_THRESHOLD)${RESET}"
        logger -t redvortex "FAIL: ip=$ip user=$user count=$count"

        if (( count >= FAIL_THRESHOLD )); then
            ban_ip "$ip" "failed_auth($count)"
        fi
        return
    fi

    # Invalid user
    if [[ "$line" =~ Invalid\ user\ ([^[:space:]]+)\ from\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
        local user="${BASH_REMATCH[1]}"
        local ip="${BASH_REMATCH[2]}"

        is_banned "$ip" && return
        is_whitelisted "$ip" && return

        record_failure "$ip"
        local count=$(count_failures "$ip")

        echo -e "${YELLOW}[INVALID]${RESET} $ip → $user ${YELLOW}($count/$FAIL_THRESHOLD)${RESET}"

        if (( count >= FAIL_THRESHOLD )); then
            ban_ip "$ip" "invalid_user($count)"
        fi
        return
    fi

    # Too many authentication failures
    if [[ "$line" =~ Disconnecting.*authenticating\ user\ ([^[:space:]]+)\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*Too\ many ]]; then
        local user="${BASH_REMATCH[1]}"
        local ip="${BASH_REMATCH[2]}"

        is_banned "$ip" && return
        is_whitelisted "$ip" && return

        record_failure "$ip"
        record_failure "$ip"
        local count=$(count_failures "$ip")

        echo -e "${RED}[ATTACK]${RESET} $ip → $user ${YELLOW}($count)${RESET}"

        if (( count >= FAIL_THRESHOLD )); then
            ban_ip "$ip" "auth_flood($count)"
        fi
        return
    fi

    # Connection closed
    if [[ "$line" =~ Connection\ closed\ by\ authenticating\ user\ ([^[:space:]]+)\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
        local user="${BASH_REMATCH[1]}"
        local ip="${BASH_REMATCH[2]}"

        is_banned "$ip" && return
        is_whitelisted "$ip" && return

        record_failure "$ip"
        local count=$(count_failures "$ip")

        echo -e "${BLUE}[CLOSE]${RESET} $ip → $user ${YELLOW}($count/$FAIL_THRESHOLD)${RESET}"

        if (( count >= FAIL_THRESHOLD )); then
            ban_ip "$ip" "preauth_close($count)"
        fi
        return
    fi

    # Successful login
    if [[ "$line" =~ Accepted\ (password|publickey)\ for\ ([^[:space:]]+)\ from\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
        local method="${BASH_REMATCH[1]}"
        local user="${BASH_REMATCH[2]}"
        local ip="${BASH_REMATCH[3]}"

        echo -e "${GREEN}[OK]${RESET} $ip → $user ($method)"
        clear_failures "$ip"
        return
    fi

    # Max auth attempts
    if [[ "$line" =~ maximum\ authentication\ attempts.*from\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
        local ip="${BASH_REMATCH[1]}"

        is_banned "$ip" && return
        is_whitelisted "$ip" && return

        record_failure "$ip"
        record_failure "$ip"
        record_failure "$ip"

        ban_ip "$ip" "max_auth_exceeded"
        return
    fi
}

#---------------------------------------
# Cleanup
#---------------------------------------
cleanup() {
    echo ""
    log_info "Shutting down..."
    flock -u 200 2>/dev/null
    exit 0
}
trap cleanup SIGINT SIGTERM

#---------------------------------------
# Show Full Status
#---------------------------------------
show_full_status() {
    echo ""
    show_firewall_status
    list_banned
    whitelist_show
    
    echo -e "${CYAN}Configuration:${RESET}"
    echo -e "  • Fail threshold: $FAIL_THRESHOLD attempts"
    echo -e "  • Time window:    $FAIL_WINDOW seconds"
    echo -e "  • Ban duration:   $BAN_DURATION seconds"
    echo ""
}

#---------------------------------------
# Interactive Menu (NEW)
#---------------------------------------
interactive_menu() {
    while true; do
        echo ""
        echo -e "${CYAN}╔════════════════════════════════════════╗${RESET}"
        echo -e "${CYAN}║       RedVortex Guard - Menu           ║${RESET}"
        echo -e "${CYAN}╠════════════════════════════════════════╣${RESET}"
        echo -e "${CYAN}║${RESET}  1. Show status                        ${CYAN}║${RESET}"
        echo -e "${CYAN}║${RESET}  2. List banned IPs                    ${CYAN}║${RESET}"
        echo -e "${CYAN}║${RESET}  3. List whitelisted IPs               ${CYAN}║${RESET}"
        echo -e "${CYAN}║${RESET}  4. Add IP to whitelist                ${CYAN}║${RESET}"
        echo -e "${CYAN}║${RESET}  5. Remove IP from whitelist           ${CYAN}║${RESET}"
        echo -e "${CYAN}║${RESET}  6. Unban an IP                        ${CYAN}║${RESET}"
        echo -e "${CYAN}║${RESET}  7. Unban ALL IPs                      ${CYAN}║${RESET}"
        echo -e "${CYAN}║${RESET}  8. Start monitoring                   ${CYAN}║${RESET}"
        echo -e "${CYAN}║${RESET}  0. Exit                               ${CYAN}║${RESET}"
        echo -e "${CYAN}╚════════════════════════════════════════╝${RESET}"
        echo -n "Choose option: "
        
        read -r choice
        
        case "$choice" in
            1)
                show_full_status
                ;;
            2)
                list_banned
                ;;
            3)
                whitelist_show
                ;;
            4)
                echo -n "Enter IP to whitelist: "
                read -r ip
                [[ -n "$ip" ]] && whitelist_add "$ip"
                ;;
            5)
                echo -n "Enter IP to remove from whitelist: "
                read -r ip
                [[ -n "$ip" ]] && whitelist_remove "$ip"
                ;;
            6)
                echo -n "Enter IP to unban: "
                read -r ip
                [[ -n "$ip" ]] && unban_ip "$ip"
                ;;
            7)
                echo -n "Are you sure? (yes/no): "
                read -r confirm
                [[ "$confirm" == "yes" ]] && unban_all
                ;;
            8)
                start_monitoring
                ;;
            0)
                exit 0
                ;;
            *)
                log_error "Invalid option"
                ;;
        esac
    done
}

#---------------------------------------
# Start Monitoring
#---------------------------------------
start_monitoring() {
    # Lock check
    exec 200>"$LOCKFILE"
    if ! flock -n 200; then
        log_error "Another instance is running"
        return 1
    fi

    setup_firewall
    
    echo ""
    echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}${BOLD}║             RedVortex SSH Guard v4.1                       ║${RESET}"
    echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    
    whitelist_show
    
    log_info "Monitoring $LOGFILE..."
    echo ""

    > "$FAIL_FILE"
    local count=0

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        process_line "$line"
        ((count++)) || true
        if ((count >= 50)); then
            clean_old_failures
            count=0
        fi
    done < <(tail -n0 -F "$LOGFILE" 2>/dev/null)
}

#---------------------------------------
# Command Line Interface
#---------------------------------------
show_help() {
    echo ""
    echo -e "${GREEN}${BOLD}RedVortex SSH Guard v4.1${RESET}"
    echo ""
    echo "Usage: $0 [command] [options]"
    echo ""
    echo -e "${CYAN}Commands:${RESET}"
    echo "  (none)              Start monitoring"
    echo "  --menu              Interactive menu"
    echo "  --status            Show full status"
    echo ""
    echo -e "${CYAN}Whitelist:${RESET}"
    echo "  --whitelist-add IP      Add IP to whitelist (also unbans)"
    echo "  --whitelist-remove IP   Remove IP from whitelist"
    echo "  --whitelist-show        Show all whitelisted IPs"
    echo ""
    echo -e "${CYAN}Ban Management:${RESET}"
    echo "  --unban IP          Remove ban for specific IP"
    echo "  --unban-all         Remove ALL bans"
    echo "  --ban IP [reason]   Manually ban an IP"
    echo "  --list-banned       Show all banned IPs"
    echo ""
    echo -e "${CYAN}Other:${RESET}"
    echo "  --test              Test firewall blocking"
    echo "  --reset             Remove all rules and data"
    echo "  --help              Show this help"
    echo ""
    echo -e "${CYAN}Examples:${RESET}"
    echo "  $0 --whitelist-add 192.168.1.100"
    echo "  $0 --unban 10.0.0.50"
    echo "  $0 --ban 203.0.113.5 \"manual block\""
    echo ""
}

# Parse command line
case "${1:-}" in
    --menu)
        interactive_menu
        ;;
    --status)
        show_full_status
        ;;
    --whitelist-add)
        if [[ -n "${2:-}" ]]; then
            whitelist_add "$2"
        else
            log_error "Usage: $0 --whitelist-add <IP>"
            exit 1
        fi
        ;;
    --whitelist-remove)
        if [[ -n "${2:-}" ]]; then
            whitelist_remove "$2"
        else
            log_error "Usage: $0 --whitelist-remove <IP>"
            exit 1
        fi
        ;;
    --whitelist-show)
        whitelist_show
        ;;
    --unban)
        if [[ -n "${2:-}" ]]; then
            unban_ip "$2"
        else
            log_error "Usage: $0 --unban <IP>"
            exit 1
        fi
        ;;
    --unban-all)
        echo -n "Unban ALL IPs? (yes/no): "
        read -r confirm
        [[ "$confirm" == "yes" ]] && unban_all
        ;;
    --ban)
        if [[ -n "${2:-}" ]]; then
            setup_firewall 2>/dev/null
            ban_ip "$2" "${3:-manual_ban}"
        else
            log_error "Usage: $0 --ban <IP> [reason]"
            exit 1
        fi
        ;;
    --list-banned)
        list_banned
        ;;
    --test)
        log_info "Testing firewall..."
        setup_firewall
        ban_ip "198.51.100.99" "test" 30
        list_banned
        log_info "Test IP will be auto-removed in 30 seconds"
        ;;
    --reset)
        log_warn "Removing all RedVortex data..."
        nft delete table inet "$NFT_TABLE" 2>/dev/null || true
        rm -f "$STATE_DIR/failures"
        log_info "Reset complete"
        ;;
    --help|-h)
        show_help
        ;;
    "")
        start_monitoring
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
