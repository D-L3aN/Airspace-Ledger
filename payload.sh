#!/bin/bash

# ==========================================================
# Airspace Ledger
# ==========================================================
# Name: Airspace Ledger
# Author:D-L3aN
# Version: 3.0
# Author:D-L3aN
# Platform: Hak5 WiFi Pineapple Pager
# Category: Reconnaissance
#
# DESCRIPTION:
# Defensive WiFi and Bluetooth inventory, device
# classification, evidence reporting and WiFi alerts.
#
# MODES:
# snapshot       Collect a local device snapshot
# event          Process a normalized WiFi alert event
# approve MAC    Approve the currently recorded device
# sort FIELD DIR Sort and display the inventory
#
# SUPPORTED SORT FIELDS:
# date, name, mac, ip, type, status
#
# CLASSIFICATION:
# RED     New device
# ORANGE  Unapproved or identity changed
# GREEN   Explicitly approved identity
#
# SAFETY:
# No packet capture.
# No deauthentication.
# No credential collection.
# No active WiFi scanning.
# No ambient BLE discovery.
# No external transmission.
#
# ==========================================================

VERSION="3.0"
PAYLOAD_NAME="Airspace Ledger"

BASE="/root/loot/airspace_ledger_sentinel"

DB="$BASE/devices.tsv"
APPROVED="$BASE/approved.tsv"
OBSERVATIONS="$BASE/observations.tsv"

REPORTS="$BASE/reports"
SNAPSHOTS="$BASE/snapshots"

mkdir -p "$BASE" "$REPORTS" "$SNAPSHOTS"

touch "$DB" "$APPROVED" "$OBSERVATIONS"

TAB=$(printf '\t')
NOW=$(date '+%Y-%m-%d %H:%M:%S')
STAMP=$(date '+%Y%m%d_%H%M%S')

# ==========================================================
# LOGGING
# ==========================================================

notify() {
    LEVEL="$1"
    MESSAGE="$2"

    if declare -F LOG >/dev/null 2>&1; then
        LOG "$LEVEL" "$MESSAGE"
    else
        printf '[%s] %s\n' "$LEVEL" "$MESSAGE"
    fi
}

# ==========================================================
# SANITIZATION
# ==========================================================

clean() {
    printf '%s' "$1" |
        tr '\t\r\n' '   ' |
        cut -c 1-100
}

valid_mac() {
    printf '%s' "$1" |
        grep -Eiq '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'
}

# ==========================================================
# DEVICE IDENTIFICATION
# ==========================================================

get_model() {
    if [ -r /tmp/sysinfo/model ]; then
        cat /tmp/sysinfo/model
    elif command -v ubus >/dev/null 2>&1; then
        ubus call system board 2>/dev/null |
            grep '"model"' |
            head -n 1 |
            sed 's/.*: "//;s/".*//'
    else
        echo "Unknown"
    fi
}

get_hostname() {
    hostname 2>/dev/null || echo "Unknown"
}

# ==========================================================
# OBSERVATION STORAGE
#
# Fields:
# TYPE MAC IP NAME CONNECTION
# ==========================================================

observe() {
    TYPE=$(clean "$1")
    MAC=$(printf '%s' "$2" | tr 'A-F' 'a-f')
    IP=$(clean "$3")
    NAME=$(clean "$4")
    CONNECTION=$(clean "$5")

    valid_mac "$MAC" || return 0

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$TYPE" "$MAC" "$IP" "$NAME" "$CONNECTION" \
        >> "$OBSERVATIONS"
}

# ==========================================================
# WIFI INVENTORY
#
# Uses local access-point station tables where available.
# This does not perform wireless discovery.
# ==========================================================

collect_wifi() {

    command -v iw >/dev/null 2>&1 || {
        notify yellow "iw unavailable"
        return
    }

    for IFACE in $(iw dev 2>/dev/null |
        awk '$1=="Interface" {print $2}'); do

        iw dev "$IFACE" station dump 2>/dev/null |
            awk '/^Station / {print $2}' |
            while read -r MAC; do

                [ -z "$MAC" ] && continue

                IP=$(ip neigh show 2>/dev/null |
                    awk -v mac="$MAC" '
                    tolower($5)==tolower(mac) {
                        print $1
                        exit
                    ')

                observe WIFI "$MAC" "$IP" \
                    "WiFi client" "CONNECTED"

            done
    done
}

# ==========================================================
# BLUETOOTH INVENTORY
#
# Paired devices only.
# No ambient BLE discovery.
# ==========================================================

collect_ble() {

    command -v bluetoothctl >/dev/null 2>&1 || {
        notify yellow "Bluetooth utility unavailable"
        return
    }

    bluetoothctl paired-devices 2>/dev/null |
        while read -r DEVICE MAC NAME; do

            [ -z "$MAC" ] && continue

            valid_mac "$MAC" || continue

            INFO=$(bluetoothctl info "$MAC" 2>/dev/null)

            CONNECTION="PAIRED"

            if printf '%s\n' "$INFO" |
                grep -q 'Connected: yes'; then
                CONNECTION="CONNECTED"
            fi

            DEVICE_NAME=$(printf '%s\n' "$INFO" |
                sed -n 's/^[[:space:]]*Alias: //p' |
                head -n 1)

            [ -z "$DEVICE_NAME" ] && DEVICE_NAME="$NAME"

            observe BLE "$MAC" "" \
                "${DEVICE_NAME:-Bluetooth device}" "$CONNECTION"

        done
}

# ==========================================================
# APPROVAL LOOKUP
#
# Approval is tied to the recorded identity:
# TYPE MAC IP NAME
#
# An IP/name change requires investigation and
# explicit reapproval.
# ==========================================================

is_approved() {
    TYPE="$1"
    MAC="$2"
    IP="$3"
    NAME="$4"

    awk -F '\t' \
        -v t="$TYPE" \
        -v m="$MAC" \
        -v i="$IP" \
        -v n="$NAME" '
        $1==t && $2==m && $3==i && $4==n {
            found=1
        }
        END {exit !found}
    ' "$APPROVED"
}

# ==========================================================
# INVENTORY MERGE
#
# Database fields:
# FIRST LAST TYPE MAC IP NAME CONNECTION STATUS
#
# Historical devices are retained.
# ==========================================================

merge_inventory() {

    TEMP="$BASE/devices.tmp"

    awk -F '\t' -v OFS='\t' \
        -v now="$NOW" -v approved="$APPROVED" '

        # Existing inventory
        FILENAME==ARGV[1] {

            mac=$4
            if (mac=="") next

            key=$3 SUBSEP mac

            first[key]=$1
            last[key]=$2
            type[key]=$3
            address[key]=$5
            name[key]=$6
            connection[key]=$7
            old_status[key]=$8

            all[key]=1
            previous[key]=1
            next
        }

        # New observations
        {
            t=$1
            mac=$2

            if (mac=="") next

            key=t SUBSEP mac

            if (!(key in all))
                first[key]=now

            last[key]=now
            type[key]=t

            if ($3!="")
                address[key]=$3

            if ($4!="")
                name[key]=$4

            connection[key]=$5
            seen[key]=1
            all[key]=1
        }

        END {

            # Load explicit approval records.
            while ((getline line < approved)>0) {
                split(line,a,"\t")
                approval[a[1] SUBSEP a[2] SUBSEP
                         a[3] SUBSEP a[4]]=1
            }

            close(approved)

            for (key in all) {

                split(key,k,SUBSEP)

                t=k[1]
                mac=k[2]

                identity=t SUBSEP mac SUBSEP \
                    address[key] SUBSEP name[key]

                if (approval[identity]) {
                    status="GREEN"
                }
                else if (previous[key]) {
                    status="ORANGE"
                }
                else {
                    status="RED"
                }

                printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                    first[key],
                    last[key],
                    type[key],
                    mac,
                    address[key],
                    name[key],
                    connection[key],
                    status
            }
        }

    ' "$DB" "$OBSERVATIONS" > "$TEMP"

    if [ -s "$TEMP" ]; then
        mv "$TEMP" "$DB"
    fi

    : > "$OBSERVATIONS"
}

# ==========================================================
# APPROVAL MANAGEMENT
# ==========================================================

approve_device() {

    TARGET=$(printf '%s' "$1" | tr 'A-F' 'a-f')

    valid_mac "$TARGET" || {
        notify red "Invalid MAC address"
        return 1
    }

    RECORD=$(awk -F '\t' -v mac="$TARGET" '
        tolower($4)==mac {print; exit}
    ' "$DB")

    [ -z "$RECORD" ] && {
        notify red "Device not in inventory"
        return 1
    }

    IFS="$TAB" read -r FIRST LAST TYPE MAC IP NAME CONNECTION STATUS \
        <<< "$RECORD"

    TMP="$BASE/approved.tmp"

    awk -F '\t' -v mac="$TARGET" '
        tolower($2)!=mac {print}
    ' "$APPROVED" > "$TMP"

    printf '%s\t%s\t%s\t%s\n' \
        "$TYPE" "$MAC" "$IP" "$NAME" >> "$TMP"

    mv "$TMP" "$APPROVED"

    notify green "Device approval recorded"
    notify blue "$NAME ($MAC)"
}

# ==========================================================
# SORTING
# ==========================================================

sort_inventory() {

    FIELD="$1"
    ORDER="$2"

    case "$FIELD" in
        date)   COL=2 ;;
        name)   COL=6 ;;
        mac)    COL=4 ;;
        ip)     COL=5 ;;
        type)   COL=3 ;;
        status) COL=8 ;;
        *)      notify red "Invalid sort field"; return 1 ;;
    esac

    case "$ORDER" in
        asc)  SORT="-k${COL},${COL}" ;;
        desc) SORT="-k${COL},${COL}r" ;;
        *)    notify red "Invalid sort direction"; return 1 ;;
    esac

    sort -t "$TAB" $SORT "$DB"
}

# ==========================================================
# INVENTORY DISPLAY
# ==========================================================

display_inventory() {

    notify blue "SENTINEL INVENTORY"

    printf '%-8s %-7s %-16s %-18s %-15s %s\n' \
        "STATUS" "TYPE" "NAME" "MAC" "IP" "CONNECTION"

    sort_inventory "${SORT_FIELD:-date}" \
        "${SORT_ORDER:-desc}" |
        while IFS="$TAB" read -r FIRST LAST TYPE MAC IP NAME CONNECTION STATUS; do

            case "$STATUS" in
                RED)
                    notify red "RED | $TYPE | $NAME | $MAC | $IP"
                    ;;
                ORANGE)
                    notify yellow "ORANGE | $TYPE | $NAME | $MAC | $IP"
                    ;;
                GREEN)
                    notify green "GREEN | $TYPE | $NAME | $MAC | $IP"
                    ;;
            esac

        done
}

# ==========================================================
# JSON EXPORT
# ==========================================================

export_json() {

    command -v python3 >/dev/null 2>&1 || {
        notify yellow "Python 3 unavailable; JSON skipped"
        return
    }

    python3 - "$DB" "$REPORTS/snapshot_$STAMP.json" <<'PY'
import csv
import json
import sys

source, destination = sys.argv[1:3]

fields = [
    "first_seen",
    "last_seen",
    "type",
    "mac",
    "ip",
    "name",
    "connection",
    "status"
]

devices = []

with open(source, newline="", encoding="utf-8") as file:
    for row in csv.reader(file, delimiter="\t"):
        if len(row) != len(fields):
            continue
        devices.append(dict(zip(fields, row)))

with open(destination, "w", encoding="utf-8") as file:
    json.dump(
        {
            "application": "Airspace Ledger",
            "version": "3.0",
            "devices": devices
        },
        file,
        indent=2
    )
PY

    if [ -s "$REPORTS/snapshot_$STAMP.json" ]; then
        notify green "JSON evidence exported"
    fi
}

# ==========================================================
# REPORT GENERATION
# ==========================================================

generate_report() {

    REPORT="$REPORTS/snapshot_$STAMP.txt"

    {
        echo "Airspace Ledger"
        echo "Version: $VERSION"
        echo "Generated: $NOW"

        echo ""
        echo "DEVICE IDENTITY"
        echo "Model: $(get_model)"
        echo "Hostname: $(get_hostname)"
        echo "Kernel: $(uname -r)"
        echo "Architecture: $(uname -m)"
        echo ""

        echo "WIFI INTERFACES"
        if command -v iw >/dev/null 2>&1; then
            iw dev 2>/dev/null
        else
            echo "Unavailable"
        fi

        echo ""
        echo "NETWORK CONFIGURATION"
        ip -brief address 2>/dev/null
        echo ""

        echo "LOCAL NEIGHBOURS"
        ip neigh show 2>/dev/null
        echo ""

        echo "BLUETOOTH CONTROLLER"
        if command -v bluetoothctl >/dev/null 2>&1; then
            bluetoothctl show 2>/dev/null
        else
            echo "Unavailable"
        fi

        echo ""
        echo "SENTINEL DEVICE REGISTER"
        cat "$DB"

        echo ""
        echo "CLASSIFICATION"
        echo "RED: New device"
        echo "ORANGE: Investigating"
        echo "GREEN: Explicitly approved"

        echo ""
        echo "COLLECTION LIMITATIONS"
        echo "WiFi inventory depends on local station visibility."
        echo "BLE inventory contains paired devices only."
        echo "This is a point-in-time snapshot."
        echo "No packet capture or external transmission."

    } > "$REPORT"

    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$REPORT" > "$REPORT.sha256"
    fi

    export_json

    notify green "Assessment report generated"
    notify blue "$REPORT"
}

# ==========================================================
# SNAPSHOT MODE
# ==========================================================

snapshot_mode() {

    notify blue "Starting Airspace Ledger"

    : > "$OBSERVATIONS"

    collect_wifi
    collect_ble

    merge_inventory

    display_inventory

    generate_report

    notify green "Sentinel snapshot completed"
}

# ==========================================================
# EVENT MODE
#
# Normalized event adapter variables:
#
# AIRSPACE_EVENT_TYPE=WIFI
# AIRSPACE_EVENT_MAC=AA:BB:CC:DD:EE:FF
# AIRSPACE_EVENT_IP=192.168.1.25
# AIRSPACE_EVENT_NAME=Client
#
# These are this payload's interface variables.
# Map them to the actual firmware alert variables
# after inspecting the installed Hak5 example.
# ==========================================================

event_mode() {

    TYPE="${AIRSPACE_EVENT_TYPE:-WIFI}"
    MAC=$(printf '%s' "$AIRSPACE_EVENT_MAC" | tr 'A-F' 'a-f')
    IP="${AIRSPACE_EVENT_IP:-}"
    NAME="${AIRSPACE_EVENT_NAME:-WiFi client}"

    if [ "$TYPE" != "WIFI" ]; then
        notify red "Unsupported alert event type"
        return 1
    fi

    valid_mac "$MAC" || {
        notify red "Missing or invalid event MAC"
        return 1
    }

    : > "$OBSERVATIONS"

    observe "$TYPE" "$MAC" "$IP" "$NAME" "CONNECTED"

    merge_inventory

    STATUS=$(awk -F '\t' -v mac="$MAC" '
        tolower($4)==mac {print $8; exit}
    ' "$DB")

    case "$STATUS" in

        RED)
            notify red "NEW WIFI CLIENT - INVESTIGATE"
            notify red "$NAME $MAC"
            ;;

        ORANGE)
            notify yellow "UNAPPROVED CLIENT - REVIEW"
            notify yellow "$NAME $MAC"
            ;;

        GREEN)
            notify green "APPROVED CLIENT CONNECTED"
            notify green "$NAME $MAC"
            ;;

        *)
            notify yellow "Client event requires review"
            ;;

    esac
}

# ==========================================================
# MAIN MENU / COMMAND LINE
# ==========================================================

case "${1:-snapshot}" in

    snapshot)
        snapshot_mode
        ;;

    event)
        event_mode
        ;;

    approve)
        approve_device "$2"
        ;;

    sort)
        SORT_FIELD="${2:-date}"
        SORT_ORDER="${3:-desc}"
        display_inventory
        ;;

    *)
        echo "Airspace Ledger $VERSION"
        echo ""
        echo "Usage:"
        echo "  payload.sh snapshot"
        echo "  payload.sh event"
        echo "  payload.sh approve MAC"
        echo "  payload.sh sort date|name|mac|ip|type|status asc|desc"
        exit 1
        ;;

esac

exit 0
