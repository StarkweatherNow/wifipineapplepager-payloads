#!/bin/bash
# Title: Counter Snoop v5.4
# Description: Hybrid Engine (iw for Names + tcpdump for Spies)
# Version: 5.4 (The Solution)

# --- 1. SETUP ---
if [ -f "/lib/hak5/commands.sh" ]; then source /lib/hak5/commands.sh; fi

LOOT_DIR="/root/loot/counter_snoop"
if [ ! -d "$LOOT_DIR" ]; then mkdir -p "$LOOT_DIR"; fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOOT_DIR}/track_${TIMESTAMP}.txt"
touch "$LOG_FILE"

# Temps
SCAN_AP="/tmp/cs_ap.txt"
SCAN_CLI="/tmp/cs_cli.txt"
COMBINED="/tmp/cs_combined.txt"
HEAT_MAP="/tmp/cs_heat.txt"

rm "$SCAN_AP" "$SCAN_CLI" "$COMBINED" "$HEAT_MAP" 2>/dev/null
touch "$HEAT_MAP"

# Global Config
WALK_THRESHOLD=3
SIT_THRESHOLD=5
STATUS_INTERVAL=180
LAST_STATUS_TIME=$(date +%s)

# --- 2. INTERFACE DETECTION (HYBRID) ---
# 1. Find MANAGED interface (Best for getting Names)
IFACE_MANAGED=$(iw dev | awk '$1=="Interface" && $2!="lo" && $2!~/mon/{print $2}' | head -n 1)

# 2. Find MONITOR interface (Best for finding Phones)
IFACE_MONITOR=$(iw dev | awk '$1=="Interface" && $2 ~ /mon/{print $2}' | head -n 1)

if [ -z "$IFACE_MANAGED" ] && [ -z "$IFACE_MONITOR" ]; then
    LOG red "ERROR: No interfaces found."
    exit 1
fi

# --- 3. HOPPER (Only needed for Monitor Mode) ---
start_hopper() {
    if [ -n "$IFACE_MONITOR" ]; then
        (
            while true; do
                for CH in 1 6 11 2 7 12 3 8 4 9 5 10; do
                    iw dev "$IFACE_MONITOR" set channel $CH 2>/dev/null
                    sleep 0.5
                done
            done
        ) &
        HOPPER_PID=$!
    fi
}
stop_hopper() {
    if [ -n "$HOPPER_PID" ]; then kill "$HOPPER_PID" 2>/dev/null; fi
}

# --- 4. HARDWARE CONTROL ---
led_threat() {
    if [ "$FB_MODE" -eq 1 ]; then return; fi
    HAK5_API_POST "system/led" '{"color":"custom","raw_pattern":[{"onms":200,"offms":100,"next":false,"rgb":{"1":[true,false,false],"2":[true,false,false],"3":[true,false,false],"4":[true,false,false]}}]}' >/dev/null 2>&1
    sleep 0.3
    HAK5_API_POST "system/led" '{"color":"custom","raw_pattern":[{"onms":0,"offms":0,"next":false,"rgb":{"1":[false,false,false],"2":[false,false,false],"3":[false,false,false],"4":[false,false,false]}}]}' >/dev/null 2>&1
}

led_heartbeat() {
    if [ "$FB_MODE" -eq 1 ]; then return; fi
    HAK5_API_POST "system/led" '{"color":"custom","raw_pattern":[{"onms":500,"offms":0,"next":false,"rgb":{"1":[false,false,true],"2":[false,false,false],"3":[false,false,false],"4":[false,false,false]}}]}' >/dev/null 2>&1
    sleep 0.5
    HAK5_API_POST "system/led" '{"color":"custom","raw_pattern":[{"onms":0,"offms":0,"next":false,"rgb":{"1":[false,false,false],"2":[false,false,false],"3":[false,false,false],"4":[false,false,false]}}]}' >/dev/null 2>&1
}

do_vibe() {
    if [ "$FB_MODE" -eq 3 ] || [ "$FB_MODE" -eq 4 ]; then
        if [ -f "/sys/class/gpio/vibrator/value" ]; then
            echo "1" > /sys/class/gpio/vibrator/value; sleep 0.5; echo "0" > /sys/class/gpio/vibrator/value
        fi
    fi
}

cleanup() {
    stop_hopper
    HAK5_API_POST "system/led" '{"color":"custom","raw_pattern":[{"onms":0,"offms":0,"next":false,"rgb":{"1":[false,false,false],"2":[false,false,false],"3":[false,false,false],"4":[false,false,false]}}]}' >/dev/null 2>&1
    rm "$SCAN_AP" "$SCAN_CLI" 2>/dev/null
    LOG green "Log: $(basename $LOG_FILE)"
    exit 0
}
trap cleanup EXIT INT TERM

# --- 5. INITIALIZATION ---
PROMPT "Counter Snoop v5.4

Hybrid Engine.
Managed: ${IFACE_MANAGED:-None}
Monitor: ${IFACE_MONITOR:-None}

Press OK."

if [ -n "$IFACE_MONITOR" ]; then
    LOG blue "Hopper Active on $IFACE_MONITOR..."
    start_hopper
    sleep 2
fi

# --- 6. CONFIG ---
PROMPT "SELECT SCENARIO

1. Walking (High Alert)
   - Threshold ($WALK_THRESHOLD)
   - Vibrate & Flash

2. Sitting (Loiter Check)
   - Threshold ($SIT_THRESHOLD)
   - LED Flash Only

Press OK."
SCENARIO=$(NUMBER_PICKER "Select Scenario" 1)

if [ "$SCENARIO" -eq 1 ]; then
    THRESHOLD=$WALK_THRESHOLD; FB_MODE=3; SCENARIO_NAME="Walking"
else
    THRESHOLD=$SIT_THRESHOLD; FB_MODE=2; SCENARIO_NAME="Sitting"
fi

# --- 7. MAIN LOOP ---
CYCLE_COUNT=0
LOG blue "Tracking: $SCENARIO_NAME"

while true; do
    CYCLE_COUNT=$((CYCLE_COUNT + 1))
    rm "$COMBINED" 2>/dev/null
    touch "$COMBINED"

    # === ENGINE A: AP SCANNER (Managed Mode - Gets Names!) ===
    if [ -n "$IFACE_MANAGED" ]; then
        # Wake up interface
        ip link set "$IFACE_MANAGED" up 2>/dev/null
        
        # Use iw scan for robust naming
        iw dev "$IFACE_MANAGED" scan 2>/dev/null | awk '
            /^BSS/ {
                mac = substr($2, 1, 17)
                ssid = ""
            }
            /SSID:/ {
                # Extract SSID reliably
                ssid = substr($0, index($0, "SSID:")+6)
                if (length(ssid) == 0) ssid = "<HIDDEN>"
                
                # Print immediately
                print mac " " ssid " [AP]"
            }
        ' > "$SCAN_AP"
        
        cat "$SCAN_AP" >> "$COMBINED"
    fi

    # === ENGINE B: UNIFIED SCANNER (Monitor Mode - Gets APs AND Clients) ===
    if [ -n "$IFACE_MONITOR" ]; then
        # Modified filter: captures Probe Requests OR Beacons
        timeout 5 /usr/bin/tcpdump -i "$IFACE_MONITOR" -e -n -s 256 -l "type mgt subtype probe-req or type mgt subtype beacon" 2>/dev/null | \
        awk '
            {
                # 1. Capture Source MAC (SA)
                mac = ""
                for(i=1; i<=NF; i++) {
                    if($i ~ /SA:([0-9a-fA-F]{2}:){5}/) {
                        mac = substr($i, 4)
                        sub(/,$/, "", mac) 
                    }
                }

                if (mac != "") {
                    ssid = ""
                    type = "[CLI]"
                    
                    # 2. Extract SSID (Universal/BusyBox Method)
                    # For APs: Look for "Beacon ("
                    if (index($0, "Beacon (") > 0) {
                        type = "[AP]"
                        split($0, a, "Beacon \\(")
                        split(a[2], b, "\\)")
                        ssid = b[1]
                    }
                    # For Clients: Look for "Request ("
                    else if (index($0, "Request (") > 0) {
                        split($0, a, "Request \\(")
                        split(a[2], b, "\\)")
                        ssid = b[1]
                    }

                    # Clean up empty SSIDs
                    if (ssid == "" || ssid == " ") ssid = "<HIDDEN>"

                    print mac " " ssid " " type
                }
            }
        ' | sort -u > "$SCAN_CLI"
        
        cat "$SCAN_CLI" >> "$COMBINED"
    fi

    # === BLUETOOTH (Bonus) ===
    if command -v hcitool >/dev/null; then
        hcitool scan > "/tmp/cs_bt.txt"
        tail -n +2 "/tmp/cs_bt.txt" | awk '{print $1 " " substr($0, index($0,$2)) " [BT]"}' >> "$COMBINED"
    fi

    # === ANALYSIS (SILENT TRACKING) ===
    while read -r line; do
        MAC=$(echo "$line" | awk '{print $1}')
        FULL_DESC=$(echo "$line" | cut -d' ' -f2-)
        
        if [ -z "$MAC" ] || [ ${#MAC} -ne 17 ]; then continue; fi
        
        EXISTING=$(grep "$MAC" "$HEAT_MAP")
        
        if [ -n "$EXISTING" ]; then
            OLD_COUNT=$(echo "$EXISTING" | cut -d'|' -f2)
            ALERTED=$(echo "$EXISTING" | cut -d'|' -f4)
            if [ -z "$ALERTED" ]; then ALERTED=0; fi
            NEW_COUNT=$((OLD_COUNT + 1))
            
            # Update Heatmap (Preserve Name if it was Hidden but now Found)
            # This allows "Hidden" MACs to be updated with real names later
            OLD_NAME=$(echo "$EXISTING" | cut -d'|' -f3)
            if [[ "$OLD_NAME" == *"<HIDDEN"* ]] && [[ "$FULL_DESC" != *"<HIDDEN"* ]]; then
                 FINAL_NAME="$FULL_DESC"
            else
                 FINAL_NAME="$OLD_NAME"
            fi
            
            # TRIGGER
            if [ "$NEW_COUNT" -ge "$THRESHOLD" ] && [ "$ALERTED" -eq 0 ]; then
                TS=$(date '+%H:%M:%S')
                echo "$TS [THREAT] $FINAL_NAME" >> "$LOG_FILE"
                
                if [ "$FB_MODE" -eq 2 ] || [ "$FB_MODE" -eq 4 ]; then led_threat; fi
                do_vibe
                LOG red "THREAT CONFIRMED: $FINAL_NAME"
                
                grep -v "$MAC" "$HEAT_MAP" > "${HEAT_MAP}.tmp"
                echo "$MAC|$NEW_COUNT|$FINAL_NAME|1" >> "${HEAT_MAP}.tmp"
                mv "${HEAT_MAP}.tmp" "$HEAT_MAP"
            else
                grep -v "$MAC" "$HEAT_MAP" > "${HEAT_MAP}.tmp"
                echo "$MAC|$NEW_COUNT|$FINAL_NAME|$ALERTED" >> "${HEAT_MAP}.tmp"
                mv "${HEAT_MAP}.tmp" "$HEAT_MAP"
            fi
        else
            echo "$MAC|1|$FULL_DESC|0" >> "$HEAT_MAP"
            LOG cyan "Found: $FULL_DESC"
        fi
    done < "$COMBINED"

    # === REPORT ===
    CURRENT_TIME=$(date +%s)
    if [ $((CURRENT_TIME - LAST_STATUS_TIME)) -ge "$STATUS_INTERVAL" ]; then
        LOG blue "--- STATUS REPORT (Cycle $CYCLE_COUNT) ---"
        led_heartbeat
        sort -t'|' -k2 -nr "$HEAT_MAP" | head -n 5 | while IFS='|' read -r m c d a; do
            SHORT_NAME="${d:0:15}"
            if [ "$a" -eq 1 ]; then LOG red "($c) $SHORT_NAME [!]"; else LOG yellow "($c) $SHORT_NAME"; fi
        done
        LOG blue "----------------------------------"
        LAST_STATUS_TIME=$CURRENT_TIME
    fi
    sleep 2
done