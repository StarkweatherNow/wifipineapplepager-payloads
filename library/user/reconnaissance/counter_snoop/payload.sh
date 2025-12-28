#!/bin/bash
# Title: Counter Snoop v5.6
# Description: Universal Parser + Smart Silence + Leaderboard
# Version: 5.6 (No Duplicates)

# --- 1. SETUP ---
if [ -f "/lib/hak5/commands.sh" ]; then source /lib/hak5/commands.sh; fi

LOOT_DIR="/root/loot/counter_snoop"
if [ ! -d "$LOOT_DIR" ]; then mkdir -p "$LOOT_DIR"; fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOOT_DIR}/track_${TIMESTAMP}.txt"
touch "$LOG_FILE"

# Temps
SCAN_CLI="/tmp/cs_cli.txt"
COMBINED="/tmp/cs_combined.txt"
HEAT_MAP="/tmp/cs_heat.txt"

rm "$SCAN_CLI" "$COMBINED" "$HEAT_MAP" 2>/dev/null
touch "$HEAT_MAP"

# Global Config
WALK_THRESHOLD=3
SIT_THRESHOLD=5
STATUS_INTERVAL=180
LAST_STATUS_TIME=$(date +%s)

# --- 2. INTERFACE DETECTION ---
IFACE_MONITOR=$(iw dev | awk '$1=="Interface" && $2 ~ /mon/{print $2}' | head -n 1)

if [ -z "$IFACE_MONITOR" ]; then
    LOG red "ERROR: No Monitor Interface Found."
    exit 1
fi

# --- 3. HARDWARE CONTROL ---
start_hopper() {
    (
        while true; do
            for CH in 1 6 11 2 7 12 3 8 4 9 5 10; do
                iw dev "$IFACE_MONITOR" set channel $CH 2>/dev/null
                sleep 0.5
            done
        done
    ) &
    HOPPER_PID=$!
}
stop_hopper() {
    if [ -n "$HOPPER_PID" ]; then kill "$HOPPER_PID" 2>/dev/null; fi
}

led_threat() {
    if [ "$FB_MODE" -eq 1 ]; then return; fi
    HAK5_API_POST "system/led" '{"color":"custom","raw_pattern":[{"onms":200,"offms":100,"next":false,"rgb":{"1":[true,false,false],"2":[true,false,false],"3":[true,false,false],"4":[true,false,false]}}]}' >/dev/null 2>&1
    sleep 0.3
    HAK5_API_POST "system/led" '{"color":"custom","raw_pattern":[{"onms":0,"offms":0,"next":false,"rgb":{"1":[false,false,false],"2":[false,false,false],"3":[false,false,false],"4":[false,false,false]}}]}' >/dev/null 2>&1
}

led_heartbeat() {
    if [ "$FB_MODE" -eq 1 ]; then return; fi
    HAK5_API_POST "system/led" '{"color":"custom","raw_pattern":[{"onms":500,"offms":0,"next":false,"rgb":{"1":[false,false,true],"2":[false,false,false],"3":[false,false,false],"4":[false,false,false]}}]}' >/dev/null 2>&1
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
    rm "$SCAN_CLI" "$COMBINED" 2>/dev/null
    LOG green "Log Saved: $(basename $LOG_FILE)"
    exit 0
}
trap cleanup EXIT INT TERM

# --- 4. STARTUP ---
PROMPT "Counter Snoop v5.6
Monitor: ${IFACE_MONITOR}

Press OK to Start."

start_hopper
sleep 2

SCENARIO=$(NUMBER_PICKER "Select Scenario" 1)
if [ "$SCENARIO" -eq 1 ]; then
    THRESHOLD=$WALK_THRESHOLD; FB_MODE=3; SCENARIO_NAME="Walking"
else
    THRESHOLD=$SIT_THRESHOLD; FB_MODE=2; SCENARIO_NAME="Sitting"
fi

# --- 5. MAIN LOOP ---
CYCLE_COUNT=0
LOG blue "Tracking: $SCENARIO_NAME"

while true; do
    CYCLE_COUNT=$((CYCLE_COUNT + 1))
    rm "$COMBINED" 2>/dev/null
    touch "$COMBINED"

    # === ENGINE: UNIVERSAL SCANNER (SPLIT METHOD) ===
    timeout 5 /usr/bin/tcpdump -i "$IFACE_MONITOR" -e -n -s 256 -l "type mgt subtype probe-req or type mgt subtype beacon" 2>/dev/null | \
    awk '
        {
            mac = ""
            for(i=1; i<=NF; i++) {
                if($i ~ /SA:([0-9a-fA-F]{2}:){5}/) {
                    mac = substr($i, 4)
                    sub(/,$/, "", mac) 
                }
            }
            if (mac != "") {
                ssid = ""; type = "[CLI]"
                
                # Universal Split Method for Name Extraction
                if (index($0, "Beacon (") > 0) {
                    type = "[AP]"
                    split($0, a, "Beacon \\(")
                    split(a[2], b, "\\)")
                    ssid = b[1]
                }
                else if (index($0, "Request (") > 0) {
                    split($0, a, "Request \\(")
                    split(a[2], b, "\\)")
                    ssid = b[1]
                }
                
                if (ssid == "" || ssid == " ") ssid = "<HIDDEN>"
                print mac " " ssid " " type
            }
        }
    ' | sort -u > "$SCAN_CLI"
    
    cat "$SCAN_CLI" >> "$COMBINED"

    # === BLUETOOTH ===
    if command -v hcitool >/dev/null; then
        hcitool scan > "/tmp/cs_bt.txt"
        tail -n +2 "/tmp/cs_bt.txt" | awk '{print $1 " " substr($0, index($0,$2)) " [BT]"}' >> "$COMBINED"
    fi

    # === ANALYSIS (SMART SILENCE) ===
    while read -r line; do
        MAC=$(echo "$line" | awk '{print $1}')
        FULL_DESC=$(echo "$line" | cut -d' ' -f2-)
        
        if [ -z "$MAC" ] || [ ${#MAC} -ne 17 ]; then continue; fi
        
        # Check if MAC exists in our Heatmap
        if grep -qF "$MAC" "$HEAT_MAP"; then
            # --- KNOWN MAC: SILENT UPDATE ---
            OLD_LINE=$(grep -F "$MAC" "$HEAT_MAP")
            OLD_COUNT=$(echo "$OLD_LINE" | cut -d'|' -f2)
            OLD_NAME=$(echo "$OLD_LINE" | cut -d'|' -f3)
            ALERTED=$(echo "$OLD_LINE" | cut -d'|' -f4)
            
            NEW_COUNT=$((OLD_COUNT + 1))
            
            # Update Name if previously hidden
            if [[ "$OLD_NAME" == *"<HIDDEN"* ]] && [[ "$FULL_DESC" != *"<HIDDEN"* ]]; then
                 FINAL_NAME="$FULL_DESC"
            else
                 FINAL_NAME="$OLD_NAME"
            fi
            
            # Threat Trigger
            if [ "$NEW_COUNT" -ge "$THRESHOLD" ] && [ "$ALERTED" -eq 0 ]; then
                TS=$(date '+%H:%M:%S')
                echo "$TS [THREAT] $FINAL_NAME" >> "$LOG_FILE"
                if [ "$FB_MODE" -eq 2 ] || [ "$FB_MODE" -eq 4 ]; then led_threat; fi
                do_vibe
                LOG red "THREAT CONFIRMED: $FINAL_NAME"
                ALERTED=1
            fi
            
            # Update File (Swap old line for new)
            grep -vF "$MAC" "$HEAT_MAP" > "${HEAT_MAP}.tmp"
            echo "$MAC|$NEW_COUNT|$FINAL_NAME|$ALERTED" >> "${HEAT_MAP}.tmp"
            mv "${HEAT_MAP}.tmp" "$HEAT_MAP"
            
        else
            # --- NEW MAC ---
            # "Smart Silence": If we have seen this SSID Name before (from another MAC),
            # DO NOT print it. Just track it silently.
            SHOULD_PRINT=1
            
            # Only apply suppression to APs that are not hidden
            if [[ "$FULL_DESC" != *"<HIDDEN"* ]] && [[ "$FULL_DESC" != *"[CLI]"* ]]; then
                 # Check if this Name string exists anywhere in the Heatmap
                 if grep -Fq "$FULL_DESC" "$HEAT_MAP"; then
                      SHOULD_PRINT=0
                 fi
            fi
            
            if [ "$SHOULD_PRINT" -eq 1 ]; then
                 LOG blue "Found: $FULL_DESC"
            fi
            
            # Always add to Heatmap
            echo "$MAC|1|$FULL_DESC|0" >> "$HEAT_MAP"
        fi
    done < "$COMBINED"

    # === LEADERBOARD REPORT ===
    CURRENT_TIME=$(date +%s)
    if [ $((CURRENT_TIME - LAST_STATUS_TIME)) -ge "$STATUS_INTERVAL" ]; then
        LOG blue "--- TOP SIGNALS (Cycle $CYCLE_COUNT) ---"
        led_heartbeat
        
        # Sort by Count (High to Low), Show Top 8
        sort -t'|' -k2 -nr "$HEAT_MAP" | head -n 8 | while IFS='|' read -r m c d a; do
            SHORT_NAME="${d:0:22}"
            if [ "$a" -eq 1 ]; then 
                LOG red "($c) $SHORT_NAME [!]"
            else 
                LOG yellow "($c) $SHORT_NAME"
            fi
        done
        LOG blue "----------------------------------"
        LAST_STATUS_TIME=$CURRENT_TIME
    fi
done