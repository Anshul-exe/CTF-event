#!/bin/bash

# SSH Connection Monitor and Terminator
# This script monitors active SSH connections and allows selective termination

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get current SSH connection's process ID and TTY
CURRENT_SSH_PID=$$
while [ "$(ps -o ppid= -p $CURRENT_SSH_PID)" != "1" ]; do
    CURRENT_SSH_PID=$(ps -o ppid= -p $CURRENT_SSH_PID | tr -d ' ')
done
CURRENT_TTY=$(ps -o tty= -p $CURRENT_SSH_PID | tr -d ' ')

echo -e "${BLUE}=== SSH Connection Monitor ===${NC}"
echo -e "${YELLOW}Your current connection:${NC}"
echo -e "PID: ${GREEN}$CURRENT_SSH_PID${NC}, TTY: ${GREEN}$CURRENT_TTY${NC}"
echo ""

function list_connections() {
    echo -e "${YELLOW}Active SSH connections:${NC}"
    echo -e "${BLUE}ID | USERNAME | PID | TTY | LOGIN TIME | IP ADDRESS${NC}"
    echo "-----------------------------------------------------"
    
    # Get list of all SSH processes
    SSH_PIDS=$(pgrep -f "sshd: [a-zA-Z]+" | tr '\n' ' ')
    
    # No SSH connections found
    if [ -z "$SSH_PIDS" ]; then
        echo -e "${RED}No SSH connections found${NC}"
        return 1
    fi
    
    # Process each SSH connection
    ID=1
    declare -g -A PID_MAP=()
    
    for PID in $SSH_PIDS; do
        # Get username of the SSH connection
        USERNAME=$(ps -o user= -p $PID | tr -d ' ')
        
        # Get TTY of the SSH connection
        TTY=$(ps -o tty= -p $PID | tr -d ' ')
        
        # Get login time
        LOGIN_TIME=$(ps -o lstart= -p $PID)
        
        # Get IP address (more complex)
        IP_ADDR=$(netstat -tnpa 2>/dev/null | grep "ESTABLISHED.*sshd" | grep -v "127.0.0.1" | awk '{print $5}' | cut -d: -f1 | sort | uniq | head -1)
        if [ -z "$IP_ADDR" ]; then
            IP_ADDR="(unknown)"
        fi
        
        # Map ID to PID for later use
        PID_MAP[$ID]=$PID
        
        # Highlight current connection
        if [ "$PID" == "$CURRENT_SSH_PID" ]; then
            echo -e "${GREEN}$ID | $USERNAME | $PID | $TTY | $LOGIN_TIME | $IP_ADDR (YOUR CONNECTION)${NC}"
        else
            echo -e "$ID | $USERNAME | $PID | $TTY | $LOGIN_TIME | $IP_ADDR"
        fi
        
        ((ID++))
    done
    
    return 0
}

function terminate_connection() {
    local PID=$1
    
    # Get username and TTY for logging purposes
    USERNAME=$(ps -o user= -p $PID | tr -d ' ')
    TTY=$(ps -o tty= -p $PID | tr -d ' ')
    
    # Kill the process
    echo -e "Terminating connection: ${RED}$USERNAME${NC} (PID: $PID, TTY: $TTY)"
    kill -9 $PID 2>/dev/null
    
    # Check if successfully terminated
    if ! ps -p $PID > /dev/null; then
        echo -e "${GREEN}Successfully terminated${NC}"
        return 0
    else
        echo -e "${RED}Failed to terminate${NC}"
        return 1
    fi
}

function terminate_selective() {
    if ! list_connections; then
        return
    fi
    
    echo ""
    echo -e "${YELLOW}Enter the IDs of connections you want to terminate (comma-separated)${NC}"
    echo -e "${YELLOW}Example: 1,3,5 or 'all' for all except yours, or 'cancel' to abort${NC}"
    read -p "IDs to terminate: " selection
    
    # Check for cancel
    if [[ "$selection" == "cancel" ]]; then
        echo "Operation cancelled"
        return
    fi
    
    # Check for "all"
    if [[ "$selection" == "all" ]]; then
        for ID in "${!PID_MAP[@]}"; do
            PID=${PID_MAP[$ID]}
            if [ "$PID" != "$CURRENT_SSH_PID" ]; then
                terminate_connection $PID
            fi
        done
        return
    fi
    
    # Process comma-separated list
    IFS=',' read -ra IDS <<< "$selection"
    for ID in "${IDS[@]}"; do
        # Trim whitespace
        ID=$(echo $ID | tr -d ' ')
        
        # Check if ID exists in our map
        if [[ -v PID_MAP[$ID] ]]; then
            PID=${PID_MAP[$ID]}
            
            # Don't terminate current connection
            if [ "$PID" == "$CURRENT_SSH_PID" ]; then
                echo -e "${RED}Cannot terminate your own connection (ID: $ID)${NC}"
                continue
            fi
            
            terminate_connection $PID
        else
            echo -e "${RED}Invalid ID: $ID${NC}"
        fi
    done
}

function terminate_others() {
    if ! list_connections; then
        return
    fi
    
    echo ""
    read -p "Are you sure you want to terminate ALL other SSH connections? (y/n): " confirm
    if [ "$confirm" == "y" ] || [ "$confirm" == "Y" ]; then
        # Counter for terminated connections
        TERMINATED=0
        
        for ID in "${!PID_MAP[@]}"; do
            PID=${PID_MAP[$ID]}
            if [ "$PID" != "$CURRENT_SSH_PID" ]; then
                if terminate_connection $PID; then
                    ((TERMINATED++))
                fi
            fi
        done
        
        echo -e "${YELLOW}Terminated $TERMINATED connections${NC}"
    else
        echo "Operation cancelled"
    fi
}

function keep_selected() {
    if ! list_connections; then
        return
    fi
    
    echo ""
    echo -e "${YELLOW}Enter the IDs of connections you want to KEEP (comma-separated)${NC}"
    echo -e "${YELLOW}All other connections will be terminated${NC}"
    echo -e "${YELLOW}Example: 1,3,5 or 'cancel' to abort${NC}"
    read -p "IDs to keep: " selection
    
    # Check for cancel
    if [[ "$selection" == "cancel" ]]; then
        echo "Operation cancelled"
        return
    fi
    
    # Create array of IDs to keep
    declare -A KEEP_MAP
    IFS=',' read -ra IDS <<< "$selection"
    for ID in "${IDS[@]}"; do
        # Trim whitespace
        ID=$(echo $ID | tr -d ' ')
        
        # Check if ID exists in our map
        if [[ -v PID_MAP[$ID] ]]; then
            KEEP_MAP[$ID]=1
        else
            echo -e "${RED}Invalid ID: $ID${NC}"
        fi
    done
    
    # Add current connection to keep list
    for ID in "${!PID_MAP[@]}"; do
        if [ "${PID_MAP[$ID]}" == "$CURRENT_SSH_PID" ]; then
            KEEP_MAP[$ID]=1
            echo -e "${GREEN}Adding your connection (ID: $ID) to keep list${NC}"
        fi
    done
    
    # Confirm the operation
    echo ""
    echo -e "${YELLOW}The following connections will be KEPT:${NC}"
    for ID in "${!KEEP_MAP[@]}"; do
        PID=${PID_MAP[$ID]}
        USERNAME=$(ps -o user= -p $PID | tr -d ' ')
        echo -e "${GREEN}ID: $ID, User: $USERNAME, PID: $PID${NC}"
    done
    
    echo ""
    read -p "Proceed with terminating all other connections? (y/n): " confirm
    if [ "$confirm" == "y" ] || [ "$confirm" == "Y" ]; then
        # Counter for terminated connections
        TERMINATED=0
        
        for ID in "${!PID_MAP[@]}"; do
            # Skip if in keep list
            if [[ -v KEEP_MAP[$ID] ]]; then
                continue
            fi
            
            if terminate_connection ${PID_MAP[$ID]}; then
                ((TERMINATED++))
            fi
        done
        
        echo -e "${YELLOW}Terminated $TERMINATED connections${NC}"
    else
        echo "Operation cancelled"
    fi
}

# Main menu
while true; do
    echo ""
    echo -e "${BLUE}Options:${NC}"
    echo "1) List active SSH connections"
    echo "2) Terminate specific SSH connections"
    echo "3) Keep specific SSH connections (terminate all others)"
    echo "4) Terminate all SSH connections except yours"
    echo "5) Monitor SSH connections in real-time (press Ctrl+C to stop)"
    echo "q) Quit"
    echo ""
    read -p "Enter your choice: " choice
    
    case $choice in
        1)
            list_connections
            ;;
        2)
            terminate_selective
            ;;
        3)
            keep_selected
            ;;
        4)
            terminate_others
            ;;
        5)
            echo -e "${YELLOW}Monitoring SSH connections. Press Ctrl+C to stop...${NC}"
            while true; do
                clear
                echo -e "${BLUE}=== SSH Connection Monitor (Refresh: $(date)) ===${NC}"
                list_connections
                sleep 2
            done
            ;;
        q|Q)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
done
