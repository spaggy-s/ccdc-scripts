#!/bin/bash

# Function to change the port state using UFW
change_port_state() {
    local port=$1
    local action=$2

    if [ "$action" == "close" ]; then
        echo "Closing port $port..."
        ufw deny $port/tcp
    elif [ "$action" == "open" ]; then
        echo "Opening port $port..."
        ufw allow $port/tcp
    fi
}

# Function to handle user input for specific ports
manage_specific_ports() {
    declare -A ports=(
        [21]="ftp"
        [22]="ssh"
        [80]="http"
        [445]="microsoft-ds"
        [631]="ipp"
        [3000]="ppp"
        [3306]="mysql"
        [3500]="rtmp-port"
        [6697]="ircs-u"
        [8080]="http-proxy"
        [8181]="intermapper"
    )

    for port in "${!ports[@]}"; do
        read -p "Port $port (${ports[$port]}) is open. Would you like to close this port? [y/N]: " close_port_choice
        if [[ "$close_port_choice" == "y" || "$close_port_choice" == "Y" ]]; then
            change_port_state $port "close"
        else
            echo "Port $port will remain open."
        fi
    done
}

# Function to handle user input for additional open ports
manage_additional_ports() {
    echo "Scanning for any additional open ports on localhost..."
    open_ports=$(ss -tuln | grep LISTEN | awk '{print $5}' | cut -d':' -f2)

    for port in $open_ports; do
        if ! [[ "$port" =~ ^(21|22|80|445|631|3000|3306|3500|6697|8080|8181)$ ]]; then
            read -p "Additional open port $port detected. Would you like to close this port? [y/N]: " close_additional_choice
            if [[ "$close_additional_choice" == "y" || "$close_additional_choice" == "Y" ]]; then
                change_port_state $port "close"
            else
                echo "Port $port will remain open."
            fi
        fi
    done
}

# Ensure UFW is enabled
echo "Enabling UFW..."
ufw enable

# Manage specific ports
manage_specific_ports

# Manage additional open ports
manage_additional_ports

echo "Firewall configuration complete."
