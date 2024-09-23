#!/bin/bash

# Run with root privileges or as sudo

echo "Starting hardening process for Ubuntu 14.04..."

# 1. Enable and configure UFW (Uncomplicated Firewall)
echo "Configuring UFW..."
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (adjust as needed, for example, allowing a specific IP)
ufw allow 22/tcp  # SSH
# You can restrict SSH access to a specific IP or subnet:
# ufw allow from <your-IP-or-subnet> to any port 22

ufw enable
echo "UFW enabled and configured."

# 2. Secure SSH
echo "Hardening SSH configuration..."

# Backup original SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Modify SSH configuration for security, but keep password login enabled
sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config  # Keep password-based login enabled
sed -i 's/#MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 1m/' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/#X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config

# Set SSH port (optional)
# sed -i 's/#Port 22/Port <new-port>/' /etc/ssh/sshd_config

# Restart SSH service (using Upstart for Ubuntu 14.04)
service ssh restart
echo "SSH configuration hardened."

# 3. Enforce password policies
echo "Enforcing password policies..."
apt-get install libpam-cracklib -y

# Set password policies in /etc/pam.d/common-password
sed -i 's/pam_unix.so.*/pam_unix.so obscure sha512 remember=5 minlen=12/' /etc/pam.d/common-password

# Update login.defs for password aging policies
sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

echo "Password policies enforced."

# 4. Install and configure automatic security updates
echo "Installing and configuring unattended-upgrades..."
apt-get install unattended-upgrades -y
dpkg-reconfigure -plow unattended-upgrades

echo "Automatic security updates configured."

# 5. Secure file permissions
echo "Securing file permissions..."

# Set permissions for sensitive files
chmod 600 /etc/ssh/sshd_config
chmod 644 /etc/passwd  # Permissions corrected here to prevent user issues
chmod 600 /etc/shadow
chmod 700 /root

# Set sticky bit on /tmp and /var/tmp
chmod +t /tmp
chmod +t /var/tmp

echo "File permissions secured."

# 6. Disable root login via console but keep root user active
echo "Disabling root login via console..."

# Backup original securetty file
cp /etc/securetty /etc/securetty.bak

# Disable root console login
sed -i 's/^\(tty[1-9]\)/#\1/' /etc/securetty

echo "Root console login disabled."

# Install auditd for system auditing
apt-get install auditd audispd-plugins -y

# Start auditd service
service auditd start

# Enable auditd at boot
update-rc.d auditd enable

# Define auditing rules in /etc/audit/audit.rules
echo "-w /etc/passwd -p wa -k passwd_changes" >> /etc/audit/audit.rules
echo "-w /etc/shadow -p wa -k shadow_changes" >> /etc/audit/audit.rules
echo "-w /etc/group -p wa -k group_changes" >> /etc/audit/audit.rules
echo "-w /etc/gshadow -p wa -k gshadow_changes" >> /etc/audit/audit.rules
echo "-w /var/log/ -p wa -k log_modifications" >> /etc/audit/audit.rules

# Restart auditd service
service auditd restart

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
echo "System hardening completed."
