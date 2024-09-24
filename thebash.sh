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

# Disable IPv6
echo "Disabling unused network protocols (IPv6)..."
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p
echo "IPv6 disabled."

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

echo "Starting ProFTPD patching process..."

# Stop the current ProFTPD service if running
echo "Stopping ProFTPD service (if running)..."
if service proftpd status &> /dev/null; then
    sudo service proftpd stop
fi

# Check if ProFTPD is installed in /opt
if [ -d "/opt/proftpd" ]; then
    echo "Found ProFTPD installed in /opt."
    
    # Backup the existing configuration file to the user's home directory
    if [ -f "/opt/proftpd/etc/proftpd.conf" ]; then
        echo "Backing up existing ProFTPD configuration..."
        BACKUP_DIR="$HOME"  # Set backup directory to user's home directory
        sudo cp /opt/proftpd/etc/proftpd.conf "$BACKUP_DIR/proftpd.conf.backup"
        echo "Backup saved to $BACKUP_DIR/proftpd.conf.backup."
    fi

    # Remove ProFTPD from /opt
    echo "Removing ProFTPD from /opt..."
    sudo rm -rf /opt/proftpd
    echo "ProFTPD removed from /opt."
else
    echo "No ProFTPD installation found in /opt."
fi

# Clean up any remaining init.d scripts or configuration files
echo "Cleaning up old ProFTPD configuration files..."
sudo rm -f /etc/init.d/proftpd
sudo rm -f /etc/proftpd/proftpd.conf
echo "Cleanup complete."

# Install ProFTPD from the official repository
echo "Updating package index..."
sudo apt-get update

# Install ProFTPD
echo "Installing the latest version of ProFTPD..."
sudo apt-get install proftpd -y

# Verify installation
echo "Verifying ProFTPD installation..."
proftpd -v

# Restart the ProFTPD service
echo "Restarting ProFTPD service..."
sudo service proftpd restart

# Final output
echo "ProFTPD patching process complete."
echo "ProFTPD is now installed and running."
Changes Made
Backup Directory: The backup directory is 

echo "Starting Samba patching process..."

# Backup the existing Samba configuration
echo "Backing up Samba configuration..."
sudo cp /etc/samba/smb.conf ~/smb.conf.backup

# Install the latest version of Samba
echo "Installing the latest version of Samba..."
sudo apt-get install samba -y

# Restart Samba services
echo "Restarting Samba services..."
sudo service smbd restart
sudo service nmbd restart

echo "Samba patching process complete."

echo installing useful tools

wget https://downloads.cisofy.com/lynis/lynis-3.1.1.tar.gz
tar -xzf lynis-latest.tar.gz
echo lynis is installed

sudo apt-get install fail2ban 

echo "Backing up default jail.conf..."
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.conf.bak

# Create or modify jail.local
echo "Creating or modifying jail.local..."

sudo tee /etc/fail2ban/jail.local > /dev/null <<EOF
[DEFAULT]
bantime = 3600                  # 1 hour ban
findtime = 600                  # 10 minutes findtime window
maxretry = 5                    # Ban after 5 failed attempts
ignoreip = 127.0.0.1/8          # Ignore local IP

# Enable SSH protection
[sshd]
enabled = true
port    = ssh
logpath = /var/log/auth.log
maxretry = 5

# Enable Samba protection
[smb]
enabled = true
port    = netbios-ssn,445
logpath = /var/log/samba/log.smbd
maxretry = 3

# Protect proftpd
[proftpd]
enabled = true
port    = ftp,ftp-data,ftps
logpath = /var/log/proftpd/proftpd.log
maxretry = 5
EOF

# Restart Fail2ban to apply changes
echo "Restarting Fail2ban service..."
sudo systemctl restart fail2ban
sudo systemctl enable fail2ban

# Show Fail2ban status and enabled jails
echo "Fail2ban status:"
sudo fail2ban-client status

sudo apt-get install -y libapache2-modsecurity

# Enable the ModSecurity module
sudo a2enmod security2

# Restart Apache to apply changes
sudo service apache2 restart

# Copy the default ModSecurity configuration file
if [ ! -f /etc/modsecurity/modsecurity.conf ]; then
    sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
fi

# Set ModSecurity to "Prevention Mode" (actively blocking threats)
sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

# Download and set up the OWASP Core Rule Set (CRS)
sudo apt-get install -y git
sudo git clone https://github.com/coreruleset/coreruleset.git /etc/apache2/modsecurity-crs
sudo cp /etc/apache2/modsecurity-crs/crs-setup.conf.example /etc/apache2/modsecurity-crs/crs-setup.conf

# Include CRS configuration in the Apache ModSecurity configuration
if ! grep -q "IncludeOptional /etc/apache2/modsecurity-crs/*.conf" /etc/apache2/mods-available/security2.conf; then
    echo "IncludeOptional /etc/apache2/modsecurity-crs/*.conf" | sudo tee -a /etc/apache2/mods-available/security2.conf
fi

# Add some custom security rules
cat <<EOT | sudo tee /etc/apache2/modsecurity-crs/custom.rules
# Block requests from certain User-Agents (e.g., curl)
SecRule REQUEST_HEADERS:User-Agent "curl" "id:1000001,phase:1,deny,status:403,msg:'Curl requests are blocked'"

# Block access to .env files
SecRule REQUEST_URI "\.env$" "id:1000002,phase:1,deny,status:403,msg:'Access to .env files is blocked'"

# Block SQL Injection attempts (basic rule)
SecRule ARGS "\b(select|union|insert|update|delete|drop|alter)\b" \
    "id:1000003,phase:2,deny,status:403,msg:'SQL Injection attempt blocked'"
EOT

# Include the custom rules in the Apache configuration
if ! grep -q "IncludeOptional /etc/apache2/modsecurity-crs/custom.rules" /etc/apache2/mods-available/security2.conf; then
    echo "IncludeOptional /etc/apache2/modsecurity-crs/custom.rules" | sudo tee -a /etc/apache2/mods-available/security2.conf
fi

# Restart Apache to apply changes
sudo service apache2 restart

echo "ModSecurity installation and configuration complete!"

# Install ClamAV
echo "Installing ClamAV..."
sudo apt-get install -y clamav clamav-daemon

# Update ClamAV virus definitions
echo "Updating ClamAV virus definitions..."
sudo freshclam

# Install rkhunter
echo "Installing rkhunter..."
sudo apt-get install -y rkhunter

# Update rkhunter data files
echo "Updating rkhunter data files..."
sudo rkhunter --update

# Configure ClamAV to run on startup
sudo systemctl enable clamav-daemon

# Restart ClamAV service
echo "Restarting ClamAV service..."
sudo systemctl restart clamav-daemon

# Display installation and update status
echo "ClamAV and rkhunter installation complete!"
echo "You can run ClamAV scans with 'clamscan' and rkhunter checks with 'rkhunter --check'."

history -c

echo "System hardening completed."
