# Define the URL for Microsoft Security Essentials
$downloadUrl = "https://download.microsoft.com/download/A/3/8/A38FFBF2-1122-48B4-AF60-E44F6DC28BD8/ENUS/amd64/MSEInstall.exe"

# Get the current directory
$currentDirectory = Get-Location

# Use WMI to find the name of the network adapter
$networkAdapter = Get-WmiObject Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -First 1 -ExpandProperty Name

# Inform the user
Write-Host "Current Directory: $currentDirectory"
Write-Host "Network Adapter: $networkAdapter"

# Start Internet Explorer to download Microsoft Security Essentials
Start-Process "iexplore.exe" -ArgumentList $downloadUrl
Write-Host "Opened Internet Explorer to download Microsoft Security Essentials."

# Starting hardening process...
Write-Host "Starting hardening process..."

# Enabling Windows Firewall
netsh advfirewall set allprofiles state on
Write-Host "Windows Firewall has been enabled."

# Block inbound connections for unknown services
$portsToBlock = @("49155", "9200", "8383", "3306", "8080", "49153", "8022", "8009", "49152", "7676", "8443", "4848", "3389", "49154", "8181", "8031", "135", "445", "139")
foreach ($port in $portsToBlock) {
    Write-Host "Do you want to block inbound connections for port $port (Y/N): "
    $response = Read-Host
    if ($response -eq "Y" -or $response -eq "y") {
        netsh advfirewall firewall add rule name="Block Port $port" dir=in action=block protocol=TCP localport=$port
        Write-Host "Blocked inbound connections for port $port."
    } else {
        Write-Host "Skipping blocking for port $port."
    }
}

# Enabling Windows Update
Set-Service -Name wuauserv -StartupType Automatic
Start-Service wuauserv
Write-Host "Windows Update has been enabled and started."

# Configure account policies
net accounts /minpwlen:12
net accounts /maxpwage:30
net accounts /lockoutthreshold:5
Write-Host "Account policies have been configured."

# Enable Firewall logging
netsh advfirewall set allprofiles logging filename "$currentDirectory\pfirewall.log"
netsh advfirewall set allprofiles logging maxfilesize 32767
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging allowedconnections enable
Write-Host "Firewall logging has been enabled."

# Disable IPv6 manually as Disable-NetAdapterBinding is not available
$interfaceIndex = Get-WmiObject Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -First 1 -ExpandProperty InterfaceIndex
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 0xFFFFFFFF /f
Write-Host "IPv6 has been disabled manually in the registry."

# Comprehensive hardening process completed.
Write-Host "Comprehensive hardening process completed."
