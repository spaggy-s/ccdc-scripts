# Define the new password as a secure string
$newPassword = ConvertTo-SecureString "IgotAnew5t1ck" -AsPlainText -Force

# Convert the secure string to plain text for net user command
$newPasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPassword))

# Get all local users on the server (excluding system accounts)
$localUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True AND Disabled=False"

# Loop through each user and set their password
foreach ($user in $localUsers) {
    try {
        # Skip built-in system accounts like Administrator and Guest
        if ($user.Name -ne "Administrator" -and $user.Name -ne "Guest") {
            # Change the password for the user
            net user $user.Name $newPasswordPlainText
            Write-Host "Password changed successfully for user: $($user.Name)"
        } else {
            Write-Host "Skipping system user: $($user.Name)"
        }
    } catch {
        Write-Host "Failed to change password for user: $($user.Name) - $($_.Exception.Message)"
    }
}

# Download the external script
$scriptUrl = "https://raw.githubusercontent.com/spaggy-s/ccdc-scripts/refs/heads/main/thepower.ps1"
$scriptPath = "thepower.ps1"  # Change this path as needed

try {
    Invoke-WebRequest -Uri $scriptUrl -OutFile $scriptPath
    Write-Host "Downloaded the script successfully."

    # Set execution policy to allow the script to run if necessary
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

    # Execute the downloaded script
    & $scriptPath
    Write-Host "Executed the script: $scriptPath"
} catch {
    Write-Host "Failed to download or execute the script - $($_.Exception.Message)"
}
