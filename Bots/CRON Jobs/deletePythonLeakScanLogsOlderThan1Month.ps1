# Set the path to the folder
$folderPath = "D:\Xampp\HTTPS\logs\password-leak-scan"

# Get files older than 30 days from last modification
$oldFiles = Get-ChildItem -Path $folderPath | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) }

# Delete each old file
foreach ($file in $oldFiles) {
    Remove-Item $file.FullName -Force
    Write-Host "Deleted: $($file.FullName)"
}

Write-Host "Deletion process completed."