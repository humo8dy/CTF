# Hunts Windows PowerShell.evtx for suspicious Event ID 400 and 800 entries
$logPath = "$env:USERPROFILE\Desktop\Logs\Windows PowerShell.evtx"

Get-WinEvent -Path $logPath -ErrorAction SilentlyContinue |
Where-Object {
    $_.Id -in @(400, 800) -and
    $_.Message -match "http|iex|irm|enc|bypass|hidden|download|temp|appdata|FromBase64String"
} |
ForEach-Object {
    "[$($_.TimeCreated)] [ID:$($_.Id)]"
    $_.Message
    "========================================"
}