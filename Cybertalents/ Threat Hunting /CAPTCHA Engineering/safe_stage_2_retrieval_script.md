# Safely decodes the Base64 URL and prints the second-stage script content without executing it
$base64Url = "<INSERT_EXTRACTED_BASE64_STRING_HERE>"
$decodedUrl = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64Url))

Write-Host "Decoded Stage 2 URL: $decodedUrl`n" -ForegroundColor Cyan

# Fetch and display as plain text only (DO NOT pipe to IEX)
(Invoke-WebRequest -Uri $decodedUrl -UseBasicParsing).Content