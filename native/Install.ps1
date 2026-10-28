$ErrorActionPreference = 'Stop'
$hostExe = Join-Path $PSScriptRoot 'CHROME-APP-TOTP.Host.exe'
if (!(Test-Path -LiteralPath $hostExe)) { & (Join-Path $PSScriptRoot 'Build.ps1') }
$registrationFolder = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'CHROME-APP-TOTP'
New-Item -ItemType Directory -Path $registrationFolder -Force | Out-Null
$manifestPath = Join-Path $registrationFolder 'com.asemenov566.chrome_app_totp.json'
$manifest = @{ name='com.asemenov566.chrome_app_totp'; description='CHROME-APP-TOTP local encrypted file access'; path=$hostExe; type='stdio'; allowed_origins=@('chrome-extension://fgjoonbdgfdpjmpjbephffmkjackfgnp/') }
[IO.File]::WriteAllText($manifestPath,($manifest | ConvertTo-Json -Depth 3),(New-Object Text.UTF8Encoding($false)))
$registryPath = 'HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.asemenov566.chrome_app_totp'
New-Item -Path $registryPath -Force | Out-Null
Set-Item -LiteralPath $registryPath -Value $manifestPath
Write-Output 'CHROME-APP-TOTP file helper installed for the current Windows user.'
Write-Output 'No service or startup task was created. Reload the extension in Chrome.'
