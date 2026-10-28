$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (!(Test-Path -LiteralPath $compiler)) { $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
& $compiler /nologo /optimize+ /target:winexe /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll /reference:System.Security.dll "/out:$PSScriptRoot\CHROME-APP-TOTP.Host.exe" "$PSScriptRoot\Host.cs"
if ($LASTEXITCODE -ne 0) { throw 'Native host compilation failed.' }
