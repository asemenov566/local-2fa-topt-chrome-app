$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# The release contains only these reviewed runtime files, never a directory glob.
$releaseFiles = @(
    'extension/app.css'
    'extension/app.html'
    'extension/app.js'
    'extension/auth-attempts.js'
    'extension/autofill.js'
    'extension/background.js'
    'extension/core.js'
    'extension/manifest.json'
    'extension/migration-export.js'
    'extension/native.js'
    'extension/qr-reader.js'
    'extension/qr.js'
    'extension/security.js'
    'extension/session.js'
    'extension/THIRD_PARTY_NOTICES.txt'
    'extension/timer.js'
    'extension/vault.js'
    'extension/icons/16.png'
    'extension/icons/32.png'
    'extension/icons/48.png'
    'extension/icons/128.png'
    'extension/vendor/dijkstrajs.LICENSE'
    'extension/vendor/qr-reader.js'
    'extension/vendor/qrcode.LICENSE'
    'extension/vendor/qrgen.js'
    'extension/vendor/zxing_reader.wasm'
    'extension/vendor/zxing-cpp.LICENSE'
    'extension/vendor/zxing-wasm-cpp.LICENSE'
    'extension/vendor/zxing-wasm.LICENSE'
    'native/Host.cs'
    'native/CHROME-APP-TOTP.Host.exe'
    'native/Build.ps1'
    'native/Install.ps1'
    'README.md'
    'INSTALL.md'
    'LICENSE'
    'Install-Windows.cmd'
)

function Assert-NoReparsePoint([string] $Path) {
    $currentPath = [IO.Path]::GetFullPath($Path)
    while ($currentPath) {
        $item = Get-Item -LiteralPath $currentPath -Force -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Links and junctions are not allowed.'
            }
        }
        $parent = [IO.Directory]::GetParent($currentPath)
        if ($null -eq $parent) { break }
        $currentPath = $parent.FullName
    }
}

function Assert-SafeTree([string] $Path) {
    # Do not follow a reparse point during the cleanup inspection.
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Links and junctions are not allowed.'
    }
    if ($item.PSIsContainer) {
        foreach ($child in Get-ChildItem -LiteralPath $Path -Force) {
            Assert-SafeTree $child.FullName
        }
    }
}

function Remove-OwnStaging([string] $Path, [string] $OutputRoot) {
    if (!(Test-Path -LiteralPath $Path)) { return }
    Assert-NoReparsePoint $Path
    $resolvedStage = (Resolve-Path -LiteralPath $Path).ProviderPath
    $resolvedOutput = (Resolve-Path -LiteralPath $OutputRoot).ProviderPath.TrimEnd('\', '/')
    $expectedStage = [IO.Path]::GetFullPath($Path)
    $stageParent = [IO.Directory]::GetParent($resolvedStage).FullName.TrimEnd('\', '/')
    if (![string]::Equals($resolvedStage, $expectedStage, [StringComparison]::OrdinalIgnoreCase) -or
        ![string]::Equals($stageParent, $resolvedOutput, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolvedStage) -notmatch '^\.release-staging-[a-f0-9]{32}$') {
        throw 'The staging cleanup path is outside its expected location.'
    }
    Assert-SafeTree $resolvedStage
    Remove-Item -LiteralPath $resolvedStage -Recurse -Force
}

$stagingPath = $null
$outputRoot = $null
$stageCreated = $false
$failed = $false
$phase = 'checking the project files'
try {
    $projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    Assert-NoReparsePoint $projectRoot
    $outputRoot = Join-Path $projectRoot 'outputs'
    Assert-NoReparsePoint $outputRoot

    # This explicit list is generated from validated site strategy classes.
    # It does not include arbitrary files from the strategy/generated folders.
    $strategyListPath = Join-Path $projectRoot 'scripts/strategy-files.json'
    Assert-NoReparsePoint $strategyListPath
    $strategyList = Get-Content -LiteralPath $strategyListPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($strategyList.version -ne 1 -or @($strategyList.files).Count -lt 3) {
        throw 'Generate the site strategy file list before building the release.'
    }
    foreach ($strategyFile in $strategyList.files) {
        if ($strategyFile -notmatch '^extension/(strategy|generated)/[a-z][a-z0-9-]*\.js$' -or $strategyFile -cin $releaseFiles) {
            throw 'The strategy release file list is invalid.'
        }
        $releaseFiles += $strategyFile
    }

    foreach ($relativePath in $releaseFiles) {
        $sourcePath = Join-Path $projectRoot $relativePath
        Assert-NoReparsePoint $sourcePath
        if (!(Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
            Write-Host ('Missing release file: ' + $relativePath)
            throw 'A required release file is missing.'
        }
    }
    $manifest = Get-Content -LiteralPath (Join-Path $projectRoot 'extension/manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $version = [string] $manifest.version
    if ($version -notmatch '^\d{1,5}(\.\d{1,5}){0,3}$') {
        throw 'The manifest version is invalid.'
    }
    foreach ($part in $version.Split('.')) {
        if ([int] $part -gt 65535) { throw 'The manifest version is invalid.' }
    }

    $archiveName = 'Local-2FA-Authenticator-' + $version + '.zip'
    $archivePath = Join-Path $outputRoot $archiveName
    $checksumPath = Join-Path $outputRoot 'SHA256SUMS.txt'
    Assert-NoReparsePoint $archivePath
    Assert-NoReparsePoint $checksumPath
    if (!(Test-Path -LiteralPath $outputRoot)) {
        New-Item -Path $outputRoot -ItemType Directory | Out-Null
    }
    if (!(Test-Path -LiteralPath $outputRoot -PathType Container)) {
        throw 'The output location must be a directory.'
    }
    foreach ($target in @($archivePath, $checksumPath)) {
        if (Test-Path -LiteralPath $target -PathType Container) {
            throw 'An output filename refers to a directory.'
        }
    }

    $phase = 'preparing the release staging directory'
    $stagingPath = Join-Path $outputRoot ('.release-staging-' + [Guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $stagingPath) { throw 'The staging directory already exists.' }
    New-Item -Path $stagingPath -ItemType Directory | Out-Null
    $stageCreated = $true
    $payloadPath = Join-Path $stagingPath 'payload'
    New-Item -Path $payloadPath -ItemType Directory | Out-Null
    foreach ($relativePath in $releaseFiles) {
        $sourcePath = Join-Path $projectRoot $relativePath
        Assert-NoReparsePoint $sourcePath
        $destinationPath = Join-Path $payloadPath $relativePath
        $destinationDirectory = [IO.Path]::GetDirectoryName($destinationPath)
        if (!(Test-Path -LiteralPath $destinationDirectory)) {
            New-Item -Path $destinationDirectory -ItemType Directory | Out-Null
        }
        Copy-Item -LiteralPath $sourcePath -Destination $destinationPath
    }

    $phase = 'creating the ZIP and checksum'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $stagedArchive = Join-Path $stagingPath $archiveName
    [IO.Compression.ZipFile]::CreateFromDirectory($payloadPath, $stagedArchive, [IO.Compression.CompressionLevel]::Optimal, $false)
    $checksum = (Get-FileHash -LiteralPath $stagedArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    $stagedChecksum = Join-Path $stagingPath 'SHA256SUMS.txt'
    [IO.File]::WriteAllText($stagedChecksum, ($checksum + '  ' + $archiveName + "`n"), (New-Object Text.UTF8Encoding($false)))

    $phase = 'saving the release outputs'
    Assert-NoReparsePoint $outputRoot
    Assert-NoReparsePoint $archivePath
    Assert-NoReparsePoint $checksumPath
    Copy-Item -LiteralPath $stagedArchive -Destination $archivePath -Force
    Copy-Item -LiteralPath $stagedChecksum -Destination $checksumPath -Force
    Write-Host ('Created outputs/' + $archiveName)
    Write-Host 'Created outputs/SHA256SUMS.txt'
} catch {
    # Avoid printing exception messages containing local absolute paths.
    Write-Host ('Release build failed while ' + $phase + '. Check the files and permissions; links and junctions are not supported.')
    $failed = $true
} finally {
    if ($stageCreated) {
        try { Remove-OwnStaging $stagingPath $outputRoot }
        catch {
            Write-Host 'Release staging cleanup was refused or failed. Inspect outputs/.release-staging-* manually.'
            $failed = $true
        }
    }
}
if ($failed) { exit 1 }
