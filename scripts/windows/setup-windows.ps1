[CmdletBinding()]
param(
    [switch]$SkipToolInstall,
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "[PiFlasher Setup] $Message" -ForegroundColor Cyan
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-Elevated {
    $scriptPath = $MyInvocation.MyCommand.Path
    $argList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$scriptPath`""
    )

    if ($SkipToolInstall) { $argList += "-SkipToolInstall" }
    if ($SkipBuild) { $argList += "-SkipBuild" }

    Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs | Out-Null
}

function Ensure-Winget {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        throw "winget is required. Install the Microsoft App Installer from Microsoft Store and run setup again."
    }
}

function Install-WithWinget {
    param(
        [string]$Id,
        [string]$DisplayName,
        [string]$OverrideArgs = "",
        [string]$Source = "winget"
    )

    Write-Step "Installing $DisplayName (winget id: $Id, source: $Source)"
    $args = @(
        "install",
        "--id", $Id,
        "--source", $Source,
        "--exact",
        "--accept-package-agreements",
        "--accept-source-agreements",
        "--disable-interactivity",
        "--silent"
    )
    if ($OverrideArgs) {
        $args += @("--override", $OverrideArgs)
    }

    & winget.exe @args
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "winget failed to install $DisplayName (id: $Id) with exit code $exitCode"
    }
}

function Ensure-RustToolchain {
    Add-CargoToPath

    if (Get-Command cargo.exe -ErrorAction SilentlyContinue) {
        Write-Step "Rust toolchain already installed."
        return
    }

    $wingetFailure = $null
    try {
        Install-WithWinget -Id "Rustlang.Rustup" -DisplayName "Rust toolchain (rustup)"
    }
    catch {
        $wingetFailure = $_
        Write-Step "winget rustup install failed. Falling back to rustup-init.exe direct installer."
        Write-Warning $_
    }

    Add-CargoToPath
    if (Get-Command cargo.exe -ErrorAction SilentlyContinue) {
        return
    }

    $rustupInit = Join-Path $env:TEMP "rustup-init.exe"
    Write-Step "Downloading rustup-init.exe from static.rust-lang.org"
    Invoke-WebRequest -Uri "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe" -OutFile $rustupInit

    Write-Step "Running rustup-init.exe in non-interactive mode"
    & $rustupInit -y --default-toolchain stable --profile default
    $rustupExitCode = $LASTEXITCODE
    if ($rustupExitCode -ne 0) {
        if ($wingetFailure) {
            throw "Rust installation failed via winget and rustup-init (exit code: $rustupExitCode). Last winget error: $($wingetFailure.Exception.Message)"
        }
        throw "rustup-init.exe failed with exit code $rustupExitCode"
    }

    Add-CargoToPath
    if (-not (Get-Command cargo.exe -ErrorAction SilentlyContinue)) {
        throw "cargo.exe was still not found after rustup-init install. Sign out/sign in and re-run setup."
    }
}

function Add-CargoToPath {
    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    if (Test-Path $cargoBin) {
        $parts = $env:Path -split ";"
        if ($parts -notcontains $cargoBin) {
            $env:Path = "$cargoBin;$env:Path"
        }
    }
}

function Test-VsBuildToolsInstalled {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        return $false
    }

    $path = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    return -not [string]::IsNullOrWhiteSpace($path)
}

if (-not (Test-IsAdministrator)) {
    Write-Step "Requesting administrator privileges..."
    Restart-Elevated
    exit 0
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..\..")).Path

Write-Step "Repository root: $repoRoot"

if (-not $SkipToolInstall) {
    Ensure-Winget

    if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
        Install-WithWinget -Id "Git.Git" -DisplayName "Git for Windows"
    } else {
        Write-Step "Git already installed."
    }

    Ensure-RustToolchain

    if (-not (Test-VsBuildToolsInstalled)) {
        Write-Step "Visual Studio Build Tools can take several minutes to complete. Please wait..."
        Install-WithWinget `
            -Id "Microsoft.VisualStudio.2022.BuildTools" `
            -DisplayName "Visual Studio 2022 Build Tools (C++)" `
            -OverrideArgs "--quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
    } else {
        Write-Step "Visual Studio C++ Build Tools already installed."
    }
}

Add-CargoToPath
if (-not (Get-Command cargo.exe -ErrorAction SilentlyContinue)) {
    throw "cargo.exe was not found on PATH. Sign out/sign in and re-run this setup script."
}

Write-Step "Ensuring Rust stable toolchain is ready..."
& cargo.exe --version | Out-Host
& rustup.exe toolchain install stable | Out-Host
& rustup.exe default stable | Out-Host

if (-not $SkipBuild) {
    Write-Step "Building PiFlasher CLI..."
    Push-Location $repoRoot
    try {
        & cargo.exe build -p piflasher-cli
    }
    finally {
        Pop-Location
    }
}

$launcher = Join-Path $scriptDir "start-piflasher.cmd"
Write-Step "Setup complete."
Write-Host "Double-click this launcher to start PiFlasher:" -ForegroundColor Green
Write-Host "  $launcher" -ForegroundColor Green
