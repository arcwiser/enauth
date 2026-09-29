[CmdletBinding()]
param(
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
$exampleDirectory = $PSScriptRoot
$buildDirectory = Join-Path $exampleDirectory "build"

function Find-CMake {
    $command = Get-Command cmake -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $standardPath = "C:\Program Files\CMake\bin\cmake.exe"
    if (Test-Path -LiteralPath $standardPath) {
        return $standardPath
    }

    return $null
}

function Test-CppBuildTools {
    $vswherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path -LiteralPath $vswherePath)) {
        return $false
    }

    $installation = & $vswherePath -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath
    return -not [string]::IsNullOrWhiteSpace($installation)
}

function Install-Package([string]$packageId, [string[]]$extraArguments = @()) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "A required build tool is missing and winget is unavailable. Install Visual Studio Build Tools 2022 (Desktop development with C++) and CMake, then run this script again."
    }

    Write-Host "Installing $packageId..."
    $arguments = @(
        "install", "--id", $packageId, "--exact", "--silent",
        "--accept-package-agreements", "--accept-source-agreements"
    ) + $extraArguments
    & winget @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "winget could not install $packageId (exit code $LASTEXITCODE)."
    }
}

$cmakePath = Find-CMake
if (-not $cmakePath) {
    if ($SkipInstall) {
        throw "CMake is required but was not found."
    }
    Install-Package "Kitware.CMake"
    $cmakePath = Find-CMake
    if (-not $cmakePath) {
        throw "CMake was installed but is not visible yet. Open a new terminal and run this script again."
    }
}

if (-not (Test-CppBuildTools)) {
    if ($SkipInstall) {
        throw "Visual Studio C++ Build Tools are required but were not found."
    }
    Install-Package "Microsoft.VisualStudio.2022.BuildTools" @(
        "--override",
        "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
    )
    if (-not (Test-CppBuildTools)) {
        throw "C++ Build Tools were installed but are not visible yet. Restart Windows if requested, then run this script again."
    }
}

Write-Host "Configuring the example client..."
& $cmakePath -S $exampleDirectory -B $buildDirectory -G "Visual Studio 17 2022" -A x64
if ($LASTEXITCODE -ne 0) {
    throw "CMake configuration failed."
}

Write-Host "Building the example client..."
& $cmakePath --build $buildDirectory --config Release
if ($LASTEXITCODE -ne 0) {
    throw "The example client build failed."
}

$executablePath = Join-Path $buildDirectory "Release\enauth-example.exe"
Write-Host "Build complete: $executablePath"
