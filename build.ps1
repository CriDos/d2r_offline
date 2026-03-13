param(
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Src = Join-Path $Root 'src'
$Build = Join-Path $Root 'build'

function Resolve-VsDevCmd {
    $override = $env:VSDEVCMD_PATH
    if (-not [string]::IsNullOrWhiteSpace($override) -and (Test-Path $override)) {
        return $override
    }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $installationPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($installationPath)) {
            $candidate = Join-Path $installationPath 'Common7\Tools\VsDevCmd.bat'
            if (Test-Path $candidate) {
                return $candidate
            }
        }
    }

    $fallbacks = @(
        'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat'
    )

    foreach ($candidate in $fallbacks) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    throw 'VsDevCmd.bat not found. Install Visual Studio C++ build tools or set VSDEVCMD_PATH.'
}

$VsDevCmd = Resolve-VsDevCmd

if ($Clean -and (Test-Path $Build)) {
    Remove-Item $Build -Recurse -Force
}

New-Item -ItemType Directory -Force $Build | Out-Null

$BatchPath = Join-Path $Build 'build.cmd'
$AsmObj = Join-Path $Build 'forwarders.obj'
$SerpentObj = Join-Path $Build 'serpent.obj'
$OutDll = Join-Path $Build 'winhttp.dll'
$OutPdb = Join-Path $Build 'winhttp.pdb'
$DefFile = Join-Path $Build 'exports.def'
$AsmIncludeFile = Join-Path $Build 'exports_asm.inc'
$ExportsListFile = Join-Path $Src 'exports\exports.inc'
$AsmFile = Join-Path $Src 'exports\forwarders.asm'
$SerpentDir = Join-Path $Src 'third_party\serpent'
$SerpentFile = Join-Path $SerpentDir 'serpent.c'
$SerpentCompileFlags = '/TC /W0 /O2 /D_CRT_SECURE_NO_WARNINGS /D_CRT_NONSTDC_NO_WARNINGS'
$CppFiles = Get-ChildItem $Src -Recurse -Filter *.cpp | Sort-Object FullName

if ($CppFiles.Count -eq 0) {
    throw "No C++ source files found under $Src"
}

if (-not (Test-Path $SerpentFile)) {
    throw "Vendored Serpent source not found: $SerpentFile"
}

if (-not (Test-Path $ExportsListFile)) {
    throw "Exports list not found: $ExportsListFile"
}

$Exports = foreach ($Line in Get-Content $ExportsListFile) {
    if ($Line -match '^\s*X\(([^,]+),\s*(\d+)\)\s*$') {
        [PSCustomObject]@{
            Name = $matches[1].Trim()
            Ordinal = $matches[2].Trim()
        }
    }
}

if (-not $Exports -or $Exports.Count -eq 0) {
    throw "No exports parsed from $ExportsListFile"
}

$DefLines = @(
    'LIBRARY "winhttp"',
    '',
    'EXPORTS'
) + ($Exports | ForEach-Object { "    $($_.Name) @$($_.Ordinal)" })
[System.IO.File]::WriteAllLines($DefFile, $DefLines, [System.Text.Encoding]::ASCII)

$AsmIncludeLines = $Exports | ForEach-Object { "X $($_.Name), $($_.Ordinal)" }
[System.IO.File]::WriteAllLines($AsmIncludeFile, $AsmIncludeLines, [System.Text.Encoding]::ASCII)

$Batch = @"
@echo off
call "$VsDevCmd" -arch=x64 -host_arch=x64 >nul || exit /b 1
ml64 /nologo /c /Fo"$AsmObj" /I"$Build" "$AsmFile" || exit /b 1
rem Build upstream reference Serpent as third-party code with relaxed warnings.
cl /nologo $SerpentCompileFlags /I"$SerpentDir" /c /Fo"$SerpentObj" "$SerpentFile" || exit /b 1
"@

$Batch += "`r`n"

$ObjectFiles = @($AsmObj, $SerpentObj)
foreach ($CppFile in $CppFiles) {
    $relative = $CppFile.FullName.Substring($Src.Length).TrimStart('\', '/')
    $objName = ($relative -replace '[\\/]', '_') -replace '\.cpp$', '.obj'
    $objPath = Join-Path $Build $objName
    $ObjectFiles += $objPath
    $Batch += "cl /nologo /std:c++20 /EHsc /W4 /O2 /I""$Src"" /I""$SerpentDir"" /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /c /Fo""$objPath"" ""$($CppFile.FullName)"" || exit /b 1`r`n"
}

$QuotedObjects = $ObjectFiles | ForEach-Object { '"' + $_ + '"' }
$Batch += "link /nologo /dll /out:""$OutDll"" /pdb:""$OutPdb"" $($QuotedObjects -join ' ') /def:""$DefFile"" Advapi32.lib Bcrypt.lib Crypt32.lib Ncrypt.lib Shell32.lib || exit /b 1`r`n"

[System.IO.File]::WriteAllText($BatchPath, $Batch, [System.Text.Encoding]::ASCII)
& cmd.exe /c $BatchPath
if ($LASTEXITCODE -ne 0) {
    throw "Build failed with exit code $LASTEXITCODE"
}

Write-Host "Built $OutDll"
