param (
    [string]$ABI = "arm64-v8a",
    [string]$pluginName = "libPlugins.so",
    [bool]$cleanDir = $false,
    [bool]$pushQBDI = $true
)

if ($ABI -ne "armeabi-v7a" -and $ABI -ne "arm64-v8a") {
    Write-Host "Invalid ABI: $($ABI)" -ForegroundColor Red
    Write-Host "ABI must be either armeabi-v7a or arm64-v8a" -ForegroundColor Red
    exit 1
}

if (-not (Get-Command "adb" -ErrorAction SilentlyContinue)) {
    Write-Host "adb not found" -ForegroundColor Red
    return 
}

if (-not (Get-Command "npm" -ErrorAction SilentlyContinue)) {
    Write-Host "npm not found" -ForegroundColor Red
    return 
}

$soPath = Join-Path $PSScriptRoot "/agent/plugins/$($ABI)/$($pluginName)"

Write-Host "building PATH: agent/plugins/$($ABI)/$($pluginName)" -ForegroundColor Green
& $PSScriptRoot/agent/plugins/buildScript.ps1 -SOURCE $PSScriptRoot/agent/plugins -ABI $ABI

& adb push $soPath /data/local/tmp
& adb shell chmod 777 /data/local/tmp/libPlugins.so

if ($pushQBDI) {
    $dirItems = adb shell ls /data/local/tmp

    if ($ABI -eq "armeabi-v7a") {
        if ($dirItems -like "libQBDI_32.so") {
            Write-Host "libQBDI_32.so exists" -ForegroundColor Green
        }
        else {
            $arm32_lib = Join-Path $PSScriptRoot "agent/plugins/QBDI/armeabi-v7a/lib/libQBDI.so"
            adb push $arm32_lib /data/local/tmp/libQBDI_32.so
            adb shell chmod 777 /data/local/tmp/libQBDI_32.so
        }
    }
    
    if ($ABI -eq "arm64-v8a") {
        if ($dirItems -like "libQBDI_64.so") {
            Write-Host "libQBDI_64.so exists" -ForegroundColor Green
        }
        else {
            $arm64_lib = Join-Path $PSScriptRoot "agent/plugins/QBDI/arm64-v8a/lib/libQBDI.so"
            adb push $arm64_lib /data/local/tmp/libQBDI_64.so
            adb shell chmod 777 /data/local/tmp/libQBDI_64.so
        }
    }
}

& adb shell setenforce 0  

if ($cleanDir) {
    Remove-Item (Split-Path $soPath) -Recurse -Force
}

npm install & npm run build