param (
    [string]$ABI = "arm64-v8a",
    [bool]$cleanDir = $false,
    [bool]$pushQBDI = $true,
    [string]$pluginName = "libPlugins.so"
)

if ($ABI -ne "armeabi-v7a" -and $ABI -ne "arm64-v8a") {
    Write-Host "Invalid ABI: $($ABI)" -ForegroundColor Red
    Write-Host "ABI must be either armeabi-v7a or arm64-v8a" -ForegroundColor Red
    exit 1
}

$soPath = Join-Path $PSScriptRoot "/agent/plugins/$($ABI)/$($pluginName)"

Write-Host "building PATH: agent/plugins/$($ABI)/$($pluginName)" -ForegroundColor Green
& $PSScriptRoot/agent/plugins/buildScript.ps1 -SOURCE $PSScriptRoot/agent/plugins -ABI $ABI

adb push $soPath /data/local/tmp
adb shell chmod 777 /data/local/tmp/libPlugins.so

if ($pushQBDI) {
    $dirItems = adb shell ls /data/local/tmp

    if ($dirItems -like "libQBDI_64.so") {
        Write-Host "libQBDI_64.so exists" -ForegroundColor Green
    }
    else {
        $arm64_lib = Join-Path $PSScriptRoot "agent/plugins/arm64-v8a/lib/libQBDI.so"
        adb push $arm64_lib /data/local/tmp/libQBDI_64.so
        adb shell chmod 777 /data/local/tmp/libQBDI_64.so
    }

    if ($dirItems -like "libQBDI_32.so") {
        Write-Host "libQBDI_32.so exists" -ForegroundColor Green
    }
    else {
        $arm32_lib = Join-Path $PSScriptRoot "agent/plugins/armeabi-v7a/lib/libQBDI.so"
        adb push $arm32_lib /data/local/tmp/libQBDI_32.so
        adb shell chmod 777 /data/local/tmp/libQBDI_32.so
    }
}

adb shell su -c 'setenforce 0'

if ($cleanDir) {
    Remove-Item (Split-Path $soPath) -Recurse -Force
}