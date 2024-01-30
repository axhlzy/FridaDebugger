param (
    [string]$ABI = "arm64-v8a",
    [bool]$cleanDir = $true
)

if ($ABI -ne "armeabi-v7a" -and $ABI -ne "arm64-v8a") {
    Write-Host "Invalid ABI: $ABI" -ForegroundColor Red
    Write-Host "ABI must be either armeabi-v7a or arm64-v8a" -ForegroundColor Red
    exit 1
}

$soPath = $PSScriptRoot + "/agent/plugins/$ABI/libpacklibs.so"
if (Test-Path $soPath) {
    Write-Host "agent/plugins/$ABI/libpacklibs.so exists" -ForegroundColor Green
}
else {
    Write-Host "agent/plugins/$ABI/libpacklibs.so not exists" -ForegroundColor Red
    # build it 
    Write-Host "build agent/plugins/$ABI/libpacklibs.so" -ForegroundColor Green
    & $PSScriptRoot/agent/plugins/buildScript.ps1 -SOURCE $PSScriptRoot/agent/plugins -ABI $ABI
}

adb push $soPath /data/local/tmp
adb shell chmod 777 /data/local/tmp/libpacklibs.so

if ($cleanDir) {
    Remove-Item (Split-Path $soPath) -Recurse -Force
}