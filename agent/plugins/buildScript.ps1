param (
    [string]$SOURCE = '.',
    [string]$ABI = "arm64-v8a",
    [string]$BUILD_TYPE = "Release",
    [string]$API_LEVEL = "24",
    [string]$TOOLCHAIN
)

if ($ABI -ne "armeabi-v7a" -and $ABI -ne "arm64-v8a") {
    Write-Host "Invalid ABI: $ABI" -ForegroundColor Red
    Write-Host "ABI must be either armeabi-v7a or arm64-v8a" -ForegroundColor Red
    exit 1
}

if ([System.Environment]::OSVersion.Platform -eq 'Unix') {
    $TOOLCHAIN = locate android.toolchain.cmake | grep 25.1.8937393
}
elseif ([System.Environment]::OSVersion.Platform -eq 'Win32NT') {
    $sdkRoot = [System.Environment]::GetEnvironmentVariable('ANDROID_SDK_ROOT', [System.EnvironmentVariableTarget]::User)
    if (-not $sdkRoot) {
        $sdkRoot = [System.Environment]::GetEnvironmentVariable('ANDROID_SDK', [System.EnvironmentVariableTarget]::User)
    }
    elseif (-not $sdkRoot) {
        $sdkRoot = [System.Environment]::GetEnvironmentVariable('ANDROID_HOME', [System.EnvironmentVariableTarget]::User)
    }
    if ($sdkRoot) {
        $TOOLCHAIN = Join-Path $sdkRoot "ndk\25.1.8937393\build\cmake\android.toolchain.cmake"
    }
}
else {
    Write-Host "Unknown platform"
}

if (-not $TOOLCHAIN) {
    Write-Host  "Android NDK not found" -ForegroundColor Red
    exit 1
}
else {
    Write-Host  "Android NDK found @ $TOOLCHAIN" -ForegroundColor Green
}

$BUILD = ($SOURCE + "/" + $ABI).Replace("/", "\")

$cmakeArgs = @(
    "-G", "Ninja",
    "-B", "$BUILD",
    "-S", "$SOURCE",
    "-DANDROID_ABI=$ABI",
    "-DCMAKE_BUILD_TYPE=$BUILD_TYPE",
    "-DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN",
    "-DCMAKE_SYSTEM_VERSION=$API_LEVEL",
    "-DANDROID_NATIVE_API_LEVEL=$API_LEVEL",
    "-DANDROID_PLATFORM=android-$API_LEVEL",
    "-DANDROID_ARM_NEON=ON",
    "-DCMAKE_SYSTEM_NAME=Android",
    "-DANDROID_ARM_MODE=arm"
)

& cmake $cmakeArgs

# cmake -G "Ninja" -B "$BUILD" -S "$SOURCE" --toolchain="$TOOLCHAIN"  -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DANDROID_ABI="$ABI" -DCMAKE_SYSTEM_VERSION="$API_LEVEL" -DANDROID_NATIVE_API_LEVEL="$API_LEVEL" -DANDROID_PLATFORM=android-"$API_LEVEL" -DANDROID_TOOLCHAIN=clang -DANDROID_ARM_NEON=ON -DCMAKE_SYSTEM_NAME="Android" -DANDROID_ARM_MODE=arm
if ($LASTEXITCODE -ne 0) {
    Write-Host "CMake configuration failed" -ForegroundColor Red
    Remove-Item -Path "$BUILD" -Recurse -Force
    Write-Host "Removed $BUILD" -ForegroundColor Yellow
    exit 1
}

cmake --build "$BUILD"