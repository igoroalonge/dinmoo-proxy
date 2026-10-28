$ErrorActionPreference = 'Stop'
$token = $env:DINMOO_PROXY_TOKEN
if ([string]::IsNullOrWhiteSpace($token) -or $token.Length -lt 32 -or $token.Length -gt 1024 -or $token -notmatch '^[A-Za-z0-9_-]+$') { throw 'Set DINMOO_PROXY_TOKEN to your enrolled URL-safe token (at least 32 characters).' }
try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 } catch { }
Add-Type -AssemblyName System.Net.Http

function Get-BoundedDownload([string]$Url, [string]$Path, [long]$Limit) {
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $true
    $handler.MaxAutomaticRedirections = 10
    $client = [System.Net.Http.HttpClient]::new($handler)
    $response = $null
    $inputStream = $null
    $outputStream = $null
    try {
        $response = $client.GetAsync($Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        if ($response.RequestMessage.RequestUri.Scheme -ne 'https' -or $response.RequestMessage.RequestUri.Host -notin @('github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com')) { throw 'Untrusted download redirect.' }
        if (-not $response.IsSuccessStatusCode) { throw "Download returned HTTP $([int]$response.StatusCode) for $Url" }
        if ($response.Content.Headers.ContentLength -gt $Limit) { throw "Download exceeds $Limit bytes: $Url" }
        $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $outputStream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $buffer = New-Object byte[] 65536
        [long]$total = 0
        while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $total += $read
            if ($total -gt $Limit) { throw "Download exceeds $Limit bytes: $Url" }
            $outputStream.Write($buffer, 0, $read)
        }
    }
    finally {
        if ($outputStream) { $outputStream.Dispose() }
        if ($inputStream) { $inputStream.Dispose() }
        if ($response) { $response.Dispose() }
        $client.Dispose()
    }
}

$downloadId = [guid]::NewGuid().ToString('N')
$manifestPath = Join-Path $env:TEMP "dinmoo-proxy-manifest-$downloadId.json"
Get-BoundedDownload 'https://github.com/igoroalonge/dinmoo-proxy/releases/latest/download/latest.json' $manifestPath 1048576
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
$null = Remove-Item -LiteralPath $manifestPath -Force
$arch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'aarch64' } else { 'x86_64' }
$key = "windows-$arch"
$bin = Join-Path $env:LOCALAPPDATA 'Programs/DinmooProxy'
New-Item -ItemType Directory -Force $bin | Out-Null
$temp = Join-Path $bin ".dinmoo-proxy-$downloadId.download"
$asset = $manifest.assets.$key
if (-not $asset -or $asset.sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw "Invalid release metadata for $key" }
$assetUri = [System.Uri]$asset.url
if ($assetUri.Scheme -ne 'https' -or $assetUri.Host -ne 'github.com' -or -not $assetUri.AbsolutePath.StartsWith('/igoroalonge/dinmoo-proxy/releases/download/') -or $assetUri.UserInfo) { throw 'Release URL is outside the trusted download host.' }
Get-BoundedDownload $assetUri.AbsoluteUri $temp 52428800
$actual = (Get-FileHash -Algorithm SHA256 $temp).Hash.ToLowerInvariant()
if ($actual -ne $asset.sha256.ToLowerInvariant()) { Remove-Item $temp -Force; throw 'Binary checksum mismatch' }
$target = Join-Path $bin 'dinmoo-proxy.exe'
$running = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $target })
foreach ($process in $running) { Stop-Process -Id $process.ProcessId -Force; Wait-Process -Id $process.ProcessId -ErrorAction SilentlyContinue }
Move-Item -Force $temp $target
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$entries = @($userPath -split ';' | Where-Object { $_ })
if ($entries -notcontains $bin) {
    [Environment]::SetEnvironmentVariable('Path', (($entries + $bin) -join ';'), 'User')
}
if (($env:Path -split ';') -notcontains $bin) { $env:Path = "$bin;$env:Path" }
Write-Host 'Installed dinmoo-proxy. Commands: dinmoo-proxy on | off | status | uninstall'
& $target install-local
if ($LASTEXITCODE -ne 0) { throw "Dinmoo Proxy setup failed ($LASTEXITCODE)" }
