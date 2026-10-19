# Copy and run the Raspberry Pi headless HDMI setup over SSH from Windows.
param(
    [string]$PiHost,
    [string]$PiUser,
    [ValidateRange(1, 65535)][int]$Port = 22,
    [ValidateSet('HDMI-A-1', 'HDMI-A-2')][string]$Output = 'HDMI-A-1',
    [switch]$Reboot
)

$ErrorActionPreference = 'Stop'

if (-not $PiHost) { $PiHost = Read-Host 'Pi IP address or hostname' }
if (-not $PiUser) { $PiUser = Read-Host 'Pi SSH username' }
if ($PiHost -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$') {
    throw 'Enter a valid Pi IPv4 address or hostname.'
}
if ($PiUser -notmatch '^[A-Za-z_][A-Za-z0-9_.-]*$') {
    throw 'Enter a valid Pi SSH username.'
}

$localScript = Join-Path $PSScriptRoot 'enable_pi_dummy_display.py'
if (-not (Test-Path -LiteralPath $localScript -PathType Leaf)) {
    throw "The companion file is missing: $localScript"
}
foreach ($program in @('scp', 'ssh')) {
    if (-not (Get-Command $program -ErrorAction SilentlyContinue)) {
        throw "$program is not available. Install the Windows OpenSSH Client."
    }
}

$target = '{0}@{1}' -f $PiUser, $PiHost
$remoteFile = 'enable_pi_dummy_display.py'
$copyTarget = '{0}:{1}' -f $target, $remoteFile
Write-Host "Copying the setup script to $target ..."
& scp -P $Port $localScript $copyTarget
if ($LASTEXITCODE -ne 0) { throw "SCP failed with exit code $LASTEXITCODE." }

# A forced terminal lets sudo ask for the Pi password when needed.
$command = "sudo python3 ./$remoteFile --dry-run --output $Output && sudo python3 ./$remoteFile --output $Output"
Write-Host "Applying the virtual HDMI setting on $target ..."
& ssh -tt -p $Port $target $command
if ($LASTEXITCODE -ne 0) {
    throw "Remote setup failed with exit code $LASTEXITCODE. Check the Pi output above."
}

if ($Reboot) {
    Write-Host 'Setup complete. Requesting reboot now ...'
    & ssh -tt -p $Port $target 'sudo reboot'
    Write-Host 'Reboot requested. The SSH disconnect during reboot is expected.'
} else {
    Write-Host 'Setup complete. Reboot the Pi when ready to activate the virtual display:'
    Write-Host "  ssh -t -p $Port $target sudo reboot"
}
