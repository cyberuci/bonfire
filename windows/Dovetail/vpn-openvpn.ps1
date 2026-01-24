param (
    [switch]$a,
    [switch]$b,
    [switch]$c,
    [switch]$d
)

$msiPath = "C:\Users\Administrator\Documents\OpenVPN.msi"

if ($a) {
    netsh a f a r n=WEB_OUT dir=out a=allow prot=TCP remoteport="80,443"

    netsh a s a state on

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $ProgressPreference = 'SilentlyContinue'

    Invoke-WebRequest "http://swupdate.openvpn.org/community/releases/OpenVPN-2.6.17-I001-amd64.msi" -o $msiPath -UseBasicParsing

    netsh a f del r n=WEB_OUT
}

if ($b) {
    $features = "OpenVPN,OpenSSL,EasyRSA,Drivers.Wintun"
    $arguments = "/i `"$msiPath`" /qn /norestart ADDLOCAL=$features"

    Write-Host "Installing OpenVPN with OpenSSL Utilities..." 
    $process = Start-Process "msiexec.exe" -ArgumentList $arguments -Wait -PassThru

    if ($process.ExitCode -eq 0) {
        Write-Host "Installation " -ForegroundColor Green
    } else {
        Write-Host "Installation failed with exit code $($process.ExitCode)" -ForegroundColor Red
    }
}

# cd "C:\Program Files\OpenVPN\easy-rsa"
# EasyRSA-Start.bat
# ./easyrsa init-pki
# ./easyrsa build-ca nopass
# ./easyrsa build-server-full server nopass
# ./easyrsa build-client-full client1 nopass
# ./easyrsa gen-dh

if ($c) {
    $pkiPath = "C:\Program Files\OpenVPN\easy-rsa\pki"
    $configPath = "C:\Program Files\OpenVPN\config"

    if (!(Test-Path $configPath)) {
        New-Item -ItemType Directory -Path $configPath
    }

    $filesToCopy = @(
        "$pkiPath\ca.crt",
        "$pkiPath\dh.pem",
        "$pkiPath\issued\server.crt",
        "$pkiPath\private\server.key"
    )

    foreach ($file in $filesToCopy) {
        if (Test-Path $file) {
            Copy-Item -Path $file -Destination $configPath -Force
            Write-Host "Successfully copied: $(Split-Path $file -Leaf)" -ForegroundColor Green
        } else {
            Write-Host "Warning: Could not find $file" -ForegroundColor Yellow
        }
    }
}

if ($d) {
    $configPath = "C:\Program Files\OpenVPN\config\server.ovpn"

    $lines = @(
        "port 1194",
        "proto udp4",
        "dev tun",
        "ca `"C:\\Program Files\\OpenVPN\\config\\ca.crt`"",
        "cert `"C:\\Program Files\\OpenVPN\\config\\server.crt`"",
        "key `"C:\\Program Files\\OpenVPN\\config\\server.key`"",
        "dh `"C:\\Program Files\\OpenVPN\\config\\dh.pem`"",
        "server 10.8.0.0 255.255.255.0",
        "keepalive 10 120",
        "cipher AES-256-GCM",
        "data-ciphers AES-256-GCM:AES-128-GCM",
        "auth SHA256",
        "persist-key",
        "persist-tun",
        "verb 3",
        "explicit-exit-notify 1",
        "ifconfig-pool-persist `"C:\\Program Files\\OpenVPN\\log\\ipp.txt`" 5"
    )

    $lines | Out-File -FilePath $configPath -Encoding ascii -Force

    Write-Host "server.ovpn created successfully!" -ForegroundColor Green

    netsh a f a r n=Allow_OpenVPN a=allow dir=in prot=UDP localport=1194

    Write-Host "firewall rule created" -ForegroundColor Green
    $configPathClient = "C:\Program Files\OpenVPN\config\client.ovpn"
    $lines2 = @(
        "port 1194",
        "proto udp4",
        "dev tun",
        "ca `"C:\\Program Files\\OpenVPN\\config\\ca.crt`"",
        "cert `"C:\\Program Files\\OpenVPN\\config\\client1.crt`"",
        "key `"C:\\Program Files\\OpenVPN\\config\\client1.key`"",
        "dh `"C:\\Program Files\\OpenVPN\\config\\dh.pem`"",
        "server 10.8.0.0 255.255.255.0",
        "keepalive 10 120",
        "cipher AES-256-GCM",
        "data-ciphers AES-256-GCM",
        "auth SHA256",
        "persist-key",
        "persist-tun",
        "explicit-exit-notify 1",
        "ifconfig-pool-persist `"C:\\Program Files\\OpenVPN\\log\\ipp.txt`"",
        "verb 3"
    )

    $lines2 | Out-File -FilePath $configPathClient -Encoding ascii -Force

    Write-Host "server.ovpn created successfully!" -ForegroundColor Green

}
