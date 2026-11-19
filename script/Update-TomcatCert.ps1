<#
.SYNOPSIS
  Updates certificate inside a keystore from the new PKCS#12 (.pfx) file.

.EXAMPLE
  .\Update-TomcatCert.ps1 -PfxPath .\new.pfx -PfxKeyPath .\Privatekey.txt
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $PfxPath,
    [Parameter(Mandatory)] [string] $PfxKeyPath
)

$ErrorActionPreference = 'Stop'

Write-Host "    ----------------------------------------------------------"
Write-Host "    __________ __       __  __          __      __            "
Write-Host "   / ___/ ___// /      / / / /___  ____/ /___ _/ /____  _____ "
Write-Host "   \__ \\__ \/ /      / / / / __ \/ __  / __ '/ __/ _ \/ ___/ "
Write-Host "  ___/ /__/ / /___   / /_/ / /_/ / /_/ / /_/ / /_/  __/ /     "
Write-Host " /____/____/_____/   \____/ .___/\__,_/\__,_/\__/\___/_/      "
Write-Host "                         /_/                                  "
Write-Host "----------------------------------------------------------    "
Write-Host "Update SSL certificate in Crystal Reports Tomcat.             "
Write-Host "----------------------------------------------------------    "
#          "by:JanTugado (2026-11-16)                                     "
#		   "https://github.com/jantugado/SSL_Updater					  "

#-------------------------------------------------------------------------
#-- 			SETTINGS												--
#-------------------------------------------------------------------------
$Keystore = '.\crtest.keystore'				# update this to the path and filename of the keystore
$KeytoolPath = 'C:\Program Files (x86)\SAP BusinessObjects\SAP BusinessObjects Enterprise XI 4.0\win64_x64\sapjvm\bin\keytool.exe'
[string] $Alias = 'tomcat'					# alias name of the certificate
[string] $ServiceName = 'BOEXI40Tomcat'     # optional: Tomcat Windows service to restart
[string] $InterCert = '.\Inter.cer'         # optional: intermediate CA .cer (PEM or DER)
[string] $RootCert = '.\Root.cer'           # optional: root CA .cer (PEM or DER)
#-------------------------------------------------------------------------

#Check required variables
foreach ($f in $KeytoolPath, $Keystore, $PfxPath, $PfxKeyPath) {
    if (-not (Test-Path $f)) { throw "File not found: $f" }
}

[SecureString] $KeystorePassword = (Read-Host 'Keystore password' -AsSecureString)
[SecureString] $PfxPassword = Get-Content -Path $PfxKeyPath -Raw | ConvertTo-SecureString -AsPlainText -Force
[string] $PfxAlias                          # alias inside the PFX (auto-detected if only one entry)

$KeystoreFile = Get-Item -Path $Keystore
$PfxFile = Get-Item -Path $PfxPath
$PfxKeyFile = Get-Item -Path $PfxKeyPath


# Check for empty variables
if (-not [string]::IsNullOrEmpty($InterCert)) {
	$InterCertFile = Get-Item -Path $InterCert
}

if (-not [string]::IsNullOrEmpty($RootCert)) {
	$RootCertFile = Get-Item -Path $RootCert
}

if (-not [string]::IsNullOrEmpty($ServiceName)) {
	$TomcatPid = (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'").ProcessId
}


function ConvertTo-Plain([SecureString]$s) {
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

function Invoke-Keytool([string[]]$ToolArgs) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $out = & $KeytoolPath @ToolArgs 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prev
    if ($code -ne 0) { throw "keytool failed: $($out -join "`n")" }
    $out
}



$ksPass  = ConvertTo-Plain $KeystorePassword
$pfxPass = ConvertTo-Plain $PfxPassword

Write-Host "------------------------------------------------------------"
Write-Host "Creating Backup..."
Write-Host "------------------------------------------------------------"
$BackupFolder = Join-Path -Path $KeystoreFile.DirectoryName -ChildPath $(Get-Date -Format yyyyMMdd)


# Create the Backup folder if it doesn't exist
if (-not (Test-Path -Path $BackupFolder)) {
    New-Item -ItemType Directory -Path $BackupFolder | Out-Null
}

# Backup the keystore file
$KeystoreFileName = $KeystoreFile.Name
$backup = "$KeystoreFileName.$(Get-Date -Format yyyyMMdd-HHmmss).bak"
$Destination = Join-Path -Path $BackupFolder -ChildPath $backup

Copy-Item $Keystore $Destination
Write-Host "Backup created: $Destination"


try {
    Write-Host "`n------------------------------------------------------------"
    Write-Host "Installing Certificate..."
    Write-Host "------------------------------------------------------------"

    # Determine alias inside the PFX
    if (-not $PfxAlias) {
        $list = Invoke-Keytool @('-list', '-keystore', $PfxPath, '-storetype', 'PKCS12', '-storepass', $pfxPass)
        $aliases = @($list | Select-String -Pattern '^(.+?), .*(PrivateKeyEntry|trustedCertEntry)' |
                     Where-Object { $_ -match 'PrivateKeyEntry' } |
                     ForEach-Object { $_.Matches[0].Groups[1].Value })
        if ($aliases.Count -ne 1) { throw "PFX has $($aliases.Count) private key entries; specify -PfxAlias." }
        $PfxAlias = $aliases[0]
    }
    Write-Host "Using PFX alias: $PfxAlias"

    # Remove existing alias if present
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $null = & $KeytoolPath -list -keystore $Keystore -storepass $ksPass -alias $Alias 2>&1
    $exists = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = $prev
    if ($exists) {
        Invoke-Keytool @('-delete', '-alias', $Alias, '-keystore', $Keystore, '-storepass', $ksPass) | Out-Null
        Write-Host "Removed existing alias '$Alias'."
    } else {
        Write-Warning "Alias '$Alias' not found; importing anyway."
    }

    # Import new key pair (key password set equal to keystore password, as Tomcat expects by default)
    Invoke-Keytool @(
        '-importkeystore',
        '-srckeystore', $PfxPath, '-srcstoretype', 'PKCS12', '-srcstorepass', $pfxPass, '-srcalias', $PfxAlias,
        '-destkeystore', $Keystore, '-deststorepass', $ksPass, '-destkeypass', $ksPass,
        '-destalias', $Alias, '-noprompt'
    ) | Out-Null
    Write-Host "Imported '$PfxAlias' as '$Alias'."



    # Rebuild the chain as leaf + intermediate + root and re-import it onto the key entry
    if ($InterCert -or $RootCert) {
        function ConvertTo-Pem([string]$Path) {
            if (-not (Test-Path $Path)) { throw "File not found: $Path" }
            $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2 (Resolve-Path $Path).Path
            $b64 = [Convert]::ToBase64String($c.RawData, 'InsertLineBreaks')
            "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n"
        }
        $leafPem = (Invoke-Keytool @('-exportcert', '-rfc', '-alias', $Alias, '-keystore', $Keystore, '-storepass', $ksPass)) -join "`n"
        $chain = $leafPem + "`n"
        if ($InterCert) { $chain += ConvertTo-Pem $InterCert }
        if ($RootCert)  { $chain += ConvertTo-Pem $RootCert }
        $chainFile = Join-Path $env:TEMP "tomcat-chain-$([guid]::NewGuid()).pem"
        try {
            [IO.File]::WriteAllText($chainFile, $chain, (New-Object Text.ASCIIEncoding))
            Invoke-Keytool @('-importcert', '-alias', $Alias, '-file', $chainFile,
                             '-keystore', $Keystore, '-storepass', $ksPass, '-keypass', $ksPass, '-noprompt') | Out-Null
        }
        finally { Remove-Item $chainFile -ErrorAction SilentlyContinue }
        Write-Host "Appended intermediate/root certificates to the '$Alias' chain."
    }

    Invoke-Keytool @('-list', '-keystore', $Keystore, '-storepass', $ksPass, '-alias', $Alias, '-v') | Write-Host


    Write-Host "`n------------------------------------------------------------"
    Write-Host "Moving Certificates to the backup folder..."
    Write-Host "------------------------------------------------------------"
    $DestinationPfx = Join-Path -Path $BackupFolder -ChildPath $PfxFile.Name
    $DestinationPfxKey = Join-Path -Path $BackupFolder -ChildPath $PfxKeyFile.Name
    $DestinationInterCert = Join-Path -Path $BackupFolder -ChildPath $InterCertFile.Name
    $DestinationRootCert = Join-Path -Path $BackupFolder -ChildPath $RootCertFile.Name    

    Move-Item -Path $PfxPath -Destination $DestinationPfx
    Write-Host $PfxPath

    Move-Item -Path $PfxKeyPath -Destination $DestinationPfxKey
    Write-Host $PfxKeyPath

    Move-Item -Path $InterCert -Destination $DestinationInterCert
    Write-Host $InterCert

    Move-Item -Path $RootCert -Destination $DestinationRootCert
    Write-Host $RootCert
    
    if ($ServiceName -and $TomcatPid) {
        Write-Host "`n------------------------------------------------------------"
        Write-Host "Restarting Service: $ServiceName..."
        Write-Host "------------------------------------------------------------"
        #Restart-Service -Name $ServiceName -Force

        #Force to kill the process since Crystal Reports tends to hangs if restart-service is used.
        taskkill /F /PID $TomcatPid

        #Delay for a few seconds for the Taskkill to complete its process
        Start-Sleep -Seconds 5

        #Starts the service
        Start-Service -Name $ServiceName -PassThru
    }

    Write-Host "`n****************************************************************************"
    Write-Host "Certificate Update Complete!"
    Write-Host "Wait for a couple of minutes in order for Crystal Reports to fully starts."
    Write-Host "****************************************************************************"
	
}
catch {
    Write-Error "Failed, keystore restored from backup. $_"
	Copy-Item $backup $Keystore -Force
}
finally {
    $ksPass = $pfxPass = $null
}
