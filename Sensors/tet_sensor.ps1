# Define the accepted parameters
Param(
    [switch] $preCheck,
    [switch] $skipPreCheck,
    [switch] $skipEnforcementCheck,
    [switch] $noInstall,
    [string] $logFile,
    [string] $proxy = "",
    [switch] $noProxy,
    [switch] $help,
    [switch] $version,
    [string] $sensorVersion,
    [switch] $ls,
    [string] $file,
    [string] $save,
    [switch] $new,
    [switch] $npcap,
    [switch] $wfp,
    [switch] $forceUpgrade,
    [switch] $upgradeLocal,
    [string] $upgradeByUUID
)

$scriptVersion="3.4.1.1-PATCH-3.4.1.6"
$minPowershellVersion=4
$installerLog="msi_installer.log"
# Sensor type is chosen by users on UI
$SensorType="enforcer"
# Powershell uses .NET Framework 4.5, which does not include TLS 1.2 as an available protocol.
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
# We override the default validation, it will apply to all https requests for the remainder of this session lifetime.
# This callback function performs Issuer, authorityKeyIdentifer and validity period check for self-signed cert.  
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback=@"
    using System;
    using System.Text;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        private static byte[] GetIdentifier(X509Certificate2 cert, string oidName)
        {
            X509ExtensionCollection extensions = cert.Extensions;
            for (int i = 0; i < extensions.Count; i++)
            {
                X509Extension extension = extensions[i];
                if (string.Equals(extensions[i].Oid.FriendlyName, oidName))
                    return extension.RawData;         
            }
            return null;
        }
        private static bool ByteArrayCompare(byte[] b1, byte[] b2)
        {
            if (b1.Length == 0 || b2.Length == 0)
                return false;
            int j = b2.Length - 1;
            for (int i = b1.Length - 1; i > 0; i--)
            {
                if (b1[i] != b2[j])
                    return false;
                j--;
            }
            return true;
        }
        public static void Validate()
        {
            if (ServicePointManager.ServerCertificateValidationCallback == null)
            {
                ServicePointManager.ServerCertificateValidationCallback +=
                    delegate
                    (
                        Object obj,
                        X509Certificate certificate,
                        X509Chain chain,
                        SslPolicyErrors errors
                    )
                    {
                        string taSensorCApem = @"
-----BEGIN CERTIFICATE-----
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
4fTl8RIf/oWBJ2vYc2DuZAFCcx1y
-----END CERTIFICATE-----

";
                        byte[] taSensorCApemByte = Encoding.UTF8.GetBytes(taSensorCApem);
                        X509Certificate2 cert1 = new X509Certificate2(taSensorCApemByte);
                        X509Certificate2 cert2 = new X509Certificate2(certificate);
                        return (string.Equals(cert1.Subject, cert2.Issuer) && cert2.NotAfter >= DateTime.Now && cert2.NotBefore <= DateTime.Now && cert1.NotAfter >= DateTime.Now && cert1.NotBefore <= DateTime.Now && ByteArrayCompare(GetIdentifier(cert1, "Subject Key Identifier"), GetIdentifier(cert2, "Authority Key Identifier")));                  
                    };
            }
        }
    }
"@   
    Add-Type $certCallback
}
[ServerCertificateValidationCallback]::Validate()

# Write text to log file if defined
function Log-Write-Host ($message) {
    if ($logFile -eq "") {
        Write-Host $message
    } else {
        Add-Content -Path $logFile -Value $message
    }
}

# Write warning to log file if defined
function Log-Write-Warning ($message) {
    if ($logFile -eq "") {
        Write-Warning $message
    } else {
        Add-Content -Path $logFile -Value ("WARNING: " + $message)
    }
}

# Check if the user has Administrator rights
function Test-Administrator {
    $user=[Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# Calculates the HMAC SHA 256 for a given message and secret,
# then encode to Base64 string.
function Calculate-Hmac ($message, $secret) {
    $hmacsha=New-Object System.Security.Cryptography.HMACSHA256
    $hmacsha.key=[Text.Encoding]::ASCII.GetBytes($secret)
    $signature=$hmacsha.ComputeHash([Text.Encoding]::ASCII.GetBytes($message))
    $signature=[Convert]::ToBase64String($signature)

    return $signature
}

# Extracts the platform string from the system.
function Extract-OsPlatform {
    # Get platform and does proper formatting
    $os_platform=Get-WmiObject Win32_OperatingSystem | Select-Object Caption
    $platform=$os_platform.Caption.Replace(" KN", "").Replace(" K", "").Replace(" N","")
    $platform=$platform.Replace(" ", "")
    $platform=$platform.Replace("Microsoftr", "")
    $platform=$platform.Replace("Microsoft", "")
    $platform=$platform.Replace("WindowsServerr", "Server")
    $platform=$platform.Replace("WindowsServer", "Server")
    $platform=$platform.Replace("Evaluation", "")
    $platform=$platform.Replace("Professional", "Pro")
    $platform="MS" + $platform

# Remove special characters from platform string
    $platform = $platform -replace '[^a-zA-Z0-9.]', ''

    return $platform
}

# Validates that the file has been signed properly, and the cert issuer is
# trusted by us. Currently we only trust "Symantec" or "Cisco".
function Check-ValidSignature ($checkValid, $filename) {
    # Currently accept only Cisco (self-signed) or Symantec (prod).
    $validIssuers=@("Cisco", "Symantec")
    $validIssuersRegex=[string]::Join('|', $validIssuers)
    # Get digital signature of the file and validate.
    $sig=Get-AuthenticodeSignature -FilePath "$filename"
    # Fail if this file is not signed.
    if ($sig.SignerCertificate -eq $null) {
        return $false
    }
    # Failed if the status is "Invalid".
    if ($checkValid -And $sig.Status -ne "Valid") {
        return $false
    }
    # Check the issuer of this certificate and make sure it matches.
    $issuer=$sig.SignerCertificate.Issuer.split(',') | ConvertFrom-StringData
    if ($issuer.CN -match $validIssuersRegex) {
        return $true
    }
    return $false
}

# Print version
function Print-Version {
    Write-Host ("Installation script for Cisco Tetration Agent (Version: " + $scriptVersion + ").")
    Write-Host ("Copyright (c) 2018-2020 Cisco Systems, Inc. All Rights Reserved.")
}

# Print usage
function Print-Usage {
    Write-Host ("Usage: " + $MyInvocation.MyCommand.Name + " [-preCheck] [-skipPreCheck] [-skipEnforcementCheck] [-noInstall] [-logFile <FileName>] [-proxy <ProxyString>] [-noProxy] [-help] [-version] [-sensorVersion <VersionInfo>] [-ls] [-file <FileName>] [-save <FileName>] [-new] [-npcap] [-forceUpgrade] [-upgradeLocal] [-upgradeByUUID <FileName>]")
    Write-Host ("  -preCheck: run pre-check only")
    Write-Host ("  -skipPreCheck: skip pre-installation check (on by default)")
    Write-Host ("  -skipEnforcementCheck: skip the check for enforcement readiness (during pre-installation check)")
    Write-Host ("  -noInstall: will not download and install sensor package onto the system")
    Write-Host ("  -logFile <FileName>: write the log to the file specified by <FileName>")
    Write-Host ("  -proxy <ProxyString>: set the value of HTTPS_PROXY, the string should be formatted as http://<proxy>:<port>")
    Write-Host ("  -noProxy: bypass system wide proxy; this flag will be ignored if -proxy flag was provided")
    Write-Host ("  -help: print this usage")
    Write-Host ("  -version: print current script's version")
    Write-Host ("  -sensorVersion <VersionInfo>: select sensor's version; e.g.: '-sensorVersion 3.4.1.0.win64'; will download the latest version by default if this flag was not provided")
    Write-Host ("  -ls: list all available sensor versions for your system (will not list pre-3.1 packages); will not download any package")
    Write-Host ("  -file <FileName>: provide local zip file to install sensor instead of downloading it from cluster")
    Write-Host ("  -save <FileName>: downloaded and save zip file as <FileName>")
    Write-Host ("  -new: cleanup installation to enable fresh install")
    Write-Host ("  -npcap: overwrite existing npcap")
    Write-Host ("  -forceUpgrade: force sensor upgrade to version given by -sensorVersion flag; e.g.: '-sensorVersion 3.4.1.0.win64 -forceUpgrade'; apply the latest version by default if -sensorVersion flag was not provided")
    Write-Host ("  -upgradeLocal: trigger local sensor upgrade to version given by -sensorVersion flag; e.g.: '-sensorVersion 3.4.1.0.win64 -upgradeLocal'; apply the latest version by default if -sensorVersion flag was not provided")
    Write-Host ("  -upgradeByUUID <FileName>: trigger sensor whose uuid is listed in <FileName> upgrade to version given by -sensorVersion flag; e.g.: '-sensorVersion 3.4.1.0.win64 -upgradeByUUID ""C:\\Program Files\\Cisco Tetration\\sensor_id""'; apply the latest version by default if -sensorVersion flag was not provided")
}


# Validate Firewall profile settings
function Validate_fw_profile_settings($profileregkey, $fwprofile, $curProfile, $profileName) {
    $addDescr=""
    if (-not $curProfile) {
        $addDescr= " when profile is active"
    }
    $RegKeys=(Get-ItemProperty -Path $profileregkey -ErrorAction SilentlyContinue)
    if (($RegKeys -ne $null) -and ($RegKeys.Length -ne 0)) {
        # Firewall must not be disabled
        if (($RegKeys.EnableFirewall -ne $null) -and ($RegKeys.EnableFirewall -eq 0)) {
            $warnMesg="GPO Firewall for "+$fwprofile + " is off, enforcement might fail" +  $addDescr
            Log-Write-Warning $warnMesg
        } elseif ($RegKeys.EnableFirewall -eq $null) {
            $localSetting=Get-NetFirewallProfile -Name $profileName|Select-Object Enabled
            if ($localSetting.Enabled -eq 'False') {
                $warnMesg="GPO Firewall for "+$fwprofile + " is off, enforcement might fail" +  $addDescr
                Log-Write-Warning $warnMesg
            } 
        }
        # DefaultInboundAction must not be defined
        if ($RegKeys.DefaultInboundAction -ne $null) {
            $warnMesg="DefaultInboundAction for  "+$fwprofile + " is not null, enforcement might fail" + $addDescr
            Log-Write-Warning $warnMesg
        }
        # DefaultOutboundAction must not be defined
        if ($RegKeys.DefaultOutboundAction -ne $null) {
            $warnMesg="DefaultOutboundAction for " + $fwprofile +" is not null, enforcement might fail" + $addDescr
            Log-Write-Warning $warnMesg
        }
        return
    }
    # This is non-GPO mode or profile is "not configured" in GPO mode
    $localSetting=Get-NetFirewallProfile -Name $profileName|Select-Object Enabled
    if ($localSetting.Enabled -eq 'False') {
        $warnMesg="Firewall for "+$fwprofile + " is off, enforcement might fail" +  $addDescr
        Log-Write-Warning $warnMesg
    } 
    return
}

# Run pre-installation checks
function Pre-Check ($enforcement) {
    # Assert that the path that it must contains "c:\windows\system32"
    Log-Write-Host "Checking system path contains c:\windows\system32..."
    if (-Not ($Env:Path).ToLower().Contains("c:\windows\system32")) {
        Log-Write-Warning "c:\windows\system32, agent installation and registration might fail"
        return $false
    }
    Log-Write-Host "Passed"

    # Reject installation on platforms prior to win2008r2
    Log-Write-Host "Checking for platform version..."
    # win7 has the same osversion as win2008r2
    $UnsupportedPlatforms = "MSWindows7Enterprise", "MSWindows7HomePremium", "MSWindows7Pro"  
    $Platform=Extract-OsPlatform
    if (($UnsupportedPlatforms.Contains($Platform)) -or ([Environment]::OSVersion.Version -lt (new-object 'Version' 6,1))) {
        Log-Write-Warning ("Platform " + $Platform + " is not supported")
        return $false
    }
    Log-Write-Host "Passed"

    if ($enforcement) {
        Log-Write-Host "Checking for enforcement readiness..."
        # Check if netsh exists
        Log-Write-Host "Checking existence for netsh..."
        if ($netshExists = (Get-Command -Name netsh)) {
            Log-Write-Host "Passed"
        } else {
            Log-Write-Warning "netsh not found"
            return $false
        }
        if (!$wfp) { 
            # Check whether GPO environment 
            $FwPath="HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall"
            
            $fwProfiles = @{'Domain*'='DomainProfile';'Public*'='PublicProfile';'Private*'='PrivateProfile'}
            # Check active network profile setting
            $curProfileList = netsh advfirewall show currentprofile 

            foreach($k in $fwProfiles.keys) {
                $isCurProfile=$curProfileList -like $k
                if ($isCurProfile) {
                    $mesg="Checking settings for active Profile " + $fwProfiles[$k] + "..."
                 } else {
                    $mesg="Checking settings for " + $fwProfiles[$k] + "..."
                }
                Log-Write-Host $mesg
                $ProfileRegKey= join-path $FwPath -ChildPath $fwProfiles[$k]
                $isProfileSetting = Validate_fw_profile_settings $ProfileRegKey $fwProfiles[$k] $isCurProfile $k
           
            }
        }
    }

    Log-Write-Host "Pre-check all passed."
    return $true
}

# Unzip the file, the method depends on powershell version 4.0 or 5.0
function Unzip-Archive ($zipFile, $expandedFolder) {
    if ($PSVersionTable.PSVersion.Major -eq $minPowershellVersion) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile, $expandedFolder)
    } else {
        Expand-Archive -Path $zipFile -DestinationPath $expandedFolder -Force
    }
}

# Get the absolute path for 'file' and 'save'
function Full-Name ($fileName) {
    return ($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($fileName))
}

function List-Available-Version {
    # Check whether this is a production sensor
    $InternalCluster=$false
    $IsProdSensor=($InternalCluster -ne $true)

    # Set platform and architect for list-available-version query
    $Platform=Extract-OsPlatform
    $Arch="x86_64"

    # set package type info
    $PkgType="sensor_w_cfg"

    $Method="GET"
    $Uri="/openapi/v1/sw_assets/download?pkg_type=$PkgType`&platform=$Platform`&arch=$Arch`&sensor_version=$sensorVersion`&list_version=$ls"
    $ChkSum=""
    $ContentType=""
    $Ts=Get-Date -UFormat "%Y-%m-%dT%H:%M:%S+0000"

    $ApiServer="https://192.168.30.5"
    $ApiKey="9774b3b6ac444c428732347b5b727493"
    $ApiSecret="0fa60ff4293b42a6dc910b6d39feb88c04b41f6e"
    $Url=$ApiServer + $Uri

    # Calculate the signature based on the params
    # <httpMethod>\n<requestURI>\n<chksumOfBody>\n<ContentType>\n<TimestampHeader>
    $Msg="$Method`n$Uri`n$ChkSum`n$ContentType`n$Ts`n"
    $Signature=(Calculate-Hmac -message $Msg -secret $ApiSecret)
    $success = $true
    # Invoke web request to list avaible sensor versions
    try {
        $webclient = New-Object System.Net.WebClient
        $webclient.Headers.Add("Timestamp",$Ts)
        $webclient.Headers.Add("Id",$ApiKey)
        $webclient.Headers.Add("Authorization",$Signature)
        if ($proxy.Length -ne 0) {
            $webproxy = New-Object System.Net.WebProxy($proxy,$true)
            $webclient.Proxy = $webproxy
        } elseif ($noProxy) {
            $webclient.Proxy = $null
        }
        $resp = $webclient.DownloadString($Url)
        Log-Write-Host "available versions:"
        Log-Write-Host $resp
    }
    catch {
        # Check the return code
        Log-Write-Warning "Error found while connecting to the server"
        # network issue
        if (!($resp)) {
            Log-Write-Warning ($_.Exception.Message)
            Log-Write-Warning ("Error details:" + $_.ErrorDetails.Message)
        } else {
            Log-Write-Warning ("StatusCode:" + $_.Exception.Response.StatusCode.value__)
            Log-Write-Warning ("StatusDescription:" + $_.Exception.Response.StatusDescription)
            Log-Write-Warning ("Error details:" + $_.ErrorDetails.Message)
        }
        $success = $false
    }
    return $success
}


# Run certifcate checks for MSI installer and NPCAP 
function VerifyCert ($npcap) {
    Log-Write-Host "Checking MSI certificate...."

    $certStore  = "Cert:\LocalMachine\Root"
    $msiRootCert = 'VeriSign Universal Root Certification Authority'
    # check for MSI validation certificate
    $certDetails = Get-ChildItem -Path $certStore | Where-Object  {$_.Subject -like "*$msiRootCert*"} 
    if ( $certDetails -eq $null )
    {
        Log-Write-Warning ($msiRootCert  + " does not exist in cert store " + $certStore)
        Log-Write-Warning "Windows Sensor Upgrade will fail if auto root certificate update is disabled."
    }

    # check npcap installed
    $npcapPath = (Get-ItemProperty $npcapReg -ErrorAction SilentlyContinue).'(default)'
    if (($npcapPath -ne $null) -and ($npcapPath.Length -ne 0)) {
       write-host "npcap already installed, do not check NPCAP certificate"
       if ($npcap -eq $false) { 
           Log-Write-Host "npcap already installed, do not check NPCAP certificate"
           return
       }
    }

    Log-Write-Host "Checking NPCAP certificate...."
 
    $rootCerts = @()

    ## check for OS
    $prodName=(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
    if ($prodName -imatch " 2008 R2 ") 
    {
        $os = "2008 R2"
        $rootCerts = $rootCerts + 'DigiCert High Assurance EV Root CA'
        $rootCerts = $rootCerts + 'DigiCert Assured ID Root CA'
    } Elseif (($prodName -imatch " 2016 ")  -or ($prodName -imatch " 2019 ")  -or ($prodName -imatch " 10 "))
    {
        $os = "windows 10 based OS"
        $rootCerts = $rootCerts + 'Microsoft Root Certificate Authority 2010'
    } else {
        $os = "other"
        $rootCerts = $rootCerts + 'COMODO RSA Certification Authority'
        $rootCerts = $rootCerts + 'DigiCert Assured ID Root CA'
    }

    foreach($certName in $rootCerts)
    {
        $certDetails = Get-ChildItem -Path $certStore | Where-Object  {$_.Subject -like "*$certName*"} 

        if ( $certDetails -eq $null )
        {
            Log-Write-Warning ($certName  + " does not exist in Trusted Root store " )
            Log-Write-Warning "NPCAP installation may fail if auto root certificate update is disabled."
        }
    }
    Log-Write-Host "VerifyCert Done..."
}

function Install-Package {
    if (!$save) {
        $isAdmin = Test-Administrator
        if (-not $isAdmin) {
            Log-Write-Warning "This script needs Administrator rights to run with defined options, try again"
            Exit
        }
    }

    # Check if Cisco binaries already exist
    $TetFolder = "C:\\Program Files\\Cisco Tetration"

    if ($new -eq $true) {
        Log-Write-Host "Cleaning up before installation"
        if (Test-Path ($TetFolder + "\\UninstallAll.lnk")) {
            Start-Process -FilePath ($TetFolder + "\\UninstallAll.lnk") -Wait
            if (Test-Path ($TetFolder)) {
                Remove-Item $TetFolder -Recurse
            }
        } else {
            $app = Get-WmiObject -Class Win32_Product | Where-Object {
                $_.Name -match "Cisco Tetration Agent"
            }
            if ($app) {
                $uninstallStatus = $app.Uninstall()
                if (Test-Path ($TetFolder)) {
                    Remove-Item $TetFolder -Recurse
                }
            }
        }
    }

    if ((Test-Path ($TetFolder + "\\TetSen.exe")) -or (Test-Path ($TetFolder + "\\WindowsSensor.exe"))) {
        if (!$save) {
            Log-Write-Warning ("Tetration agent binaries exist, it seems sensor is already installed. Please clean up and retry")
            return $false
        }
    }

    if (!$save) {
        # Validate Npcap installation state if Npcap is installed
        $npcapInvalid = 0
        $npcapReg = 'hklm:\Software\Wow6432Node\Npcap'
        Log-Write-Host("Validate Npcap installation state if Npcap is installed")
        $npcapDll = "c:\\windows\\system32\\npcap\\packet.dll"
        if (Test-Path -path $npcapReg) {
            if (!(Test-Path $npcapDll)) {
                Log-Write-Host("Npcap packet.dll missing")
                $npcapInvalid = 1
            }
        }
        if ($npcapInvalid -eq 1) {
            $npcapPath = (Get-ItemProperty $npcapReg).'(default)'
            if (($npcapPath -ne $null) -and ($npcapPath.Length -ne 0)) {
                # Check uninstall.exe and npfinstall.exe exist
                $npcapUninstall = Join-Path $npcapPath "uninstall.exe"
                $npcapInstall = Join-Path $npcapPath "NPFInstall.exe"
                if ((Test-Path ($npcapUninstall)) -and (Test-Path ($npcapInstall))) {
                    Log-Write-Host("Try to uninstall Npcap")

                    Start-Process $npcapInstall -ArgumentList "-kill_proc" -Wait 
                    Start-Process $npcapUninstall -ArgumentList "/S" -Wait
                    if (Test-Path -path $npcapReg) {
                        Log-Write-Warning("Failed to uninstall npcap")
                    } else {
                        $npcapInvalid = 0
                        Log-Write-Host("Npcap uninstalled successfully !!!!")
                    }
                }
            }
        }

        if ($npcapInvalid -eq 1) {
            Log-Write-Warning("Npcap in invalid State : Please uninstall Npcap before installing Sensor")
            Exit
        }
    }

    # Validate Certificate
    VerifyCert($npcap)

    # Check whether this is a production sensor
    $InternalCluster=$false
    $IsProdSensor=($InternalCluster -ne $true)

    # Get activation key from cluster
    $ActivationKey="434af42f36c09c7628e3d3b66c89ca5f46d7b2d4"
    $InstallationID="site_admin_20201102022711"
    Log-Write-Host "Content of user.cfg file would be:"
    Log-Write-Host "ACTIVATION_KEY=$ActivationKey"
    Log-Write-Host "HTTPS_PROXY=$proxy"
    Log-Write-Host "INSTALLATION_ID=$InstallationID"

    # Set platform and architect for download query
    $Platform=Extract-OsPlatform
    Log-Write-Host ("Platform: " + $Platform)
    $Arch="x86_64"
    Log-Write-Host ("Architecture: " + $Arch)

    # Download the package with config files
    $PkgType="sensor_w_cfg"

    $Method="GET"
    $Uri="/openapi/v1/sw_assets/download?pkg_type=$PkgType`&platform=$Platform`&arch=$Arch`&sensor_version=$sensorVersion`&list_version=$ls"
    $ChkSum=""
    $ContentType=""
    $Ts=Get-Date -UFormat "%Y-%m-%dT%H:%M:%S+0000"
    Log-Write-Host ("Uri: " + $Uri)
    Log-Write-Host ("Timestamp: " + $Ts)
    $DownloadedFolder="tet-sensor-downloaded"
    $ZipFile=$DownloadedFolder + ".zip"
    $ApiServer="https://192.168.30.5"
    $ApiKey="9774b3b6ac444c428732347b5b727493"
    $ApiSecret="0fa60ff4293b42a6dc910b6d39feb88c04b41f6e"
    $Url=$ApiServer + $Uri
    Log-Write-Host ("URL: " + $Url)
    Log-Write-Host ("Server: " + $ApiServer)
    Log-Write-Host ("Key: " + $ApiKey)
    Log-Write-Host ("Secret: " + $ApiSecret)
    Log-Write-Host ("Filename: " + $ZipFile)

    # Calculate the signature based on the params
    # <httpMethod>\n<requestURI>\n<chksumOfBody>\n<ContentType>\n<TimestampHeader>
    $Msg="$Method`n$Uri`n$ChkSum`n$ContentType`n$Ts`n"
    $Signature=(Calculate-Hmac -message $Msg -secret $ApiSecret)
    Log-Write-Host ("Signature: " + $Signature)

    # Create a map to store all <key,value> for the headers
    $MyHeaders=@{
        Timestamp=$Ts
        Id=$ApiKey
        Authorization=$Signature
    }
    Log-Write-Host ($MyHeaders | Out-String)

    # Cleanup old files
    if (Test-Path $ZipFile) {
        Remove-Item -Force $ZipFile
    }

    if (Test-Path $DownloadedFolder) {
        Remove-Item -Recurse -Force $DownloadedFolder
    }

    if (($file) -AND !(Test-Path ($file))) {
        Log-Write-Host ($file + " does not exist")
        return $false
    }
    if (!($file)) {
        $success = $false
        $count = 0
        do {
            # Invoke web request to download the file
            try {
                $webclient = New-Object System.Net.WebClient
                $webclient.Headers.Add("Timestamp",$Ts)
                $webclient.Headers.Add("Id",$ApiKey)
                $webclient.Headers.Add("Authorization",$Signature)
                if ($proxy.Length -ne 0) {
                    $webproxy = New-Object System.Net.WebProxy($proxy,$true)
                    $webclient.Proxy = $webproxy
                } elseif ($noProxy) {
                    $webclient.Proxy = $null
                }
                $resp = $webclient.DownloadFile($Url,(Full-Name $ZipFile))
            } catch {
                # Check the return code
                Log-Write-Warning "Error found while connecting to the server"
                # network issue
                if (!($resp)) {
                    Log-Write-Warning ($_.Exception.Message)
                    Log-Write-Warning ("Error details:" + $_.ErrorDetails.Message)
                } else {
                    Log-Write-Warning ("StatusCode:" + $_.Exception.Response.StatusCode.value__)
                    Log-Write-Warning ("StatusDescription:" + $_.Exception.Response.StatusDescription)
                    Log-Write-Warning ("Error details:" + $_.ErrorDetails.Message)
                }
                Log-Write-Warning ("Retry in 15 seconds...")
                Start-Sleep -Seconds 15
                $count++
                continue
            }

            Log-Write-Host "Sensor package has been downloaded, checking for content..."

            # Check if file is downloaded successfully
            if (!(Test-Path $ZipFile)) {
                Log-Write-Warning "$ZipFile absent, download failed"
                Log-Write-Warning ("Retry in 15 seconds...")
                Start-Sleep -Seconds 15
                $count++
                continue
            }
            $success = $true
        } Until ($success -or $count -eq 3)

        if (!$success) {
            Log-Write-Warning ("Failed to download package")
            return $false
        }
    } else {
        Copy-Item $file -Destination $ZipFile -Force
    }

    $CurrentFolder=(Get-Item -Path ".\\").FullName
    Log-Write-Host ("Expanding the archive " + $ZipFile)
    Unzip-Archive -zipFile ($CurrentFolder + "\\" + $ZipFile) -expandedFolder ($CurrentFolder + "\\" + $DownloadedFolder)
    $ExpandedFolder=$DownloadedFolder + "\\update"

    if (!(Test-Path $ExpandedFolder)) {
        Log-Write-Warning "$ZipFolder absent, uncompress failed"
        return $false
    }

    Push-Location -Path $ExpandedFolder

    # Overwrite the user.cfg file with new content
    $lineEnd = "`r`n"
    "ACTIVATION_KEY=$ActivationKey" + $lineEnd | Out-File -filepath "user.cfg" -Force -Encoding ASCII
    "HTTPS_PROXY=$proxy" + $lineEnd | Out-File -filepath "user.cfg" -Append -Force -Encoding ASCII
    "INSTALLATION_ID=$InstallationID" + $lineEnd | Out-File -filepath "user.cfg" -Append -Force -Encoding ASCII

    $InstallerFile="TetrationAgentInstaller.msi"
    $InstallerFileFullPath=$ExpandedFolder + "\\" + $InstallerFile
    if (!(Test-Path $InstallerFile)) {
        Log-Write-Warning "$InstallerFile absent, cannot install sensor"
        Pop-Location
        return $false
    }

    # Validate the signature for the installation msi file.
    $IsValidImage=(Check-ValidSignature -checkValid $IsProdSensor -filename $InstallerFile)
    if (-Not $IsValidImage) {
        Log-Write-Warning "$InstallerFile is not signed properly, aborting..."
        Pop-Location
        return $false
    }

    # Save zip file after signature check
    if ($save) {
        Pop-Location
        Copy-Item $ZipFile -Destination $save -Force
        if (Test-Path $DownloadedFolder) {
            Remove-Item -Recurse -Force $DownloadedFolder
        }
        if (Test-Path $ZipFile) {
            Remove-Item -Force $ZipFile
        }
        return $true
    } 

    Log-Write-Host "Installation file is ready, processing..."

    # Create sub-folders
    Log-Write-Host "Creating folder $TetFolder"
    New-Item -Path $TetFolder -ItemType Directory -ErrorAction SilentlyContinue
    New-Item -Path ($TetFolder + "\\conf") -ItemType Directory -ErrorAction SilentlyContinue
    New-Item -Path ($TetFolder + "\\cert") -ItemType Directory -ErrorAction SilentlyContinue
    New-Item -Path ($TetFolder + "\\logs") -ItemType Directory -ErrorAction SilentlyContinue
    New-Item -Path ($TetFolder + "\\proto") -ItemType Directory -ErrorAction SilentlyContinue

    # Copy all the config files
    Log-Write-Host
    Log-Write-Host "Installing Tetration Agent..."
    Copy-Item "sensor_config" -Destination $TetFolder -Force
    Copy-Item "enforcer.cfg" -Destination ($TetFolder + "\\conf") -Force
    Copy-Item "site.cfg" -Destination $TetFolder -Force

    # Write the ca.cert file
    Copy-Item "ca.cert" -Destination ($TetFolder + "\\cert\\ca.cert") -Force

    # Write the sensor_type
    $SensorType | Out-File -filepath ($TetFolder + "\\sensor_type") -Encoding ASCII

    # Copy the user.cfg file if not already existed
    if (!(Test-Path ($TetFolder + "\\user.cfg"))) {
        Copy-Item "user.cfg" -Destination ($TetFolder + "\\user.cfg") -Force
    }

    Pop-Location

    # Check whether another MSI installation in progress
    # max wait 180 sec
    $maxcnt = 18
    $sleepInterval = 10
    for ($cnt = 0; $cnt -lt $maxcnt; $cnt = $cnt + 1) {
        $retval = 0
        $prevListMsi = Get-Process -Name msiexec -ErrorAction SilentlyContinue|Select Id,SessionId,Starttime|Where SessionId -ne 0
        if ($prevListMsi -eq $null) {
            break
        }
        else {
            Log-Write-Host("Process using MSI" + $prevListMsi.Id)
            $retval = 1
            Sleep($sleepInterval)
        }
    }
    if ($retval -eq 1) {
        Log-Write-Warning("Could not proceed with installation due to another blocking MSI")
        if (Test-Path $DownloadedFolder) {
            Remove-Item -Recurse -Force $DownloadedFolder
            Remove-Item -Force $ZipFile
        }
        return $false
    }

    # Check if user wants to overwrite existing npcap
    $overwrite = ""
    if ($npcap) {
        $overwrite = "overwriteNpcap=yes"
    }

    $use_wfp = ""
    # Check if user wants to use WFP for enforcement
    if ($SensorType -eq "enforcer") { 
        if ($wfp) {
            $use_wfp = "WFP=yes"
        }
    }

    # Finally invoke the msi
    $MsiState = Start-Process -PassThru -FilePath "$env:systemroot\\system32\\msiexec.exe" -ArgumentList "/i $InstallerFileFullPath /quiet /norestart /l*v $installerLog AgentType=$SensorType $overwrite $use_wfp" -Wait -WorkingDirectory $pwd

    # Copy the log file to destination
    Copy-Item $installerLog -Destination ($TetFolder + "\\logs\\" + $installerLog) -Force

    # Cleanup new files
    if (Test-Path $DownloadedFolder) {
        Remove-Item -Recurse -Force $DownloadedFolder
        Remove-Item -Force $ZipFile
    }

    if ($MsiState.ExitCode -eq 0) {
        Log-Write-Host "Installation is done."
        return $true
    }

    Log-Write-Warning ("MSI installation failed, please check " + $installerLog + " for more info.")
    return $false
}

function ForceUpgrade {
    $zipFile = "conf_update.zip"
    $save = $TetFolder + "\\" + $zipFile
    $donotDownload = $TetFolder + "\\DONOT_DOWNLOAD"
    $versionFile = $TetFolder + "\\conf\\version"
    $checkConfUpdate = $TetFolder + "\\check_conf_update.cmd"
    $checkConfErrLog = $TetFolder + "\\logs\\upgrade_err.log"
    $isDownloadOK = (Install-Package)
    if (-not $isDownloadOK) {
        Log-Write-Warning "Failed to download package."
        return $false
    }
    if (!(Test-Path ($donotDownload))) {
        New-Item -Path $donotDownload -ItemType "file" -Force
    }
    $currentVersion = (Get-Content $versionFile -First 1)

    $tetSensorPresent = "no"
    if (Get-Service TetSensor -ErrorAction SilentlyContinue) {
      Log-Write-Host "Stopping TetSensor"
      Stop-Service TetSensor
      $tetSensorPresent = "yes"
    }
    if (Get-Service WindowsTetEngine -ErrorAction SilentlyContinue) {
      Log-Write-Host "Stopping WindowsTetEngine if present"
      Stop-Service WindowsTetEngine
    }

    Push-Location $TetFolder
    Log-Write-Host "Triggering force-upgrade..."
    $detailedErr = cmd /c $checkConfUpdate 2>&1
    $upgradeState = $LASTEXITCODE
    Pop-Location
    Remove-Item -Force $checkConfErrLog -ErrorAction Ignore
    Remove-Item -Force $donotDownload -ErrorAction Ignore
    if ($upgradeState -eq 0){
        Log-Write-Host "Force upgrade succeeded."
        $newVersion = (Get-Content $versionFile -First 1)
        Log-Write-Host "Local agent upgraded from $currentVersion to $newVersion."
        Log-Write-Host "Please wait for backend to synchronize."
        return $true
    }
    Log-Write-Host "Force upgrade failed."
    Log-Write-Host $detailedErr
    Remove-Item -Force $save -ErrorAction Ignore
    if ($tetSensorPresent -eq "yes") {
      Log-Write-Host "Start TetSensor after upgrade failure."
      Start-Service TetSensor
    } else {
      Log-Write-Host "Start WindowsTetEngine after upgrade failure."
      Start-Service WindowsTetEngine
    }
    return $false
}

function Upgrade {
    if (!(Test-Path ($upgradeByUUID))){
        Log-Write-Host ($upgradeByUUID + " does not exist")
        return $false
    }
    $uuid = (Get-Content $upgradeByUUID -First 1)
    $Method = "POST"
    $Uri = "/sensor_config/upgrade/" + $uuid + "?sensor_version=" + $sensorVersion
    $ChkSum = ""
    $ContentType = ""
    $Ts = Get-Date -UFormat "%Y-%m-%dT%H:%M:%S+0000"

    $ApiServer = "https://192.168.30.5"
    $ApiKey = "9774b3b6ac444c428732347b5b727493"
    $ApiSecret = "0fa60ff4293b42a6dc910b6d39feb88c04b41f6e"
    $Url = $ApiServer + $Uri

    # Calculate the signature based on the params
    # <httpMethod>\n<requestURI>\n<chksumOfBody>\n<ContentType>\n<TimestampHeader>
    $Msg="$Method`n$Uri`n$ChkSum`n$ContentType`n$Ts`n"
    $Signature=(Calculate-Hmac -message $Msg -secret $ApiSecret)

    $success = $true
    # Invoke web request to update sensor versions
    try {
        $webclient = New-Object System.Net.WebClient
        $webclient.Headers.Add("Timestamp",$Ts)
        $webclient.Headers.Add("Id",$ApiKey)
        $webclient.Headers.Add("Authorization",$Signature)
        if ($proxy.Length -ne 0) {
            $webproxy = New-Object System.Net.WebProxy($proxy,$true)
            $webclient.Proxy = $webproxy
        } elseif ($noProxy) {
            $webclient.Proxy = $null
        }
        $resp = $webclient.UploadString($Url,"")
        Log-Write-Host "Upgrade triggered"
    } catch {
        # Check the return code
        Log-Write-Warning "Error found while connecting to the server"
        # network issue
        if (!($resp)) {
            Log-Write-Warning ($_.Exception.Message)
            Log-Write-Warning ("Error details:" + $_.ErrorDetails.Message)
        } else {
            Log-Write-Warning ("StatusCode:" + $_.Exception.Response.StatusCode.value__)
            Log-Write-Warning ("StatusDescription:" + $_.Exception.Response.StatusDescription)
            Log-Write-Warning ("Error details:" + $_.ErrorDetails.Message)
        }
        $success = $false
    }
    return $success
}

if ($help -eq $true) {
    Print-Version
    Write-Host
    Print-Usage
    Exit
}


if ($preCheck -eq $true) {
    $checkEnforcement = (($SensorType -eq "enforcer") -and (-not $skipEnforcementCheck))
    $isPrecheckOK = (Pre-Check -enforcement $checkEnforcement)
    if (-not $isPrecheckOK) {
        Log-Write-Warning "Pre-check steps failed, please check errors before retry"
    }
    Exit
}

if ($version -eq $true) {
    Print-Version
    Exit
}

# Make sure minimum Powershell version is met
if ($PSVersionTable.PSVersion.Major -lt $minPowershellVersion) {
    Log-Write-Warning ("This script requires minimum Powershell " + $minPowershellVersion + ", please upgrade and retry")
    Exit
}

## check admin privileges for options
if ($forceUpgrade -or $new) {
    $isAdmin = Test-Administrator
    if (-not $isAdmin) {
        Log-Write-Warning "This script needs Administrator rights to run with defined options, try again"
        Exit
    }
}


if ($ls -eq $true) {
    $isListAvailableVersionOK = (List-Available-Version)
    if (-not $isListAvailableVersionOK) {
        Log-Write-Warning "Failed to list all available versions"
    }
    Exit
}


if ($save) {
    $save = (Full-Name $save)
    $isInstallOK = (Install-Package)
    if (-not $isInstallOK) {
        Log-Write-Warning "Failed to save zip file, please check errors before retry"
    }
    Exit
}

if (-not $skipPreCheck) {
    # Make sure pre-check returns true before proceeding
    $checkEnforcement = (($SensorType -eq "enforcer") -and (-not $skipEnforcementCheck))
    $isPrecheckOK = (Pre-Check -enforcement $checkEnforcement)
    if (-not $isPrecheckOK) {
        Log-Write-Warning "Pre-check steps failed, please check errors before retry"
        Exit
    }
}

if ($forceUpgrade -or $upgradeByUUID -or $upgradeLocal) {
    $Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Tetration\'
    if (!(Test-Path ($Path))) {
        Log-Write-Host("Failed to find Tetration agent path, please make sure sensor is properly installed.")
        return $false
    }
    $TetFolder = (Get-ItemProperty -Path $Path).SensorPath
    if (!(Test-Path ($TetFolder + "\\TetSen.exe")) -and !(Test-Path ($TetFolder + "\\WindowsSensor.exe"))) {
        Log-Write-Warning ("Failed to find Tetration agent binaries, please make sure sensor is properly installed.")
        return $false
    }
    if ($sensorVersion) {
        Log-Write-Host("Upgrading to the provided version: " + $sensorVersion)
    } else {
        Log-Write-Host("Upgrading to the latest version")
    }
    # Download package and force upgrade
    if ($forceUpgrade) {
        $isUpgradeOK = (ForceUpgrade)
    # Trigger sensor upgrade in backend
    } else {
        if ($upgradeLocal) {
            $upgradeByUUID = "C:\\Program Files\\Cisco Tetration\\sensor_id"
        } 
        $upgradeByUUID = (Full-Name $upgradeByUUID)
        $isUpgradeOK = (Upgrade)
    }
    if (-not $isUpgradeOK) {
        Log-Write-Warning "Upgrade failed, please check errors before retry"
    }
    Exit
}

if (-not $noInstall) {
    if ($file) {
        $file = (Full-Name $file) 
    }
    $isInstallOK = (Install-Package)
    if (-not $isInstallOK) {
        Log-Write-Warning "Installation failed, please check errors before retry"
        Exit
    }
}

Log-Write-Host "All tasks are done."
