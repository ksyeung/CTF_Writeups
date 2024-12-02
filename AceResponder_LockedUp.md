[Scenario:

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
host.name: Win11-20 AND  winlog.event_data.Image: cmd.exe AND winlog.event_data.CommandLine: *
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

'CollectGuestLogs.exe', 'tiny.bat', and 'letslockyoudown.exe' look suspicious. 

For completeness, let's find out what child processes of cmd.exe may have been doing:

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
host.name: Win11-20 AND  winlog.event_data.ParentImage: powershell.exe
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

'BackupDocuments.ps1' and 'user_simulation.ps1' look interesting, although its not clear what the latter is really doing.
](https://aceresponder.com/challenge/locked-up

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
host.name: Win11-20 AND  winlog.event_data.Image: cmd.exe AND winlog.event_data.CommandLine: *
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

'CollectGuestLogs.exe', 'tiny.bat', and 'letslockyoudown.exe' look suspicious. 

For completeness, let's find out what child processes of cmd.exe may have been doing:

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
host.name: Win11-20 AND  winlog.event_data.ParentImage: powershell.exe
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

'BackupDocuments.ps1' and 'user_simulation.ps1' look interesting, although its not clear what the latter is really doing.
)
