https://aceresponder.com/challenge/locked-up

This is an Elastic (well, a fork of Elastic called OpenSearch) SIEM challenge on the Ace Responder platform.

Scenario:

>An unknown attacker successfully breached the defenses of your organization, gaining unauthorized access to your domain. The intruder managed to distribute a potent strain of ransomware across the entire network. The impact has been swift and severe – all users are reporting an inability to access crucial files, and the administrative team is grappling with a critical issue: the ransomware has blocked access to the backup server.
>
>The security team conducted an initial investigation and identified some unusual network activity. A scan of DNS traffic flagged a high-risk domain: `anydeskhelp.com`. These connections were not known to be malicious at the time of compromise and were not blocked. Using this information, analyze the intrusion and determine whether the organization can recover without paying the ransom.

Before diving into the questions, I started with the information provided and ran with the 
query `anydeskhelp.com`, and I was quickly inundated with HTTP results (over 15k hits). 

I refined the query by excluding the most common results I was seeing that didn't have useful information (network* excludes the values 'network' and 'network_traffic'):

```
anydeskhelp.com AND NOT event.category: network*
```

Here are the results, with some of the columns that I found most interesting:


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

- Failed logins -- `event.code: 4625` which yielded no results.
- Access token manipulation -- `event.code: 4624 AND winlog.event_data.LogonType: 9` which yielded no results.
- Logon Type 4 -- `event.code: 4624 AND winlog.event_data.LogonType: 4` which yielded. This is for batch logons (Scheduled Tasks).
- Logon Type 9 -- `event.code: 4624 AND winlog.event_data.LogonType: 9` which yielded no results. This is for Alternate Credentials Specified sign-ins: the caller cloned its current token and specified new credentials for outbound connections. It can appear a result of RunAs with /netonly flag, CreateProcessWithLogonW using the LOGON_NETCREDENTIALS_ONLY flag, or LogonUserW with LOGON32_LOGON_NEW_CREDENTIALS.
- Logon Type 10 -- `event.code: 4624 AND winlog.event_data.LogonType: 10` which yielded no results. This is for Remote Interactive sign-ins over RDP: a user logged on to this computer remotely using Terminal Services or Remote Desktop.
- Logon Type 3 -- `event.code: 4624 AND winlog.event_data.LogonType: 3` 422 hits. This is for network sign-ins, ie: a user accesses a file share, a vulnerability scanner authenticates to perform checks, an admin is remotely using PS, or an attacker uses PsExec to run a payload on a remote system. Reviewing the field statistics for winlog.event_data.TargetUserName, some of the top 5 values aside from 'dc\$' included 'ace', 'WIN11-20\$', 'WIN11-21\$', and 'erin'.

**Q1. Foothold: Which of the following best describes the technique used to gain access to the domain?**

Based on the first query above, I concluded that the answer was Malvertising: erin appears to have downloaded and launched AnyDeskSetup.exe using Edge, which subsequently sent a DNS query back to anydeskhelp.com. Afterwards, msteams.exe and SystemSettings.exe also sent DNS queries for this domain. Its not immediately clear to me why these processes would do this.

**Q2. Implant: What file did Erin download and execute?**

See the last query for more information.

**Q3. Process Injection: Which process did the attacker inject into shortly after execution on Win11-20?**

Before proceeding to the actual question, I want to understand what AnyDeskSetup.exe was doing. `event.code: 1 AND winlog.event_data.Image:AnyDeskSetup.exe` didn't yield any results, so I quickly checked to see if it spawned any child processes (it did!):

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

These look like standard enumeration commands, along with a PowerShell command that looks a bit like a path traversal attack on a backup server. There may be sensitive data in 'backup_helper.ini', which looks like a configuration file. I'll make a note of this and proceed with trying to answer the question for now.

I ran this query to look for Sysmon Event ID 8 (CreateRemoteThread detected):

```host.name: "Win11-20" AND event.code: 8```

CreateRemoteThread is a Windows API function that is commonly misused for injecting malicious code into a running process. It is associated with techniques like shellcode injection, DLL injection, and reflective DLL loading.

This was the result:

| Time                         | host.name  | winlog.event_data.SourceProcessId | winlog.event_data.SourceImage                            | winlog.event_data.TargetImage                                                          | winlog.event_data.TargetProcessId |
|------------------------------|------------|------------------------------------|---------------------------------------------------------|----------------------------------------------------------------------------------------|------------------------------------|
| Feb 25, 2024 @ 12:03:44.679 | Win11-20   | 8360                               | C:\Users\Erin\Downloads\AnyDeskSetup.exe                | C:\Program Files\WindowsApps\MicrosoftTeams_24004.1403.2634.2418_x64__8wekyb3d8bbwe\msteams.exe | 6176                               |
| Feb 25, 2024 @ 12:26:58.046 | Win11-20   | 8360                               | C:\Users\Erin\Downloads\AnyDeskSetup.exe                | C:\Windows\ImmersiveControlPanel\SystemSettings.exe                                    | 7352                               |

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

It looks like the host in question was 10.0.0.4. A quick check with this query confirmed the hostname: `host.ip: 10.0.0.4`

**Q6. Lateral Tool Transfer: How did the attacker place an implant on backup?**

