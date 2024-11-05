[https://cyberdefenders.org/blueteam-ctf-challenges/goldenspray/

This is a Medium difficulty threat hunting lab, with an option to select the Splunk or Elastic SIEM. I elected to use Elastic.

Scenario:
>As a cybersecurity analyst at SecureTech Industries, you've been alerted to unusual login attempts and unauthorized access within the company's network. Initial indicators suggest a potential brute-force attack on user accounts. Your mission is to analyze the provided log data to trace the attack's progression, determine the scope of the breach, and attacker's TTPs.

---


**Q1: What's the attacker IP?**

First, I took a look at all events with Event ID 4625 using the following query:

```
winlog.event_id: 4625
```

I added some interesting fields to the columns:


| @timestamp                 | host.ip                                     | winlog.computer_name      | winlog.event_data.LogonType | winlogon.event_data.TargetUserName |
| -------------------------- | ------------------------------------------- | ------------------------- | --------------------------- | ---------------------------------- |
| Sep 9, 2024 @ 16:55:16.996 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | SECURETECH\\admin1                 |
| Sep 9, 2024 @ 16:55:16.974 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | SECURETECH\\michaelwilliams        |
| Sep 9, 2024 @ 16:55:17.021 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | SECURETECH\\backup                 |
| Sep 9, 2024 @ 16:56:05.582 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | ejohnson                           |
| Sep 9, 2024 @ 16:56:05.559 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | mwilliams                          |
| Sep 9, 2024 @ 16:56:05.627 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | admin                              |
| Sep 9, 2024 @ 16:56:05.605 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | Administrator                      |
| Sep 9, 2024 @ 16:56:05.743 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | backup                             |
| Sep 9, 2024 @ 16:56:05.714 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | admin1                             |
| Sep 9, 2024 @ 16:56:05.649 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | emilyjohnson                       |
| Sep 9, 2024 @ 18:29:34.034 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-FS01.SECURETECH.local  | -                           | -                                  |
| Sep 9, 2024 @ 18:29:35.644 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-DC01                   | -                           | -                                  |
| Sep 9, 2024 @ 18:30:45.348 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-FS01.SECURETECH.local  | -                           | -                                  |
| Sep 9, 2024 @ 18:31:16.285 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | -                           | -                                  |
| Sep 9, 2024 @ 18:31:15.061 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN01.SECURETECH.local | -                           | -                                  |
| Sep 9, 2024 @ 16:55:16.954 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | SECURETECH\\emilyjohnson           |
| Sep 9, 2024 @ 16:55:16.931 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | SECURETECH\\admin                  |
| Sep 9, 2024 @ 16:55:16.910 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | SECURETECH\\Administrator          |
| Sep 9, 2024 @ 16:55:16.889 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | SECURETECH\\ejohnson               |
| Sep 9, 2024 @ 16:55:16.867 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | SECURETECH\\mwilliams              |
| Sep 9, 2024 @ 16:46:57.691 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | -                                  |

Looks like someone is performing a password spraying attack, based on the tight interval between attempts and the variety of usernames.

Then I reviewed all events with Event ID 131 (which indicates an RDP connection was attempted, usually includes the client's IP addr, server hostname or IP addr, user credentials):

```
winlog.event_id: 131 AND winlog.event_data.ClientIP: 77.91.78.115*
```

Unfortunately, its unclear which usernames were being targeted, but it does look like a password spraying attack by 77.91.78.115 over RDP:

| @timestamp                 | host.ip                                     | winlog.computer_name      | winlog.event_data.ClientIP |
| -------------------------- | ------------------------------------------- | ------------------------- | -------------------------- |
| Sep 9, 2024 @ 17:34:14.490 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-DC01.SECURETECH.local  | 77.91.78.115:40382         |
| Sep 9, 2024 @ 17:50:12.449 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-FS01.SECURETECH.local  | 77.91.78.115:35474         |
| Sep 9, 2024 @ 17:00:20.473 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 77.91.78.115:52500         |
| Sep 9, 2024 @ 16:29:05.367 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 77.91.78.115:43610         |
| Sep 9, 2024 @ 16:29:04.748 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 77.91.78.115:58734         |
| Sep 9, 2024 @ 16:29:05.308 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 77.91.78.115:58742         |
| Sep 9, 2024 @ 16:29:01.898 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 77.91.78.115:58720         |

Then I looked at Event ID 1149 (RDP: user authentication succeeded, includes src IP address and logon username):

```
winlog.event_id: 1149
```

| @timestamp                 | host.ip                                     | winlog.computer_name      | winlog.user_data.Param2 | winlog.user_data.Param1 | winlog.user_data.Param3 |
| -------------------------- | ------------------------------------------- | ------------------------- | ----------------------- | ----------------------- | ----------------------- |
| Sep 9, 2024 @ 17:00:22.711 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | SECURETECH              | mwilliams               | 77.91.78.115            |
| Sep 9, 2024 @ 17:34:16.831 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-DC01.SECURETECH.local  | SECURETECH              | jsmith                  | 77.91.78.115            |
| Sep 9, 2024 @ 17:50:14.570 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-FS01.SECURETECH.local  | SECURETECH              | jsmith                  | 77.91.78.115            |

Two successful attempts appear: "SECURETECH\mwilliams" and "SECURETECH\jsmith"

**Q2: What country is the attack originating from?**

I used geoip.com to look up the IP address from the above query.

**Q3: What's the compromised account username used for initial access?**

This is one of the two usernames we identified in Q1.

**Q4: What's the name of the malicious file utilized by the attacker for persistence on ST-WIN02?**

```
@timestamp > "2024-09-09T17:00:00.565000" AND winlog.computer_name: "ST-WIN02"
```

**Q5: What's the full path used by the attacker for storing his tools?**

See the answer to Q6.

**Q6: What's the process ID of the tool responsible for dumping credentials on ST-WIN02?**

To answer this question, I thought it would be useful to use Sysmon Event ID 1 (process creation), which provides process ID, parent process ID, hashes, current directory, detailed command-line arguments, etc. We also have the the timestamp from the attacker's first sign-in to pivot on, due to the query from Q1.

```
event.code: 1 AND @timestamp > "2024-09-09T17:00:00.565000" AND winlog.computer_name: "ST-WIN02" AND *mimikatz*
```

There were two results. Here are some of the interesting fields from the first:

| Field                                 | Value                                                                                                                                   |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `@timestamp`                          | `Sep 9, 2024 @ 17:27:34.067`                                                                                                            |
| `host.hostname`                       | `windows`                                                                                                                               |
| `winlog.computer_name`                | `ST-WIN02.SECURETECH.local`                                                                                                             |
| `winlog.event_data.Image`             | `C:\Users\Public\Backup_Tools\mimikatz.exe`                                                                                             |
| `winlog.event_data.ParentCommandLine` | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noexit -command Set-Location -literalPath 'C:\Users\Public\Backup_Tools'` |
| `winlog.event_data.ProcessId`         | `3708`                                                                                                                                  |
| `winlog.event_data.User`              | `SECURETECH\mwilliams`                                                                                                                  |

**Q7: What's the second account username the attacker compromised and used for lateral movement?**

We have a good idea this is probably the second successful sign-in by the attacker over RDP seen in Q1. To confirm,

**Q8: Can you provide the scheduled task created by the attacker for persistence on the domain controller?**

Using the timestamp from the attacker's first sign-in to pivot, I tried the query:

```
@timestamp > "2024-09-09T17:00:00.565000" AND *schtasks.exe*
```

Here's the result, in part (I've provided the fields I thought were useful):

| Field                           | Value                                                                                                                                           |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `host.name`                     | `windows`                                                                                                                                       |
| `winlog.computer_name`          | `ST-DC01.SECURETECH.local`                                                                                                                      |
| `winlog.event_data.CommandLine` | `schtasks /create /tn "FilesCheck" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\FileCleaner.exe" /sc hourly /ru SYSTEM` |
| `winlog.event_data.User`        | `SECURETECH\jsmith`                                                                                                                             |

**Q9: What's the encryption type used in the environment Kerberos tickets?**

To start, I used the following query to sort by Event ID 4768 (a Kerberos authentication ticket request):

```
event.code: 4768
```

Next, I added the field "winlog.event_data.TicketEncryptionType" and checked the field statistics:

![image](https://github.com/user-attachments/assets/ae78cca7-3e89-4d08-9a85-0cb7cb4e592a)


I deduced that the first value was probably owing to Audit Failure, which shows up in a number of situations including incorrect passwords, lockouts, etc. I had to look up the value 0x17 at https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768

**Q10: Can you provide the full path of the output file in preparation for data exfiltration?**


](https://cyberdefenders.org/blueteam-ctf-challenges/goldenspray/

>Scenario:
As a cybersecurity analyst at SecureTech Industries, you've been alerted to unusual login attempts and unauthorized access within the company's network. Initial indicators suggest a potential brute-force attack on user accounts. Your mission is to analyze the provided log data to trace the attack's progression, determine the scope of the breach, and attacker's TTPs.

**Q1: What's the attacker IP?**

First, I took a look at all events with Event ID 4625 with the following query:

```
winlog.event_id: 4625
```

| @timestamp                 | host.ip                                     | winlog.computer_name      | winlog.event_data.LogonType | winlogon.event_data.TargetUserName |
| -------------------------- | ------------------------------------------- | ------------------------- | --------------------------- | ---------------------------------- |
| Sep 9, 2024 @ 16:55:16.996 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | SECURETECH\\admin1                 |
| Sep 9, 2024 @ 16:55:16.974 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | SECURETECH\\michaelwilliams        |
| Sep 9, 2024 @ 16:55:17.021 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | SECURETECH\\backup                 |
| Sep 9, 2024 @ 16:56:05.582 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | ejohnson                           |
| Sep 9, 2024 @ 16:56:05.559 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | mwilliams                          |
| Sep 9, 2024 @ 16:56:05.627 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | admin                              |
| Sep 9, 2024 @ 16:56:05.605 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | Administrator                      |
| Sep 9, 2024 @ 16:56:05.743 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | backup                             |
| Sep 9, 2024 @ 16:56:05.714 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | admin1                             |
| Sep 9, 2024 @ 16:56:05.649 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | emilyjohnson                       |
| Sep 9, 2024 @ 18:29:34.034 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-FS01.SECURETECH.local  | -                           | -                                  |
| Sep 9, 2024 @ 18:29:35.644 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-DC01                   | -                           | -                                  |
| Sep 9, 2024 @ 18:30:45.348 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-FS01.SECURETECH.local  | -                           | -                                  |
| Sep 9, 2024 @ 18:31:16.285 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | -                           | -                                  |
| Sep 9, 2024 @ 18:31:15.061 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN01.SECURETECH.local | -                           | -                                  |
| Sep 9, 2024 @ 16:55:16.954 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | SECURETECH\\emilyjohnson           |
| Sep 9, 2024 @ 16:55:16.931 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | SECURETECH\\admin                  |
| Sep 9, 2024 @ 16:55:16.910 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | SECURETECH\\Administrator          |
| Sep 9, 2024 @ 16:55:16.889 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | SECURETECH\\ejohnson               |
| Sep 9, 2024 @ 16:55:16.867 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | SECURETECH\\mwilliams              |
| Sep 9, 2024 @ 16:46:57.691 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 3                           | -                                  |

Looks like someone is performing a password spraying attack, based on the tight interval between attempts and the variety of usernames.

Then all events with EID 131 (indicates an RDP connection was attempted, usually includes the client's IP addr, server hostname or IP addr, user credentials). 

```
winlog.event_id: 131 AND winlog.event_data.ClientIP: 77.91.78.115*
```

Unfortunately, its unclear which usernames were being targeted, but it does look like a password spraying attack by 77.91.78.115 over RDP:

| @timestamp                 | host.ip                                     | winlog.computer_name      | winlog.event_data.ClientIP |
| -------------------------- | ------------------------------------------- | ------------------------- | -------------------------- |
| Sep 9, 2024 @ 17:34:14.490 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-DC01.SECURETECH.local  | 77.91.78.115:40382         |
| Sep 9, 2024 @ 17:50:12.449 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-FS01.SECURETECH.local  | 77.91.78.115:35474         |
| Sep 9, 2024 @ 17:00:20.473 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 77.91.78.115:52500         |
| Sep 9, 2024 @ 16:29:05.367 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 77.91.78.115:43610         |
| Sep 9, 2024 @ 16:29:04.748 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 77.91.78.115:58734         |
| Sep 9, 2024 @ 16:29:05.308 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 77.91.78.115:58742         |
| Sep 9, 2024 @ 16:29:01.898 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | 77.91.78.115:58720         |

Then I looked at Event ID 1149 (RDP: user authentication succeeded, includes src IP address and logon username):

```
winlog.event_id: 1149
```

| @timestamp                 | host.ip                                     | winlog.computer_name      | winlog.user_data.Param2 | winlog.user_data.Param1 | winlog.user_data.Param3 |
| -------------------------- | ------------------------------------------- | ------------------------- | ----------------------- | ----------------------- | ----------------------- |
| Sep 9, 2024 @ 17:00:22.711 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-WIN02.SECURETECH.local | SECURETECH              | mwilliams               | 77.91.78.115            |
| Sep 9, 2024 @ 17:34:16.831 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-DC01.SECURETECH.local  | SECURETECH              | jsmith                  | 77.91.78.115            |
| Sep 9, 2024 @ 17:50:14.570 | [fe80::2085:1815:93a4:a744, 192.168.72.133] | ST-FS01.SECURETECH.local  | SECURETECH              | jsmith                  | 77.91.78.115            |

Two successful attempts appear: "SECURETECH\mwilliams" and "SECURETECH\jsmith"

**Q2: What country is the attack originating from?**

I used geoip.com to lookup the IP address from the above query, which indicated Helsinki, Finland.

**Q3: What's the compromised account username used for initial access?**

This is one of the two usernames we identified in Q1.

**Q4: What's the name of the malicious file utilized by the attacker for persistence on ST-WIN02?**

Given the provided information, plus the timestamp for initial access in my answer for Q2, I decided to start with reviewing Run keys in the registry:

```
@timestamp > "2024-09-09T17:00:00.565000" AND winlog.computer_name: "ST-WIN02" AND *\\CurrentVersion\\Run*
```

| Field                          | Value                                                                  |
| ------------------------------ | ---------------------------------------------------------------------- |
| _id                            | x0CX1pEB8vo2BunWPkyd                                                   |
| _index                         | st-win02                                                               |
| _score                         | -                                                                      |
| @metadata.beat                 | winlogbeat                                                             |
| @metadata.type                 | _doc                                                                   |
| @metadata.version              | 8.15.1                                                                 |
| @timestamp                     | Sep 9, 2024 @ 17:17:09.631                                             |
| agent.ephemeral_id             | fbad129e-9be0-48f5-9fbc-fefaa8081bee                                   |
| agent.id                       | 0802b172-fb6c-4e5f-92e2-3ff030012cc9                                   |
| agent.name                     | Windows                                                                |
| agent.type                     | winlogbeat                                                             |
| agent.version                  | 8.15.1                                                                 |
| ecs.version                    | 8.0.0                                                                  |
| event.code                     | 13                                                                     |
| event.created                  | Sep 9, 2024 @ 21:28:34.578                                             |
| event.kind                     | event                                                                  |
| event.provider                 | Microsoft-Windows-Sysmon                                               |
| host.architecture              | x86_64                                                                 |
| host.hostname                  | windows                                                                |
| host.id                        | 0630db4b-06de-4359-b10a-3a3547b2894d                                   |
| host.ip                        | [fe80::2085:1815:93a4:a744, 192.168.72.133]                            |
| host.mac                       | 00-0C-29-95-67-5E                                                      |
| host.name                      | windows                                                                |
| host.os.build                  | 17763.3650                                                             |
| host.os.family                 | windows                                                                |
| host.os.kernel                 | 10.0.17763.3650 (WinBuild.160101.0800)                                 |
| host.os.name                   | Windows Server 2019 Standard Evaluation                                |
| host.os.platform               | windows                                                                |
| host.os.type                   | windows                                                                |
| host.os.version                | 10.0                                                                   |
| log.file.path                  | C:\Logs_65095\Microsoft-Windows-Sysmon%4Operational.evtx               |
| log.level                      | information                                                            |
| winlog.api                     | wineventlog                                                            |
| winlog.channel                 | Microsoft-Windows-Sysmon/Operational                                   |
| winlog.computer_name           | ST-WIN02.SECURETECH.local                                              |
| winlog.event_data.Details      | **C:\Windows\Temp\OfficeUpdater.exe**                                  |
| winlog.event_data.EventType    | SetValue                                                               |
| winlog.event_data.Image        | C:\Windows\system32\reg.exe                                            |
| winlog.event_data.ProcessGuid  | {b526ab8f-2d95-66df-f700-000000000b00}                                 |
| winlog.event_data.ProcessId    | 7796                                                                   |
| winlog.event_data.RuleName     | technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder |
| winlog.event_data.TargetObject | **HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OfficeUpdater**   |
| winlog.event_data.User         | SECURETECH\mwilliams                                                   |
| winlog.event_data.UtcTime      | 2024-09-09 17:17:09.628                                                |
| winlog.event_id                | 13                                                                     |
| winlog.opcode                  | Info                                                                   |
| winlog.process.pid             | 2,484                                                                  |
| winlog.process.thread.id       | 3,260                                                                  |
| winlog.provider_guid           | {5770385f-c22a-43e0-bf4c-06f5698ffbd9}                                 |
| winlog.provider_name           | Microsoft-Windows-Sysmon                                               |
| winlog.record_id               | 5,807                                                                  |
| winlog.user.domain             | NT AUTHORITY                                                           |
| winlog.user.identifier         | S-1-5-18                                                               |
| winlog.user.name               | SYSTEM                                                                 |
| winlog.user.type               | Well Known Group                                                       |
| winlog.version                 | 2                                                                      |

The bolded values were suspicious: that reg key is not part of a standard Office installation and neither is OfficeUpdater.exe -- even if it was, it wouldn't live in the C:\Windows\Temp folder!

**Q5: What's the full path used by the attacker for storing his tools?**

See the answer to Q6.

**Q6: What's the process ID of the tool responsible for dumping credentials on ST-WIN02?**

To answer this question, I thought it would be useful to use Sysmon Event ID 1 (process creation), which provides process ID, parent process ID, hashes, current directory, detailed command-line arguments, etc. We also have the the timestamp from the attacker's first sign-in to pivot on, due to the query from Q1.

```
event.code: 1 AND @timestamp > "2024-09-09T17:00:00.565000" AND winlog.computer_name: "ST-WIN02" AND *mimikatz*
```

There were two results. Here are some of the interesting fields from the first:

| Field                                 | Value                                                                                                                                   |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `@timestamp`                          | `Sep 9, 2024 @ 17:27:34.067`                                                                                                            |
| `host.hostname`                       | `windows`                                                                                                                               |
| `winlog.computer_name`                | `ST-WIN02.SECURETECH.local`                                                                                                             |
| `winlog.event_data.Image`             | `C:\Users\Public\Backup_Tools\mimikatz.exe`                                                                                             |
| `winlog.event_data.ParentCommandLine` | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noexit -command Set-Location -literalPath 'C:\Users\Public\Backup_Tools'` |
| `winlog.event_data.ProcessId`         | `3708`                                                                                                                                  |
| `winlog.event_data.User`              | `SECURETECH\mwilliams`                                                                                                                  |

**Q7: What's the second account username the attacker compromised and used for lateral movement?**

This is probably the second successful sign-in by the attacker over RDP seen in Q1.

**Q8: Can you provide the scheduled task created by the attacker for persistence on the domain controller?**

Using the timestamp from the attacker's first sign-in to pivot, I tried the query:

```
@timestamp > "2024-09-09T17:00:00.565000" AND *schtasks.exe*
```

Here's the result, in part (I've provided the fields I thought were useful):

| Field                           | Value                                                                                                                                           |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `host.name`                     | `windows`                                                                                                                                       |
| `winlog.computer_name`          | `ST-DC01.SECURETECH.local`                                                                                                                      |
| `winlog.event_data.CommandLine` | `schtasks /create /tn "FilesCheck" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\FileCleaner.exe" /sc hourly /ru SYSTEM` |
| `winlog.event_data.User`        | `SECURETECH\jsmith`                                                                                                                             |

**Q9: What's the encryption type used in the environment Kerberos tickets?**

To start, I used the following query to sort by Event ID 4768 (a Kerberos authentication ticket request):

```
event.code: 4768
```

Next, I added the field "winlog.event_data.TicketEncryptionType" and checked the field statistics:

![[Pasted image 20241103214027.png]]

I deduced that the first value was probably owing to Audit Failure, which shows up in a number of situations including incorrect passwords, lockouts, etc. I had to look up the value 0x17 at https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768

**Q10: Can you provide the full path of the output file in preparation for data exfiltration?**

Earlier, I started the hunt with looking for PowerShell execution:

```
winlog.event_data.User: 	
"SECURETECH\jsmith" AND @timestamp > "2024-09-09T17:00:00.565000" AND *powershell.exe*
```

This yielded interesting results:

| @timestamp                 | winlog.event_data.CommandLine                                                                                                                 | winlog.event_data.ProcessId |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- |
| Sep 9, 2024 @ 17:50:54.016 | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noexit -command Set-Location -literalPath 'C:\Shares'                            | 4460                        |
| Sep 9, 2024 @ 17:48:20.117 | "C:\Windows\system32\klist.exe"                                                                                                               | 2844                        |
| Sep 9, 2024 @ 17:42:27.907 | "C:\Users\Public\BackupRunner.exe"                                                                                                            | 2900                        |
| Sep 9, 2024 @ 17:41:33.967 | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noexit -command Set-Location -literalPath 'C:\Users\Public'                      | 7144                        |
| Sep 9, 2024 @ 17:38:44.390 | schtasks /create /tn "FilesCheck" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\FileCleaner.exe" /sc hourly /ru SYSTEM | 4424                        |
| Sep 9, 2024 @ 17:36:36.955 | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noexit -command Set-Location -literalPath 'C:\Windows\Temp'                      | 6964                        |

Besides "C:\Windows\system32\klist.exe" (this is part of a standard Windows installation, used to manage Kerberos tickets), the rest of these are very suspicious.

I took a closer look at the activity of each process responsible for this activity. PID 4460 in particular was interesting:

```
winlog.event_data.User: 	
"SECURETECH\jsmith" AND @timestamp > "2024-09-09T17:00:00.565000" AND winlog.event_data.ProcessId: 4460
```

1. There was a PowerShell script created (Sysmon Event ID 11) "C:\Users\jsmith\AppData\Local\Temp\_\_PSScriptPolicyTest_gpvuqvvq.rpi.ps1" followed by its deletion (Sysmon Event ID 13: File Delete Archived, which logs file deletion activity along with some metadata). 
2. There was process injection into "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clrjit.dll" (Sysmon Event ID 7)
3. Another script was created and deleted: "C:\Users\jsmith\AppData\Local\Temp\_\_PSScriptPolicyTest_qagno2xr.jow.ps1"
4. An archive was created: "C:\Users\Public\Documents\Archive_8673812.zip"

Thanks for reading!
