[https://aceresponder.com/challenge/run-of-the-mill

Scenario:
>A standard Windows domain compromise showcasing various techniques. 
>The events in your SIEM can be found in the following timespan: 7th November 2022 - 9th November 2022.

**Q1. Beachhead: Which host did the attacker compromise first?**

I started this lab out by looking for Sysmon Event ID 1 (Process Create), which is usually a great source of quick insight into an attacker's activity. However, that didn't work this time (no results!). Next, I checked for failed authentication attempts, a common indicator of a brute forcing attack. The query `event.code: 4625` showed me numerous failed logins (25 in total) for the username Administrator with the hostname dc.windomain.local, originating from IP address 192.168.56.113 and workstation name WIN10-KYLGY. No other hosts or usernames have failed login attempts.

Naturally, the next step is to determine whether the attacker was successful logging in. I continued by refining the query, then sorting the table in descending order using the timestamp:

```
winlog.event_data.TargetUserName: Administrator AND (event.code: 4625 OR event.code: 4624)
```

Here's the result (for brevity, I truncated the results as the initial rows were identical anyway. There were 27 hits for this query):

| Time                       | TargetUserName | IpAddress      | WorkstationName | event.code | TargetLogonId |
| -------------------------- | -------------- | -------------- | --------------- | ---------- | ------------- |
| Nov 8, 2022 @ 11:30:03.406 | Administrator  | 192.168.56.113 | WIN10-KYLGY     | 4625       | -             |
| Nov 8, 2022 @ 11:30:03.416 | Administrator  | 192.168.56.113 | WIN10-KYLGY     | 4625       | -             |
| Nov 8, 2022 @ 11:30:03.422 | Administrator  | 192.168.56.113 | WIN10-KYLGY     | 4625       | -             |
| Nov 8, 2022 @ 11:30:03.900 | Administrator  | 192.168.56.113 | WIN10-KYLGY     | 4624       | 0x147bdb0     |
| Nov 8, 2022 @ 11:31:23.744 | Administrator  | 192.168.56.113 | -               | 4624       | 0x147ebf0     |

The attacker was successful signing in. I added the column "winlog.event_data.TargetLogonId" so I can follow their activity on the machine. Before I do that, I want to dig into how the attacker got onto that workstation WIN10-KYLGY. After all, they may have pivoted to WIN10-KYLGY from another machine.

I start by looking at the types of Event IDs might be available: `host.name: win10-kYlgY.windomain.local`. The first three results are Sysmon Event ID 10 (Process accessed), which is very interesting:

| Time                           | event.code              | event.action          | host.name                   |
| ------------------------------ | ----------------------- | --------------------- | --------------------------- |
| Nov 8, 2022 @ 10:41:54.26810   | Process accessed        | (rule: ProcessAccess) | win10-kYlgY.windomain.local |
| Nov 8, 2022 @ 10:41:55.37710   | Process accessed        | (rule: ProcessAccess) | win10-kYlgY.windomain.local |
| Nov 8, 2022 @ 10:41:56.44710   | Process accessed        | (rule: ProcessAccess) | win10-kYlgY.windomain.local |
| Nov 8, 2022 @ 10:41:57.4194673 | Sensitive Privilege Use |                       | win10-kYlgY.windomain.local |

The rest of the content is truncated (there is, of course, more than 170k hits).

The first result's winlog.event_data.RuleName value is "technique_id=T1003,technique_name=Credential Dumping". Here's the entire event message:

```
Process accessed:
RuleName: technique_id=T1003,technique_name=Credential Dumping
UtcTime: 2022-11-08 18:41:54.267
SourceProcessGUID: {8e1127c5-990b-636a-822b-000000000b00}
SourceProcessId: 6364
SourceThreadId: 2780
SourceImage: C:\Tools\Sysinternals\procexp64.exe
TargetProcessGUID: {8e1127c5-11d5-6364-0c00-000000000b00}
TargetProcessId: 660
TargetImage: C:\Windows\system32\lsass.exe
GrantedAccess: 0x1FFFFF
CallTrace: C:\Windows\SYSTEM32\ntdll.dll+9c584|C:\Windows\System32\KERNELBASE.dll+2730e|C:\Tools\Sysinternals\procexp64.exe+c8c07|C:\Tools\Sysinternals\procexp64.exe+a0b90|C:\Tools\Sysinternals\procexp64.exe+f7792|C:\Windows\System32\KERNEL32.DLL+17bd4|C:\Windows\SYSTEM32\ntdll.dll+6ced1
SourceUser: WINDOMAIN\aubrey_olsen
TargetUser: NT AUTHORITY\SYSTEM
```

So, we know that the username WINDOMAIN\aubrey_olsen dumped the process memory of lsass.exe using procexp64.exe (Process Explorer), and had all possible access rights (GrantedAccess: 0x1FFFFF, or PROCESS_ALL_ACCESS). If you're curious about these access rights, see https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights. They likely were able to dump the hashes for the domain controller, but they were likely unable to crack the password: we noticed earlier that they attempted a brute force attack around an hour later. Its not clear to me why they dumped the process three times in three seconds, but I speculate it may be an attempt to evade or confuse EDR/AV tools.




**Q2. Defense Evasion: The attacker took action to evade detection immediately after gaining a foothold. Which MITRE ATT&CK® technique and sub-technique did the attacker use?**

I went looking first for Sysmon Event ID 26 (File Delete logged).

There was one result. Here's the event message:

```
File Delete logged:
RuleName: -
UtcTime: 2022-11-08 19:25:01.421
ProcessGuid: {8e1127c5-0040-6368-d91b-000000000b00}
ProcessId: 4304
User: WINDOMAIN\aubrey_olsen
Image: C:\Windows\Explorer.EXE
TargetFilename: C:\Users\aubrey_olsen\Downloads\explore.exe:Zone.Identifier
Hashes: SHA1=752F2D663BE838B2F23BDC2C6320B43C25513F72,MD5=7D8B230B831C3256B13C03785B4F093E,SHA256=DD764A91690307C8EE70A334EB4A95B0C538982B7CCF81CB1C5F7BE58A798C8E,IMPHASH=00000000000000000000000000000000
IsExecutable: false
```

This is interesting. Let's see what explore.exe was doing:



Anyway, moving on to the question at hand, let's see what registry changes were made. Perhaps the attacker disabled Windows Defender?

](https://aceresponder.com/challenge/run-of-the-mill

Scenario:
>A standard Windows domain compromise showcasing various techniques. 
>The events in your SIEM can be found in the following timespan: 7th November 2022 - 9th November 2022.

**Q1. Beachhead: Which host did the attacker compromise first?**

I started this lab out by looking for Sysmon Event ID 1 (Process Create), which is usually a great source of quick insight into an attacker's activity. However, that didn't work this time (no results!). Next, I checked for failed authentication attempts, a common indicator of a brute forcing attack. The query `event.code: 4625` showed me numerous failed logins (25 in total) for the username Administrator with the hostname dc.windomain.local, originating from IP address 192.168.56.113 and workstation name WIN10-KYLGY. No other hosts or usernames have failed login attempts.

Naturally, the next step is to determine whether the attacker was successful logging in. I continued by refining the query, then sorting the table in descending order using the timestamp:

```
winlog.event_data.TargetUserName: Administrator AND (event.code: 4625 OR event.code: 4624)
```

Here's the result (for brevity, I truncated the results as the initial rows were identical anyway. There were 27 hits for this query):

| Time                       | TargetUserName | IpAddress      | WorkstationName | event.code | TargetLogonId |
| -------------------------- | -------------- | -------------- | --------------- | ---------- | ------------- |
| Nov 8, 2022 @ 11:30:03.406 | Administrator  | 192.168.56.113 | WIN10-KYLGY     | 4625       | -             |
| Nov 8, 2022 @ 11:30:03.416 | Administrator  | 192.168.56.113 | WIN10-KYLGY     | 4625       | -             |
| Nov 8, 2022 @ 11:30:03.422 | Administrator  | 192.168.56.113 | WIN10-KYLGY     | 4625       | -             |
| Nov 8, 2022 @ 11:30:03.900 | Administrator  | 192.168.56.113 | WIN10-KYLGY     | 4624       | 0x147bdb0     |
| Nov 8, 2022 @ 11:31:23.744 | Administrator  | 192.168.56.113 | -               | 4624       | 0x147ebf0     |

The attacker was successful signing in. I added the column winlog.event_data.TargetLogonId so I can follow their activity on the machine. Before I do that, I want to dig into how the attacker got onto workstation WIN10-KYLGY. After all, they may have pivoted to WIN10-KYLGY from another machine.

I started by looking at the types of Event IDs available: `host.name: win10-kYlgY.windomain.local`. The first three results in chronological order are Sysmon Event ID 10 (Process accessed), which is very interesting:

| Time                           | event.code              | event.action          | host.name                   |
| ------------------------------ | ----------------------- | --------------------- | --------------------------- |
| Nov 8, 2022 @ 10:41:54.26810   | Process accessed        | (rule: ProcessAccess) | win10-kYlgY.windomain.local |
| Nov 8, 2022 @ 10:41:55.37710   | Process accessed        | (rule: ProcessAccess) | win10-kYlgY.windomain.local |
| Nov 8, 2022 @ 10:41:56.44710   | Process accessed        | (rule: ProcessAccess) | win10-kYlgY.windomain.local |
| Nov 8, 2022 @ 10:41:57.4194673 | Sensitive Privilege Use |                       | win10-kYlgY.windomain.local |

The rest of the results are truncated (there are more than 170k hits).

The first result's winlog.event_data.RuleName value is technique_id=T1003,technique_name=Credential Dumping. Here's the entire event message:

```
Process accessed:
RuleName: technique_id=T1003,technique_name=Credential Dumping
UtcTime: 2022-11-08 18:41:54.267
SourceProcessGUID: {8e1127c5-990b-636a-822b-000000000b00}
SourceProcessId: 6364
SourceThreadId: 2780
SourceImage: C:\Tools\Sysinternals\procexp64.exe
TargetProcessGUID: {8e1127c5-11d5-6364-0c00-000000000b00}
TargetProcessId: 660
TargetImage: C:\Windows\system32\lsass.exe
GrantedAccess: 0x1FFFFF
CallTrace: C:\Windows\SYSTEM32\ntdll.dll+9c584|C:\Windows\System32\KERNELBASE.dll+2730e|C:\Tools\Sysinternals\procexp64.exe+c8c07|C:\Tools\Sysinternals\procexp64.exe+a0b90|C:\Tools\Sysinternals\procexp64.exe+f7792|C:\Windows\System32\KERNEL32.DLL+17bd4|C:\Windows\SYSTEM32\ntdll.dll+6ced1
SourceUser: WINDOMAIN\aubrey_olsen
TargetUser: NT AUTHORITY\SYSTEM
```

Now we know that the user WINDOMAIN\aubrey_olsen dumped the process memory of lsass.exe using procexp64.exe (Process Explorer), and had all possible access rights (GrantedAccess: 0x1FFFFF, or PROCESS_ALL_ACCESS). If you're curious about these access rights, see https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights. They likely were able to dump hashes for the domain controller, but they were probably unable to crack the Administrator account's password: we noticed earlier that they attempted a brute force attack around an hour later. Its not clear to me why they dumped the process three times in three seconds, but I speculate it may be an attempt to evade or confuse EDR/AV tools.

We have a side mission: finding out what other machines, if any, the attacker may have tried to access, and what else they were up to while on this machine. Then we'll go back and investigate how aubrey_olsen was compromised.



**Q2. Defense Evasion: The attacker took action to evade detection immediately after gaining a foothold. Which MITRE ATT&CK® technique and sub-technique did the attacker use?**

I went looking first for Sysmon Event ID 26 (File Delete logged).

There was one result. Here's the event message:

```
File Delete logged:
RuleName: -
UtcTime: 2022-11-08 19:25:01.421
ProcessGuid: {8e1127c5-0040-6368-d91b-000000000b00}
ProcessId: 4304
User: WINDOMAIN\aubrey_olsen
Image: C:\Windows\Explorer.EXE
TargetFilename: C:\Users\aubrey_olsen\Downloads\explore.exe:Zone.Identifier
Hashes: SHA1=752F2D663BE838B2F23BDC2C6320B43C25513F72,MD5=7D8B230B831C3256B13C03785B4F093E,SHA256=DD764A91690307C8EE70A334EB4A95B0C538982B7CCF81CB1C5F7BE58A798C8E,IMPHASH=00000000000000000000000000000000
IsExecutable: false
```

This is interesting. Let's see what explore.exe was doing:



Moving on to the question at hand, let's see what registry changes were made. Perhaps the attacker disabled Windows Defender?

)
