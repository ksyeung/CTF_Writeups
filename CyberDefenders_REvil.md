https://cyberdefenders.org/blueteam-ctf-challenges/revil/

Here's the lab scenario:
>You are a Threat Hunter working for a cybersecurity consulting firm. One of your clients has been recently affected by a ransomware attack that caused the encryption of multiple of their employees' machines. The affected users has reported encountering a ransom note on their desktop and a changed desktop background. You are tasked with using Splunk SIEM containing Sysmon event logs of one of the encrypted machines to extract as much information as possible.

The description of this lab describes Sysmon, so we'll start with evaluating those event logs beginning with Sysmon Event ID 1 (Process Create) before tackling any of these questions. We will read the questions, though! This lab is offered with Splunk and Elastic, and I opted for Elastic.

Kibana query: "event.code: 1"

I add these fields (from left to right columns): 

winlog.computer_name

winlog.event_id

winlog.event_data.TargetFilename

winlog.event_data.CommandLine


Straight away, the first row indicates some suspicious behaviour:


| @timestamp                 | winlog.computer_name | winlog.event_id | winlog.event_data.TargetFilename | winlog.event_data.CommandLine                                        |
| -------------------------- | -------------------- | --------------- | --------------------------- | -------------------------------------------------------------------- |
| Sep 7, 2023 @ 15:12:21.974 | WIN-1RKSOVFDBN0      | 1               | C:\Windows\explorer.exe     | "C:\Windows\system32\mmc.exe" "C:\Windows\system32\eventvwr.msc" /s  |
| Sep 7, 2023 @ 16:09:21.393 | WIN-1RKSOVFDBN0      | 1               | C:\Windows\System32\cmd.exe | wevtutil.exe cl "Microsoft-Windows-StorageSpaces-Api/Operational"    |
| Sep 7, 2023 @ 16:09:21.421 | WIN-1RKSOVFDBN0      | 1               | C:\Windows\System32\cmd.exe | wevtutil.exe cl "Microsoft-Windows-StorageSpaces-Driver/Diagnostic"  |
| Sep 7, 2023 @ 16:09:21.443 | WIN-1RKSOVFDBN0      | 1               | C:\Windows\System32\cmd.exe | wevtutil.exe cl "Microsoft-Windows-StorageSpaces-Driver/Operational" |

My understanding is that first launching the Microsoft Management Console (MMC) with Event Viewer snap-in hinders monitoring tools that read event logs.


'wevtutil.exe cl' is a command clearing the specified event log, and someone is busy trying to clear all of the event logs on this system. It goes on like that for a while (there's much more than three lines of this log clearing: I've truncated it for brevity).


Here's what happens next:

| @timestamp              | winlog.computer_name | winlog.event_id | winlog.event_data.TargetFilename                         | winlog.event_data.CommandLine                                                                                                                                                          |
|-------------------------|----------------------|-----------------|----------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Sep 7, 2023 @ 16:09:50.836 | WIN-1RKSOVFDBN0    | 1               | C:\Windows\explorer.exe                                  | "C:\Users\Administrator\Downloads\facebook assistant.exe"                                                                                                                              |
| Sep 7, 2023 @ 16:09:53.578 | WIN-1RKSOVFDBN0    | 1               | C:\Users\Administrator\Downloads\facebook assistant.exe  | powershell -e RwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAFcAaQBuADMAMgBfAFMAaABhAGQAbwB3AGMAbwBwAHkAIAB8ACAARgBvAHIARQBhAGMAaAAtAE8AYgBqAGUAYwB0ACAAewAkAF8ALgBEAGUAbABlAHQAZQAoACkAOwB9AA== |
| Sep 8, 2023 @ 03:32:07.918 | WIN-1RKSOVFDBN0    | 1               | C:\Windows\System32\taskhostw.exe                        |                                                                                                                                                                                        |

"facebook assistant.exe" looks like its the second stage of the ransomware. I want to look closer at what its doing. First, though, the base64 content decodes to: 

```
Get-WmiObject Win32_Shadowcopy | ForEach-Object ... {$_.Delete();}
```

This deletes all Volume Shadow Copies on the system (saved restore points, snapshots), and is characteristic of ransomware execution. This is also the answer to **Q4: "Now that you've pinpointed the ransomware's executable location, let's dig deeper. It's a common tactic for ransomware to disrupt system recovery methods. Can you identify the command that was used for this purpose?"**

Moving on, I update the columns to use these fields:

winlog.computer_name

winlog.event_id

winlog.event_data.ProcessId

winlog.event_data.ParentProcessId

winlog.event_data.ParentImage

winlog.event_data.TargetFilename

winlog.event_data.CommandLine


These are the results:

| @timestamp                 | winlog.computer_name | winlog.event_id | winlog.event_data.ProcessId | winlog.event_data.ParentProcessId | winlog.event_data.ParentImage                           | winlog.event_data.TargetFilename                                                                                                                                                       | winlog.event_data.CommandLine                             |
| -------------------------- | -------------------- | --------------- | --------------------------- | --------------------------------- | ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| Sep 7, 2023 @ 16:09:50.836 | WIN-1RKSOVFDBN0      | 1               | 5348                        | 244                               | C:\Windows\explorer.exe                                 | -                                                                                                                                                                                      | "C:\Users\Administrator\Downloads\facebook assistant.exe" |
| Sep 7, 2023 @ 16:09:50.836 | WIN-1RKSOVFDBN0      | 7               | 5348                        | -                                 | -                                                       | -                                                                                                                                                                                      | -                                                         |
| Sep 7, 2023 @ 16:09:53.577 | WIN-1RKSOVFDBN0      | 13              | 5348                        | -                                 | -                                                       | -                                                                                                                                                                                      | -                                                         |
| Sep 7, 2023 @ 16:09:53.578 | WIN-1RKSOVFDBN0      | 1               | 1860                        | 5348                              | C:\Users\Administrator\Downloads\facebook assistant.exe | powershell -e RwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAFcAaQBuADMAMgBfAFMAaABhAGQAbwB3AGMAbwBwAHkAIAB8ACAARgBvAHIARQBhAGMAaAAtAE8AYgBqAGUAYwB0ACAAewAkAF8ALgBEAGUAbABlAHQAZQAoACkAOwB9AA== |                                                           |
| Sep 7, 2023 @ 16:09:59.750 | WIN-1RKSOVFDBN0      | 11              | 5348                        | -                                 | -                                                       | C:\Users\Default\5uizv5660t-readme.txt                                                                                                                                                 | -                                                         |
| Sep 7, 2023 @ 16:09:59.751 | WIN-1RKSOVFDBN0      | 11              | 5348                        | -                                 | -                                                       | C:\Users\Public\5uizv5660t-readme.txt                                                                                                                                                  | -                                                         |
| Sep 7, 2023 @ 16:09:59.759 | WIN-1RKSOVFDBN0      | 11              | 5348                        | -                                 | -                                                       | C:\Users\Administrator\Desktop\5uizv5660t-readme.txt                                                                                                                                   | -                                                         |

I've truncated the results here (it gets repetitive anyway, you get the idea of what comes later once you've seen the last three rows). So, we know the PID for "facebook assistant.exe", which should come in handy later. Also, we've found the answers to Q1-3! 

**Q1: "To begin your investigation, can you identify the filename of the note that the ransomware left behind?"**

**Q2: "After identifying the ransom note, the next step is to pinpoint the source. What's the process ID of the ransomware that's likely involved?"**

**Q3: "Having determined the ransomware's process ID, the next logical step is to locate its origin. Where can we find the ransomware's executable file?"**

I tried to find the actual contents of the text file to read it (there's usually instructions on how to remit payment that would be relevant to an investigation). Knowing ELK probably wouldn't retain something like that for performance reasons, I predictably came up empty-handed.

**Q5 asks: "As we trace the ransomware's steps, a deeper verification is needed. Can you provide the sha256 hash of the ransomware's executable to cross-check with known malicious signatures?"**


To make this easy to find, I add an additional column, the field "winlog.event_data.Hashes".


**Q6 asks: "One crucial piece remains. We need to identify the attacker's communication channel. Can you pinpoint the ransomware author's onion domain to receive the payments from the victims?"**


I struggled with this one for about an hour: 

❌ I tried a basic "\*onion\*" query, which didn't yield any results. 

❌ I combed through the VirusTotal behaviour page without success: only IP addresses were listed in the network comms section.

❌ I looked through all of the commandline results again without success. 

❌ I looked through Sysmon Event IDs 12 and 13 to see if a registry key may have been set (this was a long shot: wouldn't a .onion address have shown up in a prior query? But maybe it was base64 encoded or something like that)


Having exhausted my options (let me know if there's a way to learn this inside ELK), I resorted to a cloud sandbox: https://www.joesandbox.com/analysis/1484308/0/html

Joe Sandbox notes that the ransomware drops an onion address in the "\<random-alphanumerics\>-readme.txt" file! I was right to try to read it, although for a somewhat different reason.

Thanks for checking out this walkthrough!
