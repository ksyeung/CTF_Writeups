https://cyberdefenders.org/blueteam-ctf-challenges/meteorhit/

Scenario:
>A critical network infrastructure has encountered significant operational disruptions, leading to system outages and compromised machines. Public message boards displayed politically charged messages, and several systems were wiped, causing widespread service failures. Initial investigations reveal that attackers compromised the Active Directory (AD) system and deployed wiper malware across multiple machines.
>Fortunately, during the attack, an alert employee noticed suspicious activity and immediately powered down several key systems, preventing the malware from completing its wipe across the entire network. However, the damage has already been done, and your team has been tasked with investigating the extent of the compromise.
>You have been provided with forensic artifacts collected via KAPE SANS Triage from one of the affected machines to determine how the attackers gained access, the scope of the malware's deployment, and what critical systems or data were impacted before the shutdown.


**Q1. The attack began with the use of a Group Policy Object (GPO) to execute a malicious batch file. What is the name of the malicious GPO responsible for initiating the attack by running a script?**

Using Registry Explorer, I reviewed the Software hive: "Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0"

| Value Name    | Value Type | Data                                                                                 | Value Slack       | Is Deleted | Data Record Reallocated |
| ------------- | ---------- | ------------------------------------------------------------------------------------ | ----------------- | ---------- | ----------------------- |
| GPO-ID        | RegSz      | cn={8C069217-9EBB-454D-BE84-32317C017A0C},cn=policies,cn=system,DC=abc,DC=local      | 00-00-00-00       | Unchecked  | Unchecked               |
| SOM-ID        | RegSz      | DC=abc,DC=local                                                                      | 00-00-00-00       | Unchecked  | Unchecked               |
| FileSysPath   | RegSz      | \\abc.local\SysVol\abc.local\Policies\{8C069217-9EBB-454D-BE84-32317C017A0C}\Machine | 00-00             | Unchecked  | Unchecked               |
| DisplayName   | RegSz      | DeploySetup                                                                          | 00-00-00-00       | Unchecked  | Unchecked               |
| GPOName       | RegSz      | {8C069217-9EBB-454D-BE84-32317C017A0C}                                               | 00-00-00-00-00-00 | Unchecked  | Unchecked               |
| PSScriptOrder | RegDword   | 1                                                                                    |                   | Unchecked  | Unchecked               |

**Q2. During the investigation, a specific file containing critical components necessary for the later stages of the attack was found on the system. This file, which was expanded using a built-in tool, played a crucial role in staging the malware. What is the name of the file, and where was it located on the system? Please provide the full file path.**

I learned this by reviewing logs with Sysmon Event ID 1 (Process Create: artifacts generally include the process GUID, terminal session ID, process integrity level, current directory, parent-child relationship, hashes, current directory, and detailed command line arguments). This malicious file is relatively apparent due to its file extension.

**Q3. The attacker employed password-protected archives to conceal malicious files, making it important to uncover the password used for extraction. Identifying this password is key to accessing the contents and analyzing the attack further. What is the password used to extract the malicious files?**

I also learned this by reviewing logs with Sysmon Event ID 1. A common archive tool is used, although I needed to briefly review its documentation to understand how it is used on the command-line, as "-p" immediately precedes the password without a space to separate the option and the parameter.

**Q4. Several commands were executed to add exclusions to Windows Defender, preventing it from scanning specific files. This behavior is commonly used by attackers to ensure that malicious files are not detected by the system's built-in antivirus. Tracking these exclusion commands is crucial for identifying which files have been protected from antivirus scans. What is the name of the first file added to the Windows Defender exclusion list?**

See entries in the Sysmon log with Event ID 1.

**Q5. A scheduled task has been configured to execute a file after a set delay. Understanding this delay is important for investigating the timing of potential malicious activity. How many seconds after the task creation time is it scheduled to run? Note: Consider the system's time zone when answering questions related to time.**

I took a look at the Microsoft-Windows-TaskScheduler event logs:

| Time Created        | Provider                        | Process Id | Computer                  | User Id  | User Name | Payload Data1                                                                         |
| ------------------- | ------------------------------- | ---------- | ------------------------- | -------- | --------- | ------------------------------------------------------------------------------------- |
| 2024-09-24 16:02:51 | Microsoft-Windows-TaskScheduler | 1352       | DESKTOP-VBIOB4B.abc.local | S-1-5-18 | ABC\fred  | Task: \OneDrive Standalone Update Task-S-1-5-21-3044787129-2981273323-1937850323-1106 |
| 2024-09-24 16:04:43 | Microsoft-Windows-TaskScheduler | 1376       | DESKTOP-VBIOB4B.abc.local | S-1-5-18 | S-1-5-18  | Task: \mstask                                                                         |
| 2024-09-24 16:07:09 | Microsoft-Windows-TaskScheduler | 1376       | DESKTOP-VBIOB4B.abc.local | S-1-5-18 | S-1-5-18  | Task: \Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work                     |
| 2024-09-24 16:07:09 | Microsoft-Windows-TaskScheduler | 1376       | DESKTOP-VBIOB4B.abc.local | S-1-5-18 | S-1-5-18  | Task: \Microsoft\Windows\UpdateOrchestrator\Schedule Maintenance Work                 |
| 2024-09-24 16:08:05 | Microsoft-Windows-TaskScheduler | 1376       | DESKTOP-VBIOB4B.abc.local | S-1-5-18 | S-1-5-18  | Task: \Aa153!EGzN                                                                     |
| 2024-09-25 01:59:48 | Microsoft-Windows-TaskScheduler | 1352       | DESKTOP-VBIOB4B.abc.local | S-1-5-18 | S-1-5-20  | Task: \Microsoft\Windows\GroupPolicy\{3E0A038B-D834-4930-9981-E89C9BFF83AA}           |
| 2024-09-25 01:59:59 | Microsoft-Windows-TaskScheduler | 1352       | DESKTOP-VBIOB4B.abc.local | S-1-5-18 | S-1-5-20  | Task: \Microsoft\Windows\GroupPolicy\{A7719E0F-10DB-4640-AD8C-490CC6AD5202}           |

Alternatively, I can look at the event logs with Sysmon EID 1. In both cases there's enough information to find the delta.

**Q6. After the malware execution, the wmic utility was used to unjoin the computer system from a domain or workgroup. Tracking this operation is essential for identifying system reconfigurations or unauthorized changes. What is the Process ID (PID) of the utility responsible for performing this action?**

Sysmon Event ID 1 was very helpful in answering this question.

**Q7. The malware executed a command to delete the Windows Boot Manager, a critical component responsible for loading the operating system during startup. This action can render the system unbootable, leading to serious operational disruptions and making recovery more difficult. What command did the malware use to delete the Windows Boot Manager?**

As before, logs with Sysmon EID 1 were useful here. I won't spoil the journey -- and anyway, the overriding lesson here is that process creation events with their command-line options/parameters are important during investigations.

**Q8. The malware created a scheduled task to ensure persistence and maintain control over the compromised system. This task is configured to run with elevated privileges every time the system starts, ensuring the malware continues to execute. What is the name of the scheduled task created by the malware to maintain persistence?**

We can find this in the table of results from our answer to Q5 earlier. The Microsoft-Windows-TaskScheduler/Operational logs (Event ID 106: the user x registered the Task Scheduler task y) were crucial.

**Q9. A malicious program was used to lock the screen, preventing users from accessing the system. Investigating this malware is important to identify its behavior and mitigate its impact. What is the name of this malware? (not the filename)**

See logs with Sysmon Event ID 1.

I have copied some choice columns:

| Time Created        | Event Id | Provider                 | Process Id | Computer                  | User Id  | Map Description  | User Name           | Remote Host | Payload Data1                                                      | Payload Data2 | Payload Data3                                                                                                                                         | Payload Data4                                       | Payload Data5                                                                                                                                               | Payload Data6               | Executable Info                                                                                                               |
| ------------------- | -------- | ------------------------ | ---------- | ------------------------- | -------- | ---------------- | ------------------- | ----------- | ------------------------------------------------------------------ | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| 2024-09-24 16:08:05 | 1        | Microsoft-Windows-Sysmon | 3200       | DESKTOP-VBIOB4B.abc.local | S-1-5-18 | Process creation | NT AUTHORITY\SYSTEM |             | ProcessID: 5180, ProcessGUID: beff4a21-e3e5-66f2-3201-000000000700 | RuleName: -   | MD5=9A49102F53291A644BD14C8202D8FBE3,SHA256=074BCC51B77D8E35B96ED444DC479B2878BF61BF7B07E4D7BD4CF136CC3C0DCE,IMPHASH=3F7F4308D43022646A21416C9A7AADC5 | ParentProcess: C:\ProgramData\Microsoft\env\env.exe | ParentProcessID: 7884, ParentProcessGUID: beff4a21-e3e0-66f2-f400-000000000700, ParentCommandLine: C:\ProgramData\Microsoft\env\env.exe C:\temp\msconf.conf | "C:\temp\mssetup.exe" /LOCK | C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx |

I looked up this hash in VirusTotal to see what names other folks had already assigned to the malware: https://www.virustotal.com/gui/file/074bcc51b77d8e35b96ed444dc479b2878bf61bf7b07e4d7bd4cf136cc3c0dce

**Q10. The disk shows a pattern where malware overwrites data (potentially with zero-bytes) and then deletes it, a behavior commonly linked to Wiper malware activity. The USN (Update Sequence Number) is vital for tracking filesystem changes on an NTFS volume, enabling investigators to trace when files are created, modified, or deleted, even if they are no longer present. This is critical for building a timeline of file activity and detecting potential tampering. What is the USN associated with the deletion of the file msuser.reg?**

I used the handy program NTFS Log Tracker to parse $LogFile, $J, and $MFT. Then I used Timeline Explorer to search the column "File/Directory Name" for `msuser.reg`:

| Line   | Tag       | Time Stamp(UTC 0)   | USN      | File/Directory Name | Full Path                             | Event Info                                                      | Source Info | File Attribute                | Carving Flag | File Reference Number | Parent File Reference Number |
| ------ | --------- | ------------------- | -------- | ------------------- | ------------------------------------- | --------------------------------------------------------------- | ----------- | ----------------------------- | ------------ | --------------------- | ---------------------------- |
| 89656  | Unchecked | 2024-09-24 16:04:43 | 10056648 | msuser.reg          | \ProgramData\Microsoft\env\msuser.reg | File_Created                                                    | Normal      | Archive / Not_Content_Indexed |              | 0x0001000000018533    | 0x0002000000017B1D           |
| 89657  | Unchecked | 2024-09-24 16:04:43 | 10056728 | msuser.reg          | \ProgramData\Microsoft\env\msuser.reg | File_Created / Data_Added                                       | Normal      | Archive / Not_Content_Indexed |              | 0x0001000000018533    | 0x0002000000017B1D           |
| 89658  | Unchecked | 2024-09-24 16:04:43 | 10056808 | msuser.reg          | \ProgramData\Microsoft\env\msuser.reg | File_Created / Basic_Info_Changed / Data_Added                  | Normal      | Archive / Not_Content_Indexed |              | 0x0001000000018533    | 0x0002000000017B1D           |
| 89659  | Unchecked | 2024-09-24 16:04:43 | 10056888 | msuser.reg          | \ProgramData\Microsoft\env\msuser.reg | File_Created / Basic_Info_Changed / Data_Added / File_Closed    | Normal      | Archive / Not_Content_Indexed |              | 0x0001000000018533    | 0x0002000000017B1D           |
| 89660  | Unchecked | 2024-09-24 16:04:43 | 10056968 | msuser.reg          | \ProgramData\Microsoft\env\msuser.reg | Basic_Info_Changed / Content_Indexed_Attr_Changed               | Normal      | Archive                       |              | 0x0001000000018533    | 0x0002000000017B1D           |
| 89661  | Unchecked | 2024-09-24 16:04:43 | 10057048 | msuser.reg          | \ProgramData\Microsoft\env\msuser.reg | Basic_Info_Changed / Content_Indexed_Attr_Changed / File_Closed | Normal      | Archive                       |              | 0x0001000000018533    | 0x0002000000017B1D           |
| 89692  | Unchecked | 2024-09-24 16:04:43 | 10059624 | msuser.reg          | \ProgramData\Microsoft\env\msuser.reg | File_Renamed_Old                                                | Normal      | Archive                       |              | 0x0001000000018533    | 0x0002000000017B1D           |
| 89693  | Unchecked | 2024-09-24 16:04:43 | 10059776 | msuser.reg          | \temp\msuser.reg                      | File_Renamed_New                                                | Normal      | Archive                       |              | 0x0001000000018533    | 0x000100000001852D           |
| 89694  | Unchecked | 2024-09-24 16:04:43 | 10059856 | msuser.reg          | \temp\msuser.reg                      | File_Renamed_New / File_Closed                                  | Normal      | Archive                       |              | 0x0001000000018533    | 0x000100000001852D           |
| 103978 | Unchecked | 2024-09-24 16:08:41 | 11720848 | msuser.reg          | \temp\msuser.reg                      | Data_Overwritten                                                | Normal      | Archive                       |              | 0x0001000000018533    | 0x000100000001852D           |
| 103979 | Unchecked | 2024-09-24 16:08:41 | 11720928 | msuser.reg          | \temp\msuser.reg                      | Data_Overwritten / File_Closed                                  | Normal      | Archive                       |              | 0x0001000000018533    | 0x000100000001852D           |
| 103980 | Unchecked | 2024-09-24 16:08:41 | 11721008 | msuser.reg          | \temp\msuser.reg                      | File_Closed / File_Deleted                                      | Normal      | Archive                       |              | 0x0001000000018533    | 0x000100000001852D           |
