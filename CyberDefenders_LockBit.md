https://cyberdefenders.org/blueteam-ctf-challenges/lockbit/

Scenario: 
>A medium-sized corporation has experienced a ransomware attack, first identified when a user reported a ransom note on their screen alongside a Windows Defender alert indicating malicious activity. Your task is to analyze logs provided from the compromised machines and identify the ransomware's entry point.
><Screenshot of desktop pictured, with a wallpaper that reads: "All your important files are stolen and encrypted. You must find HHuYRxB06.README.txt file and follow the instruction!">

**Q1. DC01: Windows Defender flagged a suspicious executable. Can you identify the name of this executable?**

First, I began by converting DC01's event logs into a CSV that I can feed into Timeline Explorer:

```
EvtxECmd.exe -d "C:\Users\Administrator\Desktop\Start here\Artifacts\DC01\Windows\System32\winevt\logs" --csv "C:\Users\Administrator\Desktop" --csvf DC01_evtx.csv
```

Then I filtered on Event ID 1116 (event log provider Microsoft-Windows-Windows Defender/Operational):

| Time Created        | Process Id | Computer           | Payload Data1                                    | Payload Data2                  | Payload Data3                            | Payload Data4                                             | Payload Data5                                        | Payload Data6                   |
| ------------------- | ---------: | ------------------ | ------------------------------------------------ | ------------------------------ | ---------------------------------------- | --------------------------------------------------------- | ---------------------------------------------------- | ------------------------------- |
| 2023-12-14 15:08:13 |       3692 | DC01.NEXTECH.local | Malware name: Backdoor:Win64/CobaltStrike.NP!dha | Description: Backdoor (Severe) | Detection Time: 2023-12-14T15:08:13.734Z | Process (if real-time detection): C:\Windows\Sysmon64.exe | Detection ID: {83363BF5-2054-4A7F-BBA5-47F6893113DB} | file:_\\DC01\ADMIN$\8fe9c39.exe |

**Q2. DC01: What's the path that was added to the exclusions of Windows Defender?**

There's at least two ways to find this out: 
1. Checking the keys for "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths", or
2. Event ID 5007: "The antimalware platform configuration changed"

| Time Created        | Event Id | Process Id | Computer           | User Id  | Map Description                                | Payload Data1 | Payload Data2                                                                  |
| ------------------- | -------: | ---------: | ------------------ | -------- | ---------------------------------------------- | ------------- | ------------------------------------------------------------------------------ |
| 2023-12-14 15:07:03 |     5007 |       3692 | DC01.NEXTECH.local | S-1-5-18 | The antimalware platform configuration changed | Old Value:    | New Value: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\ = 0x0 |

**Q3. DC01: What’s the IP of the machine that initiated the remote installation of the malicious service?**



**Q4. SQLServer: What’s the name of the process that had suspicious behavior as detected by Windows Defender?**



**Q5. SQLServer: What’s the parent process name of the detected suspicious process?**



**Q6. SQLServer: Initial access often involves compromised credentials. What is the SQL Server account username that was compromised?**



**Q7. SQLServer: Following the compromise, a critical server configuration was modified. What feature was enabled by the attacker?**



**Q8. SQLServer: What’s the command executed by the attacker to disable Windows Defender on the server?**



**Q9. SQLServer: What's the name of the malicious script that the attacker executed upon disabling AV?**



**Q10. SQLServer: What's the PID of the process the attacker injected?**



**Q11. SQLServer: Attackers often maintain access by the creation of scheduled tasks. What’s the name of the scheduled task created by the attacker?**



**Q12. SQLServer: What’s the PID of the malicious process that dumped credentials?**



**Q13. SQLServer: What's the command used by the attacker to disable Windows Defender remotely on FileServer?**



**Q14. FileServer: What's the name of the malicious service executable blocked by Windows Defender?**



**Q15. DevPC: What’s the name of the ransomware executable dropped on the machine?**



**Q16. DevPC: What’s the full path of the first file dropped by the ransomware?**


