[https://cyberdefenders.org/blueteam-ctf-challenges/lockbit/

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


](https://cyberdefenders.org/blueteam-ctf-challenges/lockbit/

Scenario: 
>A medium-sized corporation has experienced a ransomware attack, first identified when a user reported a ransom note on their screen alongside a Windows Defender alert indicating malicious activity. Your task is to analyze logs provided from the compromised machines and identify the ransomware's entry point.
><Screenshot of desktop pictured, with a wallpaper that reads: "All your important files are stolen and encrypted. You must find HHuYRxB06.README.txt file and follow the instruction!">

One of the first things I often do is try to collect quick wins, and Sysmon Event ID 1 is great for this. First, I began by converting DC01's event logs into a CSV that I can feed into Timeline Explorer:

```
EvtxECmd.exe -d "C:\Users\Administrator\Desktop\Start here\Artifacts\DC01\Windows\System32\winevt\logs" --csv "C:\Users\Administrator\Desktop" --csvf DC01_evtx.csv
```

The results:

| Time Created        | Event Id | Process Id | Payload Data4                                                    | Payload Data5                                                                  | Payload Data6                                                                                                                                                           | Executable Info                                                                                                                                                                                                                                        |
| ------------------- | -------- | ---------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\smss.exe                      | ParentProcessID: 388, ParentProcessGUID: ffc4c1ab-0e2b-657b-0500-000000000d00  | ParentCommandLine: \SystemRoot\System32\smss.exe 0000014c 00000084                                                                                                      | %%SystemRoot%%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16 |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\smss.exe                      | ParentProcessID: 492, ParentProcessGUID: ffc4c1ab-0e2b-657b-0700-000000000d00  | ParentCommandLine: \SystemRoot\System32\smss.exe 00000080 00000084                                                                                                      | %%SystemRoot%%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16 |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\wininit.exe                   | ParentProcessID: 500, ParentProcessGUID: ffc4c1ab-0e2b-657b-0800-000000000d00  | ParentCommandLine: wininit.exe                                                                                                                                          | C:\Windows\system32\lsass.exe                                                                                                                                                                                                                          |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\system32\svchost.exe -k DcomLaunch -p -s LSM                                                                                                                                                                                                |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s lmhosts                                                                                                                                                                         |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\system32\svchost.exe -k LocalService -p -s nsi                                                                                                                                                                                              |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s TimeBrokerSvc                                                                                                                                                                   |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService                                                                                                                                                                       |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp                                                                                                                                                                            |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog                                                                                                                                                                        |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p                                                                                                                                                                                    |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\System32\svchost.exe -k LocalService -p -s netprofm                                                                                                                                                                                         |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\system32\svchost.exe -k LocalService -p -s EventSystem                                                                                                                                                                                      |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p                                                                                                                                                                                    |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s WinHttpAutoProxySvc                                                                                                                                                             |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\system32\svchost.exe -k LocalService -p -s FontCache                                                                                                                                                                                        |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\system32\svchost.exe -k LocalService -p -s fdPHost                                                                                                                                                                                          |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation -p -s FDResPub                                                                                                                                                                       |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding                                                                                                                                                                                              |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\System32\spoolsv.exe                                                                                                                                                                                                                        |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork -p                                                                                                                                                                                            |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                                                                                                                                                                                              |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\system32\svchost.exe -k localService -p -s RemoteRegistry                                                                                                                                                                                   |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s SysMain                                                                                                                                                                          |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"                                                                                                                                                                                 |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"                                                                                                                                                                                                    |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\System32\svchost.exe -k NetworkService -p -s WinRM                                                                                                                                                                                          |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Program Files\VMware\VMware Tools\vmtoolsd.exe | ParentProcessID: 3628, ParentProcessGUID: ffc4c1ab-0e36-657b-5100-000000000d00 | ParentCommandLine: "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"                                                                                                  | C:\Windows\system32\cmd.exe /c ""C:\Program Files\VMware\VMware Tools\poweron-vm-default.bat""                                                                                                                                                         |
| 2023-12-14 14:16:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe -Embedding                                                                                                                                                                                                       |
| 2023-12-14 14:17:13 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 1572, ParentProcessGUID: ffc4c1ab-0e2d-657b-2500-000000000d00 | ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule                                                                                            | C:\Windows\system32\cmd.exe /d /c C:\Windows\system32\silcollector.cmd configure                                                                                                                                                                       |
| 2023-12-14 14:17:13 | 1        | 3556       | ParentProcess: C:\Windows\System32\cmd.exe                       | ParentProcessID: 5564, ParentProcessGUID: ffc4c1ab-0e69-657b-6700-000000000d00 | ParentCommandLine: C:\Windows\system32\cmd.exe /d /c C:\Windows\system32\silcollector.cmd configure                                                                     | C:\Windows\system32\cmd.exe /c C:\Windows\system32\reg.exe query hklm\software\microsoft\windows\softwareinventorylogging /v collectionstate /reg:64                                                                                                   |
| 2023-12-14 14:17:14 | 1        | 3556       | ParentProcess: C:\Windows\System32\cmd.exe                       | ParentProcessID: 5616, ParentProcessGUID: ffc4c1ab-0e69-657b-6900-000000000d00 | ParentCommandLine: C:\Windows\system32\cmd.exe /c C:\Windows\system32\reg.exe query hklm\software\microsoft\windows\softwareinventorylogging /v collectionstate /reg:64 | C:\Windows\system32\reg.exe  query hklm\software\microsoft\windows\softwareinventorylogging /v collectionstate /reg:64                                                                                                                                 |
| 2023-12-14 14:17:56 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s TabletInputService                                                                                                                                                               |
| 2023-12-14 14:17:56 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\system32\svchost.exe -k LocalService -p -s CDPSvc                                                                                                                                                                                           |
| 2023-12-14 14:18:00 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding                                                                                                                                                                                              |
| 2023-12-14 14:18:03 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe -Embedding                                                                                                                                                                                                       |
| 2023-12-14 14:18:10 | 1        | 3556       | ParentProcess: C:\Windows\explorer.exe                           | ParentProcessID: 780, ParentProcessGUID: ffc4c1ab-0e95-657b-7a00-000000000d00  | ParentCommandLine: C:\Windows\Explorer.EXE /NOUACCHECK                                                                                                                  | "C:\Windows\System32\SecurityHealthSystray.exe"                                                                                                                                                                                                        |
| 2023-12-14 14:18:11 | 1        | 3556       | ParentProcess: C:\Windows\explorer.exe                           | ParentProcessID: 780, ParentProcessGUID: ffc4c1ab-0e95-657b-7a00-000000000d00  | ParentCommandLine: C:\Windows\Explorer.EXE /NOUACCHECK                                                                                                                  | "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr                                                                                                                                                                                           |
| 2023-12-14 14:18:23 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS                                                                                                                                                                                     |
| 2023-12-14 14:18:24 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s UALSVC                                                                                                                                                                           |
| 2023-12-14 14:19:13 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 1572, ParentProcessGUID: ffc4c1ab-0e2d-657b-2500-000000000d00 | ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule                                                                                            | C:\Windows\system32\sc.exe start pushtoinstall registration                                                                                                                                                                                            |
| 2023-12-14 14:19:13 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 1572, ParentProcessGUID: ffc4c1ab-0e2d-657b-2500-000000000d00 | ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule                                                                                            | C:\Windows\system32\sc.exe start wuauserv                                                                                                                                                                                                              |
| 2023-12-14 14:28:00 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding                                                                                                                                                                                              |
| 2023-12-14 14:28:03 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe -Embedding                                                                                                                                                                                                       |
| 2023-12-14 14:28:15 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s StorSvc                                                                                                                                                                          |
| 2023-12-14 14:37:35 | 1        | 3556       | ParentProcess: C:\Windows\System32\services.exe                  | ParentProcessID: 640, ParentProcessGUID: ffc4c1ab-0e2b-657b-0b00-000000000d00  | ParentCommandLine: C:\Windows\system32\services.exe                                                                                                                     | C:\Windows\system32\svchost.exe -k LocalService -p -s BthAvctpSvc                                                                                                                                                                                      |
| 2023-12-14 14:38:00 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding                                                                                                                                                                                              |
| 2023-12-14 14:38:03 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe -Embedding                                                                                                                                                                                                       |
| 2023-12-14 14:48:00 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding                                                                                                                                                                                              |
| 2023-12-14 14:48:02 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe -Embedding                                                                                                                                                                                                       |
| 2023-12-14 14:56:43 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 1572, ParentProcessGUID: ffc4c1ab-0e2d-657b-2500-000000000d00 | ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule                                                                                            | C:\Windows\system32\rundll32.exe /d acproxy.dll,PerformAutochkOperations                                                                                                                                                                               |
| 2023-12-14 14:58:00 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding                                                                                                                                                                                              |
| 2023-12-14 14:58:03 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe -Embedding                                                                                                                                                                                                       |
| 2023-12-14 15:06:10 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wsmprovhost.exe -Embedding                                                                                                                                                                                                         |
| 2023-12-14 15:06:10 | 1        | 3556       | ParentProcess: C:\Windows\System32\wsmprovhost.exe               | ParentProcessID: 1000, ParentProcessGUID: ffc4c1ab-19e2-657b-d500-000000000d00 | ParentCommandLine: C:\Windows\system32\wsmprovhost.exe -Embedding                                                                                                       | "C:\Windows\system32\reg.exe" add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f                                                                                                                       |
| 2023-12-14 15:07:01 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wsmprovhost.exe -Embedding                                                                                                                                                                                                         |
| 2023-12-14 15:07:02 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding                                                                                                                                                                                              |
| 2023-12-14 15:08:03 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe -Embedding                                                                                                                                                                                                       |
| 2023-12-14 15:08:14 | 1        | 3556       | ParentProcess: \\DC01\ADMIN$\8fe9c39.exe                         | ParentProcessID: 5236, ParentProcessGUID: ffc4c1ab-1a5d-657b-de00-000000000d00 | ParentCommandLine: \\DC01\ADMIN$\8fe9c39.exe                                                                                                                            | C:\Windows\System32\rundll32.exe                                                                                                                                                                                                                       |
| 2023-12-14 15:12:15 | 1        | 3556       | ParentProcess: C:\Windows\SysWOW64\rundll32.exe                  | ParentProcessID: 3076, ParentProcessGUID: ffc4c1ab-1a5e-657b-e100-000000000d00 | ParentCommandLine: C:\Windows\System32\rundll32.exe                                                                                                                     | C:\Windows\sysnative\rundll32.exe                                                                                                                                                                                                                      |
| 2023-12-14 15:13:16 | 1        | 3556       | ParentProcess: C:\Windows\SysWOW64\rundll32.exe                  | ParentProcessID: 3076, ParentProcessGUID: ffc4c1ab-1a5e-657b-e100-000000000d00 | ParentCommandLine: C:\Windows\System32\rundll32.exe                                                                                                                     | C:\Windows\sysnative\rundll32.exe                                                                                                                                                                                                                      |
| 2023-12-14 15:18:00 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding                                                                                                                                                                                              |
| 2023-12-14 15:18:03 | 1        | 3556       | ParentProcess: C:\Windows\System32\svchost.exe                   | ParentProcessID: 872, ParentProcessGUID: ffc4c1ab-0e2c-657b-0e00-000000000d00  | ParentCommandLine: C:\Windows\system32\svchost.exe -k DcomLaunch -p                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe -Embedding                                                                                                                                                                                                       |
| 2023-12-14 15:22:28 | 1        | 3556       | ParentProcess: C:\Windows\SysWOW64\rundll32.exe                  | ParentProcessID: 3076, ParentProcessGUID: ffc4c1ab-1a5e-657b-e100-000000000d00 | ParentCommandLine: C:\Windows\System32\rundll32.exe                                                                                                                     | vmware.exe                                                                                                                                                                                                                                             |

1. I learned that this attacker uses DCOM and WMI for lateral movement.
2. "cmd.exe /c C:\Windows\system32\reg.exe query hklm\software\microsoft\windows\softwareinventorylogging /v collectionstate /reg:64" appears to be enumerating the software inventory, perhaps in preparation for use of Living Off The Land techniques. 
3. If there was any doubt that this was a compromised machine, interaction with the DisableAntiSpyware registry key would clear that up.
4. Finally, '8fe9c39.exe' is a suspicious executable. There's no file hash available in the event, and I couldn't find the file right away on disk, but I've made a note to look for the file hash in the USN journal later.

Moving on, I search for the ransom note in DC01's event logs, and I find several entries with Sysmon Event ID 11 (File created) at:

```
C:\Users\Administrator\Desktop\\
C:\Users\Administrator\Downloads\\
C:\Users\SQLService\Desktop\\
C:\Users\SQLService\Downloads\\
C:\Windows\SYSVOL\domain\
C:\Windows\SYSVOL\domain\Policies\
C:\Windows\SYSVOL\domain\scripts\
C:\Windows\SYSVOL\sysvol\
```

Process IDs responsible for creating this file include: 1680 and 4, although there's no process name attached. A quick search for the Process ID in Timeline Explorer doesn't reveal anything either.

**Q1. DC01: Windows Defender flagged a suspicious executable. Can you identify the name of this executable?**

I filtered on Event ID 1116 (event log provider Microsoft-Windows-Windows Defender/Operational):

| Time Created        | Process Id | Computer           | Payload Data1                                    | Payload Data2                  | Payload Data3                            | Payload Data4                                             | Payload Data5                                        | Payload Data6                   |
| ------------------- | ---------: | ------------------ | ------------------------------------------------ | ------------------------------ | ---------------------------------------- | --------------------------------------------------------- | ---------------------------------------------------- | ------------------------------- |
| 2023-12-14 15:08:13 |       3692 | DC01.NEXTECH.local | Malware name: Backdoor:Win64/CobaltStrike.NP!dha | Description: Backdoor (Severe) | Detection Time: 2023-12-14T15:08:13.734Z | Process (if real-time detection): C:\Windows\Sysmon64.exe | Detection ID: {83363BF5-2054-4A7F-BBA5-47F6893113DB} | file:_\\DC01\ADMIN$\8fe9c39.exe |

We saw this file in our preliminary investigation, and its absence from the disk now makes more sense. Event ID 1117: "The antimalware platform performed an action to protect your system from malware or other potentially unwanted software" unfortunately doesn't provide a file hash, but does show that the file was quarantined. In order to pivot on it later if necessary, I identified the file creation time thanks to Sysmon Event ID 11: 2023-12-14 15:07:52.

**Q2. DC01: What's the path that was added to the exclusions of Windows Defender?**

There's at least two ways to learn this: 
1. Checking the keys for "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths", or
2. Event ID 5007: "The antimalware platform configuration changed"

| Time Created        | Event Id | Process Id | Computer           | User Id  | Map Description                                | Payload Data1 | Payload Data2                                                                  |
| ------------------- | -------: | ---------: | ------------------ | -------- | ---------------------------------------------- | ------------- | ------------------------------------------------------------------------------ |
| 2023-12-14 15:07:03 |     5007 |       3692 | DC01.NEXTECH.local | S-1-5-18 | The antimalware platform configuration changed | Old Value:    | New Value: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\ = 0x0 |

**Q3. DC01: What’s the IP of the machine that initiated the remote installation of the malicious service?**

- I searched for Event IDs 7045 and 4697: "A service was installed in the system", but it didn't yield any results. This is typically generated when a service is installed, and contains info about the executable path, service name, and account that installed it. It requires the "Security System Extension" audit policy ('auditpol.exe /set /subcategory:"Security SystemExtension" /failure:enable /success:enable') which probably explains its absence. 
- Event ID 4104 (PowerShell script logging) didn't reveal any useful results.
- I used Registry Explorer to examine the keys at "CurrentControlSet\Services" but I didn't spot any that had been recently altered. Perhaps the attacker had deleted them?
- Using the file creation time for 8fe9c39.exe, I filtered on Sysmon Event ID 3: "Network connection" and found a slew of entries just prior:

| Time Created        | Event Id | Process Id | Payload Data2                                               | Payload Data4             | Payload Data6                  |
| ------------------- | -------: | ---------: | ----------------------------------------------------------- | ------------------------- | ------------------------------ |
| 2023-12-14 15:06:10 |        3 |       3556 | RuleName: technique_id=T1021,technique_name=Remote Services | SourceIp: 192.168.170.142 | DestinationIp: 192.168.170.124 |
| 2023-12-14 15:06:12 |        3 |       3556 | RuleName: technique_id=T1021,technique_name=Remote Services | SourceIp: 192.168.170.142 | DestinationIp: 192.168.170.124 |


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


)
