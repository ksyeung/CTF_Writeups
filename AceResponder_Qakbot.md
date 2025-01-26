https://aceresponder.com/challenge/qakbot

Scenario:
>Welcome to the Qakbot challenge! In this challenge, you will step into the shoes of a seasoned threat hunter and incident responder. You have been hired by the renowned company SolidLabs to assist with investigating a string of Qakbot attacks.
>
>SolidLabs, a global leader in technological innovation, has been grappling with an increasing number of attacks that have put their valuable assets and confidential information at risk. Their network defenses have detected a recurring pattern in these attacks, pointing towards the notorious Qakbot malware as the primary culprit.
>
>Qakbot, also known as Qbot is a persistent strain of malware that has plagued organizations worldwide. It is notorious for its ability to stealthily infiltrate networks, establish a persistent presence, and exfiltrate sensitive data. SolidLabs does not possess the capabilities or expertise to investigate effectively and will rely on you to quickly and accurately scope the intrusion. You will also be asked to create detections that will uncover future attacks of the same nature.

**Q1. Initial Alert: You receive a high severity alert that states the following:**

```
WMI lateral movement detected on win10-YDF5qFA at 2023-05-31T08:27:18.604Z
```

**Is this description accurate?**

(No)

**Q2. Malicious DLL: What is the name of the malicious DLL executed in the aforementioned event?**

densitometric.dat

**Q3. Defense Evasion. Although one of our detections _did_ identify the suspicious parent/child relationship, the attacker attempted to bypass this class of detection. In addition to using rundll32 to proxy execution (T1218), which MITRE ATT&CK® technique did the attacker use?**

**Note: This defense evasion technique is in addition to T1218 - System Binary Proxy Execution**

T1202 - Indirect Command Execution

**Q4. Delivery: How did the attacker deliver this payload to the host?**

Phishing

**Q5. WScript.exe Detection: Assuming the execution of Javascript files is uncommon in the environment, write a detection for WScript.exe executing Javascript files.**

```
event.code:4688 AND winlog.event_data.NewProcessName: *wscript* AND winlog.event_data.CommandLine.keyword: *.js*
```

**Q6. Compressed: Which file directly produced document_F392_Jun_2.js on win10-YDF5qFA?**

Building on what I learned in the previous question, I crafted the following query. I excluded a keyword in order to reduce noise:

```
winlog.event_data.CommandLine: *WScript.exe* AND NOT *bginfo*
```

| Time                       | Hostname          | Parent Process Name                | Command Line                                                                                                   |
|----------------------------|-------------------|-------------------------------------|----------------------------------------------------------------------------------------------------------------|
| Jun 2, 2023 @ 02:22:53.511 | win10-Z6ySIF9     | C:\Program Files\WinRAR\WinRAR.exe | `"C:\Windows\System32\WScript.exe" "C:\Users\jjames\AppData\Local\Temp\Rar$DIa5324.33331\document_F720_Jun_2.js"` |
| Jun 2, 2023 @ 01:59:55.257 | win10-iqHqRMF     | C:\Program Files\WinRAR\WinRAR.exe | `"C:\Windows\System32\WScript.exe" "C:\Users\lsimmons\AppData\Local\Temp\Rar$DIa2748.16637\document_D965_Jun_2.js"` |
| Jun 2, 2023 @ 01:59:55.189 | win10-iqHqRMF     | C:\Program Files\WinRAR\WinRAR.exe | `"C:\Windows\System32\WScript.exe" "C:\Users\lsimmons\AppData\Local\Temp\Rar$DIa2748.9863\document_D965_Jun_2.js"` |
| Jun 2, 2023 @ 00:35:31.773 | win10-mOhW0R5     | C:\Program Files\WinRAR\WinRAR.exe | `"C:\Windows\System32\WScript.exe" "C:\Users\sfletcher\AppData\Local\Temp\Rar$ASp12.7821\document_F392_Jun_2.js"` |
| May 31, 2023 @ 02:11:41.739| win10-KxaRToG     | C:\Program Files\WinRAR\WinRAR.exe | `"C:\Windows\System32\WScript.exe" "C:\Users\mengland\AppData\Local\Temp\Rar$t420.1822\document_F392_Jun_2.js"` |
| May 31, 2023 @ 01:46:53.169| win10-OMZKwGs     | C:\Program Files\WinRAR\WinRAR.exe | `"C:\Windows\System32\WScript.exe" "C:\Users\kmasssey\AppData\Local\Temp\Rar$DIa5324.33331\document_H111_Jun_2.js"` |
| May 31, 2023 @ 01:26:50.943| win10-YDF5qFA     | C:\Program Files\WinRAR\WinRAR.exe | `"C:\Windows\System32\WScript.exe" "C:\Users\tutanner\AppData\Local\Temp\Rar$DIa4332.2743\document_F392_Jun_2.js"` |
| May 31, 2023 @ 00:56:49.139| win10-tnU2oOt     | C:\Program Files\WinRAR\WinRAR.exe | `"C:\Windows\System32\WScript.exe" "C:\Users\xcharles\AppData\Local\Temp\Rar$DIa5324.33331\document_R502_May23.js"` |
| May 31, 2023 @ 00:28:51.970| win10-zBIRDVX     | C:\Program Files\WinRAR\WinRAR.exe | `"C:\Windows\System32\WScript.exe" "C:\Users\rvalenzuela\AppData\Local\Temp\Rar$Arr08.8212\document_F392_Jun_2.js"` |
| May 30, 2023 @ 01:27:10.139| win10-fOzRZHq     | C:\Program Files\WinRAR\WinRAR.exe | `"C:\Windows\System32\WScript.exe" "C:\Users\uwilkerson\AppData\Local\Temp\Rar$DIa2782.11824\NDA_B976_May_10.wsf"` |
| May 30, 2023 @ 01:00:48.872| win10-d1tHxTH     | C:\Program Files\WinRAR\WinRAR.exe | `"C:\Windows\System32\WScript.exe" "C:\Users\wcrosby\AppData\Local\Temp\Rar$t31.1549\document_F392_Jun_2.js"`     |
| May 29, 2023 @ 00:45:34.431| win10-SuAWMT2     | C:\Program Files\WinRAR\WinRAR.exe | `"C:\Windows\System32\WScript.exe" "C:\Users\bstokes\AppData\Local\Temp\Rar$DIa5324.33331\document_H111_Jun_2.js"` |

**Q7. Attachment: Which file type did the attacker use to deliver the .zip in the original phishing email to utanner?**

We know this user's hostname: "win10-YDF5qFA", so this is quite straightforward:

```
agent.hostname: "win10-YDF5qFA" AND  winlog.event_data.CommandLine: *zip*
```

Also, I'm curious how the other users are impacted too, so I run:

```
 winlog.event_data.CommandLine: *zip*
```

We find some interesting domains, plus the use of "browser_broker.exe":

| Time                        | Hostname      | Command Line                                                                                                                                                            |
| --------------------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Jun 2, 2023 @ 02:22:53.503  | win10-Z6ySIF9 | `"C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\jjames\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\TempState\Downloads\document_F720_Jun_2 (1).zip"`   |
| Jun 2, 2023 @ 02:20:41.744  | win10-Z6ySIF9 | `"C:\Windows\System32\browser_broker.exe" https://motionindustrials.com/pie/`                                                                                           |
| Jun 2, 2023 @ 02:20:41.699  | win10-Z6ySIF9 | `"C:\Windows\System32\browser_broker.exe" https://leebpetz.com/eeb/`                                                                                                    |
| Jun 2, 2023 @ 01:59:55.189  | win10-iqHqRMF | `"C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\lsimmons\Downloads\proposal.zip"`                                                                                       |
| Jun 2, 2023 @ 00:35:31.761  | win10-mOhW0R5 | `"C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\sfletcher\Downloads\document_A155_May_2 (1).zip"`                                                                       |
| Jun 1, 2023 @ 01:24:59.035  | win10-5HSPsJo | `"C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\qglenn\Downloads\proposal.zip"`                                                                                         |
| May 31, 2023 @ 02:11:41.727 | win10-KxaRToG | `"C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\mengland\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\TempState\Downloads\document_H111_Jun_2 (1).zip"` |
| May 31, 2023 @ 01:46:53.156 | win10-OMZKwGs | `"C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\kmasssey\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\TempState\Downloads\document_H111_Jun_2 (1).zip"` |
| May 31, 2023 @ 01:44:01.485 | win10-OMZKwGs | `"C:\Windows\System32\browser_broker.exe" https://motionindustrials.com/pie/`                                                                                           |
| May 31, 2023 @ 01:44:01.271 | win10-OMZKwGs | `"C:\Windows\System32\browser_broker.exe" https://leebpetz.com/eeb/`                                                                                                    |
| May 31, 2023 @ 01:26:50.938 | win10-YDF5qFA | `"C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\tutanner\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\TempState\Downloads\document_F392_Jun_2 (1).zip"` |
| May 31, 2023 @ 00:56:49.131 | win10-tnU2oOt | `"C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\xcharles\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\TempState\Downloads\document_R502_May23 (1).zip"` |
| May 31, 2023 @ 00:53:57.371 | win10-tnU2oOt | `"C:\Windows\System32\browser_broker.exe" https://plaza-center.com/een/`                                                                                                |
| May 31, 2023 @ 00:53:57.271 | win10-tnU2oOt | `"C:\Windows\System32\browser_broker.exe" https://newfoundindustries.com/edp/`                                                                                          |
| May 31, 2023 @ 00:28:51.968 | win10-zBIRDVX | `"C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\rvalenzuela\Downloads\document_A253_May_23 (1).zip"`                                                                    |
| May 30, 2023 @ 01:27:10.135 | win10-fOzRZHq | `"C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\uwilkerson\Downloads\topexrzrf (1).zip"`                                                                                |
| May 30, 2023 @ 01:27:10.486 | win10-d1tHxTH | `"C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\wcrosby\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\TempState\Downloads\document_T01_May_27 (1).zip"`  |
| May 29, 2023 @ 00:45:34.435 | win10-SuAWMT2 | `"C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\bstokes\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\TempState\Downloads\document_H111_Jun_2 (1).zip"`  |

**Q8. Undetected: Another similar Qakbot attack was not identified by our detection. What is the name of the script that evaded our efforts?**

incidentally, we learned this in the work for question 6!

**Q9. Successful Attacks: Based on OSINT, you learn that a successful Qakbot attack results in the final dll spawning a sacrificial process. Based on this criteria, how many unique hosts have been compromised?**

```
event.code: 4688 AND winlog.event_data.ParentProcessName: "C:\\Windows\\SysWOW64\\rundll32.exe" 
```

**Q10. Sacrificial Process Detection: Write a detection for rundll32.exe spawning sacrificial processes that returns _all_ successful executions in this scenario.**

See above!

**Q11. Additional Artifacts: The incident on win10-OMZKwGs resulted in additional 4688 artifacts that expose the attacker's infrastructure. Enter one of the exposed domains.**

See the work in the results for question 7.

**Q12. Additional Artifacts 2: Which host also contains 4688 artifacts with these URLs?**

Once again, see the work in the results for question 7.

**Q13. Even More IOCs: Another host contains similar artifacts that expose more attacker infrastructure. Find them and enter one of the domains you identified.**

Take a look at the work for question 7!

**Q14. rundll32.exe .dat: Write a detection for rundll32.exe executing .dat files.**

```
event.code: 4688 AND winlog.event_data.NewProcessName: *rundll32* AND winlog.event_data.CommandLine: (*rundll32* AND *dat*)
```

**Q15. More Strange DLLs: Other than .dat, which extension did the attacker use obfuscate the downloaded .dll files?**

```
event.code: 4688 AND winlog.event_data.CommandLine: rundll32* AND NOT (winlog.event_data.CommandLine: (*.dll* OR *.dat* OR *StateRepositoryDoMaintenanceTasks* OR *SHCreateLocalServerRunDll*))
```

**Q16. Download Mechanism: For the string of attacks where a .png extension was given to the final payload, what native binary did the attacker leverage to download the malicious dlls?**

```
winlog.event_data.CommandLine: *.png*
```

**Q17. Rundll.exe and Obfuscated File Extensions: Write a detection for Rundll32.exe executing dlls with file extensions other than .dll. Tip: You can use regexes with Lucene (e.g. winlog.event_data.CommandLine://)**

```
winlog.event_data.NewProcessName: *rundll32 AND NOT winlog.event_data.CommandLine.keyword: *.dll*
```
