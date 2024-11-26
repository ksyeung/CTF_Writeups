https://aceresponder.com/challenge/volt-typhoon

Scenario: 
>Welcome to the Volt Typhoon challenge! In this challenge, you will encounter a simulated incident that draws inspiration from the Volt Typhoon's infamous tactics. As a member of the incident response team, your mission is to meticulously investigate the breach, piece together the puzzle of the attack, and assess the extent of the damage caused.
>
>Volt Typhoon primarily targets critical infrastructure for espionage purposes. They gain access to target networks by exploiting vulnerabilities in edge devices. Once a foothold is established, they use a variety of living-off-the-land techniques combined with valid credentials to evade traditional detection.
>
>Remember, each decision you make, every clue you discover, and all the evidence you gather will contribute to the overall assessment of the breach. Your ability to connect the dots and draw accurate conclusions will determine your success in this challenge. Good luck!
>
>The events in your SIEM can be found in the following timespan: 21 June 2023 - 22 June 2023.

---

First, I reviewed the CISA advisory for this threat actor: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a and the PDF: https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf 

Some details pulled from the advisory:
>Some of the built-in tools this actor uses are: `wmic`, `ntdsutil`, `netsh`, and `PowerShell`. The advisory provides examples of the actor’s commands along with detection signatures to aid network defenders in hunting for this activity. Many of the behavioral indicators included can also be legitimate system administration commands that appear in benign activity. Care should be taken not to assume that findings are malicious without further investigation or other indications of compromise.

>The actor has used Earthworm and a custom Fast Reverse Proxy (FRP) client with hardcoded C2 callbacks [[T1090](https://attack.mitre.org/versions/v13/techniques/T1090/ "(opens in a new window)")] to ports 8080, 8443, 8043, 8000, and 10443 with various filenames including, but not limited to: cisco_up.exe, cl64.exe, vm3dservice.exe, watchdogd.exe, Win.exe, WmiPreSV.exe, and WmiPrvSE.exe.

>The actor has executed the following command to gather information about local drives [[T1082]](https://attack.mitre.org/versions/v13/techniques/T1082/ "(opens in a new window)")

>`cmd.exe /C "wmic path win32_logicaldisk get caption,filesystem,freespace,size,volumename"`

>The actor may try to exfiltrate the ntds.dit file and the SYSTEM registry hive from Windows domain controllers (DCs) out of the network to perform password cracking


**Q1. Beachhead: What is the IP address of the system the attacker compromised first?**


Before investigating the initial access, I ran a few search queries based on the details in the CISA advisory:

`winlog.event_data.Image: wmic.exe`

| Time                        | event.code | host.name                  | winlog.event_data.User | winlog.event_data.ProcessId | winlog.event_data.ParentProcessId | winlog.event_data.CommandLine | winlog.event_data.ParentCommandLine                                                  |
| --------------------------- | ---------- | -------------------------- | ---------------------- | --------------------------- | --------------------------------- | ----------------------------- | ------------------------------------------------------------------------------------ |
| Jun 21, 2023 @ 17:57:42.909 | 1          | charlie-pc.windomain.local | WINDOMAIN\cmdeploy     | 9940                        | 8140                              | wmic volume list brief        | cmd.exe /Q /c wmic volume list brief 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1 |
| Jun 21, 2023 @ 17:58:03.789 | 1          | charlie-pc.windomain.local | WINDOMAIN\cmdeploy     | 3820                        | 848                               | wmic service brief            | cmd.exe /Q /c wmic service brief 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1     |

It appears an attacker is enumerating information about storage volumes and Windows services running on the system using WMIC, and redirecting the results to a file on the administrative share on the local machine.

`event.code: 1 AND winlog.event_data.Image: cmd.exe`

Excerpt from the search below (unfortunately, I couldn't copy the whole thing here due to a lack of exporting functionality in AceResponder's Elastic frontend. I relied on ChatGPT to format the markdown table from a copy of the table in the browser, and it wouldn't produce a complete table despite several attempts):

| Time                        | Host Name                  | User               | Command Line                                                                                                                                                                                                                     | Parent Command Line                   |
| --------------------------- | -------------------------- | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| Jun 21, 2023 @ 17:54:39.142 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | cmd.exe /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1                                                                                                                                                               | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:54:40.356 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | cmd.exe /Q /c cd  1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1                                                                                                                                                                | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:55:15.249 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | **cmd.exe /Q /c ifconfig /all 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1**                                                                                                                                                  | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:55:20.127 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | **cmd.exe /Q /c ipconfig /all 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1**                                                                                                                                                  | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:55:29.243 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | **cmd.exe /Q /c net localgroup administrators 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1**                                                                                                                                  | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:55:33.504 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | **cmd.exe /Q /c net localgroup 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1**                                                                                                                                                 | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:55:50.293 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | **cmd.exe /Q /c net group /dom 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1**                                                                                                                                                 | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:56:06.726 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | **cmd.exe /Q /c net group "Enterprise Admins" /dom 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1**                                                                                                                             | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:56:15.068 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | **cmd.exe /Q /c curl www.ip-api.com 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1**                                                                                                                                            | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:56:18.752 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | **cmd.exe /Q /c arp -a 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1**                                                                                                                                                         | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:56:42.501 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | **cmd.exe /Q /c netsh interface firewall show all 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1**                                                                                                                              | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:56:58.283 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | **cmd.exe /Q /c netstat -ano 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1**                                                                                                                                                   | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:57:10.032 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | **cmd.exe /Q /c reg query hklm\software 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1**                                                                                                                                        | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:57:20.462 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | **cmd.exe /Q /c systeminfo 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1**                                                                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:57:33.738 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | **cmd.exe /Q /c tasklist /v 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1**                                                                                                                                                    | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:57:42.802 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | cmd.exe /Q /c wmic volume list brief 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1                                                                                                                                             | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:58:03.694 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | cmd.exe /Q /c wmic service brief 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1                                                                                                                                                 | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:58:29.251 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | **cmd.exe /Q /c dir C:\Users\charlie\.ssh\known_hosts 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1**                                                                                                                          | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:58:37.709 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | **cmd.exe /Q /c dir C:\Users\charlie\.ssh 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1**                                                                                                                                      | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:58:58.685 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | cmd.exe /Q /c reg query hkcu\software\SimonTatham\putty\session 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1                                                                                                                  | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 17:59:11.772 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | **cmd.exe /Q /c reg query hkcu\software\SimonTatham\putty\ 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1**                                                                                                                     | C:\Windows\system32\wbem\wmiprvse.exe |
| Jun 21, 2023 @ 18:17:45.448 | charlie-pc.windomain.local | WINDOMAIN\cmdeploy | **cmd.exe /Q /c powershell -exec bypass -W hidden -nop -E cnVuZGxsMzIuZXhlIEM6XFdpbmRvd3NcU3lzdGVtMzJcY29tc3Zjcy5kbGwsIE1pbmlEdW1wIDYzMiBDOlxXaW5kb3dzXFRlbXBcdXBkYXRlLmxvZw== 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1** | C:\Windows\system32\wbem\wmiprvse.exe |

I've bolded a few of the interesting cells. The user "WINDOMAIN\cmdeploy" has probably been compromised.

Next, I ran the query `vssadmin`:

| Time                        | Host Name          | User            | Command Line                   | Parent Command Line           |
| --------------------------- | ------------------ | --------------- | ------------------------------ | ----------------------------- |
| Jun 21, 2023 @ 19:30:02.501 | dc.windomain.local | -               | vssadmin create shadow /for=C: | -                             |
| Jun 21, 2023 @ 19:30:02.519 | dc.windomain.local | WINDOMAIN\alice | vssadmin create shadow /for=C: | "C:\Windows\system32\cmd.exe" |


The user "WINDOMAIN\alice" has likely been compromised as well. This command creates a snapshot of the volume, which is useful for exfiltration of the filesystem and files that may normally be locked even to the SYSTEM user, such as the SECURITY and SYSTEM hives, SAM, pagefile.sys, hiberfil.sys, ntds.dit, and others.

Moving on, I started looking for failed logins: `event.code: 4625`

Here's a snippet of the output:

| Time                        | Host Name          | Target User Name | Sub Status | winlog.event_data.IpAddress |
| --------------------------- | ------------------ | ---------------- | ---------- | --------------------------- |
| Jun 21, 2023 @ 17:02:19.566 | dc.windomain.local | alva_brewer      | 0xc000006a | 192.168.56.105              |
| Jun 21, 2023 @ 17:02:19.577 | dc.windomain.local | tricia_irwin     | 0xc000006a | 192.168.56.105              |
| Jun 21, 2023 @ 17:02:19.587 | dc.windomain.local | amalia_santiago  | 0xc000006a | 192.168.56.105              |
| Jun 21, 2023 @ 17:02:19.599 | dc.windomain.local | ericka_wright    | 0xc000006a | 192.168.56.105              |

It goes on like that for a while (6,478 hits total). The "Sub Status" code from Event ID 4625 provides detailed information about login failure. In this case, 0xc000006a notes that the username is correct but the password is wrong. Interestingly, when I dig into this field further, all but two results from the query have this code. The two results for username "ethan_potter" have the code 0xc000006e, which indicates the specified user does not exist.

Additionally, I want to check how many times they sprayed each account, and the interval they used. I started with a spot check: `event.code: 4625 AND winlog.event_data.TargetUserName: alva_brewer` which produced three rows.

I also created a visualisation with a data table (Y-axis Aggregation: Count, X-axis Aggregation: Terms with field winlog.event_data.TargetUserName.keyword and Order by Count). Here's a truncated version:

| TargetUserName   | Count |
| ---------------- | ----- |
| edna_vazquez     | 3     |
| edward_berry     | 3     |
| edwardo_higgins  | 3     |
| edwin_crane      | 3     |
| efrain_fernandez | 3     |
| efren_dennis     | 3     |
| efren_moss       | 3     |
| efren_sanford    | 3     |
| elaine_ewing     | 3     |
| elba_kirby       | 3     |

Looking over the entire data set, I also noticed that around 500 users had two results, and shelia_henderson had four. This latter result has a simple explanation (the user was sprayed three times and failed to sign in independently on her own as well), the former not so much. 

Anyway, we've identified password spraying against hostname dc.windomain.local on Jun 21, 2023 between 17:02:19.566 and 18:40:25.096.

Given the same IP address, I reviewed successful logins:

`event.code: 4624 and winlog.event_data.IpAddress: 192.168.56.105`

Near the time range above, there is a successful login for username svc-fasso, then cmdeploy.

**Q2. Account Compromise: Which account did the attacker compromise first?**

See my response above.

**Q3. Lateral Movement: Was the attacker able to move laterally with svc-fsso?**

No. An exhaustive review of the account activity with the query `svc-fasso` didn't review any successful attempts at lateral movement.


**Q4. Initial Discovery: What discovery technique did the attacker perform shortly after compromising 192.168.56.105?


T1046 - Network Service Discovery: the attacker uses "ipconfig" to map the target network, "netstat -ano" to identify active network connections and processes as well as potential targets.


**Q5. Credential Access: How did the attacker gain access to additional credentials after performing network scanning?**


They performed password spraying.


**Q6. Credential Access: How many times did the attacker perform password spraying? Each iteration where the attacker attempts some or all of their user list is considered a round.**


We learned this while working on question one: see above.


**Q7. Password Spring Rounds: Which account did the attacker compromise as a result of password spraying?**


See the discussion for question one.


**Q8. cmdeploy Lateral Movement: Which system did the attacker move to after compromising cmdeploy?**


One of the things we noted happening in question one was extensive suspicious activity on the host charlie-pc.


**Q9. Lateral Movement Rationale: What is most likely the reason the attacker moved to charlie-pc?**

cmdeploy is a Local Administrator on charlie-pc.


**Q10. Public IP: Which domain did the attacker contact to get the internet-facing IP for charlie-pc?Answer with the domain and TLD (e.g., google.com)**


We can see this in the discussion for question one (the curl command).


**Q11. Group Enumeration: Which privileged domain group did the attacker enumerate? Answer with the group name and no domain information (e.g. `SQL Admins`)**


We can see this in the discussion for question one as well.


**Q12. Registry Creds: The attacker attempted to compromise SSH credentials in the registry. Which key did the attacker try to access? Answer with the full key as typed by the attacker (e.g. `hklm\software\OpenSSH\Agent\`)**


See the results for question one.


**Q13. Lateral Movement Procedure: Which tool or procedure did the attacker use to move laterally to charlie-pc?**

The Ace Responder lesson Lateral Movement was very helpful in learning to identify the artifacts behind this. Given this command line from a child process of wmiprvse.exe: `cmd.exe /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1687395273.1074176 2>&1` we immediately recognise it as artifacts from impacket's wmiexec.py creation of a semi-interactive shell. Here's a direct quote from the lesson:

>The basic idea is:
>1. Establish a connection over SMB and create a file on the remote machine.
>2. Execute a command and redirect stdout/sterrr to the new file.
>3. Read the file over SMB.
>4. Repeat steps 2 and 3 as needed.
>This gives the attacker a nice command prompt similar to the command prompt you would get by running cmd.exe in an interactive session.
>
$ wmiexec.py bob-pc/bob@192.168.58.166
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>
>
>This is another practice that’s not stealthy, but still used depending on the environment. There are a number of ways an attacker could obfuscate the command line and evade traditional detections. But, it does follow the same pattern as many of the other lateral movement techniques: upload file to a share, run command.

**Q14. Tool Transfer: What file did the attacker upload to charlie-pc? Answer with the file name (e.g., `malware.bat`)**


I used the following query to look for file creation events involving executables after refining the initial query to exclude prefetch files:

`agent.name: "charlie-pc" AND winlog.event_id: 11 AND winlog.event_data.TargetFilename.keyword:*.exe AND NOT winlog.event_data.TargetFilename.keyword:*.pf`


| Time                       | host.name                   | winlog.event_data.TargetFilename |
|----------------------------|-----------------------------|-----------------------------------|
| Jun 21, 2023 @ 18:36:02.323 | charlie-pc.windomain.local  | C:\Windows\Temp\7z.exe           |
| Jun 21, 2023 @ 18:10:55.407 | charlie-pc.windomain.local  | C:\Windows\Temp\update.exe       |

**Q15. lsass Dump: What _executable_ did the attacker use to dump lsass? Answer with the executable name (e.g., `mimikatz.exe`)**


We saw this earlier during the analysis in question one.  The base64-encoded snippet here `powershell -exec bypass -W hidden -nop -E cnVuZGxsMzIuZXhlIEM6XFdpbmRvd3NcU3lzdGVtMzJcY29tc3Zjcy5kbGwsIE1pbmlEdW1wIDYzMiBDOlxXaW5kb3dzXFRlbXBcdXBkYXRlLmxvZw==` decodes to `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 632 C:\Windows\Temp\update.log`


**Q16. Data Staged: What is the name of the file the attacker exfiltrated the credential data in? Answer with the file name (e.g., `DMBC2C61.rar`)**


Given that 7z.exe is on the system, I ran a query to look for a few of the most common file extensions for compressed files: `agent.name: "charlie-pc" AND winlog.event_id: 11 AND (winlog.event_data.TargetFilename.keyword: (*.zip OR *.rar OR *.z))`

**Q17. Tool Transfer 2: What is the name of the file the attacker uploaded to alice-pc? Answer with the file name (e.g., `malware.bat`)**

I started by hunting for file creation events, and progressively added additional file extension exclusions until the result was somewhat easier to review by eye (60 hits): `agent.name: "alice-pc" AND winlog.event_id: 11  and @timestamp > "2023-06-21T17:54:39.142Z" AND NOT winlog.event_data.TargetFilename.keyword: (*winlogbeat.yml.new OR *.pf* OR *tmp OR *TMP OR *.etl OR *.txt OR *Group Policy* OR *.checkpoint OR *.db OR *.ini OR *.xml OR *.dat OR *.ft OR *.inf OR *.ftl OR *.pol)` In retrospect, I could have just found the answer I was looking for by using common executable file extensions like \*.exe, \*.bat, \*.ps1, etc.


**Q18. DC Lateral Movement: Which account did the attacker use to access the domain controller? Answer with the account name without any domain information (e.g., alva_brewer)**

Checking Event ID 4624 for RDP connections (Type 10 is an RDP connection, and Type 7 is a reconnect/unlock):

`event.code: 4624 AND host.name: dc.windomain.local AND winlog.event_data.LogonType: (7 or 10)`

| Time                        | winlog.event_data.TargetUserName | winlog.event_data.IpAddress | winlog.event_data.TargetLogonId |
| --------------------------- | -------------------------------- | --------------------------- | ------------------------------- |
| Jun 21, 2023 @ 19:22:55.142 | alice                            | 192.168.56.105              | 0xf997f3                        |
| Jun 21, 2023 @ 19:22:55.142 | alice                            | 192.168.56.105              | 0xf9766f                        |

**Q19. DC Lateral Movement Procedure: Which tool or procedure did the attacker use to move laterally to the domain controller?**


See above.


**Q20. NTDS: What technique did the attacker use to compromise hashes in the AD domain database?**


Volume Shadow Copy: we know this from the advisory and the subsequent confirmation in the discussion from question one.


**Q21. Domain Hashes Staged: What path/file did the attacker stage the file extracted from the volume shadow copy? Answer with the full path and file name (e.g., `C:\Windows\Temp\windomain.dit`)**


We know from running the query `vssadmin` earlier that the CurrentDirectory was "C:\PerfLogs\". We also infer that the filename is "ntds.dit".
