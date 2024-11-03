https://cyberdefenders.org/blueteam-ctf-challenges/t1110003

This is a write-up for the threat hunting lab named T1110-003. It has a difficulty of Easy. It's available with Splunk and Elastic, and I elected to use Elastic.

Scenario:

>Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. 'Password01'), or a small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords. [[1]](http://www.blackhillsinfosec.com/?p=4645)
Typically, management services over commonly used ports are used when password spraying. Commonly targeted services include the following:
>- Telnet (23/TCP)
>- FTP (21/TCP)
>- NetBIOS / SMB / Samba (139/TCP & 445/TCP)
>- LDAP (389/TCP)
>- Kerberos (88/TCP)
>- RDP / Terminal Services (3389/TCP)
>- HTTP/HTTP Management Services (80/TCP & 443/TCP)
>- MSSQL (1433/TCP)
>- Oracle (1521/TCP)
>- MySQL (3306/TCP)
>- VNC (5900/TCP)
>In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.[[2]](https://www.us-cert.gov/ncas/alerts/TA18-086A)
In default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" event ID 4625.

---

**Q1: Who was the last logged-in user?**

```
"winlog.event_id: 4624" 
```
I used the query above, and then sorted @timestamp from New to Old:

![image](https://github.com/user-attachments/assets/f09bf328-fc82-4d95-b73d-3d03eafb731a)


**Q2: What is the logon type of the failed logons?**

```
winlog.event_id: 4625
```

Using the query above, I looked at the frequency of values:

![image](https://github.com/user-attachments/assets/97fecce0-6039-4952-89c0-953eebdc5fa5)

I also reviewed the source IP address, workstation name, and logon process:

![image](https://github.com/user-attachments/assets/0580e6bd-d279-439a-b891-5a3cae1b0114)


![image](https://github.com/user-attachments/assets/0fb458a0-a5ec-460d-a644-0561a65f1bd9)


![image](https://github.com/user-attachments/assets/64b71f4d-6ede-43fa-af0d-2c2fb2a6658e)


**Q3: What is the protocol the attacker tried to bruteforce?**

```
winlog.event_id: 5140
```

Since we know the logon type, I first checked for evidence of SMB activity, and I didn't find any results (event ID 5140 indicates a network share object was accessed.)

```
winlog.event_id: 91
```

Then, I moved on to WinRM (this event ID indicates a WinRM connection was received) which also didn't produce results. 

```
winlog.event_id: 142
```

Continuing on the WinRM search, I found two results with the event provider Microsoft-Windows-RemoteDesktopServices-RdpCoreTS (event ID 142 indicates an RDP connection was attempted, and can include the client's IP addr, server hostname or IP addr, and user credentials). 

The event's message read "The server accepted a new TCP connection from client 192.168.1.60:47244" and I attempted to use the "winlog.event_data.ClientIP" field to see if all the attempts originate from 192.168.1.60. Unfortunately, its difficult to tell as each value is unique due to different ports being used. I reviewed five events and they have the same IP address.

```
winlog.event_id: 131
```

In any case, due to the 143 hits for event ID 131, I think its safe to say we know which protocol was used for the brute force attack.

**Q4: How many users did the attacker succeed in getting their accounts?**

I put together the information we have regarding the attacker (their hostname and IP address):

```
winlog.event_id: 4624 and winlog.event_data.WorkstationName: kali and winlog.event_data.IpAddress: 192.168.1.60
```

After adding the column winlog.event_data.TargetUsername, I see this:

| @timestamp                 | winlog.event_data.TargetUserName |
| -------------------------- | -------------------------------- |
| Aug 1, 2022 @ 16:46:09.987 | Administrator                    |
| Aug 1, 2022 @ 16:34:57.020 | Administrator                    |
| Aug 1, 2022 @ 16:33:12.899 | harrashusky                      |
| Aug 1, 2022 @ 16:33:03.076 | turtledoverecall                 |
| Aug 1, 2022 @ 16:32:53.261 | infestedmerchant                 |
| Aug 1, 2022 @ 16:32:43.564 | interjectaerobics                |
| Aug 1, 2022 @ 16:32:33.587 | squadronwar                      |

To compare against the RDP event logs, I also ran:
```
winlog.event_id: 1149
```

After adding the column "winlog.user_data.Param1", I get the same results:

| @timestamp                 | winlog.user_data.Param1 |
| -------------------------- | ----------------------- |
| Aug 1, 2022 @ 16:46        | administrator           |
| Aug 1, 2022 @ 16:34:57.526 | administrator           |
| Aug 1, 2022 @ 16:33:13.409 | harrashusky             |
| Aug 1, 2022 @ 16:33:03.592 | turtledoverecall        |
| Aug 1, 2022 @ 16:32:53.768 | infestedmerchant        |
| Aug 1, 2022 @ 16:32:44.081 | interjectaerobics       |
| Aug 1, 2022 @ 16:32:34.140 | squadronwar             |

**Q5: According to Microsoft. What is the description of the "Sub Status" code for event id 4625?**

The wording of the question is a little vague here. I re-ran the query from Q2 and looked at the listed Sub Status in the event: "0xC000006A"

Next, I reviewed the Microsoft Learn documentation here: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625 This produced the answer expected by the creator.

**Q6: How long did the bruteforce last? MM:SS**

Examining the query results from Q4, it appears that the last successful automated sign-in was the second row (and the first row was the attacker manually signing in). I made a note of the time: Aug 1, 2022 @ 16:34:57.020

Then I followed up by modifying the query to look for event ID 4625, and sorting the @timestamp column by Old to New.

```
winlog.event_id: 4625 and winlog.event_data.WorkstationName: kali and winlog.event_data.IpAddress: 192.168.1.60
```

The first timestamp was Aug 1, 2022 @ 16:29:09.460. The delta between the two timestamps is 05:47.560. My first attempt to answer failed as I didn't round up.

**Q7: After How long did the attacker login to the machine again? MM:SS**

This was straightforward, using the timestamps in the results for my query in Q4.

**Q8: What is the name of the policy used to lock the account after a certain number of failed login attempts?**

This looks like another question that could be answered by Microsoft Learn. Using a search engine, I ran the query "microsoft learn account lock policy" to find the answer.
