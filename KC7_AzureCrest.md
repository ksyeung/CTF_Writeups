You can find this Azure Data Explorer (ADX) challenge by the KC7 Foundation at https://kc7cyber.com/challenges/184

## Question 1 

The email from Roy Trenneman reads (edited for brevity) --


Here’s the skinny: While I was out jet-skiing on my bonus-fueled vacation 🏝️💸, our system snagged something fishy—something health related. Couldn’t tell you more because, really, who remembers these things on a jet ski?


Now, I know you’re flying solo in the SOC today, but I’ve got unshakeable faith in the magic you’re about to work. 😎 We got an alert about a quarantined file.


Your mission, should you choose to accept it (and you should, because I’m out of office 🌴):

	1.	Dive into our alert systems and track down this mysterious health file. 🔍
	2.	Assess the threat level—remember, our systems are tougher than a two-dollar steak, so no pressure. 🦾🍽️
	3.	Fill out the enclosed super-secret-agent report template and ping it over to me. (Okay, it’s just a standard form, but let’s keep things interesting. 🕶️📝)

What is the name of that file?

---
First, I start reviewing the tables available to us with the following query, beginning with the Emails table (note: we won't be completing the report template as it isn't explicitly required for this KC7 challenge):

```
Emails
| take 10
```

(Results truncated for brevity):

| Timestamp           | Sender                  | Reply To        | Recipient                   | Subject                                                                                              | Verdict | Link                                                                                                                                        |
|---------------------|-----------------------------------|-----------------------------------|--------------------------------------|------------------------------------------------------------------------------------------------------|---------|----------------------------------------------------------------------------------------------------------|
| 2024-03-01T06:25:27Z | dinagreeno@gmail.com              | dinagreeno@gmail.com              | michel_lowe@azurecresthospital.med   | [EXTERNAL] RE: Pediatrics medical particularly the it ensure and patient we here                      | CLEAN   | http://QTBH3LF6VY.cloudfront.net                                                                         |
| 2024-03-01T06:25:27Z | dinagreeno@gmail.com              | dinagreeno@gmail.com              | marquetta_hornyak@azurecresthospital.med | [EXTERNAL] RE: Pediatrics medical particularly the it ensure and patient we here                      | CLEAN   | http://QTBH3LF6VY.cloudfront.net                                                                         |
| 2024-03-01T07:46:35Z | roy_trenneman@azurecresthospital.med | roy_trenneman@azurecresthospital.med | scott_cunningham@azurecresthospital.med | Incredible oncology to care of efforts treatment successfully the and                                |         | http://huochaipro.com/public/share/share/search/login                                                     |
| 2024-03-01T07:50:46Z | ellen_duke@emergencycarepartners.com | ellen_duke@emergencycarepartners.com | eunice_birks@azurecresthospital.med | [EXTERNAL] Our specialists and our staff medications information always rooms to                     | CLEAN   | http://testzlektury.pl/modules/share/public?search=properties?type=cashew?search=throws?tracking=dome?user=compulsory?search=properties |
| 2024-03-01T07:57:24Z | greg_chui@healthrecordsystems.tech | greg_chui@healthrecordsystems.tech | christina_tate@azurecresthospital.med | [EXTERNAL] Workshops and institution all and patient educational and encourage operations             | CLEAN   | https://en.wikipedia.org/wiki/Chicken%20with%20Plums                                                     |
| 2024-03-01T08:21:21Z | tracie_houk@emergencycarepartners.com | tracie_houk@emergencycarepartners.com | john_walker@azurecresthospital.med | [EXTERNAL] FW: Is environment community and and and data attack care plans                           | CLEAN   | https://umarniz.com/images/immunocompromised.docx                                                        |

My primary takeaway is that email links are extracted from the body of the message and included in this table. Links to files are also seemingly represented here (see 'https://umarniz.com/images/immunocompromised.docx', which would probably appear as 'immunocompromised.docx' on disk if downloaded).

Additionally, there's a system that scans emails and returns 'CLEAN', '' (not scanned yet, perhaps?), 'BLOCKED', or 'SUSPICIOUS'. I learned the latter two values by expanding my search with 'take 20'.

Moving on, I review the SecurityAlerts table, as the email from Roy indicates a quarantined file that is 'something health related'. Here's what it looks like:

```
SecurityAlerts
| take 10
```
(Results truncated):
| Timestamp           | Alert Type | Severity | Description                                                                                                                                                                                                                                                                                                         | Indicators                                                                                                                                                                          |
|---------------------|------------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 2024-03-01T10:19:54Z | HOST       | high     | A suspicious file was detected on host W3JF-DESKTOP. Filename: quickassist.exe.mui. Sha256: ab91d264a83aeeb9427000f0b1cbf94b7dbe842041c509acbb0c066ec5eacdd7                                                                                                                  | [{'hostname': 'W3JF-DESKTOP', 'sha256': 'ab91d264a83aeeb9427000f0b1cbf94b7dbe842041c509acbb0c066ec5eacdd7', 'filename': 'quickassist.exe.mui'}]                                      |
| 2024-03-01T14:38:07Z | HOST       | high     | A suspicious file was detected on host XKUV-MACHINE. Filename: BitLockerWizardElev.exe.mui. Sha256: a4feae34af98a681a8d2ced8e0030e89c0c3ad17a8c463aa143317deb59f8d9e                                                                                                        | [{'hostname': 'XKUV-MACHINE', 'sha256': 'a4feae34af98a681a8d2ced8e0030e89c0c3ad17a8c463aa143317deb59f8d9e', 'filename': 'BitLockerWizardElev.exe.mui'}]                              |
| 2024-03-01T14:48:49Z | HOST       | high     | A suspicious file was detected on host 6OEJ-MACHINE. Filename: SystemPropertiesPerformance.exe. Sha256: b266318d45a4245556a2e39b763f2f11eca780969105f6f103e53dd0a492bb30                                                                                                   | [{'hostname': '6OEJ-MACHINE', 'sha256': 'b266318d45a4245556a2e39b763f2f11eca780969105f6f103e53dd0a492bb30', 'filename': 'SystemPropertiesPerformance.exe'}]                          |

Okay, I understand the layout. Let's try to find this 'health related', quarantined file:

```
SecurityAlerts
| where description contains 'health'
```

| Timestamp           | Alert Type | Severity | Description                                                                                                                  | Indicators                                                                                                                                                                              |
|---------------------|------------|----------|------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 2024-03-14T10:39:26Z | HOST       | high     | A suspicious file was quarantined on host ZQHM-LAPTOP: New_Healthcare_Protocols.docm                                          | [{'hostname': 'ZQHM-LAPTOP', 'filename': 'New_Healthcare_Protocols.docm', 'sha256': '9195246412dc64c15e429887cac945bbde13c249d25dad01c7245219d1ac021a'}]                                 |
| 2024-03-25T16:41:08Z | EMAIL      | med      | Employee milowe reported a suspicious email with the subject "[EXTERNAL] 👶 New! Revolutionary Pediatric Healthcare Strategies ✨" | [{'username': 'milowe', 'subject': '[EXTERNAL] 👶 New! Revolutionary Pediatric Healthcare Strategies ✨'}]                                                                                 |

The first alert indicates that, on host ZQHM-LAPTOP, a file was quarantined: 'New_Healthcare_Protocols.docm' with the SHA256 file hash '9195246412dc64c15e429887cac945bbde13c249d25dad01c7245219d1ac021a'. The second alert doesn't appear to contain any links.


## Question 2

We have information that this threat actor is using two different filenames to distribute their malware.

What other filename is this threat actor using?

---

My interpretation of the question was that the file has merely been renamed and distributed as-is, so I ran a search for the file hash for 'New_Healthcare_Protocols.docm' in the alerts table:

```
SecurityAlerts
| where description contains '9195246412dc64c15e429887cac945bbde13c249d25dad01c7245219d1ac021a'
```

This didn't have any results. I looked for other Microsoft Word macro-enabled documents ('.docm') like the one that was quarantined:

```
SecurityAlerts
| where description contains '.docm'
```

| Timestamp           | Alert Type | Severity | Description                                                                                   | Indicators                                                                                                                                                                               |
|---------------------|------------|----------|-----------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 2024-03-06T12:13:43Z | HOST       | high     | A suspicious file was quarantined on host ZQHM-LAPTOP: Pediatric_Care_Update.docm              | [{'hostname': 'ZQHM-LAPTOP', 'filename': 'Pediatric_Care_Update.docm', 'sha256': '47c3fa989d3c0ba92f784111ac3a6bd538f4069f93652c7757c46bf8714ebf21'}]                                    |
| 2024-03-14T10:39:26Z | HOST       | high     | A suspicious file was quarantined on host ZQHM-LAPTOP: New_Healthcare_Protocols.docm           | [{'hostname': 'ZQHM-LAPTOP', 'filename': 'New_Healthcare_Protocols.docm', 'sha256': '9195246412dc64c15e429887cac945bbde13c249d25dad01c7245219d1ac021a'}]                                |
| 2024-03-21T11:52:06Z | HOST       | high     | A suspicious file was quarantined on host XBYY-DESKTOP: Pediatric_Care_Update.docm             | [{'hostname': 'XBYY-DESKTOP', 'filename': 'Pediatric_Care_Update.docm', 'sha256': '6ba7d0ea964f268e0fa420f53a0ce24071de33b6b30364a935d37c819086288b'}]                                    |

It seems there's two additional suspicious files named 'Pediatric_Care_Update.docm' with different hashes.

## Question 3

How many of Azure Crest's employees clicked the email link?

---

Given our results in the last query, answering this question seems straightforward:

```
FileCreationEvents
| where filename == 'Pediatric_Care_Update.docm' or filename == 'New_Healthcare_Protocols.docm'
| count
```

Alright, there were a lot of hits here: 38! I think we'll want the 'distinct' operator in case users were targeted by multiple links and clicked more than one. Also, to proceed further with the investigation, we'll generate a list of usernames that clicked the link and downloaded one or both documents:

```
FileCreationEvents
| where filename == 'Pediatric_Care_Update.docm' or filename == 'New_Healthcare_Protocols.docm'
| distinct username
```

(Results truncated):
| Username    |
|-------------|
| thmccloskey |
| sudeloatch  |
| shpella     |
| scthibault  |
| schorwath   |
| rotrenneman |
| mobaez      |
| mifrith     |
| mibauer     |
| mehudgens   |

## Question 4

Which unusual directory path is being used by the attacker to store legitimate remote access executables?

---

Alright, now that we have a list of users that may have downloaded a suspicious document, let's dig in to see who may have actually opened it. First, we'll review the ProcessEvents table to see what it looks like, as I'm expecting that it'll contain process command-line information with arguments:

```
ProcessEvents
| take 3
```

| Timestamp           | Parent Process Name | Parent Process Hash                                          | Process Command Line                                                                                                     | Process Name       | Process Hash                                             | Hostname     | Username   |
|---------------------|---------------------|--------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|--------------------|----------------------------------------------------------|--------------|------------|
| 2024-03-01T06:55:36Z | powershell.exe      | 529ee9d30eef7e331b24e66d68205ab4554b6eb3487193d53ed3a840ca7dde5d | "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=utility --utility-sub-type=asset_store.mojom.AssetStoreService | msedge.exe         | e53f4f2eaa7e619be77ac80563b26efc137901446e36546a66ff2ef31a88ec78 | 4PQX-MACHINE | adpratt    |
| 2024-03-01T06:59:57Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\103.0.1264.77\msedgewebview2.exe" --embedded-browser-webview=1 | msedgewebview2.exe | 1ebd9b29ccdc7248300aaf505d633b2a6b05ccdea2257746b143d25dd35bfc5a | VCPU-DESKTOP | hagoodson  |
| 2024-03-01T07:04:22Z | sc.exe              | 4fe6d9eb8109fb79ff645138de7cff37906867aade589bd68afa503a9ab3cfb2 | C:\Windows\System32\RuntimeBroker.exe -Embedding                                                                          | runtimebroker.exe  | e63331e41714609d8f40356272c94b9096d25257c6b62d3ff56c87ec1aace77d | TVJP-DESKTOP | jedungan   |

Excellent, it has what I'm looking for.

Let's proceed to see who opened these .docm files:

```
ProcessEvents
| where process_commandline contains 'Pediatric_Care_Update.docm' or process_commandline contains 'New_Healthcare_Protocols.docm'
```

(Results truncated):

| Timestamp           | Parent Process Name | Parent Process Hash                                          | Process Command Line                                                             | Process Name  | Process Hash                                             | Hostname      | Username    |
|---------------------|---------------------|--------------------------------------------------------------|----------------------------------------------------------------------------------|---------------|----------------------------------------------------------|---------------|-------------|
| 2024-03-01T11:59:03Z | Explorer.exe        | ebff6e6f1710cb0cbf50082064be8725e9845c5dd6080cdf9ba2cccf6305273d | Explorer.exe "C:\Users\jomarkland\Downloads\New_Healthcare_Protocols.docm"       | Explorer.exe  | 6472564eb576deb4d10f576261015c3a505389c4e1c9ca343c1d935669e30c91 | P3EX-DESKTOP | jomarkland  |
| 2024-03-01T12:06:10Z | Explorer.exe        | b4e971d4dff8b77f4c526832ca39664c2ef2e04c62b421182c6a60d53301d135 | Explorer.exe "C:\Users\mehudgens\Downloads\New_Healthcare_Protocols.docm"        | Explorer.exe  | e596f017f83545d8ebfa82b748dbc6f717da6a0d2f36ea632a843d376c430ab0 | M8D0-MACHINE | mehudgens   |
| 2024-03-01T12:09:46Z | Explorer.exe        | 450fb48e2145ed31395b38966ff758b4a9500e798f9f7dfd8e06819a30933468 | Explorer.exe "C:\Users\gearthur\Downloads\New_Healthcare_Protocols.docm"         | Explorer.exe  | f038359c2e107da0c5694f014462d1bdc2e62b356eee346c6668c82f3bc6b70c | 5QJC-DESKTOP | gearthur    |

Let's make a note of this: username 'mehudgens' on hostname 'M8D0-MACHINE' opened 'New_Healthcare_Protocols.docm' on '2024-03-01T12:06:10Z'. We'll also want to note this query, as we'll later need to remove the infection for these users and determine what else may have happened.

The question notes that the attacker is using an unusual path to store executables. Dropping files onto disk is a known attacker technique, and relatively noisy. To answer the question, let's look at the FileCreationEvents table and see what happens after username 'mehudgens' downloads the document:

```
FileCreationEvents
| where username == 'mehudgens'
| where timestamp > datetime(2024-03-01T12:06:10Z)
```

(Results truncated):
| Timestamp           | Hostname      | Username   | SHA256                                                           | Path                                              | Filename          | Process Name  |
|---------------------|---------------|------------|-------------------------------------------------------------------|---------------------------------------------------|-------------------|---------------|
| 2024-03-01T12:06:11Z | M8D0-MACHINE  | mehudgens  | 1c3ef0407d5714037504c52f7abfa86c081fd7a021b52e2abe8a669f92413252  | C:\ProgramData\Heartburn\heartburn.zip            | heartburn.zip     | 7zip.exe      |
| 2024-03-01T13:25:11Z | M8D0-MACHINE  | mehudgens  | 543b054e23582b4df76a6df1a3632097f1b15fcc2a077a63182619511db481af  | C:\ProgramData\Heartburn\anydesk.exe              | anydesk.exe       | explorer.exe  |
| 2024-03-01T13:48:11Z | M8D0-MACHINE  | mehudgens  | 125e0b8a493ee21056f021f3eeda0dd7dc7c40c83a10fe7121fbfc16a35f77db  | C:\ProgramData\Heartburn\secretsdump.exe          | secretsdump.exe   | explorer.exe  |
| 2024-03-01T14:02:11Z | M8D0-MACHINE  | mehudgens  | 6b5874c67e812e6841f078c66c14df5f5908a4256c899a316411909fbce69208  | C:\ProgramData\Heartburn\putty.exe                | putty.exe         | explorer.exe  |
| 2024-03-09T12:34:38Z | M8D0-MACHINE  | mehudgens  | 369a9d1a4612129106884d0abcd69961d5d687bdba49697a170058cae9547251  | C:\Windows\System32\WaaSMedicAgent.exe            | WaaSMedicAgent.exe| svchost.exe   |

Okay, on the same day that the user opened the suspicious file, four files were created: heartburn.zip, anydesk.exe, secretsdump.exe, and putty.exe. The latter three files are also suspicious: anydesk.exe is associated with the AnyDesk remote desktop application (which may be useful for an attacker to remotely access the infected user's computer), secretsdump.exe is associated with the Impacket toolkit that is popular for penetration testing assessments (and in particular is used to extract secrets and other data from Windows LSA, SAM, NTDS.dit, and more), and putty.exe is useful for connecting to servers over the SSH protocol.

## Question 5

What protocol did the threat actor use to establish a connection with its remote server?

---

We want to dig into ProcessEvents to answer this question, and see what happens after the user downloads the document:

```
ProcessEvents
| where username == "mehudgens"
| where timestamp > datetime(2024-03-01T12:06:10Z)
```

| Timestamp           | Parent Process Name | Parent Process Hash                                          | Process Command Line                                                                                                                                                                             | Process Name      | Process Hash                                             | Hostname      | Username   |
|---------------------|---------------------|--------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------|----------------------------------------------------------|---------------|------------|
| 2024-03-01T12:06:11Z | Explorer.exe        | 65d0e3d2ccb8c1bd717853b1616912c04e4ce9fe0f20c15e14cd62bc09d9519d | C:\ProgramData\Heartburn\heartburn.zip                                                                                                                                                           | heartburn.zip     | ea65c93cb4e8c0240bc9b5b5f3792121dcc22907c235214ba8e1596b31d26bac | M8D0-MACHINE | mehudgens  |
| 2024-03-01T13:16:11Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | cmd.exe /c Expand-Archive -Path C: \ProgramData\heartburn.zip -DestinationPath C:\ProgramData\Heartburn                                                                                           | cmd.exe           | 17ea1d1f4caa683174ee477db757df1d4d3d0f7497eb6af5ddfd77efc5e101b7 | M8D0-MACHINE | mehudgens  |
| 2024-03-01T13:47:48Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | C:\Windows\System32\powershell.exe -Nop -ExecutionPolicy bypass -enc SW52b2tlLVdtaU1ldGhvZCAtQ29tcHV0ZXJOYW1lICRTZXJ2ZXIgLUNsYXNzIENDTV9Tb2Z0d2FyZVVwZGF0ZXNNYW5hZ2VyIC1OYW1lIEluc3RhbGxVcGRhdGVzIC0gQXJndW1lbnRMaXN0ICgsICRQZW5kaW5nVXBkYXRlTGlzdCkgLU5hbWVzcGFjZSByb290WyZjY20mXWNsaWVudHNkayB8IE91dC1OdWxs" | powershell.exe    | 5077a3f88ccbe31da491d3b6607a66499c7d8b0356aaa12e5c13eb419745fde3 | M8D0-MACHINE | mehudgens  |
| 2024-03-01T13:55:11Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | cmd.exe /c C:\ProgramData\Heartburn\putty.exe -ssh 131.92.62.82 -l have_ya_tried -pw turning_it_off_and_on_again                                                                                  | cmd.exe           | 934528d9f8f2b32937aa85254b09dbaeed2d0653f25c56d078643a836674f838 | M8D0-MACHINE | mehudgens  |

I decoded the Base64, and the output was 'Invoke-WmiMethod -ComputerName $Server -Class CCM_SoftwareUpdatesManager -Name InstallUpdates - ArgumentList (, $PendingUpdateList) -Namespace root[&ccm&]clientsdk | Out-Null'. Unfortunately, it doesn't seem to be especially interesting to our investigation: I think its invoking a method on a remote server to install software udpates using Microsoft's System Center Configuration Manager (SCCM). Moving on, we see 7zip (7z.exe) encrypting files with database file extensions.


putty.exe is launched, with the arguments '-ssh 131.92.62.82 -l have_ya_tried -pw turning_it_off_and_on_again'.

## Question 6

What command was executed to extract the files into that directory?

---

We can probably find the answer by reviewing the results of the last query.

## Question 7

Which IP address associated with this threat actor is located in Croatia?

---

I think this will require two actions: a regular expression to extract the IP address from the process_commandline column in ProcessEvents, and geo_info_from_ip_address() (a function for geolocating IP addresses). I reviewed this documentation: https://learn.microsoft.com/en-us/kusto/query/regex and https://learn.microsoft.com/en-us/kusto/query/geo-info-from-ip-address-function, then proceeded with writing the below. I had some issues at first: I forgot to account for columns that don't have an IP address, had to learn how to use the 'extend' operator to add columns to a table, and how to use the 'project' operator to select specific columns while removing all others. This is the result:

```
ProcessEvents
| where process_commandline contains "-ssh"
| extend ip_address = extract(@'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', 0, process_commandline)
| where isnotempty(ip_address)
| extend geo_info = geo_info_from_ip_address(ip_address)
| extend country = tostring(geo_info.country)
| project ip_address, country
| distinct ip_address, country  //
```

(Results truncated):
| IP Address       | Country        |
|------------------|----------------|
| 131.92.62.82     | United States  |
| 16.101.245.182   | United States  |
| 93.142.203.80    | Croatia        |
| 131.190.102.173  | United States  |

## Question 8

What user-agent is associated with the threat actor?

(Just enter the last part of the string xx.xx)

---

We'll probably want to look in any logs where a user agent might be saved. Let's review InboundNetworkEvents to see if this table might have it:

```
InboundNetworkEvents
| take 2
```

| Timestamp           | Method | Source IP      | User Agent                                                                                                             | URL                                                                 | Status Code |
|---------------------|--------|----------------|------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------|-------------|
| 2024-03-01T00:00:00Z | GET    | 115.12.60.150  | Opera/9.63.(Windows CE; lb-LU) Presto/2.9.161 Version/12.00                                                            | https://azurecresthospital.med/search=hospital+network+architecture | 200         |
| 2024-03-01T08:06:42Z | GET    | 185.235.121.197| Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/536.0 (KHTML, like Gecko) FxiOS/18.7x7543.0 Mobile/61N432 Safari/536.0 | http://azurecresthospital.med/about                                 | 200         |

Great! Let's see if our IP address from Croatia appears here:

```
InboundNetworkEvents
| where src_ip == '131.190.102.173'
```

| Timestamp           | Method | Source IP       | User Agent                                                                                       | URL                                                                                      | Status Code |
|---------------------|--------|-----------------|--------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------|-------------|
| 2024-03-01T08:11:22Z | GET    | 131.190.102.173 | Opera/9.63.(Windows CE; lb-LU) Presto/2.9.161 Version/12.00                                       | https://azurecresthospital.med/search=pediatric+department+internal+procedures           | 200         |
| 2024-03-01T11:51:22Z | GET    | 131.190.102.173 | Opera/9.63.(Windows CE; lb-LU) Presto/2.9.161 Version/12.00                                       | https://azurecresthospital.med/search=Roy+Trenemman+Azure+Crest                          | 200         |
| 2024-03-01T12:23:22Z | GET    | 131.190.102.173 | Opera/9.63.(Windows CE; lb-LU) Presto/2.9.161 Version/12.00                                       | https://azurecresthospital.med/search=Azure+Crest+Hospital+financial+reports             | 200         |
| 2024-03-01T13:48:22Z | GET    | 131.190.102.173 | Opera/9.63.(Windows CE; lb-LU) Presto/2.9.161 Version/12.00                                       | https://azurecresthospital.med/search=Azure+Crest+Hospital+Cyber+Security+team           | 200         |
| 2024-03-01T15:37:22Z | GET    | 131.190.102.173 | Opera/9.63.(Windows CE; lb-LU) Presto/2.9.161 Version/12.00                                       | https://azurecresthospital.med/search=pediatric+patient+medical+records                  | 200         |
| 2024-03-01T15:50:22Z | GET    | 131.190.102.173 | Opera/9.63.(Windows CE; lb-LU) Presto/2.9.161 Version/12.00                                       | https://azurecresthospital.med/search=where+are+pediatric+patient+records+stored         | 200         |

## Question 9

What kind of system did Azure Crest think was a good idea to run on their own?

---

I found this question rather difficult to answer, spending about half an hour just reviewing logs. I looked at the NetworkFlow table first, and did some googling to review unfamiliar ports and their associated protocols. Then I looked at the InboundNetworkEvents table again, since it shows search queries from users. While reading, I noticed an interesting search: https://azurecresthospital.med/news/research/why-running-your-own-erp-systems-is-a-good-idea

I dug into this a little bit more:

```
InboundNetworkEvents
| where url contains "erp"
```

(results truncated):
| Timestamp           | Method | Source IP       | User Agent                                                                                       | URL                                                                                                                       | Status Code |
|---------------------|--------|-----------------|--------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|-------------|
| 2024-03-01T11:16:22Z | GET    | 135.103.59.74   | Opera/9.63.(Windows CE; lb-LU) Presto/2.9.161 Version/12.00                                       | https://azurecresthospital.med/search=Azure+crest+ERP+systems                                                             | 200         |
| 2024-03-01T16:30:09Z | GET    | 16.101.245.182  | Opera/9.63.(Windows CE; lb-LU) Presto/2.9.161 Version/12.00                                       | https://azurecresthospital.med/news/roy-trenemman-joins-azure-crest-to-save-money-on-erp-systems                          | 200         |
| 2024-03-01T16:30:26Z | GET    | 115.12.60.150   | Opera/9.63.(Windows CE; lb-LU) Presto/2.9.161 Version/12.00                                       | https://azurecresthospital.med/news/research/why-running-your-own-erp-systems-is-a-good-idea                              | 200         |
| 2024-03-01T16:31:06Z | GET    | 215.95.144.58   | Opera/9.63.(Windows CE; lb-LU) Presto/2.9.161 Version/12.00                                       | https://azurecresthospital.med/news/research/why-pay-for-expensive-erp-systems-when-you-can-run-your-own                  | 200         |
| 2024-03-01T16:32:39Z | GET    | 16.101.245.182  | Opera/9.63.(Windows CE; lb-LU) Presto/2.9.161 Version/12.00                                       | https://azurecresthospital.med/news/research/run-your-own-erp-systems-on-sqlite-what-could-possibly-go-wrong              | 200         |

## Question 10

What file extension is used by the threat actor to encrypt files?

---

It sounds like ransomware has executed on one of the machines. At this stage, I still don't really have a good understanding of which servers might be in this network. From my earlier research, I know that computers have hostnames like '-MACHINE', '-LAPTOP', '-DESKTOP'. Are there any hostnames with '-SERVER', or something else?

```
FileCreationEvents
| where hostname !contains "MACHINE" 
       and hostname !contains "DESKTOP" 
       and hostname !contains "LAPTOP"
| distinct hostname
```
| Hostname           |
|--------------------|
| SUPER-DB-SERVER-9000 |

Ah, there's a database server on the network. That would be a target for ransomware. Let's find out which users have created files on it:

```
FileCreationEvents
| where hostname contains "SUPER-DB"
| distinct username
```

| Username    |
|-------------|
| rotrenneman |

Hey, this is our boss, Roy Trenneman! Let's look at the results from the query in question 4, and search for the hostname "SUPER-DB-SERVER-9000":

| Timestamp           | Parent Process Name | Parent Process Hash                                          | Process Command Line                                                             | Process Name  | Process Hash                                             | Hostname              | Username    |
|---------------------|---------------------|--------------------------------------------------------------|----------------------------------------------------------------------------------|---------------|----------------------------------------------------------|-----------------------|-------------|
| 2024-03-04T11:29:21Z | Explorer.exe        | 55df41f4f034802c82b219ecc3e3339b518a4dd1ea50371b8eb8de0daa6ef354 | Explorer.exe "C:\Users\rotrenneman\Downloads\New_Healthcare_Protocols.docm"       | Explorer.exe  | e8f6a9348ea4743447d103eff057f35cb3485456c5b67f9934683d3dd386027e | SUPER-DB-SERVER-9000 | rotrenneman |

Given this timestamp, let's see what happens on this computer in terms of file creation events:

```
FileCreationEvents
| where timestamp > datetime(2024-03-04T11:29:21Z) and hostname == "SUPER-DB-SERVER-9000"
```

On 2024-03-04, we see the same pattern of files dropped as before. Then, nothing happens until the first of the following month...
(results truncated):
| Timestamp           | Hostname              | Username    | SHA256                                                           | Path                                      | Filename                    | Process Name   |
|---------------------|-----------------------|-------------|-------------------------------------------------------------------|-------------------------------------------|------------------------------|----------------|
| 2024-04-01T14:40:15Z | SUPER-DB-SERVER-9000  | rotrenneman | b68cc52498669a77a05b458299b732076ce1bbfbef75b11f8d8f46f50b5809a2  | C:\Out                                   | Out                          | explorer.exe   |
| 2024-04-01T14:50:15Z | SUPER-DB-SERVER-9000  | rotrenneman | 061083960b6a379fcc41107b3f74cd27f71bb9676bec5a195ee44f378781dbfa  | C:\In                                    | In                           | explorer.exe   |
| 2024-04-01T15:13:25Z | SUPER-DB-SERVER-9000  | rotrenneman | c9a60b1ac56610e874ccff1a01c8e4d93a11576fc9dd82dbbafa9fd45c722ede  | C:\Windows\Temp\dbhunter.exe             | dbhunter.exe                 | edge.exe       |
| 2024-04-02T10:50:22Z | SUPER-DB-SERVER-9000  | rotrenneman | ec9b98a2e9744dd3472adcfb6dc5a87d2f5e6cac125deee7fa4d7bfb81164633  | C:\ProgramData\Heartburn\anydesk_automation.ps1 | anydesk_automation.ps1       | firefox.exe    |
| 2024-04-02T11:29:37Z | SUPER-DB-SERVER-9000  | rotrenneman | 918784e25bd24192ce4e999538be96898558660659e3c624a5f27857784cd7e1  | C:\Windows\Temp\UrTottalyPwned.bat       | UrTottalyPwned.bat           | Edge.exe       |
| 2024-04-02T11:32:20Z | SUPER-DB-SERVER-9000  | rotrenneman | b7a73edf2d7903225c150762e899535cd4e560b837784861c668ec4a36ca6a5c  | C:\Users\rotrenneman\Downloads\billion.odt.scholopendra | billion.odt.scholopendra    | OneDrive.exe   |
| 2024-04-02T11:32:20Z | SUPER-DB-SERVER-9000  | rotrenneman | b891c6f27ff3a56afdedc69a0bd1718160b9fac98235b6a515420e99b89dc9c1  | C:\Users\rotrenneman\Videos\young.avi.scholopendra  | young.avi.scholopendra       | Edge.exe       |
| 2024-04-02T11:32:20Z | SUPER-DB-SERVER-9000  | rotrenneman | b0350700775fdf82e6f7bc1735eb5950bae69018064506ccd97938414341103d  | C:\Users\rotrenneman\Pictures\road.jpeg.scholopendra | road.jpeg.scholopendra      | OneDrive.exe   |

A strange executable file named "dbhunter.exe" is created, plus two scripts named "anydesk_automation.ps1" and "UrTottalyPwned.bat" appear. Then files begin to be created with the ".scholopendra" file extension tagged onto the end. This is a common pattern of ransomware encryption activity (in other cases, it may be '.locked', '.encrypted', or even random strings in the extension).

## Question 11

Which file, when executed, triggers the encryption of database files?

---

Given the order of events and the timestamps, I think its safe to say the batch file kicked off encryption of the disk.

## Question 12

When was the batch file downloaded? (paste the full timestamp)

---

We can find this information in the results of our last query.

## Question 13

What password was used to encrypt the archive containing the financial database files?

---

Since we know the ransomware waited until the first of the month, let's see what happens in the process events table, beginning the prior day:

```
ProcessEvents
| where timestamp > datetime(2024-03-31T00:00:00Z) and hostname == "SUPER-DB-SERVER-9000"
```
(results truncated)
| Timestamp           | Parent Process Name | Parent Process Hash                                          | Process Command Line                                                                                                                                                                                                                      | Process Name   | Process Hash                                             | Hostname              | Username    |
|---------------------|---------------------|--------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------|----------------------------------------------------------|-----------------------|-------------|
| 2024-04-01T15:13:37Z | powershell.exe      | 529ee9d30eef7e331b24e66d68205ab4554b6eb3487193d53ed3a840ca7dde5d | C:\Windows\System32\powershell.exe -Nop -ExecutionPolicy bypass -enc SW52b2tlLVdtaU1ldGhvZCAtQ29tcHV0ZXJOYW1lICRTZXJ2ZXIgLUNsYXNzIENDTV9Tb2Z0d2FyZVVwZGF0ZXNNYW5hZ2VyIC1OYW1lIEluc3RhbGxVcGRhdGVzIC0gQXJndW1lbnRMaXN0ICgsICRQZW5kaW5nVXBkYXRlTGlzdCkgLU5hbWVzcGFjZSByb290WyZjY20mXWNsaWVudHNkayB8IE91dC1OdWxs" | powershell.exe | 1f6f7409e0d9306bc6dbf14fa81d4b47e5a7b51487fd43c88b162ba89478fce1 | SUPER-DB-SERVER-9000 | rotrenneman |
| 2024-04-01T15:26:23Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | dbhunter.exe --search --filetype .db .sql .mdb --output C:\\In\\found_databases.txt                                                                                                                                                        | dbhunter.exe   | 191fd9ea5f7a66b56c8ba06aa19ba75e85c01bd377eb68b019a1bef20a8fbd36 | SUPER-DB-SERVER-9000 | rotrenneman |
| 2024-04-01T15:33:23Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | for /f %i in (C:\\In\\found_databases.txt) do copy %i C:\\Out\\                                                                                                                                                                            | cmd.exe        | 18915f7dbcf0fdf0c4850c3f3c6dfaeee86ee2308a336971e64041e016d46b15 | SUPER-DB-SERVER-9000 | rotrenneman |
| 2024-04-01T16:05:36Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | 7z.exe a -t7z C:\\Out\\Financial_Records.7z C:\\Out\\*financial*.db -p finnaberich                                                                                                                                                         | cmd.exe        | e1973f0e63aa68e81e20dc0a4b39f2d41c9762c5b0f74acd2a765c1c606f1208 | SUPER-DB-SERVER-9000 | rotrenneman |
| 2024-04-01T16:23:36Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | 7z.exe a -t7z C:\\Out\\Patient_Records.7z C:\\Out\\*patient*.sql -p i<3mulah                                                                                                                                                               | cmd.exe        | b590e0b702031683099aba6fd6d39887083f67a7b4d54fd3df07001abcd7ccf7 | SUPER-DB-SERVER-9000 | rotrenneman |
| 2024-04-01T17:12:36Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | 7z.exe a -t7z C:\\Out\\Roys_Meme_Collection.7z C:\\Out\\*meme*.mdb -p mommawemadeit                                                                                                                                                       | cmd.exe        | ca5bf21d9e885b0811bd066559a3a82299c6eb311cd998b5e984cf15e40570fb | SUPER-DB-SERVER-9000 | rotrenneman |

## Question 14

What is the hostname of the machine compromised by the attackers to achieve their objectives?

---

I think we have a good idea which machine has been targeted for ransomware at this stage in the investigation.

## Question 15

What command was run to let Azure Crest know that something went wrong?

---

Continuing to review the results of our last query, we spot this in process_commandline: 'cmd.exe /c reg add 'HKCU\Control Panel\Desktop' /v Wallpaper /t REG_SZ /d 'C:\Users\Public\ItWentWrong.jpg' /f && reg add 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System' /v Wallpaper /t REG_SZ /d 'C:\Users\Public\ItWentWrong.jpg' /f'


Looks like the wallpaper was updated to alert the user of ransomware execution.

## Question 16

What domain was used to target the employee that held the keys to the database?

---

Given the query results in question 10, we know Roy downloaded 'New_Healthcare_Protocols.docm'. We also have his email from the query results in question 1: roy_trenneman@azurecresthospital.med. Given this information, let's query the Emails table:

```
Email
| where recipient == 'roy_trenneman@azurecresthospital.med' and link contains 'New_Healthcare_Protocols.docm'
```

| Timestamp           | Sender                  | Reply To                 | Recipient                           | Subject                                                       | Verdict | Link                                                                                           |
|---------------------|-------------------------|--------------------------|-------------------------------------|---------------------------------------------------------------|---------|------------------------------------------------------------------------------------------------|
| 2024-03-04T10:52:18Z | healthupdate@gmail.com  | healthupdate@gmail.com    | roy_trenneman@azurecresthospital.med | [EXTERNAL] 🩺 Vital Update: Groundbreaking Pediatric Care Advances 🚀 | CLEAN   | http://unhealthyrecordsystems.tech/images/images/New_Healthcare_Protocols.docm                   |

## Question 17

Which of the legitimate Azure Crest partner domain was spoofed by the attacker's domain referenced in Question 16?

---

Reviewing the introduction to Azure Crest Hospital in the training guide, the first page notes: "Azure Crest Hospital has a series of key partners who contribute to the health of the community" followed by a table with partner names and their relationship to the hospital. Health Records Systems and their domain is listed here.
