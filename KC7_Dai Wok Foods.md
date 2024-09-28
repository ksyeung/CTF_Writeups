https://kc7cyber.com/challenges/49

# Section 2
## Question 1 
Welcome to Dai Wok Foods! You have your first task. The company's been having some issues with their systems lately. They said it all started sometime early April after they had to deal with a big food poisoning case they kept getting emails about. They think it all started when an employee, Delphia Evans, first got a food poisoning related email. Let's help investigate! First, let's get some more info. What's Delphia's username? Hint: use the Employees table.

---
This is an easy start to the real aspect of the challenge (section 1 consists of KQL 101 questions). Let's try this query:

```
Employees
| where name contains "Delphia"
```

| timestamp            | name          | user_agent                                                                                                   | ip_addr      | email_addr                    | company_domain  | username | role             | hostname     |
| -------------------- | ------------- | ------------------------------------------------------------------------------------------------------------ | ------------ | ----------------------------- | --------------- | -------- | ---------------- | ------------ |
| 2021-10-20T18:08:26Z | Delphia Evans | Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.99 Safari/537.36 | 192.168.0.31 | delphia_evans@daiwokfoods.com | daiwokfoods.com | deevans  | Restaurant Staff | ABVJ-MACHINE |

## Question 2

What's the company domain?

---

The previous query is helpful for this question.

## Question 3

What's the hostname of Delphia's computer?

---

See above.

## Question 4

What is Delphia's Role at Dai Wok Foods?

---

See the query in the answer to question one.

## Question 5

Let's take a look at the SecurityAlerts table for anything related to Delphia's username or host machine. When was the first alert related to Delphia? Right click and copy the information in the timestamp field.

---

```
SecurityAlerts
| where description contains 'deevans'
```

| timestamp            | alert_type | severity | description                                                                                                |
| -------------------- | ---------- | -------- | ---------------------------------------------------------------------------------------------------------- |
| 2023-04-04T10:14:35Z | EMAIL      | med      | Employee deevans reported a suspicious email with the subject "[EXTERNAL] Formal action on food poisoning" |

## Question 6

What's the full subject line that was listed on this alert? Provide the subject line without the quotes.

---

See above query.

## Question 7

Let's go back and check for more of Delphia's information now. What IP address is assigned to her computer?

---

See the answer to question one.

## Question 8

What is Delphia's email address?

---

See the answer to question one.

## Question 9

Let's investigate her emails using the Email table. How many emails did she receive?

---

```
Email
| where recipient == 'delphia_evans@daiwokfoods.com'
| count
```

## Question 10

How many external emails did Delphia receive?

---

```
Email
| where recipient == 'delphia_evans@daiwokfoods.com'
| where sender !contains 'daiwokfoods.com'
| count
```

## Question 11

Let's look for the specific email with the subject that was found on Q6 that was sent to Delphia. When was the email sent to her?

---

```
Email
| where recipient == 'delphia_evans@daiwokfoods.com' and subject == '[EXTERNAL] Formal action on food poisoning'
```

| timestamp            | from                    | to                         | cc                            | subject                                    | status | link                                                                                                                                                                 |
| -------------------- | ----------------------- | -------------------------- | ----------------------------- | ------------------------------------------ | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2023-04-02T20:40:54Z | county.county@yahoo.com | complaint_county@gmail.com | delphia_evans@daiwokfoods.com | [EXTERNAL] Formal action on food poisoning | CLEAN  | [https://foodadministration-legal-services.com/share/published/files/lawsuit.xlsx](https://foodadministration-legal-services.com/share/published/files/lawsuit.xlsx) |

## Question 12

Who sent the email?

---

See above.

## Question 13

How many emails did this email address send to Dai Wok Employees?

---

```
Email
| where sender == 'county.county@yahoo.com'
| count
```

## Question 14

This is odd. There seems to be a different email addresses in the `reply_to` email. Let's take the unique `reply_to` email addresses and find more sender addresses from those. How many emails are there?

---

```
let emails = Email
| where sender == 'county.county@yahoo.com'
| distinct reply_to;
Email
| where reply_to in (emails)
```

## Question 15

This is odd. There seems to be a different email addresses in the reply_to email. Let's take the unique reply_to email addresses and find more sender addresses. How many unique sender addresses did you find?

---

```
let emails = Email
| where sender == 'county.county@yahoo.com'
| distinct reply_to;
Email
| where reply_to in (emails)
| distinct sender
```

## Question 16

How many total emails were sent by this threat actor?

---

```
let emails = Email
| where sender == 'county.county@yahoo.com'
| distinct reply_to;
let senders = Email
| where reply_to in (emails)
| distinct sender;
Email
| where sender in (senders)
| count
```

## Question 17

There's a lot of domains listed in the link column from Q14. How many unique URLs are there?

----

```
let emails = Email
| where sender == 'county.county@yahoo.com'
| distinct reply_to;
Email
| where reply_to in (emails)
| project domain = tostring(parse_url(link).Host)
| distinct domain
```

## Question 18

Let's check to see if anybody clicked on links from these domains. Search the OutboundNetworkEvents table to see if there are any hits on the domains found in Q17. What is the domain name (not the full link) of the URL found?

---

```
let emails = Email
| where sender == 'county.county@yahoo.com'
| distinct reply_to;
let domains = Email
| where reply_to in (emails)
| project domain = tostring(parse_url(link).Host)
| distinct domain;
OutboundNetworkEvents
| where url has_any (domains);
```

## Question 19

Who clicked on the link? Provide the full name.

---

```
Employees
| where ip_addr == '192.168.3.86'
```

| timestamp            | name        | user_agent                                                                                                     | ip_addr      | email_addr                  | company_domain  | username | role                  | hostname    |
| -------------------- | ----------- | -------------------------------------------------------------------------------------------------------------- | ------------ | --------------------------- | --------------- | -------- | --------------------- | ----------- |
| 2018-08-10T11:54:24Z | John Garcia | Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.185 Safari/537.36 | 192.168.3.86 | john_garcia@daiwokfoods.com | daiwokfoods.com | jogarcia | Logistics Coordinator | LVJW-LAPTOP |

## Question 20

What is their role in the company?

---

See above.

## Question 21

What is their hostname?

---

See above.

## Question 22

Let's take their email address and take a look back at the emails that we've seen from the threat actor on Q14. Do we see their email address in here? Yes / No

---

See above.

## Question 23

When did this employee receive the suspicious email?

```
let emails = Email
| where sender == 'county.county@yahoo.com'
| distinct reply_to;
let senders = Email
| where reply_to in (emails)
| distinct sender;
Email
| where recipient == 'john_garcia@daiwokfoods.com'
| where sender has_any (senders)
```

| timestamp            | sender               | reply_to                    | recipient                   | subject                                       | verdict    | link                                                                                                                                                                                 |
| -------------------- | -------------------- | --------------------------- | --------------------------- | --------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 2023-04-03T18:04:56Z | official@verizon.com | service_official@yandex.com | john_garcia@daiwokfoods.com | [EXTERNAL] Legal notice of customer complaint | SUSPICIOUS | [https://complaints-cityofficialsfood.com/search/published/images/images/large_order.xlsx](https://complaints-cityofficialsfood.com/search/published/images/images/large_order.xlsx) |

## Question 24

Based on the answer you found in Question 16, how many distinct roles were targeted by the threat actor?

---

```
let emails = Email
| where sender == 'county.county@yahoo.com'
| distinct reply_to;
let senders = Email
| where reply_to in (emails)
| distinct sender;
let recipients = Email
| where sender in (senders)
| distinct recipient;
Employees
| where email_addr in (recipients)
| distinct role
```

## Question 25

What's the reply_to email address of the suspicious email found in Q23?

---

See above.

## Question 26

Using Google or Bing, search for the name of the domain in the email address (do not go to the domain directly). What country is this domain from?

---

This is straightforward -- check a search engine!

## Question 27

Let's take the domain name from the suspicious email and search for it in the PassiveDns table. How many records are related to that domain?

---

```
PassiveDns
| where domain contains 'complaints-cityofficialsfood.com'
| count
```

## Question 28

Still looking at the PassiveDNS records from question 27. We want to identify what IP address the domain resolved to at the time nearest to the time that the email was sent to the employee. Which IP address was did the domain resolved to at the time of the activity?

---

```
PassiveDns
| where domain contains 'complaints-cityofficialsfood.com'
| where timestamp > datetime(2023-04-03T18:04:56Z)
```

## Question 29

Using a GeoIP service such as MaxMind (https://www.maxmind.com/en/geoip-demo) or Censys (https://search.censys.io), let's look up this IP address. What country does this IP address appear to be located in?

---

```
let ip = '179.58.169.157';
let geo_info = geo_info_from_ip_address(ip);
print ip, country = tostring(geo_info.country)
```

## Question 30

Let's check the InboundNetworkEvents table to see if that IP address had browsed around our Dai Wok Foods website before. How many records did you find related to that IP address? Answer 0 if there are none.

---

```
InboundNetworkEvents
| where src_ip == '179.58.169.157'
```

| timestamp            | method | src_ip         | user_agent                                                                                      | url                                                        |
| -------------------- | ------ | -------------- | ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| 2023-04-13T02:12:04Z | GET    | 179.58.169.157 | Mozilla/5.0 (X11; Linux x86_64; rv:1.9.5.20) Gecko/2013-04-15 04:45:06 Firefox/3.6.13           | http://daiwokfoods.com/search?query=customer%20service     |
| 2023-04-10T21:05:50Z | GET    | 179.58.169.157 | Mozilla/5.0 (Macintosh; PPC Mac OS X 10_7_5; rv:1.9.2.20) Gecko/2011-02-07 09:29:51 Firefox/6.0 | https://daiwokfoods.com/search?query=dai%20wok%20marketing |
| 2023-04-09T16:09:54Z | GET    | 179.58.169.157 | Mozilla/5.0 (Windows NT 5.1; mai-IN; rv:1.9.0.20) Gecko/2018-01-28 13:27:14 Firefox/3.6.7       | http://daiwokfoods.com/search?query=store%20managers       |

## Question 31

What was the earliest thing the IP address searched for? Replace %20 with a space.

---

See above.

## Question 32

There were more IP addresses related to the domain from the suspicious email. Let's take all of them and search across the InboundNetworkEvents. How many records total were found?

---

```
let ip_addrs = PassiveDns
| where domain contains 'complaints-cityofficialsfood.com'
| distinct ip;
InboundNetworkEvents
| where src_ip has_any (ip_addrs)
| count
```

## Question 33

When was the earliest timestamp observed in Q32?

---

```
let ip_addrs = PassiveDns
| where domain contains 'complaints-cityofficialsfood.com'
| distinct ip;
InboundNetworkEvents
| where src_ip has_any (ip_addrs)
```

## Question 34

Let's check the login attempts from our compromised employee in AuthenticationEvents. How many distinct source IP addresses were used by the employee to log in?

---

```
AuthenticationEvents
| where username == 'jogarcia'
| distinct src_ip
```

## Question 35 

One IP looks like a private (local) IP address. What country is the other IP address from?

---

```
let ip_addresses = AuthenticationEvents
| where username == 'jogarcia'
| distinct src_ip;
ip_addresses
| extend geo_info = geo_info_from_ip_address(src_ip)
| extend country = tostring(geo_info.country)
| project src_ip, country
| distinct src_ip, country
```

## Question 36

How many records in AuthenticationEvents are related to that IP address?

---

```
AuthenticationEvents
| where src_ip == '2.20.114.29'
```

## Question 37

Let's go back to the suspicious email we first found in Q23. The link field has the domain name we've been tracking but also has a reference to a filename at the end of it. What is it?

---

```
let emails = Email
| where sender == 'county.county@yahoo.com'
| distinct reply_to;
let senders = Email
| where reply_to in (emails)
| distinct sender;
Email
| where recipient == 'john_garcia@daiwokfoods.com'
| where sender has_any (senders)
| project parse_path(link).Filename;
```

## Question 38

How many emails reference the same filename?

---

```
Email
| where link contains 'large_order.xlsx'
```

## Question 39

Let's search the FileCreationEvents table for this file. How many host machines have this file?

---

```
FileCreationEvents
| where filename == 'large_order.xlsx'
```

| timestamp            | hostname    | username | file_hash                                                        | file_path                                    | file_name        | process    |
| -------------------- | ----------- | -------- | ---------------------------------------------------------------- | -------------------------------------------- | ---------------- | ---------- |
| 2023-04-03T18:39:12Z | LVJW-LAPTOP | jogarcia | b9d3c969135f1e9abe22fd744c691ec1d1bc0853beffe5aed3f8b78b3d738501 | C:\Users\jogarcia\Downloads\large_order.xlsx | large_order.xlsx | chrome.exe |

## Question 40

Where was this file located on the host machine? Copy and paste the full path.

---

See above.

## Question 41

When was this file created on the host machine?

---

See above.

## Question 42

What's the SHA256 hash of this file?

---

See above.

## Question 43

Let's use VirusTotal (https://www.virustotal.com/gui/home/search) to search for this SHA256 hash. Were there any results? Yes / No.

---

This is easy enough!

## Question 44

Let's look at the ProcessEvents table for this host machine. How many records are associated with this compromised host?

---

```
ProcessEvents
| where hostname == 'LVJW-LAPTOP'
```

Question 45: Let's filter starting with the first time we saw the suspicious file created on Q41. What's the name of the file from the `process_commandline` that occurs not long after the file was created?

```
ProcessEvents
| where timestamp > datetime(2023-04-03T18:39:12Z)
| where hostname == 'LVJW-LAPTOP'
```

| timestamp            | parent_process_name | parent_process_hash                                              | process_commandline                                                                                                                     | process_name | process_hash                                                     | hostname   | username |
| -------------------- | ------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ---------------------------------------------------------------- | ---------- | -------- |
| 2023-04-03T19:28:46Z | ClearTemp.ps1       | 662124b0c998fd0826c192514b1f57f8002f2ab031996aa6dd7832f561679779 | cmd.exe /c start %SYSTEMROOT%\system32\WindowsPowerShell\v1.0\powershell.exe -noni -nop -exe bypass -f \\share1\Admin$\c5k3fsys.3bp.ps1 | cmd.exe      | 464475c64386c5170b13c97d409eda273d953cfadbb81999068c88470b1bb3b6 | LVJW-LAP​⬤ |          |

## Question 46

What's the `parent_process_hash` from Question 45?

---

See above.

## Question 47

Using VirusTotal, search the `parent_process_hash` from Q46. What is the popular threat label for this hash?

---

Review the VT content.

## Question 48

What threat actor is this file associated with?

---

Review the VT content.

## Question 49

What is the md5 hash of this file?

---

Review the VT content.

## Question 50

The indicator is referenced in a threat report by a well known cybersecurity company. What type of operations did the company mention this threat actor shifted to doing?

---

Review the Mandiant link.

# Section 3 
## Question 1

A law enforcement agency warned Dai Wok Foods that they may been targeted by a threat actor. This coincides with a lot of computers at different restaurants sites being locked out recently. The agency said the threat actor may have sent the malware with the file name "`Local_County_Updates.xlsx`". When was the first time this file was seen?

---

```
Email
| where link contains 'Local_County_Updates.xlsx'
```

| timestamp            | sender                 | reply_to                         | recipient                    | subject                                                |
| -------------------- | ---------------------- | -------------------------------- | ---------------------------- | ------------------------------------------------------ |
| 2023-05-12T09:22:48Z | restaurant@verizon.com | miguel_waters@hoisumsupplies.com | doreen_myers@daiwokfoods.com | [EXTERNAL] FW: News: Dai Wok major changes and updates |

## Question 2

Who was the email sender?

---

See above.

## Question 3

Who was the reply_to email address?

---

See above.

## Question 4

Oh no! Looks like one of our partners may have been affected. Let's investigate our employees and see if they may have clicked on the link. When did the first employee click on the link?

---

```
OutboundNetworkEvents
| where url == 'http://operations-management.hk/published/share/share/modules/Local_County_Updates.xlsx'
```

## Question 5

What's the role of the employee who clicked on the link?

---

```
Employees
| where ip_addr == '192.168.1.176'
```

## Question 6

Investigate all of the domains and emails associated with the threat actor. When is the first time this threat actor sent an email to Dai Wok Foods?

---

This took me a while to put together! 
```
let emails =
(Email
| where link contains 'Local_County_Updates.xlsx'
| project email_value = sender
| union (Email | where link contains 'Local_County_Updates.xlsx' | project email_value = reply_to)
);
let distinct_emails = emails
| distinct email_value;
let domains = Email
| where sender has_any (distinct_emails) or reply_to has_any (distinct_emails)
| distinct tostring(parse_url(link).Host);
Email
| where link has_any (domains)
```

## Question 7

How many unique domains are associated with this threat actor?

---

```
let emails =
(Email
| where link contains 'Local_County_Updates.xlsx'
| project email_value = sender
| union (Email | where link contains 'Local_County_Updates.xlsx' | project email_value = reply_to)
);
let distinct_emails = emails
| distinct email_value;
let links = Email
| where sender has_any (distinct_emails) or reply_to has_any (distinct_emails)
| distinct tostring(parse_url(link).Host);
links
```

## Question 8

How many malware files placed by the threat actor are still present across all of the Dai Wok host machines?

---

Using the results of the query used in question 6, we have a list of filenames:
Closing_Locations.xlsx
Pay_Raises.lnk
HR_Notes.pdf
Schedule_Changes.xlsx
Local_County_Updates.xlsx

I investigated an infected machine's ProcessEvents activity following the timestamp of when its file was created.

```
let emails =
Email
| where link contains 'Local_County_Updates.xlsx'
| project email_value = coalesce(sender, reply_to); // Combine sender and reply_to in a single pass
let distinct_emails = emails
| distinct email_value;
let domains =
Email
| where sender in (distinct_emails) or reply_to in (distinct_emails)
| distinct tostring(parse_url(link).Host);
let filenames =
Email
| where link has_any (domains)
| project Filename = tostring(parse_path(link).Filename)
| distinct Filename;
let infected_hosts =
FileCreationEvents
| where filename in (filenames)
| distinct hostname;
let new =
FileCreationEvents
| where hostname in (infected_hosts)
| order by timestamp asc
| serialize
| extend newfile = next(filename)
| where filename in (filenames)
| where newfile !in (filenames)
| distinct newfile;
FileCreationEvents
| where filename in (filenames) or filename in (new);
```

## Question 9

Which threat actor is this publicly reported as?

---

Used VirusTotal to look up the file hash for libexpa.dll, 21ff279ba30d227e32e63cb388bf8c2d21c4fd7e935b3087088579b29e56d81d

## Question 10

What is the MITRE ID for the technique used by the threat actor to execute malware payloads?

---

Reviewed this blog post referenced on the VT Community page: https://www.group-ib.com/blog/bablock-ransomware, which reads: "... the BabLock ransomware used in the investigated attack employs DLL side-loading to load **winutils.dll** targeting the vulnerable legitimate software file **cy.exe**."

## Question 11

What is the SHA256 hash of the file used for the technique found in Q10?

---

See the results of the query in question eight.

## Question 12

What legitimate process is being used by the threat actor from what you found for Q10?

---

```
ProcessEvents
| where process_commandline contains 'cy.exe'
```

| timestamp            | parent_process_name | parent_process_hash                                              | process_commandline                                                                                                                           | process_name | process_hash                                                     | hostname     | username   |
| -------------------- | ------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ---------------------------------------------------------------- | ------------ | ---------- |
| 2023-05-08T10:28:35Z | libexpa.dll         | 21ff279ba30d227e32e63cb388bf8c2d21c4fd7e935b3087088579b29e56d81d | cy.exe --run=3308 --pt=C:\Users\Public\Documents\winutils.dll --cg=C:\Users\Public\Documents\config.ini --we=C:\Users\Public\Documents\cy.exe | notepad.exe  | 7c707158b6afb37c23ef0666522954339aaaa5950da4b16acd87e9efcc1689fd | JP9Y-DESKTOP | kemullings |
| 2023-05-08T10:31:16Z | cy.exe              | 4874d336c5c7c2f558cfd5954655cacfc85bcfcb512a45fb0ff461ce9c38b86d | cy.exe --run=1337 --pt=C:\Users\Public\Desktop\winutils.dll --cg=C:\Users\Public\Desktop\config.ini --we=C:\Users\Public\Desktop\cy.exe       | notepad.exe  | e798fd83b026f6b5da6a193d2a5e1ea62a44805b8f0829826a25bf5d17fa05cc | S3XE-DESKTOP | meespino   |
| 2023-05-08T10:36:51Z | config.ini          | b99d114b267ffd068c3289199b6df95a9f9e64872d6c2b666d63974bbce75bf2 | cy.exe --run=1337 --pt=C:\Users\Public\Desktop\winutils.dll --cg=C:\Users\Public\Desktop\config.ini --we=C:\Users\Public\Desktop\cy.exe       | notepad.exe  | e798fd83b026f6b5da6a193d2a5e1ea62a44805b8f0829826a25bf5d17fa05cc | VQRT-DESKTOP | kacox      |
| 2023-05-09T12:16:37Z | scvhost.exe         | 7ef2cc079afe7927b78be493f0b8a735a3258bc82801a11bc7b420a72708c250 | cy.exe --run=1337 --pt=C:\Users\Public\Desktop\winutils.dll --cg=C:\Users\Public\Desktop\config.ini --we=C:\Users\Public\Desktop\cy.exe       | notepad.exe  | e798fd83b026f6b5da6a193d2a5e1ea62a44805b8f0829826a25bf5d17fa05cc | KLWM-DESKTOP | reblair    |
| 2023-05-11T10:48:43Z | config.ini          | 82a7241d747864a8cf621f226f1446a434d2f98435a93497eafb48b35c12c180 | cy.exe --run=3308 --pt=C:\Users\Public\Documents\winutils.dll --cg=C:\Users\Public\Documents\config.ini --we=C:\Users\Public\Documents\cy.exe | notepad.exe  | 7c707158b6afb37c23ef0666522954339aaaa5950da4b16acd87e9efcc1689fd | 1FK7-MACHINE | yomccay    |
| 2023-05-12T12:02:07Z | libexpa.dll         | aa48acaef62a7bfb3192f8a7d6e5229764618ac1ad1bd1b5f6d19a78864eb31f | cy.exe --run=1337 --pt=C:\Users\Public\Desktop\winutils.dll --cg=C:\Users\Public\Desktop\config.ini --we=C:\Users\Public\Desktop\cy.exe       | notepad.exe  | e798fd83b026f6b5da6a193d2a5e1ea62a44805b8f0829826a25bf5d17fa05cc | RWK7-MACHINE | domyers    |

## Question 13

What file was used by the threat actor for Q10 but is no longer found on any of the host machines?

---

This is "winutils.dll", which I learned via the blog post.

## Question 14

What type of attack is this? What will likely happen soon?

---

This is a ransomware attack.

## Question 15

What command line argument did they use to delete things on a host machine?

---

```
ProcessEvents
| where hostname == '1FK7-MACHINE'
| where process_commandline contains "delete"
```

| timestamp            | parent_process_name | parent_process_hash                                              | process_commandline                     | process_name | process_hash                                                     | hostname     | username |
| -------------------- | ------------------- | ---------------------------------------------------------------- | --------------------------------------- | ------------ | ---------------------------------------------------------------- | ------------ | -------- |
| 2023-05-11T10:03:33Z | config.ini          | 82a7241d747864a8cf621f226f1446a434d2f98435a93497eafb48b35c12c180 | vssadmin.exe delete shadows /All /Quiet | notepad.exe  | ce8bdb07e773bb3b7435752c873b15b8146c15c2c1d96818fec2bde8a34903bd | 1FK7-MACHINE | yomccay  |
