https://cyberdefenders.org/blueteam-ctf-challenges/azurehunt

Scenario:
>Anomalous activity has emerged from an unexpected country. Your job as a soc analyst is to Investigate the recent surge in the suspicious activity, Dive into the available logs and data sources to uncover the threats associated with it. Your analysis is crucial to ensure the security of our systems.  
Note: Your Azure environment has been configured to forward AD Logs, Activity Logs and Blob Logs to ELK which are required for this investigation.

This is my first ever cloud forensics lab on the Cyber Defenders BlueYard platform. I really appreciate their work: not many platforms today have labs with cloud logs in a SIEM. Here's what I've found so far:

Cyber Defenders
- AzureHunt (ELK) Az/M365 challenge
- AWSRaid (Splunk) AWS challenge
- IMDSv1 (Splunk) AWS challenge

ACE Responder
- Pwned 365 (ELK) Az/M365 challenge
- Infiltration (ELK) Az/M365 challenge
- Investigating Entra ID Attacks (ELK) Az/M365 learning module

XINTRA
- Waifu University (ELK) Az/M365 challenge
- Assassin Kitty (ELK) Az/M365 challenge

Pwned Labs
- Detect Threats in the Cloud with ELK Stack (ELK) challenge
- Hunt in the Cloud (Splunk) challenge

Blue Team Labs Online
- Spilled Bucket (Splunk) AWS challenge

Anyway, let's proceed to the lab.

**Q1. As a US-based company, the security team has observed significant suspicious activity from an unusual country. What is the name of the country from which the attacker originated?**

To start, I took a circuitous route: I mistakenly used the field `azure.signinlogs.properties.authentication_details.succeeded`, which actually has two boolean values in some rows (ie, '\[true, false\]' for password authentication then MFA). This is helpful, but not precisely what we need.

I reviewed the fields that were available, and crafted a new query. I added the columns for the User Principal Name (UPN) and geographic location, then proceeded with the following search:

```
event.category: authentication AND event.outcome: failure
```

The question indicates the suspicious activity is non-US, and all 46 results are from the United States! The attacker didn't apparently use any credential stuffing, bruteforcing, or related attacks to gain access. Maybe they phished a user? Let's find out which successful logins originated from outside the US:

```
event.category: authentication AND NOT source.geo.country_name: "United States"
```

Here are the results:

| @timestamp                 | azure.signinlogs.properties.user_principal_name | source.ip     | source.geo.country_name | event.outcome |
| -------------------------- | ----------------------------------------------- | ------------- | ----------------------- | ------------- |
| Oct 5, 2023 @ 15:09:57.010 | alice@cybercactus.onmicrosoft.com               | 85.203.15.6   | Germany                 | success       |
| Oct 5, 2023 @ 15:09:59.545 | alice@cybercactus.onmicrosoft.com               | 85.203.15.6   | Germany                 | success       |
| Oct 5, 2023 @ 15:13:58.915 | alice@cybercactus.onmicrosoft.com               | 85.203.15.6   | Germany                 | success       |
| Oct 5, 2023 @ 15:23:27.842 | it.admin1@cybercactus.onmicrosoft.com           | 84.247.59.224 | Germany                 | success       |
| Oct 5, 2023 @ 15:27:55.524 | it.admin1@cybercactus.onmicrosoft.com           | 84.247.59.224 | Germany                 | success       |
| Oct 5, 2023 @ 15:28:26.180 | it.admin1@cybercactus.onmicrosoft.com           | 84.247.59.224 | Germany                 | success       |
| Oct 5, 2023 @ 15:36:25.342 | it.admin1@cybercactus.onmicrosoft.com           | 20.19.30.14   | France                  | success       |
| Oct 5, 2023 @ 15:41:41.264 | it.admin1@cybercactus.onmicrosoft.com           | 85.203.15.15  | Germany                 | success       |
| Oct 5, 2023 @ 15:42:01.775 | it.admin1@cybercactus.onmicrosoft.com           | 85.203.15.15  | Germany                 | success       |
| Oct 5, 2023 @ 15:42:57.731 | it.admin1@cybercactus.onmicrosoft.com           | 85.203.15.15  | Germany                 | success       |
| Oct 5, 2023 @ 15:42:59.363 | it.admin1@cybercactus.onmicrosoft.com           | 85.203.15.4   | Germany                 | success       |
| Oct 6, 2023 @ 07:30:43.113 | it_support@cybercactus.onmicrosoft.com          | 85.203.15.22  | Germany                 | success       |
| Oct 6, 2023 @ 07:31:59.626 | it_support@cybercactus.onmicrosoft.com          | 85.203.15.22  | Germany                 | success       |

All but one of fourteen results originate from Germany. It is odd that it_support@cybercactus.onmicrosoft.com authenticated eight times within twenty minutes across four different IP addresses.

Reviewing the first event, I made a note of the following fields/values:

| Field                                                  | Value                        |
| ------------------------------------------------------ | ---------------------------- |
| azure.signinlogs.category                              | NonInteractiveUserSignInLogs |
| azure.signinlogs.properties.authentication_requirement | singleFactorAuthentication   |
| azure.signinlogs.properties.app_display_name           | Azure Portal                 |
| azure.signinlogs.properties.is_interactive             | false                        |

In the third event, I noticed the user requested a Primary Refresh Token using the Graph API, and the OAuth Scope Info `azure.signinlogs.properties.authentication_processing_details.Oauth Scope Info` field with a value of \["email","openid","Organization.Read.All","Policy.ReadWrite.ApplicationConfiguration","profile","User.Read"\].

After additional investigation, it doesn't appear that the attacker does anything interesting with this user account (such as lateral movement, privilege escalation, data exfiltration, etc).

**Q2. To accurately track the activities carried out by the attacker within the environment, it is essential to identify the source of the attack. How many IPs were employed by the attacker?**

Initially, I attempted to submit a count based on the unique IP addresses in the results for Q1. This didn't work, and I realised that query doesn't include all possible IPs that may be performing an action in an Azure tenant, such as those in VMs and Storage Accounts. 

Based on the table in Q1, it looks like the attacker is using the 85.203.15.0 /24 subnet. Stepping back a bit, I tried the query:

```
client.ip: 85.203.15.*
```

This produced the following table. I added some columns to provide context.

| @timestamp                 | client.ip    | user                                   | event.action                                          | user.email                            |
| -------------------------- | ------------ | -------------------------------------- | ----------------------------------------------------- | ------------------------------------- |
| Oct 5, 2023 @ 15:09:57.010 | 85.203.15.6  | alice@cybercactus.onmicrosoft.com      | Sign-in activity                                      | -                                     |
| Oct 5, 2023 @ 15:09:59.545 | 85.203.15.6  | alice@cybercactus.onmicrosoft.com      | Sign-in activity                                      | -                                     |
| Oct 5, 2023 @ 15:13:58.915 | 85.203.15.6  | alice@cybercactus.onmicrosoft.com      | Sign-in activity                                      | -                                     |
| Oct 5, 2023 @ 15:24:53.094 | 85.203.15.34 | -                                      | MICROSOFT.COMPUTE/VIRTUALMACHINES/START/ACTION        | it.admin1@cybercactus.onmicrosoft.com |
| Oct 5, 2023 @ 15:24:53.282 | 85.203.15.34 | -                                      | MICROSOFT.COMPUTE/VIRTUALMACHINES/START/ACTION        | it.admin1@cybercactus.onmicrosoft.com |
| Oct 5, 2023 @ 15:25:13.289 | 85.203.15.34 | -                                      | MICROSOFT.COMPUTE/VIRTUALMACHINES/START/ACTION        | it.admin1@cybercactus.onmicrosoft.com |
| Oct 5, 2023 @ 15:26:39.930 | 85.203.15.34 | -                                      | MICROSOFT.NETWORK/NETWORKWATCHERS/IPFLOWVERIFY/ACTION | it.admin1@cybercactus.onmicrosoft.com |
| Oct 5, 2023 @ 15:26:40.055 | 85.203.15.34 | -                                      | MICROSOFT.NETWORK/NETWORKWATCHERS/IPFLOWVERIFY/ACTION | it.admin1@cybercactus.onmicrosoft.com |
| Oct 5, 2023 @ 15:26:46.342 | 85.203.15.34 | -                                      | MICROSOFT.NETWORK/NETWORKWATCHERS/IPFLOWVERIFY/ACTION | it.admin1@cybercactus.onmicrosoft.com |
| Oct 5, 2023 @ 15:33:24.892 | 85.203.15.37 | -                                      | MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION     | it.admin1@cybercactus.onmicrosoft.com |
| Oct 5, 2023 @ 15:33:24.939 | 85.203.15.37 | -                                      | MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION     | it.admin1@cybercactus.onmicrosoft.com |
| Oct 5, 2023 @ 15:33:31.424 | 85.203.15.37 | -                                      | MICROSOFT.SQL/SERVERS/DATABASES/EXPORT/ACTION         | it.admin1@cybercactus.onmicrosoft.com |
| Oct 5, 2023 @ 15:33:31.627 | 85.203.15.37 | -                                      | MICROSOFT.SQL/SERVERS/DATABASES/EXPORT/ACTION         | it.admin1@cybercactus.onmicrosoft.com |
| Oct 5, 2023 @ 15:41:41.264 | 85.203.15.15 | it.admin1@cybercactus.onmicrosoft.com  | Sign-in activity                                      | -                                     |
| Oct 5, 2023 @ 15:42:01.775 | 85.203.15.15 | it.admin1@cybercactus.onmicrosoft.com  | Sign-in activity                                      | -                                     |
| Oct 5, 2023 @ 15:42:53.536 | 85.203.15.23 | -                                      | Add user                                              | -                                     |
| Oct 5, 2023 @ 15:42:57.731 | 85.203.15.15 | it.admin1@cybercactus.onmicrosoft.com  | Sign-in activity                                      | -                                     |
| Oct 5, 2023 @ 15:42:59.363 | 85.203.15.4  | it.admin1@cybercactus.onmicrosoft.com  | Sign-in activity                                      | -                                     |
| Oct 5, 2023 @ 15:44:23.722 | 85.203.15.85 | -                                      | MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE         | it.admin1@cybercactus.onmicrosoft.com |
| Oct 5, 2023 @ 15:44:26.425 | 85.203.15.85 | -                                      | MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE         | it.admin1@cybercactus.onmicrosoft.com |
| Oct 6, 2023 @ 07:30:43.113 | 85.203.15.22 | it_support@cybercactus.onmicrosoft.com | Sign-in activity                                      | -                                     |
| Oct 6, 2023 @ 07:31:59.626 | 85.203.15.22 | it_support@cybercactus.onmicrosoft.com | Sign-in activity                                      | -                                     |
| Oct 6, 2023 @ 07:31:59.626 | 85.203.15.22 | it_support@cybercactus.onmicrosoft.com | Sign-in activity                                      | -                                     |

A quick count of the unique `client.ip` values result in the expected answer.

**Q3. In order to establish an accurate incident timeline, what is the timestamp of the initial activity originating from the country?**

We can answer this thanks to the query we ran in question one.

**Q4. To assess the scope of compromise, we must determine the attacker's entry point. What is the display name of the user account that was compromised?**

We can learn this by reviewing the event for the first row in Q1. The answer is the value for the field `azure.signinlogs.properties.user_display_name`.

**Q5. To gain insights into the attacker's tactics and enumeration strategy, what is the name of the script file the attacker accessed within blob storage?**

To tackle this, I started with the query:

```azure-eventhub.eventhub: bloblogs```

This produced 141 hits. Here's a short excerpt of the results:

| @timestamp                 | azure.resource.name                    | azure.eventhub.properties.objectKey                   | azure.eventhub.operationName | azure.eventhub.statusText |
| -------------------------- | -------------------------------------- | ----------------------------------------------------- | ---------------------------- | ------------------------- |
| Oct 5, 2023 @ 14:55:48.111 | cactusstorage2023/blobServices/default | /cactusstorage2023                                    | GetBlobServiceProperties     | Success                   |
| Oct 5, 2023 @ 14:55:51.209 | cactusstorage2023/blobServices/default | /cactusstorage2023                                    | GetBlobServiceProperties     | Success                   |
| Oct 5, 2023 @ 14:55:51.951 | cactusstorage2023/blobServices/default | /cactusstorage2023                                    | ListContainers               | Success                   |
| Oct 5, 2023 @ 14:55:51.958 | cactusstorage2023/blobServices/default | /cactusstorage2023/$blobchangefeed                    | GetContainerProperties       | ContainerNotFound         |
| Oct 5, 2023 @ 14:55:52.267 | cactusstorage2023/blobServices/default | /cactusstorage2023/$logs                              | GetContainerProperties       | Success                   |
| Oct 5, 2023 @ 14:55:52.271 | cactusstorage2023/blobServices/default | /cactusstorage2023/$logs                              | GetContainerServiceMetadata  | Success                   |
| Oct 5, 2023 @ 14:55:52.947 | cactusstorage2023/blobServices/default | /cactusstorage2023                                    | BlobPreflightRequest         | Success                   |
| Oct 5, 2023 @ 14:55:53.231 | cactusstorage2023/blobServices/default | /cactusstorage2023                                    | GetBlobServiceProperties     | Success                   |
| Oct 5, 2023 @ 14:56:02.781 | cactusstorage2023/blobServices/default | /cactusstorage2023/service-configs                    | BlobPreflightRequest         | Success                   |
| Oct 5, 2023 @ 14:56:03.052 | cactusstorage2023/blobServices/default | /cactusstorage2023/service-configs                    | ListBlobs                    | Success                   |
| Oct 5, 2023 @ 14:56:03.684 | cactusstorage2023/blobServices/default | /cactusstorage2023/service-configs                    | GetContainerProperties       | Success                   |
| Oct 5, 2023 @ 14:56:03.688 | cactusstorage2023/blobServices/default | /cactusstorage2023/service-configs                    | GetContainerServiceMetadata  | Success                   |
| Oct 5, 2023 @ 14:56:03.698 | cactusstorage2023/blobServices/default | /cactusstorage2023/service-configs                    | GetContainerProperties       | Success                   |
| Oct 5, 2023 @ 14:56:03.702 | cactusstorage2023/blobServices/default | /cactusstorage2023/service-configs                    | GetContainerServiceMetadata  | Success                   |
| Oct 5, 2023 @ 14:56:05.333 | cactusstorage2023/blobServices/default | /cactusstorage2023/service-configs/service-config.ps1 | BlobPreflightRequest         | Success                   |
| Oct 5, 2023 @ 14:56:05.341 | cactusstorage2023/blobServices/default | /cactusstorage2023/service-configs/service-config.ps1 | BlobPreflightRequest         | Success                   |

**Q6. For a detailed analysis of the attacker's actions, what is the name of the storage account housing the script file?**

See above.

**Q7. Tracing the attacker's movements across our infrastructure, what is the user principal name (UPN) of the second user account the attacker compromised?**

We can infer this from the second account that was successfully logged in, shown in the results of the query for question one! It occurred at Oct 5, 2023 @ 15:23:27.842.

it.admin1@cybercactus.onmicrosoft.com

**Q8. Analyzing the attacker's impact on our environment, what is the name of the Virtual Machine (VM) the attacker started?**

To find out, I pivoted on the username and timestamp from the work performed in Q7:

```
azure.activitylogs.identity.claims_initiated_by_user.name.keyword: "it.admin1@cybercactus.onmicrosoft.com" AND @timestamp > "2023-10-05T15:23:27Z"
```

| `@timestamp`                 | `source.ip`    | `azure.resource.name`                     | `event.action`                                          | `azure.activitylogs.result_type` | `azure.activitylogs.properties.status_code` |
| ---------------------------- | -------------- | ----------------------------------------- | ------------------------------------------------------- | -------------------------------- | ------------------------------------------- |
| `Oct 5, 2023 @ 15:24:53.094` | `85.203.15.34` | `DEV01VM`                                 | `MICROSOFT.COMPUTE/VIRTUALMACHINES/START/ACTION`        | `Start`                          | `-`                                         |
| `Oct 5, 2023 @ 15:24:XX.XXX` | `85.203.15.34` | `DEV01VM`                                 | `MICROSOFT.COMPUTE/VIRTUALMACHINES/START/ACTION`        | `Accept`                         | `Accepted`                                  |
| `Oct 5, 2023 @ 15:25:13.289` | `85.203.15.34` | `DEV01VM`                                 | `MICROSOFT.COMPUTE/VIRTUALMACHINES/START/ACTION`        | `Success`                        | `-`                                         |
| `Oct 5, 2023 @ 15:26:39.930` | `85.203.15.34` | `NETWORKWATCHER_FRANCECENTRAL`            | `MICROSOFT.NETWORK/NETWORKWATCHERS/IPFLOWVERIFY/ACTION` | `Start`                          | `-`                                         |
| `Oct 5, 2023 @ 15:26:40.055` | `85.203.15.34` | `NETWORKWATCHER_FRANCECENTRAL`            | `MICROSOFT.NETWORK/NETWORKWATCHERS/IPFLOWVERIFY/ACTION` | `Accept`                         | `Accepted`                                  |
| `Oct 5, 2023 @ 15:26:46.342` | `85.203.15.34` | `NETWORKWATCHER_FRANCECENTRAL`            | `MICROSOFT.NETWORK/NETWORKWATCHERS/IPFLOWVERIFY/ACTION` | `Success`                        | `-`                                         |
| `Oct 5, 2023 @ 15:33:24.892` | `85.203.15.37` | `CACTUSSTORAGE2023`                       | `MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION`     | `Start`                          | `-`                                         |
| `Oct 5, 2023 @ 15:33:24.939` | `85.203.15.37` | `CACTUSSTORAGE2023`                       | `MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION`     | `Success`                        | `OK`                                        |
| `Oct 5, 2023 @ 15:33:31.424` | `85.203.15.37` | `CACTUSDBSERVER/DATABASES/CUSTOMERDATADB` | `MICROSOFT.SQL/SERVERS/DATABASES/EXPORT/ACTION`         | `Start`                          | `-`                                         |
| `Oct 5, 2023 @ 15:33:31.627` | `85.203.15.37` | `CACTUSDBSERVER/DATABASES/CUSTOMERDATADB` | `MICROSOFT.SQL/SERVERS/DATABASES/EXPORT/ACTION`         | `Accept`                         | `Accepted`                                  |
| `Oct 5, 2023 @ 15:44:23.722` | `85.203.15.85` | `-`                                       | `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE`         | `Start`                          | `-`                                         |
| `Oct 5, 2023 @ 15:44:26.425` | `85.203.15.85` | `-`                                       | `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE`         | `Success`                        | `Created`                                   |

The answer is in the first row.

Before we move on, we also notice a value at the end of the table: "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE". Looking closer at the event, there is a field `azure.activitylogs.properties.requestbody` with this JSON object (pretty-printed for readability):

```
{
  "Id": "572a0399-b006-418a-9860-6943855911e0",
  "Properties": {
    "PrincipalId": "99000683-91fc-40ea-b942-87868f0eadcd",
    "PrincipalType": "User",
    "RoleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
    "Scope": "/subscriptions/42439ab4-76df-453b-a380-2f7a4580f01f",
    "Condition": null,
    "ConditionVersion": null
  }
}
```

We know a few things:
- The user that performed this action is it.admin1@cybercactus.onmicrosoft.com (this is in the event, rather than shown in the JSON above).
- The user that received the new role assignment ("PrincipalId": "99000683-91fc-40ea-b942-87868f0eadcd") belongs to IT_Support@cybercactus.onmicrosoft.com.
- The role that was assigned ("RoleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635") is Owner. This is an Azure built-in role, and there is a handy table here with IDs: https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles.

**Q9. To assess the potential data exposure, what is the name of the database exported?**

See above!

**Q10. In your pursuit of uncovering persistence techniques, what is the display name associated with the user account you have discovered?**

This is the display name associated with IT_Support@cybercactus.onmicrosoft.com, and if I didn't already learn it from reviewing previous events, I could use this query:

```
azure.signinlogs.properties.user_principal_name: IT_Support@cybercactus.onmicrosoft.com
```

Then add the column `azure.signinlogs.properties.user_display_name`.

**Q11. By knowing the attacker's intention. What role was added to the account created to persist in the environment?**

See the work performed at the end of the answer for Q8!

**Q12. For a comprehensive timeline and understanding of the breach progression, what's the timestamp of the first successful login recorded for this user account?**

See the table from Q1.
