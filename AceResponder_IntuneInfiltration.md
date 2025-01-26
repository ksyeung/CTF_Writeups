# WIP

https://aceresponder.com/challenge/intune-infiltration

Scenario:
>A user named Emily Cline contacted the SOC to report a suspicious interaction. A software vendor reached out to inform her of a breaking change to an enterprise application. She began troubleshooting the issue with a representative who requested they install an extension. After completing the instructions they gave her via email and over the phone, the representative abruptly ceased contact.

**Q1. Initial Compromise: What technique did the attacker use to compromise Emily Cline’s account?**

First, I went looking for sign-in events from the cloud (the multiple choice options are all cloud-related):

```
userPrincipalName: "emilycline@s05xf.onmicrosoft.com" AND signInEventTypes: *
```

This yielded two results:

| Time                         | ipAddress     | userPrincipalName                | signInEventTypes | originalTransferMethod | status.failureReason                                                                                                       | authenticationDetails                                                                                                                                                                                                                                                                                                                                                                                      |
| ---------------------------- | ------------- | -------------------------------- | ---------------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| June 22, 2024 @ 05:33:15.000 | 213.109.20.69 | emilycline@s05xf.onmicrosoft.com | interactiveUser  | deviceCodeFlow         | For security reasons, user confirmation is required for this request. Please repeat the request allowing user interaction. | {<br>  "authenticationStepDateTime": "2024-06-22T12:33:15Z",<br>  "authenticationMethod": "Password",<br>  "authenticationMethodDetail": "Password Hash Sync",<br>  "succeeded": false,<br>  "authenticationStepResultDetail": "For security reasons, user confirmation is required for this request. Please repeat the request allowing user interaction.",<br>  "authenticationStepRequirement": ""<br>} |
| June 22, 2024 @ 05:33:20.000 | 37.46.121.11  | emilycline@s05xf.onmicrosoft.com | interactiveUser  | deviceCodeFlow         | Other                                                                                                                      |                                                                                                                                                                                                                                                                                                                                                                                                            |

37.46.121.11 geolocates to Stockholm,Sweden and 213.109.200.69 geolocates to Hessen, Germany.

For completeness, I moved on to reviewing Event ID 4624 logins:

```
event.code: 4624 AND winlog.event_data.TargetUserName: "emilycline" 
```

(Truncated) results:

|                        Time | winlog.event_data.IpAddress |
| --------------------------: | --------------------------: |
| Jun 22, 2024 @ 05:37:18.114 |                 10.100.20.5 |
| Jun 22, 2024 @ 05:37:18.641 |                 10.100.20.5 |
| Jun 22, 2024 @ 05:44:32.880 |              213.109.200.69 |
| Jun 22, 2024 @ 05:44:34.926 |              213.109.200.69 |
| Jun 22, 2024 @ 05:44:38.864 |              213.109.200.69 |
| Jun 22, 2024 @ 05:59:41.195 |                 10.100.20.5 |
| Jun 22, 2024 @ 06:40:15.089 |              213.109.200.69 |
| Jun 22, 2024 @ 06:40:17.042 |              213.109.200.69 |
| Jun 22, 2024 @ 06:40:21.430 |              213.109.200.69 |
| Jun 22, 2024 @ 06:40:26.627 |                 10.100.20.5 |

This user signs into the computer named "win10-2". There are no results in a search for Event ID 4625 (failed login).

**Q2. IP Address IoC: What IP address did the attacker use to complete the device code auth flow?**

This is known from the table generated to answer Q1.

**Q3. Token Abuse:**
**• They used it to approve a malicious OAuth app**
**• They used her mailbox to perform another device code phishing attack**
**• They used it to register a malicious OAuth app**
**• They used it to hijack an existing OAuth app**

The actual question was missing here, so I've printed the multiple-choice options instead.

```
properties.initiatedBy.user.userPrincipalName: "emilycline"  AND operationName: *
```

| Time                        | callerIpAddress | properties.initiatedBy.user.userPrincipalName | operationName                                            | properties.result |
| --------------------------- | --------------- | --------------------------------------------- | -------------------------------------------------------- | ----------------- |
| Jun 22, 2024 @ 05:42:11.252 | -               | emilycline@s05xf.onmicrosoft.com              | Add application                                          | success           |
| Jun 22, 2024 @ 05:42:11.252 | -               | emilycline@s05xf.onmicrosoft.com              | Add application                                          | success           |
| Jun 22, 2024 @ 05:42:11.252 | -               | emilycline@s05xf.onmicrosoft.com              | Add application                                          | success           |
| Jun 22, 2024 @ 05:42:12.764 | 138.199.55.183  | emilycline@s05xf.onmicrosoft.com              | Update application – Certificates and secrets management | success           |
| Jun 22, 2024 @ 05:42:12.764 | 138.199.55.183  | emilycline@s05xf.onmicrosoft.com              | Update application – Certificates and secrets management | success           |
| Jun 22, 2024 @ 05:42:12.764 | 138.199.55.183  | emilycline@s05xf.onmicrosoft.com              | Update application – Certificates and secrets management | success           |
| Jun 22, 2024 @ 05:45:49.831 | 138.199.55.183  | emilycline@s05xf.onmicrosoft.com              | Update application – Certificates and secrets management | success           |
| Jun 22, 2024 @ 05:45:56.078 | -               | emilycline@s05xf.onmicrosoft.com              | Add application                                          | success           |

Unfortunately, the fields aren't mapped, so I've instead copied the JSON value from the field `properties.targetResources` here (and pretty-ified it a bit for readability) from one of the "Add application" events:

```
{
  "id": "a0847fad-c428-4478-bd58-d4ad0d9f48be",
  "type": "Application",
  "administrativeUnits": [],
  "modifiedProperties": [
    {
      "oldValue": "[]",
      "newValue": [
        {
          "AddressType": 0,
          "Address": "https://intuneapp.com/auth",
          "ReplyAddressClientType": 1,
          "ReplyAddressIndex": null,
          "IsReplyAddressDefault": false
        }
      ],
      "displayName": "AppAddress"
    },
    {
      "oldValue": "[]",
      "newValue": [
        "5bee10b5-db93-4475-ae1a-3d87e059d287"
      ],
      "displayName": "AppId"
    },
    {
      "oldValue": "[]",
      "newValue": [
        false
      ],
      "displayName": "AvailableToOtherTenants"
    },
    {
      "oldValue": "[]",
      "newValue": [
        "Intune App"
      ],
      "displayName": "DisplayName"
    },
    {
      "oldValue": "[]",
      "newValue": [
        {
          "ResourceAppId": "00000003-0000-0000-c000-000000000000",
          "RequiredAppPermissions": [
            {
              "EntitlementId": "243333ab-4d21-40cb-a475-36241daa0842",
              "DirectAccessGrant": true,
              "ImpersonationAccessGrants": []
            },
            {
              "EntitlementId": "9241abd9-d0e6-425a-bd4f-47ba86e767a4",
              "DirectAccessGrant": true,
              "ImpersonationAccessGrants": []
            },
            {
              "EntitlementId": "5b07b0dd-2377-4e44-a38d-703f09a0dc3c",
              "DirectAccessGrant": true,
              "ImpersonationAccessGrants": []
            }
          ],
          "EncodingVersion": 1
        }
      ],
      "displayName": "RequiredResourceAccess"
    },
    {
      "oldValue": "[]",
      "newValue": [
        "s05xf.onmicrosoft.com"
      ],
      "displayName": "PublisherDomain"
    },
    {
      "oldValue": null,
      "newValue": [
        "AppAddress",
        "AppId",
        "AvailableToOtherTenants",
        "DisplayName",
        "RequiredResourceAccess",
        "PublisherDomain"
      ],
      "displayName": "Included Updated Properties"
    }
  ],
  "displayName": "Intune App"
}
```

Looks like an application with the display name "Intune App" was registered that is available to other tenants and has the redirect URI of https://intuneapp.com/auth.

The `properties.targetResources` value from an event with the operation "Update application – Certificates and secrets management":

```
{
  "id": "a0847fad-c428-4478-bd58-d4ad0d9f48be",
  "type": "Application",
  "administrativeUnits": [],
  "modifiedProperties": [
    {
      "oldValue": [],
      "newValue": [
        {
          "KeyIdentifier": "91c6c5e1-83ec-4b80-8acd-c32ccf5c8a0c",
          "KeyType": "Password",
          "KeyUsage": "Verify",
          "DisplayName": "ClientSecret1"
        }
      ],
      "displayName": "KeyDescription"
    },
    {
      "oldValue": null,
      "newValue": [
        "KeyDescription"
      ],
      "displayName": "Included Updated Properties"
    }
  ],
  "displayName": "Intune App"
}
```

The attacker also added a client secret to this application, which would be a handy backdoor in case their access to Emily's user account is disabled.

Although its clear the attacker registered a malicious OAuth application, I'm going to take a look at the outgoing emails from this user anyway:

```
AuditData.ExchangeMetaData.From: "emilycline@s05xf.onmicrosoft.com"
```

| Time                        | AuditData.ExchangeMetaData.Sent | AuditData.ExchangeMetaData.From  | AuditData.ExchangeMetaData.To    | AuditData.ExchangeMetaData.Subject                  |
| --------------------------- | ------------------------------- | -------------------------------- | -------------------------------- | --------------------------------------------------- |
| Jun 22, 2024 @ 05:49:08.000 | Jun 22, 2024 @ 05:49:04.000     | emilycline@s05xf.onmicrosoft.com | HenriettaM@s05xf.onmicrosoft.com | Need help with the vendor to deploy my extension!!! |
| Jun 22, 2024 @ 05:49:08.000 | Jun 22, 2024 @ 05:49:04.000     | emilycline@s05xf.onmicrosoft.com | HenriettaM@s05xf.onmicrosoft.com | Need help with the vendor to deploy my extension!!! |

Its possible this is a device code phishing attack. To confirm this isn't the case:

```
originalTransferMethod: "deviceCodeFlow"
```

| Time                        | userPrincipalName                | signInEventTypes | originalTransferMethod |
|-----------------------------|-----------------------------------|------------------|-------------------------|
| Jun 22, 2024 @ 05:33:15.000 | emilycline@s05xf.onmicrosoft.com | interactiveUser  | deviceCodeFlow          |
| Jun 22, 2024 @ 05:33:20.000 | emilycline@s05xf.onmicrosoft.com | interactiveUser  | deviceCodeFlow          |

Emily Cline is the only user who experienced a device code event.

**Q4. Malicious OAuth App: What is the display name of the malicious app registered by the attacker?**

See the work above.

**Q5. IP IoC 2: What IP did the attacker register and update the malicious OAuth app?**

See the work for Q3.

**Q6. Admin Consent: Which user consented to the malicious app?**

Initially, I tried the query:

```
operationName: "Consent to application"
```

But there weren't any results. I was more fortunate with:

```
"Consent to application"
```

This was another case of unmapped fields. 13 of 14 hits had these fields/values: 

| Time                        | callerIpAddress | properties.initiatedBy.user.userPrincipalName | operationName         | properties.result |
| --------------------------- | --------------- | --------------------------------------------- | --------------------- | ----------------- |
| Jun 22, 2024 @ 05:51:15.074 | 40.76.97.127    | HenriettaM@s05xf.onmicrosoft.com              | Add service principal | success           |

Here's the value from the field `properties.targetResources`:

```
{
  "id": "79fa50fb-03bf-4001-8db8-143ccda27687",
  "type": "ServicePrincipal",
  "administrativeUnits": [],
  "modifiedProperties": [
    {
      "oldValue": [],
      "newValue": [true],
      "displayName": "AccountEnabled"
    },
    {
      "oldValue": [],
      "newValue": [
        {
          "AddressType": 0,
          "Address": "https://intuneapp.com/auth",
          "ReplyAddressClientType": 1,
          "ReplyAddressIndex": null,
          "IsReplyAddressDefault": false
        }
      ],
      "displayName": "AppAddress"
    },
    {
      "oldValue": [],
      "newValue": ["5bee10b5-db93-4475-ae1a-3d87e059d287"],
      "displayName": "AppPrincipalId"
    },
    {
      "oldValue": [],
      "newValue": ["Intune App"],
      "displayName": "DisplayName"
    },
    {
      "oldValue": [],
      "newValue": ["5bee10b5-db93-4475-ae1a-3d87e059d287"],
      "displayName": "ServicePrincipalName"
    },
    {
      "oldValue": [],
      "newValue": [
        {
          "CredentialType": 2,
          "KeyStoreId": "291154f0-a9f5-45bb-87be-9c8ee5b6d62c",
          "KeyGroupId": "291154f0-a9f5-45bb-87be-9c8ee5b6d62c"
        }
      ],
      "displayName": "Credential"
    },
    {
      "oldValue": null,
      "newValue": [
        "AccountEnabled",
        "AppAddress",
        "AppPrincipalId",
        "DisplayName",
        "ServicePrincipalName",
        "Credential"
      ],
      "displayName": "Included Updated Properties"
    },
    {
      "oldValue": null,
      "newValue": "5bee10b5-db93-4475-ae1a-3d87e059d287",
      "displayName": "TargetId.ServicePrincipalNames"
    }
  ],
  "displayName": "Intune App"
}
```

This JSON indicates that the Service Principal account was enabled with a client secret.

**Q7. Internal Phishing: What was the subject of the email the attacker used to get Henrietta to consent?**

```
AuditData.ExchangeMetaData.To: "HenriettaM@s05xf.onmicrosoft.com"
```

| Time                        | AuditData.ExchangeMetaData.Sent | AuditData.ExchangeMetaData.From  | AuditData.ExchangeMetaData.To    | AuditData.ExchangeMetaData.Subject                  |
| --------------------------- | ------------------------------- | -------------------------------- | -------------------------------- | --------------------------------------------------- |
| Jun 22, 2024 @ 05:49:08.000 | Jun 22, 2024 @ 05:49:04.000     | emilycline@s05xf.onmicrosoft.com | HenriettaM@s05xf.onmicrosoft.com | Need help with the vendor to deploy my extension!!! |
| Jun 22, 2024 @ 05:49:08.000 | Jun 22, 2024 @ 05:49:04.000     | emilycline@s05xf.onmicrosoft.com | HenriettaM@s05xf.onmicrosoft.com | Need help with the vendor to deploy my extension!!! |

**Q8. Malicious App Role: What role did Henrietta consent to for Intune App?**

We can learn this by reviewing the field `records` in the "Consent to application" event above. Unfortunately, its too large to display here. Here's the `modifiedProperties` value nested in the JSON:

```
"modifiedProperties": [
          {
            "oldValue": null,
            "newValue": "\"243333ab-4d21-40cb-a475-36241daa0842\"",
            "displayName": "AppRole.Id"
          },
          {
            "oldValue": null,
            "newValue": "\"DeviceManagementManagedDevices.ReadWrite.All\"",
            "displayName": "AppRole.Value"
          },
          {
            "oldValue": null,
            "newValue": "\"Read and write Microsoft Intune devices\"",
            "displayName": "AppRole.DisplayName"
          },
          {
            "oldValue": null,
            "newValue": "\"2024-06-22T12:51:15.0953467Z\"",
            "displayName": "AppRoleAssignment.CreatedDateTime"
          },
          {
            "oldValue": null,
            "newValue": "\"2024-06-22T12:51:15.0953467Z\"",
            "displayName": "AppRoleAssignment.LastModifiedDateTime"
          },
          {
            "oldValue": null,
            "newValue": "\"79fa50fb-03bf-4001-8db8-143ccda27687\"",
            "displayName": "ServicePrincipal.ObjectID"
          },
          {
            "oldValue": null,
            "newValue": "\"Intune App\"",
            "displayName": "ServicePrincipal.DisplayName"
          },
          {
            "oldValue": null,
            "newValue": "\"5bee10b5-db93-4475-ae1a-3d87e059d287\"",
            "displayName": "ServicePrincipal.AppId"
          },
          {
            "oldValue": null,
            "newValue": "\"5bee10b5-db93-4475-ae1a-3d87e059d287\"",
            "displayName": "ServicePrincipal.Name"
          },
          {
            "oldValue": null,
            "newValue": "\"00000003-0000-0000-c000-000000000000/ags.windows.net;00000003-0000-0000-c000-000000000000;https://canary.graph.microsoft.com;https://graph.microsoft.com;https://ags.windows.net;https://graph.microsoft.us;https://graph.microsoft.com/;https://dod-graph.microsoft.us;https://canary.graph.microsoft.com/;https://graph.microsoft.us/;https://dod-graph.microsoft.us/\"",
            "displayName": "TargetId.ServicePrincipalNames"
          }
        ],
```

**Q9. Role Abuse: Which Graph API endpoint did the attacker use to gain a foothold in the environment?**

Since we know the malicious app that was created, I searched for the associated Service Principal Name:

```
"5bee10b5-db93-4475-ae1a-3d87e059d287" AND properties.requestUri: *
```

I added some columns for clarity:

| Time                        | operationName               | properties.requestUri                                                                                  |
|-----------------------------|-----------------------------|--------------------------------------------------------------------------------------------------------|
| Jun 22, 2024 @ 06:38:21.584 | Microsoft Graph Activity    | https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts                             |
| Jun 22, 2024 @ 06:38:21.584 | Microsoft Graph Activity    | https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts                             |
| Jun 22, 2024 @ 06:38:22.498 | Microsoft Graph Activity    | https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/ed2f3cb5-a423-4ad8-8a9f-abc2fb16bc25/assign |
| Jun 22, 2024 @ 06:38:22.498 | Microsoft Graph Activity    | https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/ed2f3cb5-a423-4ad8-8a9f-abc2fb16bc25/assign |
| Jun 22, 2024 @ 06:42:48.743 | Microsoft Graph Activity    | https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/ed2f3cb5-a423-4ad8-8a9f-abc2fb16bc25/assign |
| Jun 22, 2024 @ 06:42:56.813 | Microsoft Graph Activity    | https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts                             |

**Q10: Foothold: Which process spawned the attacker’s malicious Intune script?**

I started my investigation with this:

```
event.code: 1 AND winlog.event_data.Image: *powershell.exe*
```

Yielding the following:

| Time                        | host.name                     | winlog.event_data.ParentProcessId | winlog.event_data.ParentImage                                                  | winlog.event_data.ProcessId | winlog.event_data.Image                                   | winlog.event_data.CommandLine                                                                                                                                                                                                                                      |
| --------------------------- | ----------------------------- | --------------------------------- | ------------------------------------------------------------------------------ | --------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Jun 22, 2024 @ 06:53:06.882 | win10-1.s05xf.onmicrosoft.com | 5176                              | C:\Windows\explorer.exe                                                        | 5900                        | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"                                                                                                                                                                                                        |
| Jun 22, 2024 @ 07:09:45.151 | win10-1.s05xf.onmicrosoft.com | 8856                              | C:\Program Files (x86)\Microsoft Intune Management Extension\AgentExecutor.exe | 9004                        | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -executionPolicy bypass -file "C:\Program Files (x86)\Microsoft Intune Management Extension\Policies\Scripts\8edb7a2f-46b1-4b8a-b2e4-0eb8f27a2dd0_ed2f3cb5-a423-4ad8-8a9f-abc2fb16bc25.ps1" |
| Jun 22, 2024 @ 07:14:48.022 | win10-1.s05xf.onmicrosoft.com | 1424                              | C:\Windows\System32\svchost.exe                                                | 6808                        | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | "Powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "C:\Windows\Temp\intunehelperJob.ps1"                                                                                                                                                                    |
| Jun 22, 2024 @ 07:16:57.055 | win10-1.s05xf.onmicrosoft.com | 5536                              | C:\Windows\Temp\intunehelper.exe                                               | 3012                        | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8                                                                                                                                     |

I initially thought the responsible process was svchost.exe, but that turned out not to be the case. The platform provided the correct answer after several failed attempts, which I won't print here. I was still unable to identify the parent-child hierarchy connecting the script to the correct answer that is related to Intune, although it makes sense because it executes scripts and commands.

**Q11. Stage1: From which IP address did the attacker retrieve an executable file?**

This was tricky to work out. I still wasn't completely sure what executable is malicious (although I strongly suspected it was Intunehelper.exe), and I went looking for confirmation. A search for Event ID 1116: "The antimalware platform detected malware or other potentially unwanted software" didn't produce any results. Sysmon Event ID 7: "Image load" also did not, although this is rarely enabled by default as it is very noisy. 

Sysmon Event ID 8: "CreateRemoteThread" had some hits:

```
event.code: 8
```

One of the results in this query confirmed my suspicion:

| Time                        | host.name                     | event.action                          | winlog.event_data.SourceImage    | winlog.event_data.TargetImage                                |
| --------------------------- | ----------------------------- | ------------------------------------- | -------------------------------- | ------------------------------------------------------------ |
| Jun 22, 2024 @ 07:42:59.028 | win10-1.s05xf.onmicrosoft.com | CreateRemoteThread detected (rule: Cr | C:\Windows\Temp\intunehelper.exe | C:\Program Files\Microsoft Office\root\Office16\ONENOTEM.EXE |

So, armed with this, I backtracked a bit:

```
winlog.event_data.TargetFilename: *intunehelper.exe
```

| Time                        | host.name                     | winlog.event_data.ProcessId | winlog.event_data.Image                                   | winlog.event_data.TargetFilename      | event.action            |
|-----------------------------|-------------------------------|-----------------------------|----------------------------------------------------------|---------------------------------------|-------------------------|
| Jun 22, 2024 @ 07:14:50.545 | win10-1.s05xf.onmicrosoft.com | 6808                        | C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe | C:\Windows\Temp\intunehelper.exe      | File created (rule: FileCreate) |

We saw this process earlier in Q10.

Now, I'm going to use Sysmon Event ID 3: "Network connection detected" along with the information we already have about the process that created the malicious executable and the timestamp from when this occurred:

```
(event.code: 3 AND winlog.event_data.Image: *powershell.exe AND winlog.event_data.ProcessId: 6808) OR winlog.event_data.TargetFilename: *intunehelper.exe AND (@timestamp>"2024-06-22T07:14:30" AND @timestamp<"2024-06-22T07:14:59")
```

| Time                        | event.code | host.name                     | winlog.event_data.ProcessId | winlog.event_data.Image                                   | winlog.event_data.TargetFilename | winlog.event_data.DestinationIp |
| --------------------------- | ---------- | ----------------------------- | --------------------------- | --------------------------------------------------------- | -------------------------------- | ------------------------------- |
| Jun 22, 2024 @ 07:14:50.545 | 11         | win10-1.s05xf.onmicrosoft.com | 6808                        | C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe | C:\Windows\Temp\intunehelper.exe | -                               |
| Jun 22, 2024 @ 07:14:51.531 | 3          | win10-1.s05xf.onmicrosoft.com | 6808                        | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | -                                | 100.25.143.198                  |

The inconsistency of the timestamps (file creation being logged before the network activity) is likely due to the file handle creation occurring first, and then the actual content retrieval over the network occurring afterwards.

**Q12. Defense Evasion: Which process did the attacker migrate to?**

We figured this out in the work on the prior question!

**Q13. Remote Execution: Which system did the attacker execute on next?**

I struggled unsuccessfully to learn the answer for this question. I checked for a number of lateral movement techniques:

- DCOM lateral movement using mmc.exe: `event.code:1 AND winlog.event_data.Image:mmc.exe` and `winlog.event_data.ParentImage:mmc.exe`
- WinRM lateral movement with WMI or PowerShell: 
	`event.code:1 AND winlog.event_data.Image:wsmprovhost.exe`
	`event.code:1 AND winlog.event_data.ParentImage:wsmprovhost.exe`
	`winlog.event_data.ParentImage:WmiPrvSe.exe`
- Remote service creation using named pipes:
	`event.code: 7045`
- Remote service creation using TCP:
	`event.code: 5145`
- SCShell (where an attacker changes the config of a service):
	`event.code: 13 AND "HKLM\\System\\CurrentControlSet\\Services\\*\\ImagePath"`
- Scheduled Task over RPC:
	On "win10-1", I did see a scheduled task created named "\IntuneHelper" that launched Powershell.exe with the arguments "-NoProfile -ExecutionPolicy Bypass -File "C:\Windows\Temp\intunehelperJob.ps1", but there's no indication this task was created on any other machine.

**Q14. Azure Tools: What is the name of the suite of tools the attacker used to escalate privileges on aadconnect-1?**

```
host.name: "aadconnect-1.s05xf.onmicrosoft.com" AND winlog.event_data.CommandLine: *powershell*
```

| Time                        | host.name                          | winlog.event_data.ParentImage | winlog.event_data.CommandLine                               |
| --------------------------- | ---------------------------------- | ----------------------------- | ----------------------------------------------------------- |
| Jun 22, 2024 @ 07:31:23.523 | aadconnect-1.s05xf.onmicrosoft.com | -                             | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" |
| Jun 22, 2024 @ 07:46:51.812 | aadconnect-1.s05xf.onmicrosoft.com | -                             | "powershell.exe" -File AADSyncSettings_job.ps1              |
| Jun 22, 2024 @ 07:51:41.517 | aadconnect-1.s05xf.onmicrosoft.com | -                             | "powershell.exe" -File AADSyncSettings_job.ps1              |
| Jun 22, 2024 @ 07:56:59.619 | aadconnect-1.s05xf.onmicrosoft.com | -                             | "powershell.exe" -File AADSyncSettings_job.ps1              |
| Jun 22, 2024 @ 07:57:48.481 | aadconnect-1.s05xf.onmicrosoft.com | -                             | "powershell.exe" -File AADSyncSettings_job.ps1              |
| Jun 22, 2024 @ 08:09:44.034 | aadconnect-1.s05xf.onmicrosoft.com | -                             | "powershell.exe" -File AADSyncSettings_job.ps1              |
| Jun 22, 2024 @ 08:12:51.990 | aadconnect-1.s05xf.onmicrosoft.com | -                             | "powershell.exe" -File AADSyncSettings_job.ps1              |

A quick search of the script name revealed the answer.

**Q15. Privesc: Which user did the attacker compromise with AADInternals?**

I need to revisit this question.
