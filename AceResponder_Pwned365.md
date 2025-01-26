https://aceresponder.com/challenge/pwned-365

Scenario:
>The compliance team is currently in the process of hardening the Microsoft 365 environment. One of their primary goals is to restrict the ability of users to grant consent to risky applications. A step in this process requires an audit of existing applications and permissions. While reviewing the results, they noted an unusual application named **Microsoft Activation App**. This discovery prompted a notification to the SOC.
>
>After initial investigation, the SOC identified a possible phishing attempt in Exchange logs just prior to the granting of permissions to Microsoft Activation App. They based this assessment on the subject of the message: **\[URGENT] Microsoft Activation Code**. Your task is to determine _if_, and to what extent, the Microsoft 365 environment is compromised.

**Q1. Initial Foothold: Which user granted consent to Microsoft Activation App?**

The fields are a little different than those in the Entra ID learning module, so I spent a few minutes working them out based on context. Initially I tried to filter on `activityDisplayName: "Consent to application"` but it wasn't available, so I moved on to just `"Activation App"`:

| Time                        | UserId                      | Operation                              | ResultStatus | ModifiedProperties.ConsentAction.Permissions.NewValue                                                                                                                                                                                                                                                                                                                       | Target                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| --------------------------- | --------------------------- | -------------------------------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Nov 21, 2023 @ 07:00:24.000 | DiegoSe05xf.onmicrosoft.com | Add app role assignment grant to user. | Success      | -                                                                                                                                                                                                                                                                                                                                                                           | {<br>  "ID": "ServicePrincipal_d2892cdb-5b43-4f85-992f-dd8f44f823fe",<br>  "Type": 2<br>},<br>{<br>  "ID": "d2892cdb-5b43-4f85-992f-dd8f44f823fe",<br>  "Type": 2<br>},<br>{<br>  "ID": "ServicePrincipal",<br>  "Type": 2<br>},<br>{<br>  "ID": "Microsoft Activation App",<br>  "Type": 1<br>},<br>{<br>  "ID": "ca7f46b4-ab03-4aa9-81e1-a9508e0115e0",<br>  "Type": 2<br>},<br>{<br>  "ID": "ca7f46b4-ab03-4aa9-81e1-a9508e0115e0",<br>  "Type": 4<br>} |
| Nov 21, 2023 @ 07:00:24.000 | DiegoSe05xf.onmicrosoft.com | Consent to application.                | Success      | \[] => \[\[<br>Id: 2yyJ0kNbhU-ZL92PRPgj_oOXhVuK1ylAiXDE34zz3xjIM2lew82PT59IOnODOBQE, ClientId: d2892cdb-5b43-4f85-992f-dd8f44f823fe, <br>PrincipalId: 5e6933c8-cdc3-4f8f-9f48-3a7383381404, <br>ResourceId: 5b859783-d78a-4029-8970-c4df8cf3df18, <br>ConsentType: Principal, <br>**Scope: Files.ReadWrite.All,** <br>CreatedDateTime: , <br>LastModifiedDateTime <br>]];\| | {<br>  "ID": "ServicePrincipal_d2892cdb-5b43-4f85-992f-dd8f44f823fe",<br>  "Type": 2<br>},<br>{<br>  "ID": "d2892cdb-5b43-4f85-992f-dd8f44f823fe",<br>  "Type": 2<br>},<br>{<br>  "ID": "ServicePrincipal",<br>  "Type": 2<br>},<br>{<br>  "ID": "Microsoft Activation App",<br>  "Type": 1<br>},<br>{<br>  "ID": "ca7f46b4-ab03-4aa9-81e1-a9508e0115e0",<br>  "Type": 2<br>},<br>{<br>  "ID": "ca7f46b4-ab03-4aa9-81e1-a9508e0115e0",<br>  "Type": 4<br>} |

**Q2. Risky Permissions: Which [permission](https://learn.microsoft.com/en-us/graph/permissions-reference) did Diego grant the attacker?**

See the table from Q1.

**Q3. IP Address: What is the attacker's IP address?**

Pivoting on Diego's UserId and the consent to application timestamp (less 10 seconds), I crafted the following query:

```
UserId: "DiegoS@s05xf.onmicrosoft.com" AND ActorIpAddress: * AND @timestamp>"2023-11-21T07:00:14"
```

| Time                        | ActorIpAddress  | Operation       |
| --------------------------- | --------------- | --------------- |
| Nov 21, 2023 @ 07:00:18.000 | 54.86.50.139    | UserLoginFailed |
| Nov 21, 2023 @ 07:00:18.000 | 54.86.50.139    | UserLoginFailed |
| Nov 21, 2023 @ 07:00:21.000 | 54.86.50.139    | UserLoginFailed |
| Nov 21, 2023 @ 07:00:24.000 | 54.86.50.139    | UserLoggedIn    |
| Nov 21, 2023 @ 07:04:25.000 | 150.158.135.188 | UserLoggedIn    |
| Nov 21, 2023 @ 07:25:48.000 | 150.158.135.188 | UserLoggedIn    |

A geolocation lookup for 150.158.135.188 points to Shanghai, China while 54.86.50.139 points to Ashburn, Virginia (USA).

**Q4. Data Access: What file did the attacker view on Diego's account?**

Given the overseas IP address of the attacker, I proceeded to identify their actions:

```
ClientIP: 150.158.135.188
```

There are 67 hits, and this is the truncated output (the remaining events are either UserLoggedIn or UserLoginFailed operations):

| Time                        | Operation                |
| --------------------------- | ------------------------ |
| Nov 21, 2023 @ 07:04:25.000 | UserLoggedIn             |
| Nov 21, 2023 @ 07:25:47.000 | UserLoggedIn             |
| Nov 21, 2023 @ 07:25:48.000 | UserLoggedIn             |
| Nov 21, 2023 @ 07:26:16.000 | FileAccessed             |
| Nov 21, 2023 @ 07:26:16.000 | UserLoggedIn             |
| Nov 21, 2023 @ 07:26:16.000 | SignInEvent              |
| Nov 21, 2023 @ 07:26:21.000 | PageViewed               |
| Nov 21, 2023 @ 07:26:41.000 | PageViewed               |
| Nov 21, 2023 @ 07:26:42.000 | AnonymousLinkCreated     |
| Nov 21, 2023 @ 07:26:42.000 | AddedToGroup             |
| Nov 21, 2023 @ 07:26:42.000 | AddedToGroup             |
| Nov 21, 2023 @ 07:26:42.000 | SharingSet               |
| Nov 21, 2023 @ 07:26:42.000 | SharingSet               |
| Nov 21, 2023 @ 07:26:42.000 | SharingSet               |
| Nov 21, 2023 @ 07:26:42.000 | SharingInheritanceBroken |
| Nov 21, 2023 @ 07:27:05.000 | SensitivityLabelApplied  |
| Nov 21, 2023 @ 07:27:08.000 | Create                   |
| Nov 21, 2023 @ 07:27:08.000 | Create                   |
| Nov 21, 2023 @ 07:27:08.000 | Create                   |
| Nov 21, 2023 @ 07:27:08.000 | Create                   |
| Nov 21, 2023 @ 07:27:25.000 | Send                     |
| Nov 21, 2023 @ 07:27:25.000 | Send                     |
| Nov 21, 2023 @ 07:27:25.000 | Send                     |
| Nov 21, 2023 @ 07:27:25.000 | Send                     |
| Nov 21, 2023 @ 07:30:10.000 | UserLoggedIn             |
| Nov 21, 2023 @ 07:30:15.000 | UserLoginFailed          |

The FileAccessed operation from SharePoint has the answer we need.

**Q5. Exfil: In addition to viewing the file, the attacker exfiltrated the it from Diego's OneDrive. How did they accomplish this?**

See the rows that follow the FileAccessed operation in Q4.

**Q6. Credential Access: What did the attacker _likely_ do with the contents of passwords.xlsx?**

There are around 40 additional rows that weren't shown in the output for Q4. I added some columns to dig into the attacker's authentication activity:

| Time                        | Operation       | UserPrincipalName                | ResultStatus                            |
| --------------------------- | --------------- | -------------------------------- | --------------------------------------- |
| Nov 21, 2023 @ 07:30:11.000 | UserLoginFailed | HenriettaM@S05xf.onmicrosoft.com | InvalidUserNameOrPassword               |
| Nov 21, 2023 @ 07:30:15.000 | UserLoginFailed | NestorWe@S05xf.onmicrosoft.com   | InvalidUserNameOrPassword               |
| Nov 21, 2023 @ 07:30:15.000 | UserLoginFailed | MeganBe@S05xf.onmicrosoft.com    | InvalidUserNameOrPassword               |
| Nov 21, 2023 @ 07:30:15.000 | UserLoginFailed | DiegoSe@S05xf.onmicrosoft.com    | InvalidResourceServicePrincipalNotFound |
| Nov 21, 2023 @ 07:30:15.000 | UserLoginFailed | IsaiahLse@S05xf.onmicrosoft.com  | InvalidUserNameOrPassword               |
| Nov 21, 2023 @ 07:30:15.000 | UserLoginFailed | PattiEs@S05xf.onmicrosoft.com    | InvalidUserNameOrPassword               |
| Nov 21, 2023 @ 07:30:15.000 | UserLoginFailed | AdeleVe@S05xf.onmicrosoft.com    | InvalidUserNameOrPassword               |
| Nov 21, 2023 @ 07:30:15.000 | UserLoginFailed | LeeGe@S05xf.onmicrosoft.com      | InvalidUserNameOrPassword               |
| Nov 21, 2023 @ 07:30:15.000 | UserLoginFailed | JohannaL@S05xf.onmicrosoft.com   | InvalidUserNameOrPassword               |
| Nov 21, 2023 @ 07:30:16.000 | UserLoginFailed | PradeepG@S05xf.onmicrosoft.com   | InvalidUserNameOrPassword               |
| Nov 21, 2023 @ 07:30:16.000 | UserLoginFailed | LidiaHe@S05xf.onmicrosoft.com    | InvalidUserNameOrPassword               |
| Nov 21, 2023 @ 07:30:16.000 | UserLoginFailed | AlexWe@S05xf.onmicrosoft.com     | InvalidUserNameOrPassword               |
| Nov 21, 2023 @ 07:30:16.000 | UserLoginFailed | GradyAe@S05xf.onmicrosoft.com    | InvalidUserNameOrPassword               |
| Nov 21, 2023 @ 07:30:16.000 | UserLoginFailed | MiriamGe@S05xf.onmicrosoft.com   | InvalidUserNameOrPassword               |
| Nov 21, 2023 @ 07:30:16.000 | UserLoginFailed | JoniSe@S05xf.onmicrosoft.com     | InvalidUserNameOrPassword               |

**Q7. Password Spray: Was the attacker successful at compromising additional credentials as a result of the password spraying attack?**

The remaining rows in the query output I used in Q4 are all logins for DiegoS, so it doesn't appear that the attack was successful.

**Q8. Password Spraying Targets: How many users did the attacker spray?**

This is easy to answer (see the table in Q6)!

**Q9. Additional Victim: Which user did the attacker compromise next?**

As the user has previously attempted a credential spray, let's take a step back and look at all failed logins:

```
@timestamp>"2023-11-21T07:00:14" AND Operation: (UserLoggedIn OR UserLoginFailed)
```

There are 49 hits with 8 unique IP addresses. It wasn't apparent to me upon review of the results whether any of these users had been sprayed and subsequently logged in. I decided to review the attacker's activity again:

```
UserId: "DiegoS@s05xf.onmicrosoft.com" AND @timestamp>"2023-11-21T07:00:14"
```

I noticed a few rows with an Operation value of "MipLabel": I checked the table for audit log record types at https://learn.microsoft.com/en-us/azure/sentinel/microsoft-purview-record-types-activities and learned its used for "Events detected in the transport pipeline of email messages that are tagged (manually or automatically) with sensitivity labels." Interestingly, there's four identical rows like this (I added some columns for clarity):

| Time                        | Operation | UserId                       | ExchangeMetaData.To          | ExchangeMetaData.Subject            | ExchangeMetaData.RecipientCount |
| --------------------------- | --------- | ---------------------------- | ---------------------------- | ----------------------------------- | ------------------------------- |
| Nov 21, 2023 @ 07:27:31.000 | MipLabel  | DiegoS@S05xf.onmicrosoft.com | LidiaH@S05xf.onmicrosoft.com | [URGENT] Personnel File Access Code | 1                               |

This subject line was mentioned in the scenario description. To proceed, I'd like to find out whether this is a device code attack.

To confirm:

```
UserId: "LidiaH@s05xf.onmicrosoft.com" AND @timestamp>"2023-11-21T07:27:31"
```

| Time                        | UserId                       | Operation                                                | ResultStatus | ClientIP                                |
| --------------------------- | ---------------------------- | -------------------------------------------------------- | ------------ | --------------------------------------- |
| Nov 21, 2023 @ 07:30:16.000 | LidiaH@S05xf.onmicrosoft.com | UserLoginFailed                                          | Failed       | 150.158.135.188                         |
| Nov 21, 2023 @ 07:34:04.000 | LidiaH@S05xf.onmicrosoft.com | UserLoginFailed                                          | Success      | 96.0.102.2                              |
| Nov 21, 2023 @ 07:34:04.000 | LidiaH@S05xf.onmicrosoft.com | UserLoginFailed                                          | Success      | 96.0.102.2                              |
| Nov 21, 2023 @ 07:34:07.000 | LidiaH@S05xf.onmicrosoft.com | UserLoggedIn                                             | Success      | 96.0.102.2                              |
| Nov 21, 2023 @ 07:35:12.000 | LidiaH@S05xf.onmicrosoft.com | UserLoginFailed                                          | Success      | 96.0.102.2                              |
| Nov 21, 2023 @ 07:35:12.000 | LidiaH@S05xf.onmicrosoft.com | UserLoggedIn                                             | Success      | 96.0.102.2                              |
| Nov 21, 2023 @ 07:35:38.000 | LidiaH@S05xf.onmicrosoft.com | UserLoginFailed                                          | Success      | 96.0.102.2                              |
| Nov 21, 2023 @ 07:35:44.000 | LidiaH@S05xf.onmicrosoft.com | UserLoginFailed                                          | Success      | 96.0.102.2                              |
| Nov 21, 2023 @ 07:35:49.000 | LidiaH@S05xf.onmicrosoft.com | UserLoggedIn                                             | Success      | 96.0.102.2                              |
| Nov 21, 2023 @ 07:38:08.000 | LidiaH@S05xf.onmicrosoft.com | Add owner to application.                                | Success      | -                                       |
| Nov 21, 2023 @ 07:38:08.000 | LidiaH@S05xf.onmicrosoft.com | Add application.                                         | Success      | -                                       |
| Nov 21, 2023 @ 07:38:08.000 | LidiaH@S05xf.onmicrosoft.com | Update application.                                      | Success      | -                                       |
| Nov 21, 2023 @ 07:38:10.000 | LidiaH@S05xf.onmicrosoft.com | Update application – Certificates and secrets management | Success      | -                                       |
| Nov 21, 2023 @ 07:40:50.000 | LidiaH@S05xf.onmicrosoft.com | MailItemsAccessed                                        | Succeeded    | -                                       |
| Nov 21, 2023 @ 10:34:09.000 | LidiaH@S05xf.onmicrosoft.com | MailItemsAccessed                                        | Succeeded    | -                                       |
| Nov 21, 2023 @ 10:34:09.000 | LidiaH@S05xf.onmicrosoft.com | UserLoginFailed                                          | Failed       | 174.246.128.195                         |
| Nov 21, 2023 @ 10:34:45.000 | LidiaH@S05xf.onmicrosoft.com | UserLoginFailed                                          | Failed       | 2600:100c:b231:2fa1:51da:f2cc:742d:3927 |
| Nov 21, 2023 @ 11:15:44.000 | LidiaH@S05xf.onmicrosoft.com | MailItemsAccessed                                        | Succeeded    | -                                       |

**Q10. LidiaH: What is the subject of the message the attacker sent to LidiaH?**

See the second table in Q6.

**Q11. LidiaH Spearphish: How did the attacker likely gain access to LidiaH's account?**

Based on the email that was sent, this was likely a device code phishing attack.

**Q12. Persistence: What steps did the attacker take to establish a level of persistence?**

When we review the second table in Q9, we see that the attacker created an application, added the user LidiaH as an owner, and also added an application secret.

**Q13. App Registration: What is the display name of the application registration the attacker created within the tenant?**

We can learn this by reviewing the "Add application" operation event details.

**Q14. App Redirect: What domain did the attacker use for the redirect address of the application?**

We can also learn this by reviewing the "Add application" operation event details!
