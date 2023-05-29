# 5145 - A network share object was checked to see whether client can be granted desired access

## Description
This event is generated every time an application attempts to access a network share object, such as a file or folder.
If an access request is either allowed or denied based on a sharing access control list, or if no more shared resources are available, this event is generated.
It's important to note that failure events are generated only when access is denied at the file share level. No events are generated if access was denied at the file system (NTFS) level.

Monitoring Event ID 5145 is crucial as it enables the identification of potential security incidents associated with unauthorized access attempts, discovery scans, lateral movement (such as **PSEXEC-like tools**) and data exfiltration on network share objects.

## 5140 vs 5145 ?
The Event ID 5140 captures successful access to network share objects, including direct access and file system-level access, while Event ID 5145 focuses specifically on application-based access attempts, potentially leaving out cases where direct or non-application access occurs.

- Some Use cases examples that would be relevant for 5140 but not for 5145:
  - Manual Remote File inclusions attempts
  - Unauthorized access to sensitive files when an attacker directly accesses them through network shares without making an application-level access attempt.
  - Monitoring the manual mounting of network shares, especially external IP share access, can be interesting.
  - Manual Data Exfiltration to remote shares 

Monitoring both events provides a more comprehensive view of access activity on network shares, check the page of [5140](https://github.com/mthcht/awesome-lists/blob/main/Lists/wineventlogs/EventIDs/Security-5140.md)

## Documentation:
- microsoft: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5145

### Fields list for 5145

- System fields:
  - Provider: The name of the provider that generated the event log, "Microsoft-Windows-Security-Auditing." (String)
  - Guid: The globally unique identifier (GUID) associated with the provider. (String)
  - EventID: The specific event identifier for Event ID 5145. (Integer)
  - Version: The version number of the event log. (Integer)
  - Level: The severity level of the event. (Integer)
  - Task: The task associated with the event. (Integer)
  - Opcode: The opcode or operation code associated with the event. (Integer)
  - Keywords: The keywords assigned to the event. (Hexadecimal)
  - TimeCreated: The timestamp indicating when the event occurred. (Date and Time)
  - EventRecordID: The unique identifier assigned to the event record. (Integer)
  - Correlation: Additional information related to event correlation. (String)
  - Execution: Details about the execution context of the event, such as process ID and thread ID. (String)
  - Channel: The channel or log category where the event is recorded. In this case, "Security." (String)
  - Computer: The name of the computer where the event occurred. (String)
  - Security: Additional security-related information associated with the event. (String)

- EventData fields:
  - SubjectUserSid: The security identifier (SID) of the user who initiated the action. (String)
  - SubjectUserName: The username of the user who initiated the action. (String)
  - SubjectDomainName: The domain name of the user who initiated the action. (String)
  - SubjectLogonId: The logon ID of the user who initiated the action. (Hexadecimal)
  - ObjectType: The type of the accessed object, typically "File" or "Directory". (String)
  - IpAddress: The IP address of the client computer that initiated the access attempt. (String)
  - IpPort: The port number used by the client computer. (Integer)
  - ShareName: The UNC path of the accessed network share. (String)
  - ShareLocalPath: The local path of the accessed network share. (String)
  - RelativeTargetName: The name of the accessed object. (String)
  - AccessMask: The hexadecimal mask indicating the requested access rights. (Hexadecimal)
  - AccessList: The access control list (ACL) associated with the object. (String)
  - AccessReason: The reason or explanation for the access granted or denied. (String)


## Detection opportunities with 5145:
*Please note that the following use cases may not be straightforward to implement and could potentially generate false positives. Some of them may be more suitable for creating dashboards rather than specific detection rules. It's important to understand that this is not a comprehensive guide on implementing each use case. Instead, each page dedicated to an EventID serves as an overview of possible detection opportunities and helps identify which EventIDs should be integrated into your monitoring strategy.*

- Honeypots
  - Create honeypot shares on your file server by setting up shares with enticing names that mimic sensitive directories or files. These honeypots act as decoys to lure potential unauthorized access attempts. 
  - Monitor Event ID 5145 (and 5140) entries specifically for access to these honeypot share names. Any access should trigger an alert, indicating potential unauthorized activity and providing an early warning of an intrusion attempt.

- Access to critical files or directories:
  - Implement a proactive approach similar to the honeypot detection by creating a list of critical files and directories within your network shares. These critical assets can include sensitive information, confidential documents, or important system files.
Continuously monitor Event ID 5145 entries and compare the accessed file or directory paths against a predefined list of authorized assets and users. This comparison helps identify any potential instances of unauthorized access to critical information.

- Search for external IP address in ShareName UNC path or the IpAddress field (collection/exfiltration). (It would be very unlikely to see an external IP address in the IpAddress field unless you exposed your file server on the internet)

- Access denied
  - Monitor for Event ID 5145 entries where a specific source IP or user account is consistently associated with a high number of access denied events. Look for instances where the AccessMask field indicates access denied (AccessMask=0x0).This pattern of frequent access denied events can be indicative of scanning activity or unauthorized reconnaissance attempts, where an attacker is systematically attempting to access various network share objects.

- Traffic anomaly detection:
  - High volume of access events within a short period of time or access occurring outside of normal business hours. Deviations from normal access patterns can be detected by comparing the frequency and timing of Event ID 5145 entries against baseline or predefined thresholds which can be established using advanced search capabilities or machine learning techniques provided by tools like Splunk [MLTK](https://splunkbase.splunk.com/app/2890).

- Keywords detections on file names using the collection from https://github.com/mthcht/ThreatHunting-Keywords

- Privilege escalation and Accesses rights:
  - Monitor the source IP addresses adding files under `\\\\*\\SYSVOL*` with `AccessMask` value `0x2`
  - Inspect the AccessList field within Event ID 5145 entries, which represents the access control list (ACL) associated with the network share object. Look for modifications or additions to the ACL entries, such as new access control entries [ACEs](https://learn.microsoft.com/en-gb/windows/win32/secauthz/ace-strings) being added or permissions being modified, which may indicate attempts to escalate privileges on the network share object. (For example, an ACE string like `D:(A;;KA;;;WD)` grants unrestricted Full Access to the "Everyone" group. Monitoring for such access control entries can be highly valuable in detecting potential security risks)
  - Focuse on the Access Request Information\Accesses rights, particularly in cases of failures. Within a dashboard of critical assets monitor these specific critical rights for potential security incidents:
    - WriteData (or AddFile):
      - AccessMask value: 0x2
      - Monitors attempts to write data or add files to a network share object.
    - AppendData (or AddSubdirectory or CreatePipeInstance): 
      - AccessMask value: 0x4
      - Monitors attempts to append data, create subdirectories, or create pipe instances within a network share object.
    - WriteEA:
      - AccessMask value: 0x10
      - Monitors attempts to write extended attributes (EAs) to a network share object.
    - DeleteChild:
      - AccessMask value: 0x40
      - Monitors attempts to delete child objects within a network share, such as files or subdirectories.
    - WriteAttributes:
      - AccessMask value: 0x80
      - Monitors attempts to modify or write attributes of a network share object.
    - DELETE:
      - AccessMask value: 0x10000
      - Monitors attempts to delete a network share object.
    - WRITE_DAC:
      - AccessMask value: 0x40000
      - Monitors attempts to modify the discretionary access control list (DACL) of a network share object.
    - WRITE_OWNER:
      - AccessMask value: 0x80000
      - Monitors attempts to modify the owner of a network share object

- Enumeration:
  - Monitor Event ID 5145 entries for occurrences where the same SubjectUserSid, SubjectUserName, or Computer is associated with multiple network share objects within a short timeframe, including file, folder, and share name enumerations.
    - You could implement four distinct detection rules to capture different scenarios:
      - User Enumerating Shares: Identify instances where a user is accessing or enumerating multiple network shares in a short period of time.
      - User Enumerating Share Objects: Detect situations where a user is accessing or enumerating various objects (files, folders) within multiple network shares within a short timeframe.
      - Computer Enumerating Shares: Monitor for cases where a specific computer is accessing or enumerating multiple network shares consecutively.
      - Computer Enumerating Share Objects: Identify instances where a specific computer is accessing or enumerating objects within multiple network shares within a short span of time.
- Lateral Movovement:
  - **PSEXEC**:
    - Official PSEXEC invocation: The field `RelativeTargetName` contains `*-stdin`, `*-stdout` or `*-stderr`
    - Official PSEXEC invocation: The field `RelativeTargetName` contains `psexecsvc*`
    - Impacket psexec.py invocation: The field `RelativeTargetName` contains `Remcom_Communication`, `RemCom_stdint*`, `RemCom_stderrt*` or `RemCom_stdoutt*` and `ShareName` contains `\\\\*\\IPC$*`
    - Executable dropped in admin$: `ShareName` contains `\\\\*\\Admin$*`, `RelativeTargetName` ends with `*.exe` or `*.dll` and `AccessMask` is `0x2`
    - Monitoring access to IPC$, ADMIN$, and C$ shares can be beneficial for identifying potential lateral movement techniques such as WMI, WinRM, COM, and Impacket (WMI/SMB...). While these accesses may be observed in legitimate administration tasks, it is crucial to enforce good hygiene practices and maintain control over the environment to distinguish between authorized and unauthorized activities.
  - With **WMIEXEC** usage, search for the Event ID 5145 with the field `ShareName` containing `*\\windows\\temp\*` and  `RelativeTargetName` containing `wmi.dll` 

- Credential Access:
  -  Monitor the source IP addresses that access multiple files under the `\\\\*\\SYSVOL*` path within a short timeframe, tools like `Get-GPPPassword` from PowerSploit or `Find-GPOPasswords` can attempt to retrieve GPP and GPO passwords in this path.


Please note that the detection of lateral movement tools like PSEXEC can be done with multiple EventIDs and not just 5145, check out the community detection rules at the end of the page for more complete detections rules involving the Event ID 5145.

If you want a reports on detecting the official psexec, check out the reports from [jpcertcc](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/PsExec.htm)  


### More examples of collection, discovery, lateral movement and exfiltration Hunting ideas: 

#### [ThreatHunting Mindmap](https://github.com/sbousseaden/Slides/tree/master/Hunting%20MindMaps) for EventID 5145 from [@SBousseaden](https://github.com/sbousseaden) 

![5145](https://github.com/mthcht/awesome-lists/assets/75267080/d3b22114-e7d2-400b-ba41-d958adcaaf79)


### Community rules using 5145: 
  - https://github.com/search?q=%28repo%3ASigmaHQ%2Fsigma+OR+repo%3Asplunk%2Fsecurity_content++OR+repo%3Aelastic%2Fdetection-rules%29+5145&type=code
