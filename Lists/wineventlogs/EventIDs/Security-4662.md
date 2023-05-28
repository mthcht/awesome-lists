# 4662 - An operation was performed on an object

## Description
Event ID 4662 is crucial for tracking access to critical objects within Active Directory, including high-value targets like the AdminSDHolder object and trust objects. It captures attempts to perform specific operations, such as Write Property or Control Access, on these vital Active Directory objects. The Event ID is generated for any access attempts to a directory service object with an assigned Security Access Control List (SACL).

This event becomes particularly significant when investigating operations that involve manipulation of security-sensitive attributes, such as unixUserPassword, ms-PKI-AccountCredential or when alterations are made to access control lists of domain objects.

By monitoring Event ID 4662, organizations can effectively identify and respond to various threats, including **DCSYNC attacks**, attempts to extract LSA secret DPAPI domain backup keys or illicit replication of the ntds.dit file.

## Documentation:
- microsoft: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662

### Fields list for 4662:
- System fields:
  - Provider: The name of the provider that generated the event log. In this case, "Microsoft-Windows-Security-Auditing." (String)
  - Guid: The globally unique identifier (GUID) associated with the provider. (String)
  - EventID: The specific event identifier for Event ID 4662. (Integer)
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
  - SubjectUserSid: The security identifier (SID) of the subject user who initiated the operation. (String)
  - SubjectUserName: The username of the subject user. (String)
  - SubjectDomainName: The domain name of the subject user. (String)
  - SubjectLogonId: The logon ID of the subject user. (Hexadecimal)
  - ObjectServer: The name of the object server involved in the event. (String)
  - ObjectType: The type of the object that the operation was performed on. (GUID)
  - ObjectName: The name or identifier of the object. (String)
  - OperationType: The type of operation that was performed on the object. (String)
  - HandleId: The identifier of the handle associated with the operation. (Hexadecimal)
  - AccessList: The access control list (ACL) associated with the object. (String)
  - AccessMask: The access mask indicating the specific permissions granted or denied. (Hexadecimal)
  - Properties: The properties or attributes of the object that were modified during the operation. (String)
  - AdditionalInfo: Additional information related to the event, if available. (String)
  - AdditionalInfo2: Additional information field, if available. (String)

## Detection opportunities with 4662:
*Please note that the following use cases may not be straightforward to implement and could potentially generate false positives. Some of them may be more suitable for creating dashboards rather than specific detection rules. It's important to understand that this is not a comprehensive guide on implementing each use case. Instead, each page dedicated to an EventID serves as an overview of possible detection opportunities and helps identify which EventIDs should be integrated into your monitoring strategy.*

- Track interactions with Active Directory object attributes that house sensitive information, including credentials and decryption keys. Key attributes to monitor encompass unixUserPassword, ms-PKI-AccountCredentials and msPKI-CredentialRoamingTokens. These attributes hold critical data, and any unauthorized access or alterations can pose a severe security risk.
  - `ms-PKI-AccountCredentials` attribute (b8dfa744-31dc-4ef1-ac7c-84baf7ef9da7) https://learn.microsoft.com/en-us/windows/win32/adschema/a-mspkiaccountcredentials
  - `unixUserPassword` attribute (612cb747-c0e8-4f92-9221-fdd5f15b550d) https://learn.microsoft.com/en-us/windows/win32/adschema/a-unixuserpassword
  - `ms-PKI-Credential-Roaming-Tokens` attribute (b7ff5a38-0818-42b0-8110-d3d154c97f24) https://learn.microsoft.com/en-us/windows/win32/adschema/a-mspki-credentialroamingtokens

- Detecting **DCSYNC Attacks** involves monitoring requests made to the following entities (refer to the community detection rules at the end of this page for more details on implementing them with the required filters)
  - `DS-Replication-Get-Changes` attribute (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2) https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes
  - `DS-Replication-Get-Changes-All` attribute (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2) https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all
  - `DS-Replication-Get-Changes-In-Filtered-Set` attribute (89e95b76-444d-4c62-991a-0facbeda640c) https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-in-filtered-set
  - `DS-Install-Replica extended right` attribute (9923a32a-3607-11d2-b9be-0000f87a36b2) https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-install-replica
  - `Domain-DNS class WRITE_DAC` attribute (19195a5b-6da0-11d0-afd3-00c04fd930c9) https://learn.microsoft.com/en-us/windows/win32/adschema/c-domaindns

- During a DCSync command, the attacker exploits the DS-Replication-Get-changes-All extended right (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2) in the **Domain-DNS** class to retrieve data for replication to a non-domain controller user or system. This activity triggers the logging of Event ID 4662 on the targeted domain controller, providing a detection opportunity:
  - Monitor occurrences of `WRITE_DAC` modifications to a domain object, in this case we should see "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" and "19195a5b-6da0-11d0-afd3-00c04fd930c9" on DCs (The WRITE_DAC permission pertains to the ability to alter access control lists of a domain object)
 
- Monitors instances of domain user access originating from a non-machine account (`user!=*$`). When non-machine accounts attempt to engage with domain user accounts, it  could signify unauthorized activity.

- Identifies instances where tools are attempting to retrieve the Local Security Authority (LSA) secret DPAPI domain backup key from Domain Controllers. This detection flags potential intrusions by malicious software seeking to access highly sensitive data by exploiting domain backup keys.

- The extraction of the `ntds.dit` file through synchronization with a legitimate domain controller using the Directory Replication Service Remote Protocol can be recognized. The Event ID 4662 can be used in correlation with other Events to detect such attempts.

- Detect Domain Object Ownership Changes: Monitor for `WRITE_OWNER` operations on a domain object. A WRITE_OWNER event can indicate an attempt to change the owner of a domain object, which can be a significant security issue as it might enable a threat actor to gain control of the object.

- Track Unusual Operations on `AdminSDHolder` Object: The AdminSDHolder object holds a security descriptor that is enforced on all privileged Active Directory accounts. An unauthorized change to the AdminSDHolder object could impact the security of all privileged accounts. Therefore, tracking any operations on the "CN=AdminSDHolder,CN=System,DC=domain,DC=com" object can provide valuable insights.

- Detect Attempts to Bypass Group Managed Service Accounts (GMSA): Keep an eye on any operations that target the `msDS-GroupMSAMembership` attribute. This attribute is involved in GMSA operations, and any unauthorized access attempts might indicate an effort to bypass GMSA protections.

- Identify Unusual Activity on Trust Objects: Monitor operations on trust objects in Active Directory (AD). Trusts are crucial elements of AD infrastructure, enabling users in one domain to access resources in another. Detecting any unusual operations on trust objects can help you identify potential security threats.

- Detect Failed Unauthorized Access (Access Denied):
  - Filter for high-value targets like the AdminSDHolder object mentionned earlier, trust objects and other sensitive objects.
  - Monitor for failed attempts to perform specific operations, such as Write Property or Control Access on these critical objects.
  - Monitor for failed attempts to modify security descriptors, access control lists, or sensitive attributes within Active Directory objects.

- Detecting Attempts to Gain Persistence: Unauthorized modifications to ACLs of Key Domain Objects might suggest attempts to maintain persistence in the environment.

### Some key domain objects to monitor:

While monitoring specific group-related Event IDs can provide more focused information on group modifications, monitoring Event ID 4662 alongside other relevant Event IDs can provide a broader context and comprehensive coverage for monitoring object modifications in Active Directory.

- AdminSDHolder Object:
  - Object: CN=AdminSDHolder,CN=System,DC=domain,DC=com
  - ACL: Monitor any modifications to the security descriptor of the AdminSDHolder object as it impacts the security of all privileged accounts.
- Domain Controllers:
  - Object: CN=Domain Controllers,CN=Users,DC=domain,DC=com
  - ACL: Keep an eye on any modifications to the access control lists of the Domain Controllers container as it houses critical accounts for managing domain controllers.
- Domain Admins Group:
  - Object: CN=Domain Admins,CN=Users,DC=domain,DC=com
  - ACL: Monitor any changes to the security descriptor of the Domain Admins group, which has high privileges within the domain.
- Enterprise Admins Group:
  - Object: CN=Enterprise Admins,CN=Users,DC=domain,DC=com
  - ACL: Keep track of any modifications to the security descriptor of the Enterprise Admins group, which has elevated privileges across the entire forest.
- Schema Admins Group:
  - Object: CN=Schema Admins,CN=Users,DC=domain,DC=com
  - ACL: Monitor any alterations to the security descriptor of the Schema Admins group, which has permissions to modify the Active Directory schema.
- Domain Trusts:
  - Object: CN=System,DC=domain,DC=com (or specific trust objects)
  - ACL: Keep an eye on any modifications to the access control lists of domain trust objects as they control access between domains and can be potential targets for unauthorized changes.
- Built-in Administrators Group:
  - Object: CN=Builtin,DC=domain,DC=com
  - ACL: Monitor any modifications to the security descriptor of the Built-in Administrators group, which has full control over the domain.
- Domain Computers Group:
  - Object: CN=Computers,DC=domain,DC=com
  - ACL: Keep track of any changes to the access control lists of the Domain Computers container as it contains computer accounts in the domain.
- Domain Users Group:
  - Object: CN=Users,DC=domain,DC=com
  - ACL: Monitor any alterations to the security descriptor of the Domain Users group, which represents all user accounts in the domain.
- Domain Guests Group:
  - Object: CN=Guests,DC=domain,DC=com
  - ACL: Keep an eye on any modifications to the access control lists of the Domain Guests group, which represents guest accounts in the domain.
- Domain Name System (DNS) Zones:
  - Object: CN=MicrosoftDNS,DC=DomainDnsZones,DC=domain,DC=com (or specific DNS zone objects)
  - ACL: Monitor any changes to the security descriptors of DNS zone objects as they control access to DNS zones within the domain.

### Community rules using 4662: 
While it might not be possible to incorporate all of the detection opportunities i've mentioned, I'd highly recommend looking into existing detection rules to enhance your security monitoring capabilities. For this, the community rules available on platforms like Splunk, Elastic, and Sigma repositories are excellent resources.
  - https://github.com/search?q=%28repo%3ASigmaHQ%2Fsigma+OR+repo%3Asplunk%2Fsecurity_content++OR+repo%3Aelastic%2Fdetection-rules%29+4662&type=code
