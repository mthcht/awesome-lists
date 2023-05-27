# 4662 - An operation was performed on an object

## Description for SOC team
Event ID 4662 plays a crucial role in tracking access to critical objects within Active Directory, including high-value targets like the AdminSDHolder object and trust objects. It captures attempts to perform specific operations, such as Write Property or Control Access on these vital Active Directory objects.

This event becomes particularly significant when investigating operations that involve manipulation of security-sensitive attributes, such as unixUserPassword, ms-PKI-AccountCredential or when alterations are made to access control lists of domain objects.

By monitoring Event ID 4662, organizations can effectively identify and respond to various threats, including **DCSYNC attacks**, attempts to extract LSA secret DPAPI domain backup keys or illicit replication of the ntds.dit file.

## Documentation:
- https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662

## Detection Use cases with 4662:
- Track interactions with Active Directory object attributes that house sensitive information, including credentials and decryption keys. Key attributes to monitor encompass unixUserPassword, ms-PKI-AccountCredentials, and msPKI-CredentialRoamingTokens. These attributes hold critical data, and any unauthorized access or alterations can pose a severe security risk.
- Detect DCSYNC Attacks
- Monitors occurrences of WRITE_DAC modifications to a domain object. The WRITE_DAC permission pertains to the ability to alter access control lists (ACLs) of a domain object, which can indicate potential security breaches if performed without authorization.
- Monitors instances of domain user access originating from a non-machine account. This surveillance detects potential anomalies when non-machine accounts attempt to engage with domain user accounts, which could signify unauthorized activity.
- Identifies instances where tools are attempting to retrieve the Local Security Authority (LSA) secret DPAPI domain backup key from Domain Controllers. This detection flags potential intrusions by malicious software seeking to access highly sensitive data by exploiting domain backup keys.
- Recognizes instances where the ntds.dit file is being extracted through synchronization with a legitimate domain controller using the Directory Replication Service (DRS) Remote Protocol. This flags possible attempts to illegitimately access Active Directory data by masquerading as a legitimate domain controller.
- Detect Domain Object Ownership Changes: Monitor for WRITE_OWNER operations on a domain object. A WRITE_OWNER event can indicate an attempt to change the owner of a domain object, which can be a significant security issue as it might enable a threat actor to gain control of the object.
- Track Unusual Operations on AdminSDHolder Object: The AdminSDHolder object holds a security descriptor that is enforced on all privileged Active Directory accounts. An unauthorized change to the AdminSDHolder object could impact the security of all privileged accounts. Therefore, tracking any operations on the "CN=AdminSDHolder,CN=System,DC=domain,DC=com" object can provide valuable insights.
- Detect Attempts to Bypass Group Managed Service Accounts (GMSA): Keep an eye on any operations that target the msDS-GroupMSAMembership attribute. This attribute is involved in GMSA operations, and any unauthorized access attempts might indicate an effort to bypass GMSA protections.
- Identify Unusual Activity on Trust Objects: Monitor operations on trust objects in Active Directory (AD). Trusts are crucial elements of AD infrastructure, enabling users in one domain to access resources in another. Detecting any unusual operations on trust objects can help you identify potential security threats.
- Detecting Attempts to Gain Persistence: Unauthorized modifications to ACLs of Key Domain Objects might suggest attempts to maintain persistence in the environment.

community rules using 4662: 
- https://github.com/search?q=%28repo%3ASigmaHQ%2Fsigma+OR+repo%3Asplunk%2Fsecurity_content++OR+repo%3Aelastic%2Fdetection-rules%29+4662&type=code
