## Critical Users

This would include a list of individuals who have elevated importance in your organization.

This could be due to their position, the sensitive information they handle, or their access to critical systems.

It is crucial to closely monitor the activities of critical users due to the potential impact of a security breach involving their accounts. A compromise of a critical user's account can potentially grant an attacker access to sensitive information or systems.

The list could include:

- CEO, CFO, CTO: The top-level executives who have the most comprehensive access and whose identities are most likely to be targeted in spear-phishing attacks.
- Team managers: As they often oversee critical operations and potentially have access to sensitive data within their team, their accounts, if compromised, could provide significant leverage to an attacker.
- HR and Finance Managers: They handle sensitive employee and financial data respectively.
- IT Admins: They have elevated privileges that could be used to access or control critical systems.
- Key business unit leaders or project managers: Their accounts may have access to valuable intellectual property.
- Security Team Members: Given their access to the SIEM system and other security products, which contains critical logs and security alerts, they possess a high level of access to sensitive information. A compromise of their accounts could undermine the entire security posture of the organization.
  - Regular SIEM Access Review and Monitoring: Since the Security Team has elevated privileges in the SIEM, it is essential to strictly control and monitor SIEM access. Implement specific detection rules to flag anomalous behavior such as unusual access times, access from unexpected locations, or attempts to modify the SIEM configuration or rule sets.

This list should be tailored to your organization and should consider the various ways in which different users could be "important" or "high-value" in your context.

This list can help prioritize security awareness training:
- Phishing campaigns with specific training on recognizing and responding to phishing attempts, which are often the starting point for attacks
- Web Browsing: Incorporate these users into a dedicated detection rule for unsafe web browsing. Also, teach safe web browsing best practices.
- Strong Password: Enforce a robust password policy for these accounts and encourage the use of an enterprise password manager.
- Social Engineering: Training on recognizing social engineering attempts, which can be used to gain information or manipulate actions. 
- Safe Use of Social Media: Offer guidance on safe information sharing on social media, as personal details can be used in targeted attacks. Additionally, monitor what technical information is shared by the communication or commercial team.
- Bastion Sessions: Monitor server connections made by IT admins (session recording) and train them on best practices for using bastion hosts. Also, set detection rules for unusual activities, such as working outside usual hours, bypassing bastion, unauthorized connections, executed commands, access to critical servers...

Implement detection rules:
- Dedicated SIEM Detection Rules: Develop custom rules for your SIEM, targeting your list of critical users to monitor for potential threats such as data exfiltration, email usurpation, phishing attempts, brute force attacks, access to critical servers, anomalies in user behavior, logins at irregular hours or from unexpected locations, modifications to critical security groups, risky web browsing, and unusual access to sensitive shared resources. Also, include rules designed to detect misuse or abuse of your internal applications, as part of your fraud detection strategy.

And additional security measures:
- Forcing MFA authentication for these users.
- Strict Access Controls: Implement strict access control policies. Grant privileges based on the principle of least privilege (PoLP), where users are given the minimum levels of access necessary to complete their job functions.
- Regular Account Reviews: Conduct regular account reviews to ensure that access privileges remain appropriate to each user's job function, and to check for signs of anomalous activity with your detection rules using this list
- Separation of Duties: As much as possible, avoid a situation where one individual can control an entire process or system, to reduce the potential impact of their account being compromised.
- Active Surveillance by the Cyber Threat Intelligence (CTI) Team: Monitoring of critical users should not be limited to internal activities. The CTI team should proactively track any mention of these users or their credentials in public forums, darknet markets, or data leaks. They should also watch for impersonation attempts on social media platforms like LinkedIn. The goal is to identify threats to these users from external sources before they impact the organization. This process can be aided by threat intelligence platforms and automated alerting for predefined keywords or identifiers associated with these users.
- User Behavior Analytics: Implement User Behavior Analytics to continually assess the behavior of these critical users.
- Incident Response Plan: Ensure that there's a robust incident response plan in place specifically tailored to situations involving these critical users. The plan should outline the steps to take in the event of a security incident, such as a compromised account, to minimize damage and recover quickly.
- Red Teaming Exercises: Regularly conduct red teaming exercises targeting these critical users to test your organization's defenses and the users' ability to respond to an attack. This also helps in identifying potential vulnerabilities and improving security measures.
- Secure methods for sharing informations: Encourage the use of secure and encrypted communication channels for these users, especially when they are dealing with sensitive information.
- Access to Critical Assets: Keep a close track of these users' access to critical business assets. Any change in their access patterns should be flagged and reviewed for potential security implications.
- Control and force updates on the devices of critical users
- Ensure that the devices used by these critical users are equipped with full-disk encryption to safeguard sensitive data in the event of device theft or loss (but it should be apply to all your users)
- Network Segmentation: Consider isolating these users' systems in a separate network zone to limit potential lateral movement of an attacker within the network (could be complicated to implement)
- VPN Usage: Enforce the use of the enterprise VPN whenever they are accessing the organization's systems (should be applied for all the users)
- Threat Hunting sessions: Schedule Threat Hunting sessions targeting these users activities (should be complementary to the detection rules recommanded earlier)
- Secure Backup: Ensure regular secure backups of these users' data to mitigate the risk of data loss in the event of a device compromise.
- Restricted Use of Removable Media: Limit the use of removable media, such as USB drives, on these users' devices, as these can be a source of malware or data exfiltration (should be applied on most of the users of your company)
- Priorize the deployment of an EDR solution on these users devices.


As suggested by [@QueenSquishy](https://github.com/QueenSquishy) `The coolest people build their VIP lists from observed behaviour because if CFO goes on holiday who they going to give his tasks too` and that is a great point ! It can be challenging to track dynamically changing roles and behaviors (risking more FPs), especially when the telltale signs of role-specific behaviors are not clear in the logs. However, if your environment logs enables accurate identification of role changes within your company, start by building a predifined list of a critical users as a solid baseline and you can continue building on top of it with dynamic detections to keep your list updated and accurate.


Any other suggestions are welcome :)
