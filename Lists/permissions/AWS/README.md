## Role Assignments events in AWS cloudtrail logs:
- `AttachRolePolicy`: Indicates that a policy has been attached to a role.
- `CreateRole`: Indicates that a new IAM role has been created.
- `AddRoleToInstanceProfile`: Indicates that a role has been added to an instance profile.
- `PutRolePolicy`: Indicates that an inline policy has been added to a role.
- `UpdateAssumeRolePolicy`: Indicates that the assume role policy document for a role has been updated.
- `CreateInstanceProfile`: Indicates that an instance profile has been created, which may include role assignments.

### Example json log format for AttachRolePolicy:
```json
{
   "awsRegion": "us-east-1",
   "eventCategory": "Management",
   "eventID": "xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
   "eventName": "AttachRolePolicy",
   "eventSource": "iam.amazonaws.com",
   "eventTime": "2024-08-10T16:02:06Z",
   "eventType": "AwsApiCall",
   "eventVersion": "1.09",
   "managementEvent": true,
   "readOnly": false,
   "recipientAccountId": "xxxxxxxxxxxx",
   "requestID": "xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
   "requestParameters": {
     "policyArn": "arn:aws:iam::aws:policy/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
     "roleName": "datascience-xxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
   },
   "responseElements": null,
   "sourceIPAddress": "cloudformation.amazonaws.com",
   "userAgent": "cloudformation.amazonaws.com",
   "userIdentity": {
     "accessKeyId": "XXXXXXXXXXXXXXXXXXXX",
     "accountId": "xxxxxxxxxxxx",
     "arn": "arn:aws:sts::xxxxxxxxxxxx:assumed-role/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/i-xxxxxxxxxxxxxxxxx",
     "invokedBy": "cloudformation.amazonaws.com",
     "principalId": "xxxxxxxxxxxxxxxxxxxxx:i-xxxxxxxxxxxxxxxxx",
     "sessionContext": {},
     "type": "AssumedRole"
   }
}
```

Fields in Splunk:
- The initiator: `userIdentity.arn`
- the policy added to the role: `requestParameters.policyArn`
- the role: `requestParameters.roleName`

### Example json log format for AddRoleToInstanceProfile:

```json
{
   "awsRegion": "us-east-1",
   "eventCategory": "Management",
   "eventID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
   "eventName": "AddRoleToInstanceProfile",
   "eventSource": "iam.amazonaws.com",
   "eventTime": "2024-06-20T08:17:03Z",
   "eventType": "AwsApiCall",
   "eventVersion": "1.09",
   "managementEvent": true,
   "readOnly": false,
   "recipientAccountId": "xxxxxxxxxxxx",
   "requestID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
   "requestParameters": {
     "instanceProfileName": "AdministratorAccess",
     "roleName": "AdministratorAccess"
   },
   "responseElements": null,
   "sessionCredentialFromConsole": true,
   "sourceIPAddress": "xxx.xxx.xxx.xxx",
   "tlsDetails": {
     "cipherSuite": "TLS_AES_128_GCM_SHA256",
     "clientProvidedHostHeader": "iam.amazonaws.com",
     "tlsVersion": "TLSv1.3"
   },
   "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
   "userIdentity": {
     "accessKeyId": "XXXXXXXXXXXXXXXXXXXX",
     "accountId": "xxxxxxxxxxxx",
     "arn": "arn:aws:sts::xxxxxxxxxxxx:assumed-role/ADFS-Admin/xxxxxxxxxxxxxxxxxxxx",
     "principalId": "xxxxxxxxxxxxxxxxxxxxx:xxxxxxxxxxxxxxxxxxxx",
     "sessionContext": {},
     "type": "AssumedRole"
   }
}
```

Fields in Splunk:
- The initiator: `userIdentity.arn`
- the role: `requestParameters.roleName` is the role that was attempted to be added
- to target: `requestParameters.instanceProfileName` to determine to which instance profile the role was added.
