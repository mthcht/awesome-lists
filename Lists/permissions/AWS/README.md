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
{
   "awsRegion": "us-east-1",
   "errorCode": "LimitExceededException",
   "errorMessage": "Cannot exceed quota for InstanceSessionsPerInstanceProfile: 1",
   "eventCategory": "Management",
   "eventID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
   "eventName": "AddRoleToInstanceProfile",
   "eventSource": "iam.amazonaws.com",
   "eventTime": "2024-05-14T15:42:10Z",
   "eventType": "AwsApiCall",
   "eventVersion": "1.09",
   "managementEvent": true,
   "readOnly": false,
   "recipientAccountId": "xxxxxxxxxxxx",
   "requestID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
   "requestParameters": {
     "instanceProfileName": "AmazonSSMRoleForInstancesQuickSetup",
     "roleName": "AmazonSSMRoleForInstancesQuickSetup"
   },
   "responseElements": null,
   "sourceIPAddress": "xxx.xxx.xxx.xxx",
   "tlsDetails": {
     "cipherSuite": "TLS_AES_128_GCM_SHA256",
     "clientProvidedHostHeader": "iam.amazonaws.com",
     "tlsVersion": "TLSv1.3"
   },
   "userAgent": "Boto3/1.34.93 md/Botocore#1.34.93 md/internal ua/2.0 os/linux#5.10.214-222.855.amzn2.x86_64 md/arch#x86_64 lang/python#3.8.19 md/pyimpl#CPython exec-env/AWS_Lambda_python3.8 cfg/retry-mode#adaptive Botocore/1.34.93",
   "userIdentity": {
     "accessKeyId": "XXXXXXXXXXXXXXXXXXXX",
     "accountId": "xxxxxxxxxxxx",
     "arn": "arn:aws:sts::xxxxxxxxxxxx:assumed-role/AWS-QuickSetup-xxxxxxxxxxxxxxxxxx/Automation-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
     "principalId": "xxxxxxxxxxxxxxxxxxxxx:Automation-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
     "sessionContext": {
       "attributes": {
         "creationDate": "2024-05-14T15:42:09Z",
         "mfaAuthenticated": false
       },
       "sessionIssuer": {
         "accountId": "xxxxxxxxxxxx",
         "arn": "arn:aws:iam::xxxxxxxxxxxx:role/AWS-QuickSetup-xxxxxxxxxxxxxxxxxx",
         "principalId": "xxxxxxxxxxxxxxxxxxxxx",
         "type": "Role",
         "userName": "AWS-QuickSetup-xxxxxxxxxxxxxxxxxx"
       }
     },
     "type": "AssumedRole"
   }
}
```

Fields in Splunk:
- The initiator: `userIdentity.arn`
- the role: `requestParameters.roleName` is the role that was attempted to be added
- to target: `requestParameters.instanceProfileName` to determine to which instance profile the role was added.
