## Role Assignments events in AWS cloudtrail logs:
- `AttachRolePolicy`: Indicates that a policy has been attached to a role.
- `CreateRole`: Indicates that a new IAM role has been created.
- `AddRoleToInstanceProfile`: Indicates that a role has been added to an instance profile.
- `PutRolePolicy`: Indicates that an inline policy has been added to a role.
- `UpdateAssumeRolePolicy`: Indicates that the assume role policy document for a role has been updated.
- `CreateInstanceProfile`: Indicates that an instance profile has been created, which may include role assignments.

Example json log format for AttachRolePolicy:
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

In SPlunk:
- The initiator: `userIdentity.arn`
- the policy added to the role: `requestParameters.policyArn`
- the role: `requestParameters.roleName`
