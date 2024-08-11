## Monitor important roles assigned in Entra ID (Azure AD)

### audit logs 

*for splunk users, the logs are often collected in sourcetype azure:aad:audit by default*

Assigned roles can be found with `category="RoleManagement" activityDisplayName="Add member to role" operationType="Assign"`

json format example:
```json
{
  "id": "Directory_12345678-abcd-1234-abcd-1234567890ab_XYZ_987654321",
  "category": "RoleManagement",
  "correlationId": "12345678-abcd-1234-abcd-1234567890ab",
  "result": "success",
  "resultReason": "",
  "activityDisplayName": "Add member to role",
  "activityDateTime": "2024-08-09T12:34:56.789012Z",
  "loggedByService": "Core Directory",
  "operationType": "Assign",
  "initiatedBy": {
    "user": null,
    "app": {
      "appId": null,
      "displayName": "ExampleApp",
      "servicePrincipalId": "abcdef12-3456-7890-abcd-ef1234567890",
      "servicePrincipalName": null
    }
  },
  "targetResources": [
    {
      "id": "abcdef12-3456-7890-abcd-ef1234567890",
      "displayName": null,
      "type": "User",
      "userPrincipalName": "john.doe@example.com",
      "groupType": null,
      "modifiedProperties": [
        {
          "displayName": "Role.ObjectID",
          "oldValue": null,
          "newValue": "\"12345678-abcd-1234-abcd-1234567890ab\""
        },
        {
          "displayName": "Role.DisplayName",
          "oldValue": null,
          "newValue": "\"Application Developer\""
        },
        {
          "displayName": "Role.TemplateId",
          "oldValue": null,
          "newValue": "\"abcd1234-5678-90ab-cdef-1234567890ab\""
        },
        {
          "displayName": "Role.WellKnownObjectName",
          "oldValue": null,
          "newValue": "\"ApplicationDevelopers\""
        }
      ]
    },
    {
      "id": "12345678-abcd-1234-abcd-1234567890ab",
      "displayName": null,
      "type": "Role",
      "userPrincipalName": null,
      "groupType": null,
      "modifiedProperties": []
    }
  ],
  "additionalDetails": []
}

```

### Graph API
fixme
