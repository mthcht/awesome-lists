rule HackTool_MacOS_BloodHound_A_2147832769_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/BloodHound.A!MTB"
        threat_id = "2147832769"
        type = "HackTool"
        platform = "MacOS: "
        family = "BloodHound"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bloodhoundad/azurehound" ascii //weight: 1
        $x_1_2 = "QK40JKJyMdUDz+h+xvCsru/bJhvG0UxvePV0ufL/AcE=" ascii //weight: 1
        $x_1_3 = "fY5BOSpyZCqRo5OhCuC+XN+r/bBCmeuuJtjz+bCNIf8=" ascii //weight: 1
        $x_1_4 = "tjENF6MfZAg8e4ZmZTeWaWiT2vXtsoO6+iuOjFhECwM=" ascii //weight: 1
        $x_1_5 = "fZHgsYlfvtyqToslyjUt3VOPF4J7aK/3MPcK7xp3PDk=" ascii //weight: 1
        $x_1_6 = "D8xgwECY7CYvx+Y2n4sBz93Jn9JRvxdiyyo8CTfuKaY=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_BloodHound_B_2147956182_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/BloodHound.B!MTB"
        threat_id = "2147956182"
        type = "HackTool"
        platform = "MacOS: "
        family = "BloodHound"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/home/runner/work/AzureHound/AzureHound/main.go" ascii //weight: 1
        $x_1_2 = "/bloodhoundad/azurehound/v2/cmd.Execute" ascii //weight: 1
        $x_1_3 = "/v2/cmd.listVirtualMachineUserAccessAdmins" ascii //weight: 1
        $x_1_4 = "/v2/models.KeyVaultUserAccessAdmins" ascii //weight: 1
        $x_1_5 = "/client.(*azureClient).ListAzureADUsers" ascii //weight: 1
        $x_1_6 = "/v2/cmd.listWebAppRoleAssignments" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

