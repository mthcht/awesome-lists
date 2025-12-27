rule HackTool_Linux_PenteraPayload_A_2147947437_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PenteraPayload.A"
        threat_id = "2147947437"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PenteraPayload"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Actions.DBServiceTerminationAction.GetOsCommands" ascii //weight: 1
        $x_1_2 = "Actions.BackupServiceTerminationAction.GetOsCommands" ascii //weight: 1
        $x_1_3 = "Actions.EDRServiceTerminationAction.GetOsCommands" ascii //weight: 1
        $x_1_4 = "Actions.FilesEncryptionAction.EncryptFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_PenteraPayload_B_2147947438_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PenteraPayload.B"
        threat_id = "2147947438"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PenteraPayload"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Actions/BackupServiceTerminationAction.go" ascii //weight: 1
        $x_1_2 = "Actions/DBServiceTerminationAction.go" ascii //weight: 1
        $x_1_3 = "Actions/EDRTerminationAction.go" ascii //weight: 1
        $x_1_4 = "Actions/SendInjectedStringsAction.go" ascii //weight: 1
        $x_1_5 = "Actions/FilesEncryptionAction.go" ascii //weight: 1
        $x_1_6 = "Actions/OsCommandsAction.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

