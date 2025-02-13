rule MonitoringTool_AndroidOS_Dinolog_A_334602_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Dinolog.A!MTB"
        threat_id = "334602"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Dinolog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HackingKeyBoard" ascii //weight: 1
        $x_1_2 = "recordCharacter" ascii //weight: 1
        $x_1_3 = "saveCharacterToDatabase" ascii //weight: 1
        $x_1_4 = "getHackingStatus" ascii //weight: 1
        $x_1_5 = "hack/hackit/pankaj/keyboardlisten" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

