rule MonitoringTool_AndroidOS_Ceshark_A_300152_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Ceshark.A!MTB"
        threat_id = "300152"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Ceshark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CellSharkContacts" ascii //weight: 1
        $x_1_2 = "PUSH_CONTACTS" ascii //weight: 1
        $x_1_3 = "toSharknet" ascii //weight: 1
        $x_1_4 = "Setting cell shark to operational mode" ascii //weight: 1
        $x_1_5 = "Registering SMS observer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

