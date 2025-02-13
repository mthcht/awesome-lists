rule HackTool_AndroidOS_DDos_A_2147849807_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/DDos.A!MTB"
        threat_id = "2147849807"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "DDos"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/scott/herbert/AnDOSid" ascii //weight: 1
        $x_1_2 = "/AsyncDOS" ascii //weight: 1
        $x_1_3 = "/DOService" ascii //weight: 1
        $x_1_4 = "addNewDoS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_AndroidOS_DDos_B_2147902249_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/DDos.B!MTB"
        threat_id = "2147902249"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "DDos"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com/droidproject/ddos" ascii //weight: 2
        $x_1_2 = "DOSLock" ascii //weight: 1
        $x_1_3 = "lockClicked" ascii //weight: 1
        $x_1_4 = "dosService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

