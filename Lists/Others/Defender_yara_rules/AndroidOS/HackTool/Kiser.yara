rule HackTool_AndroidOS_Kiser_A_2147818676_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Kiser.A!MTB"
        threat_id = "2147818676"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Kiser"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {12 02 34 52 0a 00 22 00 ?? ?? 70 20 ?? ?? 10 00 11 00 d1 00 00 00 6e 10 ?? ?? 04 00 0a 03 6e 20 ?? ?? 30 00 0a 03 6e 20 ?? ?? 34 00 0a 03 50 03 01 02 d8 02 02 01}  //weight: 1, accuracy: Low
        $x_1_2 = "AvApplicationsMonitor" ascii //weight: 1
        $x_1_3 = "DataWipeFoldersStorage" ascii //weight: 1
        $x_1_4 = "SpamListItem" ascii //weight: 1
        $x_1_5 = "locateAndSendSms" ascii //weight: 1
        $x_1_6 = "backup_at_block" ascii //weight: 1
        $x_1_7 = "at_device_blocked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

