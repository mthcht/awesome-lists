rule TrojanSpy_AndroidOS_ProjSpy_A_2147819608_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/ProjSpy.A!MTB"
        threat_id = "2147819608"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "ProjSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RepeatTask.uploadFiles" ascii //weight: 1
        $x_1_2 = "PhoneMonitor" ascii //weight: 1
        $x_1_3 = "notifyServerOfCommandExecution" ascii //weight: 1
        $x_1_4 = "ForceWifiOnForRecordUpload" ascii //weight: 1
        $x_1_5 = "/getcommands.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

