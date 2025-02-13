rule MonitoringTool_AndroidOS_Sgps_A_340519_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Sgps.A!MTB"
        threat_id = "340519"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Sgps"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HiddenUpload" ascii //weight: 1
        $x_1_2 = "DeviceInfoAsyncTask" ascii //weight: 1
        $x_1_3 = "YourAsyncTask_PhoneWipe" ascii //weight: 1
        $x_1_4 = "getSMSDetail" ascii //weight: 1
        $x_5_5 = "SpyCall" ascii //weight: 5
        $x_1_6 = "saveBROWSER_PreCount" ascii //weight: 1
        $x_5_7 = "smsgpspy" ascii //weight: 5
        $x_5_8 = "main_spy" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

