rule MonitoringTool_AndroidOS_Phonesher_B_340520_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Phonesher.B!MTB"
        threat_id = "340520"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Phonesher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Phone Wipe" ascii //weight: 1
        $x_1_2 = "SIM Info" ascii //weight: 1
        $x_10_3 = "phonesher" ascii //weight: 10
        $x_1_4 = "KEY_IS_STOP_MONITORING" ascii //weight: 1
        $x_1_5 = "getPreparedContactLogs" ascii //weight: 1
        $x_1_6 = "Browser Records" ascii //weight: 1
        $x_1_7 = "UPLOAD_ALL_LOGS" ascii //weight: 1
        $x_10_8 = "com.retina.ps.v2" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

