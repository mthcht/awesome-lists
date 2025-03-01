rule MonitoringTool_AndroidOS_Mspy_C_353352_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Mspy.C!MTB"
        threat_id = "353352"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Mspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "performDataGatherer" ascii //weight: 1
        $x_1_2 = "mspy" ascii //weight: 1
        $x_1_3 = "mspyonline" ascii //weight: 1
        $x_1_4 = "KEYLOGS_WIFI_ONLY" ascii //weight: 1
        $x_1_5 = "SMS_WIFI_ONLY" ascii //weight: 1
        $x_1_6 = "LocationGatheringService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

