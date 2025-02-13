rule MonitoringTool_AndroidOS_Spyset_A_299312_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Spyset.A!MTB"
        threat_id = "299312"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Spyset"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SpyMainView" ascii //weight: 1
        $x_1_2 = "removeUpdates" ascii //weight: 1
        $x_1_3 = "SpyService$MyLocationListener" ascii //weight: 1
        $x_1_4 = "SpyService" ascii //weight: 1
        $x_1_5 = "SpySatPrefs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

