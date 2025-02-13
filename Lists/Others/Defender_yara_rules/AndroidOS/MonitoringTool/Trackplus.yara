rule MonitoringTool_AndroidOS_Trackplus_A_301099_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Trackplus.A!MTB"
        threat_id = "301099"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Trackplus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/spy2mobile/light" ascii //weight: 1
        $x_1_2 = "gps_root_ll" ascii //weight: 1
        $x_1_3 = "TrackerLocation" ascii //weight: 1
        $x_1_4 = "getLastKnownLocation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Trackplus_A_301099_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Trackplus.A!MTB"
        threat_id = "301099"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Trackplus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "trackerplus.db" ascii //weight: 1
        $x_1_2 = "CoordsManager readfromDb" ascii //weight: 1
        $x_1_3 = "Spy and Screen On" ascii //weight: 1
        $x_1_4 = "TrackerLocation.isDistanceValid" ascii //weight: 1
        $x_1_5 = "Lru/intech/lib/TrackerService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Trackplus_DS_311705_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Trackplus.DS!MTB"
        threat_id = "311705"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Trackplus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spy and Screen On" ascii //weight: 1
        $x_1_2 = "SPY2MOBILE" ascii //weight: 1
        $x_1_3 = "sms_history" ascii //weight: 1
        $x_1_4 = "CONTACTS_HASH" ascii //weight: 1
        $x_1_5 = "IS_SEND_INFO" ascii //weight: 1
        $x_1_6 = "call_history" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Trackplus_B_350621_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Trackplus.B!MTB"
        threat_id = "350621"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Trackplus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".intel64fre." ascii //weight: 1
        $x_1_2 = "InternetLocationLoader" ascii //weight: 1
        $x_1_3 = "SettingsActivity_permissions_required" ascii //weight: 1
        $x_1_4 = "WifiRaw{ScanResultList=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

