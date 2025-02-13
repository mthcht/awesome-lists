rule MonitoringTool_AndroidOS_Alltracker_B_333285_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Alltracker.B!MTB"
        threat_id = "333285"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Alltracker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcity/russ/alltrackercorp/receiver" ascii //weight: 1
        $x_1_2 = "readContacts" ascii //weight: 1
        $x_1_3 = "PhoneUnlockedReceiver" ascii //weight: 1
        $x_1_4 = "alltracker-family.com" ascii //weight: 1
        $x_1_5 = "collectNewSMSs" ascii //weight: 1
        $x_1_6 = "collectPhotos" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule MonitoringTool_AndroidOS_Alltracker_C_359870_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Alltracker.C!MTB"
        threat_id = "359870"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Alltracker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Lcity/russ/alltrackercorp" ascii //weight: 5
        $x_1_2 = "LocationLoggerService" ascii //weight: 1
        $x_1_3 = "history_calls" ascii //weight: 1
        $x_1_4 = "CollectPhotosService" ascii //weight: 1
        $x_1_5 = "UploadScreenOnPhotos" ascii //weight: 1
        $x_1_6 = "MonitoredActivity" ascii //weight: 1
        $x_5_7 = "city/russ/alltrackerfamily" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

