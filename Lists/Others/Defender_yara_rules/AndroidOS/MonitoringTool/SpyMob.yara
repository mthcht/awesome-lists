rule MonitoringTool_AndroidOS_Spymob_A_300150_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Spymob.A!MTB"
        threat_id = "300150"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Spymob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "spy2mobile.db" ascii //weight: 2
        $x_1_2 = "mobilespy" ascii //weight: 1
        $x_1_3 = "TrackerService" ascii //weight: 1
        $x_1_4 = "sms_history" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Spymob_A_300150_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Spymob.A!MTB"
        threat_id = "300150"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Spymob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 00 29 00 38 00 18 00 22 00 6c 00 70 10 3f 01 00 00 1a 02 d9 00 6e 20 43 01 20 00 0c 00 6e 20 43 01 30 00 0c 00 6e 10 44 01 00 00 0c 00 71 20 4a 00 40 00 63 00 21 00}  //weight: 1, accuracy: High
        $x_1_2 = "deleteApp" ascii //weight: 1
        $x_1_3 = "getPackageName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Spymob_B_353934_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Spymob.B!MTB"
        threat_id = "353934"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Spymob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HiddenAppsConfigActivity" ascii //weight: 1
        $x_1_2 = "TrackPhone" ascii //weight: 1
        $x_1_3 = "PhoneWasLinked" ascii //weight: 1
        $x_1_4 = "CallReceiver" ascii //weight: 1
        $x_1_5 = "deliverSelfNotifications" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

