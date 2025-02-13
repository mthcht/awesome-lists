rule MonitoringTool_AndroidOS_AllTrack_C_423287_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/AllTrack.C!MTB"
        threat_id = "423287"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "AllTrack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOCKET_SECRET" ascii //weight: 1
        $x_5_2 = "Lcity/russ/alltrackercorp/StartActivity" ascii //weight: 5
        $x_1_3 = "ActionGetBrowserHistory" ascii //weight: 1
        $x_1_4 = "ActionGetSMS" ascii //weight: 1
        $x_1_5 = "FusedLocationReceiver" ascii //weight: 1
        $x_5_6 = "city.russ.CHECK_LAST_ENTRY" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

