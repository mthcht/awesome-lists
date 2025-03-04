rule MonitoringTool_AndroidOS_TrackPlus_C_409935_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/TrackPlus.C!MTB"
        threat_id = "409935"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "TrackPlus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/phonetrackerofficial1/BootReceiver" ascii //weight: 1
        $x_1_2 = "www.phonetracker.com/secure" ascii //weight: 1
        $x_1_3 = "spyTrackerUserData" ascii //weight: 1
        $x_1_4 = "GetContacts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

