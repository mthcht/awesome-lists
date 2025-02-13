rule MonitoringTool_AndroidOS_LockTrack_A_353354_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/LockTrack.A!MTB"
        threat_id = "353354"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "LockTrack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.av.find.finder" ascii //weight: 1
        $x_1_2 = "activity_info" ascii //weight: 1
        $x_1_3 = "activity_smsis" ascii //weight: 1
        $x_1_4 = "ttps://www.cafe-apps.com/" ascii //weight: 1
        $x_1_5 = "ttps://wa.me/+98" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

