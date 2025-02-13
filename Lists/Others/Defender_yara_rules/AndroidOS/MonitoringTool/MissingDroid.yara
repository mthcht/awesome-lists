rule MonitoringTool_AndroidOS_MissingDroid_A_309850_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MissingDroid.A!MTB"
        threat_id = "309850"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MissingDroid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SmsMsgRec" ascii //weight: 1
        $x_1_2 = "sentSmsLocationFound" ascii //weight: 1
        $x_1_3 = "FindMyDroid" ascii //weight: 1
        $x_1_4 = "SmsStolenMsg" ascii //weight: 1
        $x_1_5 = "hideApp" ascii //weight: 1
        $x_1_6 = "friendsWipe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

