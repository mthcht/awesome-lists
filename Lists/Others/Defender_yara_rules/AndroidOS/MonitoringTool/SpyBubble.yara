rule MonitoringTool_AndroidOS_SpyBubble_A_298989_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpyBubble.A!MTB"
        threat_id = "298989"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpyBubble"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallLogService" ascii //weight: 1
        $x_1_2 = "SpyService" ascii //weight: 1
        $x_1_3 = "contactUpload" ascii //weight: 1
        $x_1_4 = "Exception while start the SpyService at" ascii //weight: 1
        $x_1_5 = "endSecretCall" ascii //weight: 1
        $x_1_6 = "CallTrack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

