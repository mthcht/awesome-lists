rule MonitoringTool_AndroidOS_Chmon_A_420992_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Chmon.A!MTB"
        threat_id = "420992"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Chmon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Lcom/jlzb/android/TurnActivity" ascii //weight: 10
        $x_1_2 = "SmsSendContentWatcher" ascii //weight: 1
        $x_1_3 = "PhoneIsOnLineService" ascii //weight: 1
        $x_1_4 = "HiddenOpenAppService" ascii //weight: 1
        $x_1_5 = "UploadOftenGoPlaceService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

