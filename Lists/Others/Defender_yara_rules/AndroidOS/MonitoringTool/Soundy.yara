rule MonitoringTool_AndroidOS_Soundy_A_335971_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Soundy.A!MTB"
        threat_id = "335971"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Soundy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stalkList" ascii //weight: 1
        $x_1_2 = "OutGoingNumDetector" ascii //weight: 1
        $x_1_3 = "com.kfhdha.fkjfgjdi" ascii //weight: 1
        $x_1_4 = "SavePhotoTask" ascii //weight: 1
        $x_1_5 = "ScreenLiveActivity" ascii //weight: 1
        $x_1_6 = "system/bin/chmod 744 capturescr" ascii //weight: 1
        $x_1_7 = "SMSObserver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

