rule MonitoringTool_AndroidOS_Wspy_A_348392_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Wspy.A!MTB"
        threat_id = "348392"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Wspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "webhistory" ascii //weight: 1
        $x_1_2 = "keylogger" ascii //weight: 1
        $x_1_3 = "ScreenLockUnlock" ascii //weight: 1
        $x_1_4 = "/mobile/upload/remotephoto" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Wspy_B_406901_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Wspy.B!MTB"
        threat_id = "406901"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Wspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "modelWhatsAppCall" ascii //weight: 1
        $x_1_2 = "WhatsAppAudioWorker" ascii //weight: 1
        $x_1_3 = "com/sdk/moduleapp/App" ascii //weight: 1
        $x_1_4 = "PhotoPhotoTakerService" ascii //weight: 1
        $x_1_5 = "modalInstagramCall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

