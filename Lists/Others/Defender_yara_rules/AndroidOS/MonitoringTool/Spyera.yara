rule MonitoringTool_AndroidOS_Spyera_A_332364_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Spyera.A!MTB"
        threat_id = "332364"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Spyera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SEND_NUMBER" ascii //weight: 1
        $x_1_2 = "contactInfo" ascii //weight: 1
        $x_1_3 = "callsObserver" ascii //weight: 1
        $x_1_4 = "UploadMsgService" ascii //weight: 1
        $x_1_5 = "uploadPhotos" ascii //weight: 1
        $x_1_6 = "runningAppProcessInfos" ascii //weight: 1
        $x_1_7 = "SPY =" ascii //weight: 1
        $x_1_8 = "UPLOAD_ACTIVE_URL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

