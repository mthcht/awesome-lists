rule MonitoringTool_AndroidOS_Bulgok_A_331736_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Bulgok.A!MTB"
        threat_id = "331736"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Bulgok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.bulgakov.controlphone" ascii //weight: 1
        $x_1_2 = "call_recording" ascii //weight: 1
        $x_1_3 = "HISTORY_SMS" ascii //weight: 1
        $x_1_4 = "UPDATE_HIS_CALL" ascii //weight: 1
        $x_1_5 = "updateRecSmsLoc" ascii //weight: 1
        $x_1_6 = "updateHisCallContact" ascii //weight: 1
        $x_1_7 = "SEND_RECORD_SMS_LOCATION" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

