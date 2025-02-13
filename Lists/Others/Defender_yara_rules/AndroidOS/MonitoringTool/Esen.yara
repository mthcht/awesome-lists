rule MonitoringTool_AndroidOS_Esen_A_333899_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Esen.A!MTB"
        threat_id = "333899"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Esen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SavedSendingMsg " ascii //weight: 1
        $x_1_2 = "doScreenCapture" ascii //weight: 1
        $x_1_3 = "locbackupinfo" ascii //weight: 1
        $x_1_4 = "sendCallLog" ascii //weight: 1
        $x_1_5 = "sendLocationInfo" ascii //weight: 1
        $x_1_6 = "/pa_insertcalllog.php" ascii //weight: 1
        $x_1_7 = "com.esen.fyttarget2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

