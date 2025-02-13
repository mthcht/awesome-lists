rule MonitoringTool_AndroidOS_OwnSpy_B_336207_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/OwnSpy.B!MTB"
        threat_id = "336207"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "OwnSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "trackingrate" ascii //weight: 1
        $x_1_2 = "sms_connect" ascii //weight: 1
        $x_1_3 = "prevent_uninstall" ascii //weight: 1
        $x_1_4 = "OWNSPY" ascii //weight: 1
        $x_1_5 = "appsTorecord" ascii //weight: 1
        $x_1_6 = "KeyLogger" ascii //weight: 1
        $x_1_7 = "ChromeURLMonitor" ascii //weight: 1
        $x_1_8 = "ScreenRecordService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule MonitoringTool_AndroidOS_OwnSpy_C_359865_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/OwnSpy.C!MTB"
        threat_id = "359865"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "OwnSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/ownspy.php" ascii //weight: 1
        $x_1_2 = "com.ownspy.android.App" ascii //weight: 1
        $x_1_3 = "53974974995305292532ownspy8382724929400349423041" ascii //weight: 1
        $x_1_4 = "onUniversalReceive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

