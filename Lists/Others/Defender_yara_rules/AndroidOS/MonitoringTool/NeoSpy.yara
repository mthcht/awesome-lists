rule MonitoringTool_AndroidOS_NeoSpy_A_301101_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/NeoSpy.A!MTB"
        threat_id = "301101"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "NeoSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PhoneCallLengthTracker" ascii //weight: 1
        $x_1_2 = "checkAndReinstallAlarms" ascii //weight: 1
        $x_1_3 = "SendApps" ascii //weight: 1
        $x_1_4 = "SendKeystrokes" ascii //weight: 1
        $x_1_5 = "SendSms" ascii //weight: 1
        $x_1_6 = "ns.antapp.module" ascii //weight: 1
        $x_1_7 = "neospy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule MonitoringTool_AndroidOS_NeoSpy_B_352036_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/NeoSpy.B!MTB"
        threat_id = "352036"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "NeoSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keystrokesOn" ascii //weight: 1
        $x_1_2 = "RootScreenshotService" ascii //weight: 1
        $x_1_3 = "KeyLoggger" ascii //weight: 1
        $x_1_4 = "/system/bin/screencap -p" ascii //weight: 1
        $x_1_5 = "sendPhotoScreen" ascii //weight: 1
        $x_1_6 = "com.nsmon.guard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

