rule MonitoringTool_MacOS_Spyrix_DS_329160_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Spyrix.DS!MTB"
        threat_id = "329160"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Spyrix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spyrix.SPScreenshots" ascii //weight: 1
        $x_1_2 = "com.spyrix.skm" ascii //weight: 1
        $x_1_3 = "/monitor/iupload.php" ascii //weight: 1
        $x_1_4 = "startMonitoringClipboard" ascii //weight: 1
        $x_1_5 = "CallRecordViewController" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_MacOS_Spyrix_A_345574_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Spyrix.A!MTB"
        threat_id = "345574"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Spyrix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "isMonitoringKeylogger" ascii //weight: 1
        $x_1_2 = "isEnableAutoCallRecorder" ascii //weight: 1
        $x_1_3 = "monitor/data_upload.php" ascii //weight: 1
        $x_1_4 = "LiveWebCam" ascii //weight: 1
        $x_1_5 = "com.spyrix.skm" ascii //weight: 1
        $x_1_6 = "ScreenRecorder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule MonitoringTool_MacOS_Spyrix_A_345574_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Spyrix.A!MTB"
        threat_id = "345574"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Spyrix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.spyrix.skm" ascii //weight: 1
        $x_1_2 = "Spyrix.SPScreenshots" ascii //weight: 1
        $x_1_3 = "isMonitoringClipboard" ascii //weight: 1
        $x_1_4 = "spyrix.net/usr/monitor/iorder.php?id=%@" ascii //weight: 1
        $x_1_5 = "SPMonitoringKeyboardDelegate" ascii //weight: 1
        $x_1_6 = "monitor/upload3.php" ascii //weight: 1
        $x_1_7 = "spyrix-keylogger-for-mac-manual.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule MonitoringTool_MacOS_Spyrix_K_418697_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Spyrix.K!MTB"
        threat_id = "418697"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Spyrix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "com.spyrix.skm" ascii //weight: 3
        $x_1_2 = "monitor/upload" ascii //weight: 1
        $x_1_3 = "/monitor/iupload" ascii //weight: 1
        $x_1_4 = "dashboard.spyrix.com/" ascii //weight: 1
        $x_1_5 = "/Library/skm/Spyrix.app" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_MacOS_Spyrix_J_418698_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Spyrix.J!MTB"
        threat_id = "418698"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Spyrix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "com.actual.akm" ascii //weight: 3
        $x_3_2 = "com.spyrix.apskm" ascii //weight: 3
        $x_1_3 = "dashboard.spyrix.com/" ascii //weight: 1
        $x_1_4 = "/Library/akm/Spyrix.app" ascii //weight: 1
        $x_1_5 = "pathSpyrix" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

