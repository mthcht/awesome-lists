rule MonitoringTool_MacOS_Refog_TB_314550_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Refog.TB!xp"
        threat_id = "314550"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Refog"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RefogViewer" ascii //weight: 1
        $x_1_2 = "smoke" ascii //weight: 1
        $x_1_3 = "sendCommand:toViewerNotMonitor" ascii //weight: 1
        $x_1_4 = "MASecKey" ascii //weight: 1
        $x_1_5 = "MAShy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_MacOS_Refog_TA_322243_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Refog.TA!xp"
        threat_id = "322243"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Refog"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Refog Keylogger" ascii //weight: 1
        $x_1_2 = "Monitoring Tool" ascii //weight: 1
        $x_1_3 = "www.refog.com/mac/" ascii //weight: 1
        $x_1_4 = {52 65 66 6f 67 [0-2] 61 70 70}  //weight: 1, accuracy: Low
        $x_1_5 = "/Library/.Refog/" ascii //weight: 1
        $x_1_6 = "Log.refog" ascii //weight: 1
        $x_1_7 = "/Monitor/SSCrypto.m" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule MonitoringTool_MacOS_Refog_B_462960_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Refog.B!MTB"
        threat_id = "462960"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Refog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.hoverwatch.monitor" ascii //weight: 1
        $x_1_2 = "MAChatGrabber" ascii //weight: 1
        $x_1_3 = "installedMonitorURL" ascii //weight: 1
        $x_1_4 = "com.hw.hwinstaller" ascii //weight: 1
        $x_1_5 = "kTCCServiceScreenCapture" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

