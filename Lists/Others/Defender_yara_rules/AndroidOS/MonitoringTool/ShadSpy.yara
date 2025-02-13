rule MonitoringTool_AndroidOS_ShadSpy_B_333901_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/ShadSpy.B!MTB"
        threat_id = "333901"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "ShadSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MakeStealthActivity" ascii //weight: 1
        $x_1_2 = "CallLogger" ascii //weight: 1
        $x_1_3 = "logInstalledApps" ascii //weight: 1
        $x_1_4 = "contact tracked" ascii //weight: 1
        $x_1_5 = "PhotoLoggerObserver" ascii //weight: 1
        $x_1_6 = "OutgoingSmsLogger" ascii //weight: 1
        $x_1_7 = "shadow-spy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_ShadSpy_C_359511_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/ShadSpy.C!MTB"
        threat_id = "359511"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "ShadSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shadow-spy" ascii //weight: 1
        $x_1_2 = "IncomingSmsLogger" ascii //weight: 1
        $x_1_3 = "ContactLogger.java" ascii //weight: 1
        $x_1_4 = "NewCallFinder" ascii //weight: 1
        $x_1_5 = "AppLogger.java" ascii //weight: 1
        $x_1_6 = "/datastoresv0.db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

