rule MonitoringTool_AndroidOS_RudrAdmin_A_420991_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/RudrAdmin.A!MTB"
        threat_id = "420991"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "RudrAdmin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lclout/com/wifiservice/SplashActivity" ascii //weight: 1
        $x_1_2 = "FakeShutdownService" ascii //weight: 1
        $x_1_3 = "FakeLauncherActivity" ascii //weight: 1
        $x_1_4 = "startMyOwnForeground" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

