rule MonitoringTool_AndroidOS_Nasp_A_332678_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Nasp.A!MTB"
        threat_id = "332678"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Nasp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PanSpy" ascii //weight: 1
        $x_1_2 = "SASCaptureTask " ascii //weight: 1
        $x_1_3 = "KeyLogApplication" ascii //weight: 1
        $x_1_4 = "Clipboardinfo" ascii //weight: 1
        $x_1_5 = "historyCallLog" ascii //weight: 1
        $x_1_6 = "com.panspy.android.keyloglib" ascii //weight: 1
        $x_1_7 = "RemoveIconActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

