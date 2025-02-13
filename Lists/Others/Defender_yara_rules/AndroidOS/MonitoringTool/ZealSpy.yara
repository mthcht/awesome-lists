rule MonitoringTool_AndroidOS_ZealSpy_B_330148_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/ZealSpy.B!MTB"
        threat_id = "330148"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "ZealSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "com.zeal.zealspydesign" ascii //weight: 10
        $x_1_2 = "History.csv" ascii //weight: 1
        $x_1_3 = "_hideapp" ascii //weight: 1
        $x_1_4 = "sms data call" ascii //weight: 1
        $x_1_5 = "/.ZealRecorder" ascii //weight: 1
        $x_1_6 = "_installapplogs" ascii //weight: 1
        $x_1_7 = "spyemail" ascii //weight: 1
        $x_1_8 = "infoscreen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

