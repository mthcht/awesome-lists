rule MonitoringTool_AndroidOS_FunSpy_A_416182_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/FunSpy.A!MTB"
        threat_id = "416182"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "FunSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "accessibilityinfo" ascii //weight: 1
        $x_1_2 = "keyloggerto" ascii //weight: 1
        $x_1_3 = "ForSMSCommandCodes" ascii //weight: 1
        $x_1_4 = "CallRecordingAndControlService" ascii //weight: 1
        $x_1_5 = "check_screenshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

