rule MonitoringTool_AndroidOS_TTSpy_A_343782_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/TTSpy.A!MTB"
        threat_id = "343782"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "TTSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "loadAndSaveDeviceInfo" ascii //weight: 1
        $x_1_2 = "com.backup.tt" ascii //weight: 1
        $x_1_3 = "ttspy" ascii //weight: 1
        $x_1_4 = "createScreenCaptureIntent" ascii //weight: 1
        $x_1_5 = "/browser/history" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

