rule MonitoringTool_AndroidOS_FlexiSpy_D_352037_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/FlexiSpy.D!MTB"
        threat_id = "352037"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "FlexiSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SpyCallService" ascii //weight: 1
        $x_1_2 = "Lcom/android/phone/spc/ISpyCallInterface" ascii //weight: 1
        $x_1_3 = "checkMonitoringNumber" ascii //weight: 1
        $x_1_4 = "CallBlockerScreeningService" ascii //weight: 1
        $x_1_5 = "Lcom/android/phone/dialer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

