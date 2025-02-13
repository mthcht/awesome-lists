rule MonitoringTool_AndroidOS_OneSpy_B_325146_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/OneSpy.B!MTB"
        threat_id = "325146"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "OneSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sbin/.magisk/img/phonespy-stub" ascii //weight: 1
        $x_1_2 = "send.onespy.com" ascii //weight: 1
        $x_1_3 = "feature_call_recordings" ascii //weight: 1
        $x_1_4 = "keylogger_last_time" ascii //weight: 1
        $x_1_5 = "com/android/system/app/services/CallRecorderService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_OneSpy_C_350757_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/OneSpy.C!MTB"
        threat_id = "350757"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "OneSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallUploadIntentService" ascii //weight: 1
        $x_1_2 = "DisableAppsIntentService" ascii //weight: 1
        $x_1_3 = "/sbin/.magisk/img/phonespy-stub" ascii //weight: 1
        $x_1_4 = "ScreenshotWithRootIntentService" ascii //weight: 1
        $x_1_5 = "SurroundRecorderService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

