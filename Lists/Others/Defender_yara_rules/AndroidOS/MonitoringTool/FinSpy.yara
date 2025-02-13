rule MonitoringTool_AndroidOS_FinSpy_A_309563_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/FinSpy.A!MTB"
        threat_id = "309563"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "FinSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Module Spy Call" ascii //weight: 1
        $x_1_2 = "TlvTypeMobileTargetExtendedHeartBeatV10" ascii //weight: 1
        $x_1_3 = "TlvTypeMobileTrackingConfigRaw" ascii //weight: 1
        $x_1_4 = "TlvTypeMobileLoggingMetaInfo" ascii //weight: 1
        $x_1_5 = "TlvTypeMobilePhoneCallLogsData" ascii //weight: 1
        $x_1_6 = "Records All Sms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule MonitoringTool_AndroidOS_FinSpy_A_328570_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/FinSpy.A!xp"
        threat_id = "328570"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "FinSpy"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Installed Modules SypCall" ascii //weight: 1
        $x_1_2 = "TlvTypeConfigVoIPScreenshotEnabled" ascii //weight: 1
        $x_1_3 = "StartScreenRecording" ascii //weight: 1
        $x_1_4 = "Sent: GetRecordedFilesReply" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

