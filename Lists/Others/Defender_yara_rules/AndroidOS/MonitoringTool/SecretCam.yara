rule MonitoringTool_AndroidOS_SecretCam_A_349982_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SecretCam.A!MTB"
        threat_id = "349982"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SecretCam"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/house/apps/secretcamcorder" ascii //weight: 1
        $x_1_2 = "ListVideoActivity" ascii //weight: 1
        $x_1_3 = "tktechsite.com/myads" ascii //weight: 1
        $x_1_4 = "QuickRecording" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_SecretCam_B_433106_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SecretCam.B!MTB"
        threat_id = "433106"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SecretCam"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "com.house.apps.secretcamcorder" ascii //weight: 5
        $x_1_2 = "QuickRecordingEmail" ascii //weight: 1
        $x_1_3 = "AUTO_RECORD_WHEN_UNLOCK_SCREEN" ascii //weight: 1
        $x_1_4 = "ENABLE_RECORDING_BY_SMS" ascii //weight: 1
        $x_1_5 = "CamcorderProfile" ascii //weight: 1
        $x_1_6 = "QuickRecordingRecord" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

