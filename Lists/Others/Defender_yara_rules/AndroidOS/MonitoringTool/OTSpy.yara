rule MonitoringTool_AndroidOS_OTSpy_B_354605_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/OTSpy.B!MTB"
        threat_id = "354605"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "OTSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SILENT_BACK_CAM_PASSWORD" ascii //weight: 1
        $x_1_2 = "EraseContactsActivity" ascii //weight: 1
        $x_1_3 = "rs_silent_video" ascii //weight: 1
        $x_1_4 = "REMOTE_CONTACT_PASSWORD" ascii //weight: 1
        $x_1_5 = {63 6f 6d 2e ?? ?? ?? 2e 72 65 6d 6f 74 65 73 65 63 75 72 69 74 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_OTSpy_B_354605_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/OTSpy.B!MTB"
        threat_id = "354605"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "OTSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SendVideoAndLocationSMSTask" ascii //weight: 1
        $x_1_2 = "sendLCPSMS" ascii //weight: 1
        $x_1_3 = "SendVideoAndLocEmailTask" ascii //weight: 1
        $x_1_4 = "TrackerLocationListener" ascii //weight: 1
        $x_5_5 = {4c 63 6f 6d 2f [0-4] 6c 61 64 69 65 73 63 68 69 6c 64 70 72 6f 74 65 63 74 69 6f 6e 2f 61 63 74 69 76 69 74 69 65 73}  //weight: 5, accuracy: Low
        $x_5_6 = "Lcom/ots/womenchildsafety" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

