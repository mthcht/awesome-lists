rule MonitoringTool_AndroidOS_CellTracker_A_340517_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/CellTracker.A!MTB"
        threat_id = "340517"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "CellTracker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "www.trackmyphones.com" ascii //weight: 1
        $x_1_2 = "streetlens" ascii //weight: 1
        $x_1_3 = "gcmcallsmstracker" ascii //weight: 1
        $x_1_4 = {72 65 6d 6f 74 65 [0-2] 63 65 6c 6c [0-2] 74 72 61 63 6b 65 72}  //weight: 1, accuracy: Low
        $x_1_5 = "trackyapps" ascii //weight: 1
        $x_1_6 = "CellTrackerActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule MonitoringTool_AndroidOS_CellTracker_A_340517_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/CellTracker.A!MTB"
        threat_id = "340517"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "CellTracker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CALLDATA" ascii //weight: 1
        $x_10_2 = "com.jyotin.ct" ascii //weight: 10
        $x_1_3 = "is_app_hide" ascii //weight: 1
        $x_1_4 = "sms_sync" ascii //weight: 1
        $x_1_5 = "call_log_sync" ascii //weight: 1
        $x_1_6 = "screen_capture" ascii //weight: 1
        $x_1_7 = "send_audio_wifi" ascii //weight: 1
        $x_1_8 = "last_sync_contacts_count" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_AndroidOS_CellTracker_C_423286_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/CellTracker.C!MTB"
        threat_id = "423286"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "CellTracker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "tracker.mob.gps" ascii //weight: 5
        $x_1_2 = "sms_sync" ascii //weight: 1
        $x_1_3 = "screen_capture" ascii //weight: 1
        $x_1_4 = "last_sync_contacts_count" ascii //weight: 1
        $x_1_5 = "call_log_sync" ascii //weight: 1
        $x_1_6 = "send_audio_wifi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

