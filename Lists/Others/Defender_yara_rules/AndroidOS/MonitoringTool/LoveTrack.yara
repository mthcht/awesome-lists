rule MonitoringTool_AndroidOS_LoveTrack_A_301024_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/LoveTrack.A!MTB"
        threat_id = "301024"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "LoveTrack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com/bettertomorrowapps/spyyourlove" ascii //weight: 2
        $x_1_2 = "sms_unlock_full" ascii //weight: 1
        $x_1_3 = "content://call_log/calls" ascii //weight: 1
        $x_1_4 = "partner_last_sync" ascii //weight: 1
        $x_1_5 = "journal.tmp" ascii //weight: 1
        $x_1_6 = "You can't use Couple Tracker without proper consent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

