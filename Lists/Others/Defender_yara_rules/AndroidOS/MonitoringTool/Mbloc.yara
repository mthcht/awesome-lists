rule MonitoringTool_AndroidOS_Mbloc_A_406821_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Mbloc.A!MTB"
        threat_id = "406821"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Mbloc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Lcom/lifeproto/rmt" ascii //weight: 5
        $x_5_2 = "ru.lifeproto.rmt" ascii //weight: 5
        $x_1_3 = "AnswerPostFile" ascii //weight: 1
        $x_1_4 = "BROAD_IDCALL" ascii //weight: 1
        $x_1_5 = "NotificationManagerMon" ascii //weight: 1
        $x_1_6 = "BROADCAST_END_SYNC_ALL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

