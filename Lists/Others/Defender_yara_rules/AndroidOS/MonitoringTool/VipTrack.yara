rule MonitoringTool_AndroidOS_VipTrack_B_331794_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/VipTrack.B!MTB"
        threat_id = "331794"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "VipTrack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stop_stare.php?idgps=" ascii //weight: 1
        $x_1_2 = "stopMONITORIZARE" ascii //weight: 1
        $x_1_3 = "VIPTrackPRO_" ascii //weight: 1
        $x_1_4 = "/receive_data.php" ascii //weight: 1
        $x_1_5 = "neighbor_CellInfo" ascii //weight: 1
        $x_5_6 = "toSend_data" ascii //weight: 5
        $x_1_7 = "startMonit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

