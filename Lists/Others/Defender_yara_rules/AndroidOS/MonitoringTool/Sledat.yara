rule MonitoringTool_AndroidOS_Sledat_A_331735_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Sledat.A!MTB"
        threat_id = "331735"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Sledat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sledat_SMS" ascii //weight: 1
        $x_1_2 = "vmesnik.php" ascii //weight: 1
        $x_1_3 = "sledat.client.sledat_" ascii //weight: 1
        $x_1_4 = "/dodatki/android/upload.php" ascii //weight: 1
        $x_1_5 = "getinfo" ascii //weight: 1
        $x_1_6 = "sd_tracker_data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

