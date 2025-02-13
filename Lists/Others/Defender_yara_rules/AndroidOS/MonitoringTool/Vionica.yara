rule MonitoringTool_AndroidOS_Vionica_A_357162_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Vionica.A!MTB"
        threat_id = "357162"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Vionica"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FakePictureInPictureActivity" ascii //weight: 1
        $x_1_2 = "Lcom/vionika/mobivement" ascii //weight: 1
        $x_1_3 = "OUTGOING_CALL_NUMBER" ascii //weight: 1
        $x_1_4 = "keyloggers_monitoring" ascii //weight: 1
        $x_1_5 = "prevent_uninstallation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

