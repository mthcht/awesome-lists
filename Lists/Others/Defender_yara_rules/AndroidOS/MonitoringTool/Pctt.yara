rule MonitoringTool_AndroidOS_Pctt_A_343783_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Pctt.A!MTB"
        threat_id = "343783"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Pctt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeyStrokePayLoad" ascii //weight: 1
        $x_1_2 = "PC Tattletale" ascii //weight: 1
        $x_1_3 = "RemoteMonitoring" ascii //weight: 1
        $x_1_4 = "PREVENT_UNINSTALL" ascii //weight: 1
        $x_1_5 = "lastGPSCallDateTimestamp" ascii //weight: 1
        $x_10_6 = "com.avi.scbase" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

