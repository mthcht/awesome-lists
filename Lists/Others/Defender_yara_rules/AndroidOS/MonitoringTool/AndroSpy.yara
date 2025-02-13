rule MonitoringTool_AndroidOS_AndroSpy_A_359868_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/AndroSpy.A!MTB"
        threat_id = "359868"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "AndroSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RecordGps" ascii //weight: 1
        $x_1_2 = "gpstracker_Broadcast" ascii //weight: 1
        $x_5_3 = "apk/gpstracker/AutoDelete" ascii //weight: 5
        $x_5_4 = "Lcom/as/gpstracker" ascii //weight: 5
        $x_1_5 = "a-spy" ascii //weight: 1
        $x_1_6 = "hide_notification" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

