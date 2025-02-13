rule MonitoringTool_AndroidOS_Fmph_B_357164_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Fmph.B!MTB"
        threat_id = "357164"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Fmph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "com.mango.findmyphone" ascii //weight: 10
        $x_1_2 = "FindMyPhone Activity" ascii //weight: 1
        $x_1_3 = "sim_card_monitoring_on" ascii //weight: 1
        $x_1_4 = "Alarm_Wipe" ascii //weight: 1
        $x_1_5 = "findmyphoneBackCamera" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

