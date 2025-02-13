rule MonitoringTool_AndroidOS_LifeMon_A_299182_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/LifeMon.A!MTB"
        threat_id = "299182"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "LifeMon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "spy.lifemonitor" ascii //weight: 1
        $x_1_2 = "addLocation.php" ascii //weight: 1
        $x_1_3 = "onStartTrackingTouch" ascii //weight: 1
        $x_1_4 = "Lspy/lifemonitor/com/tracking" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_LifeMon_B_331320_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/LifeMon.B!MTB"
        threat_id = "331320"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "LifeMon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "onStartTrackingTouch" ascii //weight: 1
        $x_1_2 = "spy.lifemonitor.ru" ascii //weight: 1
        $x_1_3 = "addLocation.php" ascii //weight: 1
        $x_1_4 = "LifemonitorActivity" ascii //weight: 1
        $x_1_5 = "hSBYkyyDxFhWvfWn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

