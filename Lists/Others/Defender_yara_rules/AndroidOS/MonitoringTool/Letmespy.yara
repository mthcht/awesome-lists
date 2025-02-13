rule MonitoringTool_AndroidOS_Letmespy_A_350410_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Letmespy.A!MTB"
        threat_id = "350410"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Letmespy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMS OUT" ascii //weight: 1
        $x_1_2 = "isCollectPhone" ascii //weight: 1
        $x_1_3 = "loadPhonesDo" ascii //weight: 1
        $x_1_4 = "checkCollectPhoneTask" ascii //weight: 1
        $x_1_5 = "logCallLog" ascii //weight: 1
        $x_1_6 = "pl.lidwin.letmespy" ascii //weight: 1
        $x_1_7 = "iconHide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

