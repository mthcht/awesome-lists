rule MonitoringTool_AndroidOS_Avancar_A_335970_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Avancar.A!MTB"
        threat_id = "335970"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Avancar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/monitor/sendmail.php" ascii //weight: 1
        $x_1_2 = "WipeIcon" ascii //weight: 1
        $x_1_3 = "/monitor/andsave.php" ascii //weight: 1
        $x_1_4 = "UpdImgContacts" ascii //weight: 1
        $x_1_5 = "/monitor/getcfg.php" ascii //weight: 1
        $x_1_6 = "com.devicemon.services.main" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

