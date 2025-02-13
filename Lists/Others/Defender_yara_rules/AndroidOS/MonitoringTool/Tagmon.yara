rule MonitoringTool_AndroidOS_Tagmon_A_357607_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Tagmon.A!MTB"
        threat_id = "357607"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Tagmon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EmulatorDetector" ascii //weight: 1
        $x_1_2 = "chkWhatsApp" ascii //weight: 1
        $x_1_3 = "/alterasenha.php" ascii //weight: 1
        $x_1_4 = "com.iswsc.smackdemo.contact" ascii //weight: 1
        $x_1_5 = "contactVoList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

