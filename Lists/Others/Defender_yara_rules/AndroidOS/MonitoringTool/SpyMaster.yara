rule MonitoringTool_AndroidOS_SpyMaster_A_359867_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpyMaster.A!MTB"
        threat_id = "359867"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpyMaster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DOMAIN_SPY" ascii //weight: 1
        $x_1_2 = "urltracking.php" ascii //weight: 1
        $x_1_3 = "spymasterpro.com" ascii //weight: 1
        $x_1_4 = "phototracking.php" ascii //weight: 1
        $x_1_5 = "smstracking.php" ascii //weight: 1
        $x_1_6 = "Spy app" ascii //weight: 1
        $x_1_7 = "spyMobile/upload.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

