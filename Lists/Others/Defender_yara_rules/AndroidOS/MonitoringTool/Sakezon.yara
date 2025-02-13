rule MonitoringTool_AndroidOS_Sakezon_A_349732_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Sakezon.A!MTB"
        threat_id = "349732"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Sakezon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "slon.skz.SafeKidZone" ascii //weight: 1
        $x_1_2 = "login.safekidzone.com/android/upload.php" ascii //weight: 1
        $x_1_3 = ".com/php/session.php" ascii //weight: 1
        $x_1_4 = ".com/listener.php" ascii //weight: 1
        $x_1_5 = "GpsPlusService" ascii //weight: 1
        $x_1_6 = "safetrec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

