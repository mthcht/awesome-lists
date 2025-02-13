rule MonitoringTool_MSIL_FamilyWatcher_205392_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/FamilyWatcher"
        threat_id = "205392"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FamilyWatcher"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FamilyWatcher" wide //weight: 1
        $x_1_2 = "Keylogger" ascii //weight: 1
        $x_1_3 = "shreeTemp.tif" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

