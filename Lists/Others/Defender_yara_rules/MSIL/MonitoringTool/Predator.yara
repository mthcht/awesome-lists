rule MonitoringTool_MSIL_Predator_201827_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/Predator"
        threat_id = "201827"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Predator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Predator Logger 10 - Key Recorder - [" wide //weight: 1
        $x_1_2 = "Predator Logger 10 - Notification Email - [" wide //weight: 1
        $x_1_3 = "Predator Logger 10 - Stealer Log - [" wide //weight: 1
        $x_1_4 = "/stext" wide //weight: 1
        $x_1_5 = "screens\\screenshot" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

