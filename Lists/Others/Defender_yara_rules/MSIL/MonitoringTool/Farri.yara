rule MonitoringTool_MSIL_Farri_204969_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/Farri"
        threat_id = "204969"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Farri"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Farri keylogger" wide //weight: 1
        $x_1_2 = "Test Email ID & Password" wide //weight: 1
        $x_1_3 = "\\Server.exe" wide //weight: 1
        $x_1_4 = "smtp.gmail.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

