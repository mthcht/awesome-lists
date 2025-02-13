rule MonitoringTool_MSIL_UltraKeylogger_224398_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/UltraKeylogger"
        threat_id = "224398"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "UltraKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Ultra Keylogger" wide //weight: 2
        $x_1_2 = {1f 1d 0f 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
        $x_1_3 = {1f 1d 0f 01 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

