rule MonitoringTool_MSIL_Auxlogger_204840_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/Auxlogger"
        threat_id = "204840"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Auxlogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Aux Logger" wide //weight: 1
        $x_1_2 = "[Copied to clipboard]" wide //weight: 1
        $x_1_3 = "Anti Virus:" wide //weight: 1
        $x_1_4 = "Firewall:" wide //weight: 1
        $x_1_5 = {06 02 08 6f ?? 00 00 0a 28 ?? 00 00 0a 1b 58 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 08 17 58 0c 08 09 31 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

