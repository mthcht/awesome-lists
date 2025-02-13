rule MonitoringTool_MSIL_Ultimate_213094_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/Ultimate"
        threat_id = "213094"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ultimate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Ultimate Logger - Log:" wide //weight: 1
        $x_1_2 = {5c 00 6c 00 6f 00 67 00 5f 00 ?? ?? 2e 00 74 00 78 00 74 00 ?? ?? 5c 00 73 00 63 00 72 00 ?? ?? 2e 00 62 00 6d 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = {65 00 6d 00 61 00 69 00 6c 00 73 00 65 00 72 00 76 00 65 00 72 00 [0-64] 65 00 6d 00 61 00 69 00 6c 00 70 00 6f 00 72 00 74 00 [0-64] 65 00 6d 00 61 00 69 00 6c 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

