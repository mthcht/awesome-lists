rule MonitoringTool_Win32_Mipko_205563_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Mipko"
        threat_id = "205563"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mipko"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 00 45 00 46 00 4f 00 47 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 00 22 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

