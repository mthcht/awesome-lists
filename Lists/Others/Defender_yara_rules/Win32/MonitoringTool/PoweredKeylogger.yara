rule MonitoringTool_Win32_PoweredKeylogger_17328_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PoweredKeylogger"
        threat_id = "17328"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PoweredKeylogger"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 6f 77 65 72 65 64 20 6b 65 79 6c 6f 67 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = "use \"secretword\" " wide //weight: 1
        $x_1_3 = "test e-mail!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

