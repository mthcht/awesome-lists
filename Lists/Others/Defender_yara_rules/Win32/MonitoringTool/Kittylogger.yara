rule MonitoringTool_Win32_Kittylogger_A_166167_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Kittylogger.A"
        threat_id = "166167"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Kittylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kitty Logger Started [" wide //weight: 1
        $x_1_2 = "KLpeek.txt" wide //weight: 1
        $x_1_3 = "Business\\Kitty Logger\\KL.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

