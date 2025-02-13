rule MonitoringTool_Win32_Senza_132887_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Senza"
        threat_id = "132887"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Senza"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Senzala Keylogger" ascii //weight: 10
        $x_1_2 = "Teclas capturadas" ascii //weight: 1
        $x_1_3 = "Windows Media Player\\skype.exe" ascii //weight: 1
        $x_1_4 = "smtp.mail.yahoo.com.br" ascii //weight: 1
        $x_1_5 = "@hotmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

