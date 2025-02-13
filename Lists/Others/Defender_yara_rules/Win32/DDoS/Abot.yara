rule DDoS_Win32_Abot_A_2147656521_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Abot.A"
        threat_id = "2147656521"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Abot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "/gate.php?hwid=" ascii //weight: 1
        $x_1_3 = "&localip=" ascii //weight: 1
        $x_1_4 = "&winver=" ascii //weight: 1
        $n_100_5 = "Magnet.Content.Artifacts.dll" wide //weight: -100
        $n_100_6 = "System.Collections.Generic.IComparer<Microsoft.Sounder.Protocols.Frame>" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

