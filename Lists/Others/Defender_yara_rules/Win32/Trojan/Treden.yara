rule Trojan_Win32_Treden_A_2147614276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Treden.A"
        threat_id = "2147614276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Treden"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "@*\\AD:\\Apple\\VB" wide //weight: 10
        $x_10_2 = "C:\\windows\\notepad.exe %1" wide //weight: 10
        $x_10_3 = "125.67.67.197   www.yahoo.com" wide //weight: 10
        $x_10_4 = "You will dead next month!" wide //weight: 10
        $x_10_5 = "Trenderdia" ascii //weight: 10
        $x_1_6 = "hosts" wide //weight: 1
        $x_1_7 = "\\drivers\\etc" wide //weight: 1
        $x_1_8 = "explore.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

