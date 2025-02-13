rule Trojan_Win32_Ddosaz_A_2147691739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ddosaz.A"
        threat_id = "2147691739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ddosaz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IM Mr.Fllen" ascii //weight: 1
        $x_1_2 = "Ahzs Ddos" ascii //weight: 1
        $x_1_3 = "Yow! Bad host lookup" ascii //weight: 1
        $x_1_4 = "%.f|%d%%" ascii //weight: 1
        $x_1_5 = "System.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

