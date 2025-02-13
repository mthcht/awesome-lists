rule Trojan_Win32_Pawntilla_A_2147693326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pawntilla.A"
        threat_id = "2147693326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pawntilla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UgotPwnedByW1Nt3R" ascii //weight: 1
        $x_1_2 = "Schw4rz" ascii //weight: 1
        $x_1_3 = "TBotConfig," ascii //weight: 1
        $x_1_4 = "\\k-meleon.exe" ascii //weight: 1
        $x_1_5 = "ping -n 1 localhost" ascii //weight: 1
        $x_1_6 = "Sil.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

