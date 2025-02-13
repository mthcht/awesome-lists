rule Trojan_Win32_Ficerip_A_2147723680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ficerip.A!dha!!Ficerip.A"
        threat_id = "2147723680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ficerip"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        info = "Ficerip: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 00 00 83 c4 ?? 89 45 ?? 83 7d ?? 00 75 ?? eb ?? c6 45 ?? 45 c6 45 ?? 78 c6 45 ?? 65 c6 45 ?? 63 c6 45 ?? 00 8b 45 ?? 50 8d 4d ?? 51 6a 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {08 00 00 00 c7 45 ?? 02 00 00 00 c7 45 ?? 04 00 00 00 c7 45 ?? 10 00 00 00 c7 45 ?? 80 00 00 00 c7 45 ?? 20 00 00 00 c7 45 ?? 40 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 c6 44 24 ?? 78 c6 44 24 ?? 65 c6 44 24 ?? 63 c6 44 24 ?? 00 48 8b 44 24 ?? 48 89 44 24 ?? 4c 8d 4c 24 ?? 45 33 c0 33 d2}  //weight: 1, accuracy: Low
        $x_1_4 = {08 00 00 00 c7 44 24 ?? 02 00 00 00 c7 44 24 ?? 04 00 00 00 c7 44 24 ?? 10 00 00 00 c7 44 24 ?? 80 00 00 00 c7 44 24 ?? 20 00 00 00 c7 44 24 ?? 40 00 00 00 48 63 44 24 ?? 48 6b c0 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

