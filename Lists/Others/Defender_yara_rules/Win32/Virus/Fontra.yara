rule Virus_Win32_Fontra_C_2147600079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Fontra.C"
        threat_id = "2147600079"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Fontra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 8b c6 66 9c 66 81 3e 4d 5a 75 23 83 7e 3c 40 76 1d 03 76 3c 0b d2 74 06 03 c2 3b f0 73 10 66 81 3e 50 45 75 09 66 9d 61 b8 01 00 00 00 c3}  //weight: 1, accuracy: High
        $x_1_2 = {83 7e 08 0a 75 ?? 8d 85 ?? ?? ?? ?? eb ?? 83 7e 08 5a 75 ?? 8d 85 ?? ?? ?? ?? eb ?? 83 7e 08 00 75 ?? 83 7e 10 02 75 ?? 8d 85 ?? ?? ?? ?? eb ?? 8d 85 ?? ?? ?? ?? eb ?? 83 7e 04 03 75 ?? 83 7e 08 33}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 07 24 0f 8a 04 30 88 07 47 e2 f4 8b 3c 24 c6 07 7b c6 47 09 2d c6 47 0e 2d c6 47 13 2d c6 47 18 2d c6 47 25 7d c6 47 26 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

