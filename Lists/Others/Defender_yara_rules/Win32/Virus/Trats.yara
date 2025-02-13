rule Virus_Win32_Trats_G_2147600887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Trats.G"
        threat_id = "2147600887"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Trats"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 53 56 6a 00 6a 69 68 ?? ?? ?? ?? 6a 00 32 db ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 56 6a 00 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 55 57 50 ff 15 ?? ?? ?? ?? 56 6a 00 8b e8 ff 15 ?? ?? ?? ?? 8b f8 83 ff 01 76 ?? 8b 44 24 18 85 c0 b3 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 44 24 10 50 8d 4c 24 24 51 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 8d 94 24 ?? ?? ?? ?? 52 6a 00 c7 44 24 48 44 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {53 56 57 68 ?? ?? ?? ?? 8d 44 24 10 50 6a 68 6a 00 ff 15 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 8d 4c 24 0c 51 ff d3 8b f0 33 ff 85 f6 75 ?? 8d 54 24 0c 52 e8 ?? ?? ff ff 83 c4 04 84 c0 74 ?? 8d 44 24 0c 50 ff d3 8b f0 85 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

