rule Virus_Win32_Kies_AKI_2147966562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Kies.AKI!MTB"
        threat_id = "2147966562"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Kies"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 b9 11 00 00 00 33 c0 8d 7c 24 14 f3 ab 8d 44 24 04 8d 4c 24 14 8b 54 24 5c 50 51 6a 00 6a 00 6a 20 6a 00 6a 00 6a 00 6a 00 52 c7 44 24 3c 44 00 00 00 ff 15}  //weight: 1, accuracy: High
        $x_2_2 = {6a 00 6a 00 6a 00 68 30 17 40 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 7d 98 89 45 cc a1 10 74 41 00 89 45 e8 8b 45 d4 c6 45 fc 02}  //weight: 2, accuracy: Low
        $x_3_3 = {83 c4 04 85 c0 75 7d 8d 4c 24 10 68 1c 64 41 00 51 e8 ?? ?? ?? ?? 83 c4 08 85 c0 75 2c 8d 54 24 10 68 0c 64 41 00 52 e8 ?? ?? ?? ?? 83 c4 08 85 c0 75 16 8d 44 24 10 68 00 64 41 00 50 e8 ab 0c 00 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

