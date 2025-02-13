rule Virus_Win32_Drowor_B_2147600983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Drowor.B"
        threat_id = "2147600983"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Drowor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 24 0d ff 0f 00 00 35 ff 0f 00 00 66 81 38 4d 5a 74 ?? 2d 00 10 00 00 85 c0 78 ?? eb ?? 89 85 ?? ?? ?? ?? 8b 50 3c 03 d0 66 81 3a 50 45 75 ?? c3}  //weight: 1, accuracy: Low
        $x_1_2 = {57 b9 04 01 00 00 32 c0 f2 ae 4f 4f 80 3f 5c 74 04 47 c6 07 5c 47 8d b5 ?? ?? ?? ?? b9 1e 00 00 00 f3 a4 5f 6a 00 68 80 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40 57 ff 95 ?? ?? ?? ?? 85 c0 0f 88 ?? ?? ff ff 8b d8 53 8d b5 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 6a 00 8d 85 ?? ?? ?? ?? 50 51 56 53 ff 95 ?? ?? ?? ?? ff 95 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 14 6a 40 e8 ?? ?? 00 00 89 45 fc 8b 7d fc c7 07 49 73 44 65 c7 47 04 62 75 67 67 c7 47 08 65 72 50 72 c7 47 0c 65 73 65 6e 66 c7 47 10 74 00}  //weight: 1, accuracy: Low
        $x_1_4 = {89 42 0c c7 42 08 00 60 00 00 b8 60 00 00 00 05 71 03 00 00 03 05 ?? ?? ?? ?? 89 42 10 8d 02 8d 0d ?? ?? ?? ?? 51 8b 09 89 08 59 83 c1 04 8b 09 89 48 04 c7 42 24 e0 00 00 e0 8b 46 14 03 46 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

