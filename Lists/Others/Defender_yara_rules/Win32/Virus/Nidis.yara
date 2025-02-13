rule Virus_Win32_Nidis_A_2147599840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Nidis.A"
        threat_id = "2147599840"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Nidis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 32 5f 6f 76 6f 73 5f 32 00 00 00 5c 00 3f 00 3f 00 5c 00 63 00 3a 00 5c 00 63 00 64 00 00 00 2e 00 6e 00 6c 00 73 00 00 00 00 00 63 00 3a 00 5c 00 63 00 64 00 00 00 2e 00 6e 00 6c 00 73 00}  //weight: 2, accuracy: High
        $x_1_2 = {57 66 81 3a 4d 5a 74 ?? b8 be 00 00 00 eb ?? 8b 7a 3c 01 d7 66 81 3f 50 45 74 ?? b8 c8 00 00 00 eb ?? 8b 47 28 e8 ?? ?? 00 00 83 f8 00 75 ?? b8 d2 00 00 00 5f c3}  //weight: 1, accuracy: Low
        $x_1_3 = {53 51 57 56 66 81 3a 4d 5a 74 ?? b8 be 00 00 00 e9 ?? ?? 00 00 8b 7a 3c 01 d7 66 81 3f 50 45 74 ?? b8 c8 00 00 00 eb ?? 8b 87 a0 00 00 00 8b bf a4 00 00 00 e8 ?? ?? 00 00 83 f8 00 75 ?? b8 d2 00 00 00 eb ?? 89 c6 01 c7 39 fe 73 ?? 8b 4e 04 83 e9 02 83 f9 08}  //weight: 1, accuracy: Low
        $x_1_4 = {51 52 56 57 53 89 c6 89 da 66 81 3a 4d 5a 74 ?? b8 46 00 00 00 e9 ?? ?? 00 00 8b 7a 3c 01 d7 66 81 3f 50 45 74 ?? b8 50 00 00 00 e9 ?? ?? 00 00 8b 47 78 e8 ?? ?? 00 00 83 f8 00 75 ?? b8 5a 00 00 00 e9 ?? ?? 00 00 89 c3 89 f7 8b 43 20 e8 ?? ?? 00 00 89 c6 31 c9 83 fe 00 75 ?? b8 64 00 00 00 eb ?? 3b 4b 18}  //weight: 1, accuracy: Low
        $x_1_5 = {57 51 66 81 3a 4d 5a 74 ?? b8 0a 00 00 00 eb ?? 8b 7a 3c 01 d7 66 81 3f 50 45 74 ?? b8 14 00 00 00 eb ?? 8b 87 80 00 00 00 e8 ?? ?? ff ff 83 f8 00 75 ?? b8 1e 00 00 00 eb ?? 89 c1 83 79 0c 00 74 ?? e8 ?? ?? ff ff 83 c1 14 eb ?? e8 ?? ?? ff ff 59 5f c3}  //weight: 1, accuracy: Low
        $x_1_6 = {57 53 8a 1f 8a 38 80 fb 41 7c ?? 80 fb 5a 7f ?? 80 c3 20 80 ff 41 7c ?? 80 ff 5a 7f ?? 80 c7 20 38 fb 75 ?? 80 fb 00 74 ?? 47 40 eb ?? b8 01 00 00 00 eb ?? b8 00 00 00 00 5b 5f c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

