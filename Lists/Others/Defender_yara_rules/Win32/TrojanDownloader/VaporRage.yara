rule TrojanDownloader_Win32_VaporRage_A_2147781394_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VaporRage.A!dha"
        threat_id = "2147781394"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VaporRage"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 34 36 68 72 66 79 66 73 76 76 75 32 ?? 35 36 33 32 35 34 32 38 33 34}  //weight: 1, accuracy: Low
        $x_1_2 = {73 65 73 73 69 6f 6e 5f 69 6e 66 6f [0-4] 73 65 73 73 69 6f 6e 3d [0-32] 26 76 69 65 77 5f 74 79 70 65 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {25 73 3f 25 73 3d 25 73 26 25 73 00 47 45 54 00 5c 4d 69 63 72 6f 73 6f 66 74 5c 4e 61 74 69 76 ?? 43 61 63 68 65 5c 4e 61 74 69 76 65 43 61 ?? 68 65 53 76 63 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 64 6c 6c 00 00 00 25 77 73 25 73 ?? ?? ?? 25 73 5f 25 73 00 00 00 25 30 32 78}  //weight: 1, accuracy: Low
        $x_2_5 = {8a 11 88 55 ff 83 45 f4 01 80 7d ff 00 75 ?? 8b 45 f4 2b 45 e8 89 45 e4 8b 4d e4 83 e9 01 39 4d f0 77 ?? 8b 55 0c 83 ea 01 39 55 f8 7d ?? 8b 45 08 03 45 f8 0f b6 08 8b 55 ec 03 55 f0 0f be 02 33 c8 8b 55 08 03 55 f8 88 0a 8b 45 f8 83 c0 01 89 45 f8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VaporRage_B_2147788504_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VaporRage.B!dha"
        threat_id = "2147788504"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VaporRage"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 75 74 65 ?? 57 69 6e 4c 6f 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 6b 6c 40 24 ?? 31 32 34 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 69 6c 65 20 6e 6f ?? 20 65 78 69 73 74 00}  //weight: 1, accuracy: Low
        $x_1_4 = {61 73 64 61 73 ?? 61 73 64 67 74 67 67 66 00}  //weight: 1, accuracy: Low
        $x_2_5 = {50 50 4b 61 73 64 61 73 ?? 31 38 35 58 77 64 61 68 6b 6c 40 24 31 31 32 34 00}  //weight: 2, accuracy: Low
        $x_2_6 = {61 73 64 61 73 64 61 ?? 64 61 73 32 33 32 40 67 74 67 67 66 00}  //weight: 2, accuracy: Low
        $x_2_7 = {26 6c 6f 67 69 6e 3d 32 ?? 75 73 32 39 6f 26 6e 61 6d 65 3d 00}  //weight: 2, accuracy: Low
        $x_2_8 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 28 58 31 31 3b 47 3b 4c 69 6e ?? 78 20 69 32 31 35 37 3b 65 6e 2d 55 53 3b 72 76 3a 31 2e 37 29 20 47 65 63 6b 6f 2f 32 34 32 38 39 35 31 31 36 20 46 69 72 65 66 6f 78 2f 31 2e 33 32 20 40 00 00}  //weight: 2, accuracy: Low
        $x_3_9 = {64 6c 6c 5f 62 6f 74 2e 64 ?? 6c 00 53 65 72 76 69 63 65 43 6f 6e 6e 65 63 74 69 6f 6e 43 68 65 63 6b 00 00 00 00}  //weight: 3, accuracy: Low
        $x_3_10 = {83 f9 1a 8d 52 01 1b c0 23 c8 8a 44 17 ff 32 84 ?? ?? ?? ?? ?? 41 88 42 ff 4e 75 e4 8b 7c ?? ?? 68 ?? ?? ?? ?? e8 8b ?? ?? ?? 83 c4 04 6a 40 68 00 10 00 00 57 6a 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VaporRage_D_2147806298_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VaporRage.D!dha"
        threat_id = "2147806298"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VaporRage"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 e0 89 84 ?? ?? ?? 00 00 [0-32] 0f be ?? ?? ?? ?? 00 83 ?? ?? 88 ?? 88 ?? ?? ?? ?? 00 00 0f be ?? ?? ?? ?? 00 83 ?? ?? 88 ?? 88 ?? ?? ?? ?? 00 00 8a ?? ?? ?? ?? 00 c6 ?? ?? ?? 00 88 ?? 22}  //weight: 1, accuracy: Low
        $x_1_2 = {31 e0 89 84 ?? ?? ?? 00 00 [0-32] 0f be ?? ?? ?? ?? 00 83 ?? ?? 88 ?? 80 ?? ?? 88 ?? ?? ?? ?? 00 00 0f be ?? ?? ?? ?? 00 89 ?? c1 e6 01 89 ?? ?? ?? 8b ?? ?? ?? 81 ?? ?? 00 00 00 89}  //weight: 1, accuracy: Low
        $x_1_3 = {31 e0 89 84 ?? ?? ?? 00 00 [0-32] 0f be ?? ?? ?? ?? 00 89 ?? c1 e2 01 89 ?? ?? ?? 8b ?? ?? ?? be ?? 00 00 00 89 ?? c1 e7 01 89 ?? ?? ?? 23 ?? ?? ?? 89 ?? ?? ?? 8b}  //weight: 1, accuracy: Low
        $x_1_4 = {31 eb 89 9c ?? ?? ?? 00 00 [0-64] 0f ?? ?? ?? 00 00 8d ?? ?? ?? ?? 00 00 0f be ?? ?? ?? ?? 00 83 ?? ?? 88 ca 88 ?? ?? ?? ?? 00 00 8a ?? ?? ?? ?? 00 80 ?? ?? 0f ?? ?? 83 f1 ?? 88 ca 88 ?? ?? ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {31 e1 89 8c ?? ?? ?? 00 00 [0-48] 0f be ?? ?? ?? ?? 00 83 f1 ?? 88 ca 88 ?? ?? ?? ?? 00 00 0f be ?? ?? ?? ?? 00 83 f1 ?? 88 ca 88 ?? ?? ?? ?? ?? ?? 0f be ?? ?? ?? ?? 00 83 f1 ?? 88 ca 88 ?? ?? ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {31 e1 89 8c ?? ?? ?? 00 00 [0-48] 0f be ?? ?? ?? ?? 00 89 ?? 81 ?? ?? ?? 00 00 89 ?? ?? ?? 8b ?? ?? ?? 83 ?? ?? 89 ?? ?? ?? 8b ?? ?? ?? c1 ?? ?? 89 ?? ?? ?? 8b ?? ?? ?? c1}  //weight: 1, accuracy: Low
        $x_1_7 = {31 ea 89 94 ?? ?? ?? 00 00 [0-48] 0f be ?? ?? ?? ?? 00 83 ?? ?? 88 ?? 88 ?? ?? ?? ?? 00 00 0f be ?? ?? ?? ?? 00 83 ?? ?? 88 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 ?? ?? 88 ca 88 ?? ?? ?? ?? 00 00 0f be ?? ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_VaporRage_G_2147819366_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VaporRage.G!dha"
        threat_id = "2147819366"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VaporRage"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {44 0f b6 04 11 48 89 d0 83 e0 07 48 c1 e0 03 c4 c2 fb f7 c1 44 31 c0 88 04 11 48 ff c2 48 83 fa 1b 75}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

