rule TrojanDownloader_Win32_Bredolab_B_2147799819_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bredolab.B"
        threat_id = "2147799819"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bredolab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {eb 17 81 e1 ff 00 00 00 8d 5a 01 03 db 33 cb 33 db 8a d8}  //weight: 2, accuracy: High
        $x_2_2 = {b8 4b 4c 43 cf e8}  //weight: 2, accuracy: High
        $x_2_3 = {83 c0 17 01 d0 80 38 a1 75 07 c6 05}  //weight: 2, accuracy: High
        $x_2_4 = {c7 45 fc a1 00 00 00 6a 01 8d 45 fc}  //weight: 2, accuracy: High
        $x_2_5 = {72 bb 5b 8b 46 28 03 45 fc 89 45 f0 8b 55 1c 81 c2 a4 00 00 00}  //weight: 2, accuracy: High
        $x_1_6 = "Entity-Info" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bredolab_X_2147799820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bredolab.X"
        threat_id = "2147799820"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bredolab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 06 02 14 24 32 d3 88 14 06 40 3d 58 1b 00 00 75 ed 5a 5e 5b c3 07 00 e8 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bredolab_AC_2147803106_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bredolab.AC"
        threat_id = "2147803106"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bredolab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 54 24 08 8a 18 80 f3 ?? 81 e3 ff 00 00 00 33 d9 88 1a 41 42 40 83 f9 10 75 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {80 fa 24 75 61 8d 58 01 ba fe 00 00 00 2b d0 2b d3 72 53 42 80 3c 1e 3a 75 48}  //weight: 1, accuracy: High
        $x_1_3 = {7c 1a 41 33 d2 8b 1c 24 8d 3c 13 8a 1c 30 30 1f 46 83 fe 10 75 02}  //weight: 1, accuracy: High
        $x_1_4 = {75 11 8b c3 e8 ?? ?? ?? ?? 83 f8 01 75 05 bf 02 00 00 00 83 ff 02 75 ?? 6a 00 6a 04}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 7b 8d a8 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Bredolab_AA_2147803107_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bredolab.AA"
        threat_id = "2147803107"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bredolab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {85 ed 74 5f 83 c5 0e 8b dd a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 57 ff 15 ?? ?? ?? ?? 83 c4 08 8b e8 a1}  //weight: 2, accuracy: Low
        $x_1_2 = {57 b9 50 00 00 00 8b d3 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b f8 8b c6 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 6e 65 77 2f 63 6f 6e 74 72 6f 6c 6c 65 72 2e 70 68 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bredolab_A_2147803981_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bredolab.A"
        threat_id = "2147803981"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bredolab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 36 ef 46 e2 fa 8b 0d ?? ?? 40 00 8b 35 ?? ?? 40 00 80 3e 0d 75 03 c6 06 00 80 3e 0a 75 03 c6 06 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bredolab_F_2147804122_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bredolab.F"
        threat_id = "2147804122"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bredolab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 14 06 8b 5c 24 10 32 14 19 41 88 10 3b 4c 24 14 72 02}  //weight: 2, accuracy: High
        $x_2_2 = {c6 40 05 e9 8b 45 fc 2b 45 0c 83 e8 0a 89 45 f8 8b 45 0c 8b 4d f8 89 48 06 6a 05 58}  //weight: 2, accuracy: High
        $x_1_3 = "action=bot&entity_list=" ascii //weight: 1
        $x_1_4 = "ction=report&guid=0&rnd=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bredolab_B_2147804142_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bredolab.gen!B"
        threat_id = "2147804142"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bredolab"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 e2 0c 8b 5f 08 8b 44 24 10 03 c1 8a 1c 1e 32 da 30 18 46 3b 37 72 02 33 f6}  //weight: 2, accuracy: High
        $x_2_2 = {6a 01 8d 44 11 ff 5a 80 e3 0c 2b d1 8b 4e 08 8a 4c 39 ff 32 08 32 cb 4f 88 08 75 02 8b 3e}  //weight: 2, accuracy: High
        $x_2_3 = {8b 75 08 81 7d 0c f8 00 00 00 8b 46 3c 8d 3c 30 0f 82 f9 00 00 00 81 3f 50 45 00 00 0f 85 ed 00 00 00 3b c3 0f 8e e5 00 00 00 6a 04 68 00 30 00 00}  //weight: 2, accuracy: High
        $x_1_4 = "Magic-Number:" ascii //weight: 1
        $x_1_5 = "Entity-Info:" ascii //weight: 1
        $x_2_6 = "/loaderbb.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bredolab_D_2147804198_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bredolab.gen!D"
        threat_id = "2147804198"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bredolab"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 74 24 08 33 c0 85 f6 7e ?? 8d 4c 24 08 83 c1 04 8a 11 80 f2 05 88 90 ?? ?? ?? ?? 40 3b c6 7c ed}  //weight: 2, accuracy: Low
        $x_2_2 = {57 6a 01 6a 1a 8d 85 ?? ?? ff ff 50 33 ff 57 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 57 57 6a 04 57 57 68 00 00 00 80 8d 85 ?? ?? ff ff 50 ff 15}  //weight: 2, accuracy: Low
        $x_1_3 = {50 6a 01 6a 00 ff 15 ?? ?? ?? ?? 8b d8 ff 15 ?? ?? ?? ?? 3d b7 00 00 00 0f 85 ?? ?? ff ff 6a 01 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c4 1c 50 6a 01 6a 00 ff d7 8b 1d ?? ?? ?? ?? 89 44 24 10 ff d3 bd b7 00 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_5 = {ff 75 08 56 56 ff 15 ?? ?? ?? ?? 83 f8 20 0f 9f c0 eb 02 b0 01 5e}  //weight: 1, accuracy: Low
        $x_1_6 = {61 6e 74 69 6b 6c 75 73 00}  //weight: 1, accuracy: High
        $x_1_7 = {2f 64 62 67 34 2e 70 68 70 3f 00}  //weight: 1, accuracy: High
        $x_1_8 = {45 6e 74 69 74 79 2d 49 6e 66 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

