rule TrojanDownloader_Win32_Bedobot_A_2147646609_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bedobot.A"
        threat_id = "2147646609"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bedobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 8b 45 ec 80 3c 30 40 74 09 3b 77 38 0f 8e}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 ec 69 45 08 e8 03 00 00 89 45 f0 8d 45 ec 89 45 e8 eb 05}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 4d fe c1 e9 08 32 0e 88 08 02 4d fe 0f b6 c9 66 0f af 4d fa 66 03 4d fc 66 89 4d fe}  //weight: 1, accuracy: High
        $x_1_4 = {0f b7 4d fe c1 e9 08 32 0e 88 08 02 4d fe 0f b6 c9 66 0f af 4d fa 66 03 4d fc 66 89 4d fe 46 40 4a 75 dd b0 01}  //weight: 1, accuracy: High
        $x_1_5 = {e8 00 00 00 00 5f 81 ef ?? ?? 49 00 8b c7 81 c7 ?? ?? 49 00 3b 47 2c 75 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Bedobot_B_2147651728_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bedobot.B"
        threat_id = "2147651728"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bedobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {46 8b 45 ec 80 3c 30 40 74 09 3b 77 38 0f 8e}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 ec 80 3c 30 3e 74 09 3b 77 38 0f 8e}  //weight: 2, accuracy: High
        $x_2_3 = {8d 44 24 01 50 68 b8 0b 00 00 8d 4c 24 08 33 d2 8b c6 e8}  //weight: 2, accuracy: High
        $x_2_4 = {89 45 ec 69 45 08 e8 03 00 00 89 45 f0 8d 45 ec 89 45 e8 eb 05}  //weight: 2, accuracy: High
        $x_2_5 = {8d 40 00 53 51 8b d8 c7 04 24 01 00 00 00 54 68 7e 66 04 80 8b 43 08 50 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Bedobot_C_2147653018_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bedobot.C"
        threat_id = "2147653018"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bedobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 6d 61 69 00 [0-16] 2e 65 6d 6c 00 [0-16] 2e 74 62 62 00 [0-16] 2e 6d 62 6f 78 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 70 68 70 3f 49 3d 31 00}  //weight: 1, accuracy: High
        $x_2_3 = {74 1a 8d 4d ?? 8b d3 8b 45 ?? 8b 38 ff 57 ?? 8b 55 ?? b1 06 8b 45 ?? e8 ?? ?? ?? ?? 43 4e 0f 85 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_2_4 = {75 0d 8d 45 ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 ?? 8b 45 ?? e8 ?? ?? ?? ?? 48 0f 85 ?? ?? ?? ?? 80 7d ?? 01 75 04 b3 02 eb 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

