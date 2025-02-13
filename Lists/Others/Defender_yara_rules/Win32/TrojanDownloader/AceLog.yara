rule TrojanDownloader_Win32_AceLog_A_2147767193_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AceLog.A!dha"
        threat_id = "2147767193"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AceLog"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 64 3d 25 73 ?? 25 73 23 25 75 26 63 6d 64 3d 79 00}  //weight: 2, accuracy: Low
        $x_2_2 = {69 64 3d 25 73 23 25 73 23 25 ?? 26 63 75 72 72 65 6e 74 3d 25 73 26 74 6f 74 61 6c 3d ?? 73 26 64 61 74 61 3d 00}  //weight: 2, accuracy: Low
        $x_1_3 = {64 6d 63 62 6a ?? 2e 64 6c 6c 00 00 64 00 6d 00 63 00 62 00 6a 00 65 ?? 2e 00 64 00 6c 00 6c 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {43 4d 44 00 2d 00 2d 00 2d 00 2d ?? 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 00 00 00 00 0d 00 0a 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {69 6e 74 5f 6d 6f 64 2e 64 6c ?? 00 52 75 6e 4d 6f 64 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {54 00 45 00 53 00 54 00 00 ?? 00 00 50 00 4f 00 53 00 54 00 00 00 00 00 00 00 00 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2d 00 54 00 79 00 70 00 65 00 3a 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 78 00 2d 00 77 00 77 00 77 00 2d 00}  //weight: 1, accuracy: Low
        $x_1_7 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d ?? 20 00 46 00 69 00 6c 00 65 00 73 00 00 00 00 00 2a 00 00 00 2e 00 00 00 2e 00 2e 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {2a 00 00 00 2e 00 00 00 2e 00 2e ?? 00 00 00 00 73 79 73 74 65 6d 69 6e 66 6f 00 00 74 61 73 6b 6c 69 73 74 00 00 00 00}  //weight: 1, accuracy: Low
        $n_10_9 = {52 00 55 00 4e 00 44 00 4c 00 ?? 00 33 00 32 00 2e 00 45 00 58 00 45 00 20 00 22 00 25 00 73 00 22 00 2c 00 20 00 23 00 31 00 00 00 63 6d 64 20 2f ?? 20 44 45 4c 20 00 20 22 00 00}  //weight: -10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_AceLog_B_2147780964_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AceLog.B!dha"
        threat_id = "2147780964"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AceLog"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 4f 00 4e 00 4f 00 55 00 54 00 24 00 00 00 41 00 00 00 17 00 00 00 63 6d ?? 20 2f 63 20 44 45 4c 20 00 20 22 00 00 [0-16] 2e 64 6c 6c 00 00 [0-32] 2e 00 64 00 6c 00 6c 00 00 00 00 00 43 4d 44 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 00 00 00 00 2a 00 00 00 [0-48] 00 00 73 79 73 74 ?? 6d 69 6e 66 6f 00 00 74 61 73 6b ?? 69 73 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 6c 75 73 68 46 69 6c 65 42 75 66 66 65 72 73 [0-80] 00 69 6e 74 5f 6d ?? 64 2e 64 6c 6c 00 52 75 6e 4d 6f 64 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {33 d2 8b c1 b9 00 00 20 00 f7 f1 33 c9 89 8d ?? ?? ff ff 3b ca 89 95 ?? ?? ff ff 1b d2 f7 da 03 d0 89 95 ?? ?? ff ff 0f 84 ?? ?? ?? ?? 8b ff}  //weight: 1, accuracy: Low
        $x_1_5 = {03 d0 89 95 ?? ?? ff ff 0f 84 ?? ?? 00 00 8b ff 8b b5 ?? ?? ff ff 85 f6 74 09 8d 42 ff 8b fe 3b c8 74 05 bf 00 00 20 00 57 6a 08 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

