rule TrojanDownloader_Win32_Zemot_A_2147687059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zemot.A"
        threat_id = "2147687059"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zemot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 18 68 00 00 00 a0 6a ff ff 34 b0 57 ff 15 ?? ?? ?? ?? 46 3b 75 1c 72 e6}  //weight: 1, accuracy: Low
        $x_2_2 = {65 00 78 00 65 00 00 00 4a 00 61 00 76 00 61 00 5f 00 55 00 70 00 64 00 61 00 74 00 65 00 5f 00}  //weight: 2, accuracy: High
        $x_1_3 = {66 31 45 ec b8 d6 48 00 00 66 31 45 ee 33 c9 33 c0 8a 54 05 f8 30 54 0d f0 40 83 f8 04 75 02 0c 00 81 75 e8 ?? ?? ?? ?? b8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6c 6f 61 64 65 72 33 32 2e 62 69 6e 00 6c 6f 61 64 65 72 43 6f 6e 66 69 67 53 6f 75 72 63 65 00}  //weight: 1, accuracy: High
        $x_2_5 = "UpdateFlashPlayer_" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zemot_B_2147687062_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zemot.B"
        threat_id = "2147687062"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zemot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e6 ff 00 00 00 8a 14 06 30 14 39 47 3b 7d 0c 72 c8}  //weight: 1, accuracy: High
        $x_1_2 = "vfs\\soft32.dll" wide //weight: 1
        $x_1_3 = {89 08 c7 40 04 ?? ?? ?? ?? c7 40 08 ?? ?? ?? ?? 8b 56 04 8b 4e 0c 2b 4a 34 81 c1 ?? ?? ?? ?? 74 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Zemot_E_2147687937_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zemot.E"
        threat_id = "2147687937"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zemot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "UpdateFlashPlayer_" wide //weight: 2
        $x_2_2 = "%s%08x.%s" wide //weight: 2
        $x_1_3 = "\"%s\" %s" wide //weight: 1
        $x_1_4 = "\"%s\" -child" wide //weight: 1
        $x_3_5 = {8b 47 34 ff 77 08 85 c0 74 0c ff 77 30 50 56 e8 ?? ?? ff ff eb 0c 8b 47 30 8b 5d 08 56 e8 ?? ?? ff ff}  //weight: 3, accuracy: Low
        $x_2_6 = {b8 00 00 20 03 3b fe 74 04 3b f8 76 02}  //weight: 2, accuracy: High
        $x_1_7 = {b8 de c0 ad 0b 56 89 44 31 10}  //weight: 1, accuracy: High
        $x_1_8 = {b9 de c0 0d 60 39 4e 08 75 11 39 48 04 75 0c 8b 4e 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zemot_A_2147688916_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zemot.A!!Zemot"
        threat_id = "2147688916"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zemot"
        severity = "Critical"
        info = "Zemot: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 18 68 00 00 00 a0 6a ff ff 34 b0 57 ff 15 ?? ?? ?? ?? 46 3b 75 1c 72 e6}  //weight: 1, accuracy: Low
        $x_2_2 = {65 00 78 00 65 00 00 00 4a 00 61 00 76 00 61 00 5f 00 55 00 70 00 64 00 61 00 74 00 65 00 5f 00}  //weight: 2, accuracy: High
        $x_1_3 = {66 31 45 ec b8 d6 48 00 00 66 31 45 ee 33 c9 33 c0 8a 54 05 f8 30 54 0d f0 40 83 f8 04 75 02 0c 00 81 75 e8 ?? ?? ?? ?? b8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6c 6f 61 64 65 72 33 32 2e 62 69 6e 00 6c 6f 61 64 65 72 43 6f 6e 66 69 67 53 6f 75 72 63 65 00}  //weight: 1, accuracy: High
        $x_2_5 = "UpdateFlashPlayer_" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zemot_A_2147694651_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zemot.gen!A"
        threat_id = "2147694651"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zemot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 18 68 00 00 00 a0 6a ff ff 34 b0 57 ff 15 ?? ?? ?? ?? 46 3b 75 1c 72 e6}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 78 04 0f b6 18 0f b7 ca 66 0f be 3c 0f 66 33 fb 66 33 fa bb ff 00 00 00 66 23 fb 42 66 89 3c 4e 66 3b 50 02 72 d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

