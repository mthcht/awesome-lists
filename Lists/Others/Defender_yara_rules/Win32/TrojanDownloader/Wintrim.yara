rule TrojanDownloader_Win32_Wintrim_A_90453_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wintrim.gen!A"
        threat_id = "90453"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wintrim"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 33 d2 f7 f6 8a 04 3a 30 04 19 41 3b 4d 0c 72 ee}  //weight: 1, accuracy: High
        $x_1_2 = "WAOL.EXE" ascii //weight: 1
        $x_1_3 = "EGDHTML" ascii //weight: 1
        $x_1_4 = "Opening the port..." ascii //weight: 1
        $x_1_5 = "Registering your computer on the network..." ascii //weight: 1
        $x_1_6 = "All Internet Explorer have been closed." ascii //weight: 1
        $x_1_7 = "rundll32.exe EGDACCESS.dll" ascii //weight: 1
        $x_1_8 = "XORFile2File : " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Wintrim_BX_141431_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wintrim.BX"
        threat_id = "141431"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wintrim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {3c 5f 45 47 4d 43 5f 3e 00}  //weight: 2, accuracy: High
        $x_2_2 = {53 6f 66 74 77 61 72 65 5c 66 63 6e 00}  //weight: 2, accuracy: High
        $x_2_3 = {25 73 25 63 69 74 79 70 65 3d 25 64 26 72 65 73 3d 25 64 00}  //weight: 2, accuracy: High
        $x_1_4 = {5f 50 52 4f 47 52 41 4d 46 49 4c 45 53 5f 44 49 52 5f 00}  //weight: 1, accuracy: High
        $x_1_5 = {5f 53 59 53 54 45 4d 5f 44 49 52 5f 00}  //weight: 1, accuracy: High
        $x_1_6 = {5f 57 49 4e 44 4f 57 53 5f 44 49 52 5f 00}  //weight: 1, accuracy: High
        $x_1_7 = {26 67 72 70 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_8 = {26 61 76 72 65 73 75 6c 74 3d 00}  //weight: 1, accuracy: High
        $x_1_9 = {26 61 76 65 72 72 6f 72 3d 00}  //weight: 1, accuracy: High
        $x_1_10 = {26 64 6c 5f 6c 61 73 74 65 72 72 6f 72 3d 00}  //weight: 1, accuracy: High
        $x_1_11 = {26 64 6c 5f 73 74 61 74 75 73 63 6f 64 65 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Wintrim_BY_143220_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wintrim.BY"
        threat_id = "143220"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wintrim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {88 0a 8b 45 08 03 85 ?? ?? ff ff 8b 8d ?? ?? ff ff 8a 10 32 94 0d ?? ?? ff ff 8b 45 08 03 85 ?? ?? ff ff 88 10 8b 4d 08 03 8d ?? ?? ff ff 8b 95 ?? ?? ff ff 8a 01 32 84 15 ?? ?? ff ff 8b 4d 08 03 8d ?? ?? ff ff 88 01 e9 9f fe ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = {3b 55 ac 0f 83 07 01 00 00 8b 85 ?? ?? ff ff 25 ff 00 00 00 39 85 ?? ?? ff ff 75 0a}  //weight: 2, accuracy: Low
        $x_2_3 = {83 78 28 00 74 1b 8b 8d ?? ?? ff ff 8b 95 ?? ?? ff ff 03 51 28 89 95 d8 f7 ff ff ff 95 d8 f7 ff ff 68 0f 00 01 00 ff 55 ?? b8 0f 00 01 00}  //weight: 2, accuracy: Low
        $x_1_4 = {66 8b 11 81 fa 4d 5a 00 00 74 12 68 04 00 01 00 ff 55 ?? b8 04 00 01 00 e9 ?? 0e 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {83 fa 43 0f 85 ?? 00 00 00 8b 45 f0 0f be 48 01 83 f9 3a 0f 85 ?? 00 00 00 8b 55 f0 0f be 42 02 83 f8 5c 75 7c 8b 4d f0 0f be 51 03 83 fa 6d 75 70}  //weight: 1, accuracy: Low
        $x_1_6 = {c6 45 d4 25 c6 45 d5 30 c6 45 d6 38 c6 45 d7 58 c6 45 d8 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Wintrim_BZ_144247_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wintrim.BZ"
        threat_id = "144247"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wintrim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 3a 0f 85 ?? ?? 00 00 80 ?? 02 5c 0f 85 ?? ?? 00 00 80 ?? 03 6d 0f 85 ?? ?? 00 00 80 ?? 04 79 0f 85 ?? ?? 00 00 80 ?? 05 61 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {df e0 f6 c4 40 75 ?? d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Wintrim_CA_144980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wintrim.CA"
        threat_id = "144980"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wintrim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {dd d8 c3 90}  //weight: 1, accuracy: High
        $x_1_2 = {dd d8 d9 41}  //weight: 1, accuracy: High
        $x_1_3 = {d9 c0 d8 c9}  //weight: 1, accuracy: High
        $x_5_4 = {2c 31 00 00 02 00 81 (f8|2d|ff) ?? ?? ?? ?? [0-34] 0f 8c ?? ?? ff ff}  //weight: 5, accuracy: Low
        $x_5_5 = {2c 31 00 00 01 00 3d ?? ?? ?? ?? [0-34] 0f 8c ?? ?? ff ff}  //weight: 5, accuracy: Low
        $x_10_6 = {df e0 f6 c4 40 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

