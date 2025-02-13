rule TrojanDownloader_Win32_Moure_B_2147663540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Moure.B"
        threat_id = "2147663540"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Moure"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 34 30 30 32 31 31 74 2e 64 6c 6c 00 43 72 6f 6e 45 78 69 65 65 65 6e 66 69 65 57 65 33 33 33 66 73 62 64 45 61 73 64 77 66 73 61 74 61 73 66 67 45 78 57 00 53 74 66 52 75 61 41 72 65 73 64 67 66 68 73 77 63 76 57 33 32 31 45 64 73 33 33 33 6e 71 77 65 71 66 63 77 75 72 5f 72 74 00 53 74 72 66 41 6c 6f 73 64 71 77 68 67 66 77 67 68 61 66 67 6e 69 45 33 33 77 71 72 71 73 64 67 6f 66 74 45 78 57 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Moure_C_2147681661_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Moure.C"
        threat_id = "2147681661"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Moure"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 0c 3d 27 7a e1 eb e2 1d 33 d2 99 94 e4 77 61 74 14 6f 82 35 de 0c 00 ef a7 0d 50 5a 95 76 66 4a 14 6f 82 3c 6f 6e d5 1b dd 07 ad 2b 42 20 54}  //weight: 1, accuracy: High
        $x_1_2 = {d8 ab 75 2c 19 22 54 2d df 65 dc ab 65 dc 1b 66 38 52 e0 cb 1d ab 75 dc 2f 97 24 71 ab 24 a3 23 65 28 1b e6 56 39 1b 65 cc 53 34 ab 24 b7 23 65 28 70 df 55 28 df 35 94 05 60 00 a5 e0 54 0b a5}  //weight: 1, accuracy: High
        $x_1_3 = {7c 53 59 53 57 4f 57 16 14 7c 53 56 43 48 4f 53 54 0e 45 58 45 00 00 00 7c 53 59 53 54 45 4d 13 12 7c 57 55 41 55 43 4c 54 0e 45 58 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Moure_A_2147681963_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Moure.gen!A"
        threat_id = "2147681963"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Moure"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {81 78 12 33 c0 5d c2 0f}  //weight: 5, accuracy: High
        $x_5_2 = {81 78 0a 90 90 c3 90 0f}  //weight: 5, accuracy: High
        $x_1_3 = {03 00 41 00 56 00 49 00}  //weight: 1, accuracy: High
        $x_5_4 = {81 78 0a b8 00 00 00 0f}  //weight: 5, accuracy: High
        $x_5_5 = {81 78 0e 00 c2 2c 00 0f}  //weight: 5, accuracy: High
        $x_5_6 = {81 78 0e 00 c2 40 00 0f}  //weight: 5, accuracy: High
        $x_5_7 = {81 78 0d 00 c2 40 00 0f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Moure_B_2147684275_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Moure.gen!B"
        threat_id = "2147684275"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Moure"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {35 e1 7a d7 af 3b ce 73 ?? 8b 54 24 ?? 8b 14 11 8b 7c 24 ?? 33 d0 89 14 0f 83 c1 04 3b ce}  //weight: 10, accuracy: Low
        $x_1_2 = "MSASCui.exe" ascii //weight: 1
        $x_1_3 = "MpCmdRun.exe" ascii //weight: 1
        $x_1_4 = "MsMpEng.exe" ascii //weight: 1
        $x_1_5 = "NisSrv.exe" ascii //weight: 1
        $x_1_6 = "msseces.exe" ascii //weight: 1
        $x_10_7 = {8d 50 01 8a 08 40 3a cb 75 ?? 2b c2 3b c3 74 ?? 80 bc 04 9f 00 00 00 5c 74 ?? c6 84 04 a0 00 00 00 5c 40}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Moure_C_2147689008_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Moure.gen!C"
        threat_id = "2147689008"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Moure"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "105"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {ff b5 dc fe ff ff 50 6a 01 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 6a 01 56 ff 15 ?? ?? ?? ?? 56 03 d8 ff 15 ?? ?? ?? ?? 8d 85 d4 fe ff ff 50 57 ff 15 ?? ?? ?? ?? 85 c0 75 ?? 57 ff 15}  //weight: 100, accuracy: Low
        $x_100_2 = {8b 5d f4 3b df 0f 86 ?? ?? ?? ?? b8 ?? ?? ?? ?? 8d 50 01 8a 08 40 84 c9 75 ?? 2b c2 6a 06 8d 74 33 e8 83 c3 e8 8d b8 ?? ?? ?? ?? 59 f3 a5}  //weight: 100, accuracy: Low
        $x_100_3 = {3a cb 75 f9 2b c2 3b c3 74 1a 80 bc 04 97 00 00 00 5c 74 10 c6 84 04 98 00 00 00 5c 40 88 9c 04 98}  //weight: 100, accuracy: High
        $x_100_4 = {33 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a 8b 5a 10 8b 12}  //weight: 100, accuracy: High
        $x_1_5 = {00 4d 53 41 53 43 75 69 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 4d 70 43 6d 64 52 75 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 4d 73 4d 70 45 6e 67 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 4e 69 73 53 72 76 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 6d 73 73 65 63 65 73 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 5 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

