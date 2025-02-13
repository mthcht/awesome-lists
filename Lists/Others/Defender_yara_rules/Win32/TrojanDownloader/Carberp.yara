rule TrojanDownloader_Win32_Carberp_A_2147631028_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carberp.A"
        threat_id = "2147631028"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 fc f6 eb 02 c2 30 01 43 8a 14 33 84 d2 75 ef}  //weight: 1, accuracy: High
        $x_1_2 = {ac 84 c0 74 09 2c ?? 34 ?? 04 ?? aa eb f2 aa}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 40 28 59 85 c0 74 ?? 03 c3 74 0d 6a 00 33 (f6|ff) 53 ff d0}  //weight: 1, accuracy: Low
        $x_1_4 = {68 35 bf a0 be 6a 01 6a 00 e8 ?? ?? ff ff 83 c4 0c ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff d0}  //weight: 1, accuracy: Low
        $x_1_5 = {68 b3 74 18 e6 6a 01 6a 00 e8 ?? ?? ff ff 83 c4 0c ff 75 20 ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff d0}  //weight: 1, accuracy: Low
        $x_1_6 = {35 bf a0 be c7 45 ?? 8f 88 d6 9b}  //weight: 1, accuracy: Low
        $x_1_7 = {b3 74 18 e6 c7 45 ?? 35 bf a0 be}  //weight: 1, accuracy: Low
        $x_1_8 = {56 33 f6 80 3a 30 75 08 80 7a 01 78 75 02 42 42 8a 0a 8a c1 2c 30 3c 09 77 0c 0f be c1 c1 e6 04 8d 74 06}  //weight: 1, accuracy: High
        $x_1_9 = {8d 41 0c c7 01 53 4d 53 54 89 51 08 c6 04 10 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Carberp_C_2147634177_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carberp.C"
        threat_id = "2147634177"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ac 84 c0 74 09 2c ?? 34 ?? 04 ?? aa eb f2 aa}  //weight: 2, accuracy: Low
        $x_2_2 = {68 35 bf a0 be 6a 01 6a 00 e8}  //weight: 2, accuracy: High
        $x_2_3 = {68 b3 74 18 e6 6a 01 6a 00 e8}  //weight: 2, accuracy: High
        $x_2_4 = {eb 4b c6 45 ?? 4c c6 45 ?? 65 c6 45 ?? 74 c6 45 ?? 73 c6 45 ?? 44 c6 45 ?? 61 c6 45 ?? 6e c6 45 ?? 63}  //weight: 2, accuracy: Low
        $x_2_5 = {0f be c9 c1 c0 07 42 33 c1 8a 0a 84 c9 75 f1 c3}  //weight: 2, accuracy: High
        $x_2_6 = {7e 07 80 31 4d 41 48 75 f9 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 75 ?? e8 ?? ?? ?? ?? 59 59 83 f8 ff 74 28}  //weight: 2, accuracy: Low
        $x_2_7 = {7d 17 8b 4d 08 03 4d ?? 0f be 11 6b d2 ff 83 ea 01 8b 45 08 03 45 f0 88 10}  //weight: 2, accuracy: Low
        $x_1_8 = "%s?id=%s&task=%d" ascii //weight: 1
        $x_1_9 = "uptime=%d&downlink=%d&uplink=%d&id=%s&statpass=%s&comme" ascii //weight: 1
        $x_1_10 = {00 6d 79 2e 63 61 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Carberp_J_2147640834_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carberp.J"
        threat_id = "2147640834"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 6e 73 53 43 4d 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = "GoogleUpdateBeta.exe /svc" ascii //weight: 1
        $x_1_3 = {47 6f 6f 67 6c 65 20 55 70 64 61 74 65 20 53 65 72 76 69 63 65 00 49 6e 73 74 61 6c 6c 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Carberp_G_2147642240_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carberp.G"
        threat_id = "2147642240"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 b3 74 18 e6 6a 01 6a 00 e8}  //weight: 2, accuracy: High
        $x_2_2 = {0f be 02 83 f0 4d 8b 4d 08 88 01 8b 55 08 83 c2 01 89 55 08 eb d6}  //weight: 2, accuracy: High
        $x_2_3 = {eb 5c c6 45 ?? 4c c6 45 ?? 65 c6 45 ?? 74 c6 45 ?? 73 c6 45 ?? 44 c6 45 ?? 61 c6 45 ?? 6e c6 45 ?? 63 c6 45 ?? 65 c6 45 ?? 00}  //weight: 2, accuracy: Low
        $x_2_4 = {66 89 04 4a 83 7d 0c 00 74 23 8b 45 0c 83 e8 01 89 45 0c ff 55 f8 99 b9 1a 00 00 00 f7 f9 83 c2 61}  //weight: 2, accuracy: High
        $x_2_5 = {ac 84 c0 74 09 2c 10 34 05 04 10 aa eb f2}  //weight: 2, accuracy: High
        $x_2_6 = {8b 43 28 03 45 ?? c6 00 68 40 8b 55 ?? 89 10 83 c0 04 c6 00 c3}  //weight: 2, accuracy: Low
        $x_2_7 = {b8 5c 00 00 00 66 89 ?? ?? b9 73 00 00 00 66 89 ?? ?? ba 6d 00 00 00 66 89 ?? ?? b8 73 00 00 00 66 89 ?? ?? b9 73}  //weight: 2, accuracy: Low
        $x_2_8 = {83 fa 63 75 7e 0f b7 45 ?? 83 f8 06 74 05 e9}  //weight: 2, accuracy: Low
        $x_1_9 = "uptime=%d&downlink=%d&uplink=%d&id=%s&statpass=%s&comme" ascii //weight: 1
        $x_1_10 = "SYSTEM_DLL_UPDATE!" ascii //weight: 1
        $x_1_11 = "\\bot_Dll" ascii //weight: 1
        $x_1_12 = {5c 63 61 72 62 65 72 70 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Carberp_K_2147645351_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carberp.K"
        threat_id = "2147645351"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0c 17 32 0c 03 40 3b c5 88 0a 72 02}  //weight: 1, accuracy: High
        $x_1_2 = {8a 10 80 f2 4d 88 10 40 49 75 f5}  //weight: 1, accuracy: High
        $x_1_3 = "s&statpass=%s" ascii //weight: 1
        $x_1_4 = {c6 44 24 10 63 66 c7 44 24 13 03 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Carberp_S_2147650970_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carberp.S"
        threat_id = "2147650970"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 65 f8 10 81 e1 80 00 00 00 89 75 fc 8b f2 81 e2 80 80 00 00 c1 e1 08 0b ca 8b 55 fc c1 ea 07 c1 e1 09 8d 1c 3f}  //weight: 1, accuracy: High
        $x_1_2 = "s&statpass=%s" ascii //weight: 1
        $x_1_3 = ".apartmsk.ru" ascii //weight: 1
        $x_1_4 = ".ruporno.tv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Carberp_A_2147651616_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carberp.gen!A"
        threat_id = "2147651616"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 44 24 01 02 44 24 02 88 44 24 01 8b ca 32 4c 24 02 02 c8 88 4c 24 02 32 54 24 03 02 14 24}  //weight: 1, accuracy: High
        $x_1_2 = {8d 54 24 08 8a 18 80 f3 18 81 e3 ff 00 00 00 33 d9 88 1a 41}  //weight: 1, accuracy: High
        $x_1_3 = {80 3c 07 a1 75 27 80 7c 07 05 c7 75 20}  //weight: 1, accuracy: High
        $x_1_4 = {80 7c 07 06 80 75 19 80 7c 07 0f c3 75 12}  //weight: 1, accuracy: High
        $x_1_5 = {03 d2 33 c2 33 d2 8a d3 33 c2 88 04 3e 84 c0 75 04 c6 04 3e ff 47 8a 04 3e}  //weight: 1, accuracy: High
        $x_1_6 = {89 0b 83 c2 05 c6 02 c3 c7 44 24 0c 30 00 00 00 c7 44 24 10 80 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Carberp_Z_2147654394_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carberp.Z"
        threat_id = "2147654394"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 6e 6b 2e 6c 69 73 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {b9 04 01 00 00 8d 68 0c c7 00 53 4d 53 54 89 48 04 89 48 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Carberp_AD_2147658558_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carberp.AD"
        threat_id = "2147658558"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 ee 0f b6 ee 0f b6 2c ed ?? ?? ?? ?? c1 e5 08 31 ee 0f b6 ef 0f b6 2c ed ?? ?? ?? ?? c1 e5 18 31 ee 0f b6 ea 0f b6 2c ed ?? ?? ?? ?? 31 ef 0f b6 ec 0f b6 2c ed ?? ?? ?? ?? c1 e5 08 31 ef}  //weight: 10, accuracy: Low
        $x_10_2 = {89 74 24 10 8b 3c d5 ?? ?? ?? ?? f2 ae f7 d1 2b f9 8b c1 8b f7 8b 7c 24 10 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8b 34 d5 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 01 eb 45 ff d5 99 f7 3d ?? ?? ?? ?? 83 c9 ff}  //weight: 10, accuracy: Low
        $x_1_3 = {b9 ff 09 00 00 8d 7c 24 09 f3 ab 66 ab aa 33 c0 b9 00 0a 00 00 bf ?? ?? ?? ?? f3 ab b9 00 0a 00 00 8d 7c 24 08 f3 ab 8d 44 24 04 50 8d 4c 24 0c}  //weight: 1, accuracy: Low
        $x_1_4 = {b9 ff 09 00 00 8d bd f9 d7 ff ff f3 ab 66 ab be 00 28 00 00 56 aa 53 bf ?? ?? ?? ?? 57 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Carberp_BO_2147670727_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carberp.BO"
        threat_id = "2147670727"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 46 0e 8a 43 0f 32 47 0f 88 46 0f 83 c3 10 83 c6 10 83 c1 10 8d 41 0f}  //weight: 1, accuracy: High
        $x_1_2 = {b9 ff 09 00 00 33 c0 8d bd fd d7 ff ff f3 ab 66 ab aa 68 00 28 00 00 6a 00 68 ?? ?? ?? ?? e8 ec 28 00 00 83 c4 0c 68 00 28 00 00 6a 00}  //weight: 1, accuracy: Low
        $x_10_3 = {31 ee 0f b6 ee 0f b6 2c ed ?? ?? ?? ?? c1 e5 08 31 ee 0f b6 ef 0f b6 2c ed ?? ?? ?? ?? c1 e5 18 31 ee 0f b6 ea 0f b6 2c ed ?? ?? ?? ?? 31 ef 0f b6 ec 0f b6 2c ed ?? ?? ?? ?? c1 e5 08 31 ef}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Carberp_BS_2147681930_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carberp.BS"
        threat_id = "2147681930"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 30 4d 40 39 d0 75 ?? 89 4c 24 08 89 5c 24 04 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 c4 10 28 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "daemonupd.exe /app" ascii //weight: 1
        $x_1_3 = {47 6f 6f 67 6c 65 5c 55 70 64 61 74 65 00 77 69 6e 75 70 64 61 74 65}  //weight: 1, accuracy: High
        $x_10_4 = {31 ee 0f b6 ee 0f b6 2c ed ?? ?? ?? ?? c1 e5 08 31 ee 0f b6 ef 0f b6 2c ed ?? ?? ?? ?? c1 e5 18 31 ee 0f b6 ea 0f b6 2c ed ?? ?? ?? ?? 31 ef 0f b6 ec 0f b6 2c ed ?? ?? ?? ?? c1 e5 08 31 ef}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Carberp_BT_2147682628_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carberp.BT"
        threat_id = "2147682628"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 e2 04 8d 54 0a d0 89 c1 83 e1 01 40 85 c9 74 08 89 c1 d1 f9 88 54 0c 3b 83 f8 20}  //weight: 10, accuracy: High
        $x_5_2 = {8a 04 2a 32 06 88 07 47 43 46 45 39 6c 24 24 0f 9f c1 83 fb 0f 0f 9e c0 84 c1 75}  //weight: 5, accuracy: High
        $x_5_3 = {8a 04 29 32 06 88 04 29 88 07 47 46 45 eb 0a 31 ed 89 d0 29 f0 89 44 24 24 8b 4c 24 24 01 f1 89 4c 24 10 83 f9 0f 7f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Carberp_BU_2147683706_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carberp.BU"
        threat_id = "2147683706"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 5f 42 54 5f 56 45 52 3a [0-10] 00}  //weight: 1, accuracy: Low
        $x_1_2 = {45 53 54 52 5f 50 41 53 53 5f 00}  //weight: 1, accuracy: High
        $x_2_3 = {5f 44 4c 4c 5f 44 41 54 41 5f [0-16] 4d 5a}  //weight: 2, accuracy: Low
        $x_3_4 = {8e fe 1f 4b (e8|74)}  //weight: 3, accuracy: Low
        $x_3_5 = {68 f8 7f d6 aa 6a 02 6a 00 e8}  //weight: 3, accuracy: High
        $x_3_6 = {68 f8 7f d6 aa 6a 02 53 a4 89 5d f8 89 5d f4 89 5d f0 89 5d fc e8}  //weight: 3, accuracy: High
        $x_1_7 = "bki.plug" ascii //weight: 1
        $x_1_8 = "installbk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Carberp_BV_2147724976_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carberp.BV!bit"
        threat_id = "2147724976"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 c7 45 f0 eb fe cc cc 8b 06 ff 76 08 89 45 f8 a1 ?? ?? ?? 00 89 45 ec e8 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 89 45 ?? 58 53 68 00 00 00 08 50 89 45 ?? 8d 45 ?? 50 8d 45 ?? c7 45 ?? 18 00 00 00 50 68 1f 00 0f 00 8d 45 ?? 89 5d ?? 50 89 5d ?? 89 5d ?? 89 5d ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 47 fc 48 03 c2 23 c1 74 1b 50 8b 07 03 c3 50 8b 47 f8 03 45 08 50 e8 ?? ?? ?? 00 8b 4d f4 83 c4 0c 8b 55 0c}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 40 68 00 30 00 00 68 ?? ?? ?? 00 56 ff 37 ff 15 ?? ?? ?? 00 89 45 08 85 c0 0f 84 cc 00 00 00 8d 85 ?? ?? ?? ff 50 ff 77 04 ff 15 ?? ?? ?? 00 85 c0 79 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Carberp_BW_2147724979_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carberp.BW!bit"
        threat_id = "2147724979"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 1e 0f b6 06 80 e3 1f 33 f8 0f b6 cb d3 c7 8d 76 02 33 c0 66 39 06 75 e7}  //weight: 1, accuracy: High
        $x_1_2 = {8a 6d 10 8d 58 01 0f b6 c3 89 45 fc 8b f8 8a 0c 10 02 e9 0f b6 c5 89 45 10 8a 04 10 88 04 17 8b 45 10 88 0c 10 8a 04 17 8b 7d 08 02 c1 0f b6 c0 8a 04 10 30 04 3e 46 8b 45 fc 3b 75 0c 7c c1}  //weight: 1, accuracy: High
        $x_1_3 = {76 6e 63 64 6c 6c 33 32 2e 64 6c 6c 00 56 6e 63 53 74 61 72 74 53 65 72 76 65 72 00 56 6e 63 53 74 6f 70 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

