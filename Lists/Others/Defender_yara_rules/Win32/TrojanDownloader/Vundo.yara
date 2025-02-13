rule TrojanDownloader_Win32_Vundo_2147623060_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vundo"
        threat_id = "2147623060"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 43 60 bf 8b 0d f8 6c 40 00 c6 43 65 90 89 4b 61}  //weight: 1, accuracy: High
        $x_1_2 = {89 35 3c 68 40 00 a3 2c 68 40 00 72 c1 8b 15 5c 6c 40 00 8d 83 c2 02 00 00 8d 8b 72 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Vundo_J_2147641757_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vundo.J"
        threat_id = "2147641757"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 80 fa 8b 74 05 80 fa 55 75 (11)}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d9 0f b6 1b 0f b6 d2 2b d3 83 fa 12 74 (3b)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Vundo_J_2147641757_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vundo.J"
        threat_id = "2147641757"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 38 21 43 46 47}  //weight: 1, accuracy: High
        $x_1_2 = {81 7c 11 fd 0d 0a 0d 0a}  //weight: 1, accuracy: High
        $x_1_3 = {81 3e 77 77 77 2e}  //weight: 1, accuracy: High
        $x_1_4 = {c7 07 68 74 74 70 c7 47 04 3a 2f 2f 00}  //weight: 1, accuracy: High
        $x_2_5 = {81 fa 47 45 54 20 75 04 33 d2 eb 0b 81 fa 50 4f 53 54 75 b7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Vundo_HIY_2147644197_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vundo.HIY"
        threat_id = "2147644197"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {47 45 54 20 75 04 33 ?? eb 0b 81 ?? 50 4f 53 54 75 ?? 6a 04}  //weight: 3, accuracy: Low
        $x_3_2 = {c7 07 68 74 74 70 c7 47 04 3a 2f 2f 00 83 c7 07}  //weight: 3, accuracy: High
        $x_3_3 = {81 3e 77 77 77 2e 75 03 83 c6 04}  //weight: 3, accuracy: High
        $x_1_4 = {81 7c 11 fd 0d 0a 0d 0a}  //weight: 1, accuracy: High
        $x_1_5 = {81 7c 0a fd 0d 0a 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Vundo_F_2147648994_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vundo.F"
        threat_id = "2147648994"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 1d 5c a0 00 10 03 03 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {00 10 8b 48 28 85 c9 74 14 a1 ?? ?? 00 10 6a 00 03 c8 6a ?? 50 89 0d ?? ?? 00 10 ff d1 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {83 ec 20 e8 ?? e4 ff ff ff 15 ?? 90 00 10 68 d2 04 00 00 50 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Vundo_HIZ_2147650795_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vundo.HIZ"
        threat_id = "2147650795"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 40 10 8b 04 85 e8 3e 41 00 8a 00 88 45 c0 a1 d0 3e 41 00 03 05 4c 36 41 00 8a 00 32 45 c0 8b 0d d0 3e 41 00 03 0d 4c 36 41 00 88 01 e9 99 fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {e8 37 35 00 00 e8 fb 5c ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Vundo_HIZ_2147650795_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vundo.HIZ"
        threat_id = "2147650795"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 10 8b 48 28 85 c9 74 14 a1 ?? ?? 00 10 6a 00 03 c8 6a ?? 50 89 0d ?? ?? 00 10 ff d1 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {31 48 04 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 31 48 08}  //weight: 1, accuracy: Low
        $x_1_3 = {03 03 ff e0 83 7c 24 08 01}  //weight: 1, accuracy: High
        $x_1_4 = {0f b7 55 f4 33 4d f4 33 c2 5f 5e 66 85 c9 75 05 b8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Vundo_A_2147651472_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vundo.A"
        threat_id = "2147651472"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 48 28 85 c9 74 14 a1 ?? ?? ?? 10 6a 00 03 c8 6a 03 50 89 0d ?? ?? ?? 10 ff d1 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 00 88 45 b0 0f b6 45 ac 0f b6 4d b0 33 c1 8b 0d ?? ?? ?? 10 03 0d ?? ?? ?? 10 88 01 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Vundo_HJA_2147652995_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vundo.HJA"
        threat_id = "2147652995"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 40 10 8b 04 85 c8 3e 01 01 8a 00 88 45 c0 a1 b0 3e 01 01 03 05 2c 36 01 01 8a 00 32 45 c0 8b 0d b0 3e 01 01 03 0d 2c 36 01 01 88 01 e9 99 fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {e8 37 35 00 00 e8 9a 5c ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Vundo_HJB_2147653039_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vundo.HJB"
        threat_id = "2147653039"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 40 10 8b 04 85 40 3e 01 01 8a 00 88 45 d8 a1 28 3e 01 01 03 05 8c 35 01 01 8a 00 32 45 d8 8b 0d 28 3e 01 01 03 0d 8c 35 01 01 88 01 e9 8c fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {e8 79 3c 00 00 e8 1d 5c ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Vundo_HJC_2147653414_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vundo.HJC"
        threat_id = "2147653414"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 40 10 8b 04 85 e8 3e 01 01 8a 00 88 45 c0 a1 d0 3e 01 01 03 05 4c 36 01 01 8a 00 32 45 c0 8b 0d d0 3e 01 01 03 0d 4c 36 01 01 88 01 e9 99 fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {e8 37 35 00 00 e8 fb 5c ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Vundo_A_2147653972_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vundo.A"
        threat_id = "2147653972"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "39diei39-d83kdjei-dkc8edi-dkdiekfu" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "IPv6 I-Am-Here" wide //weight: 1
        $x_1_4 = "IPv6 Where-Are-You" wide //weight: 1
        $x_1_5 = {64 ff 30 64 89 20 6a 00 6a 00 8b 45 f8 e8 ?? ?? ?? ?? 50 8b 45 fc e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 85 c0 75 04 b3 01 eb 02 33 db 33 c0}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 45 f8 89 45 f0 8b 45 e4 8b 40 08 89 45 e0 81 45 e0 48 02 00 00 6a 04 8d 4d f0 8b 55 e0 8b c7 e8 ?? ?? ?? ?? 8b 45 f0 c1 e8 04 c1 e0 04 03 45 f8 89 45 f0 6a 04 8d 4d f0 8b 55 e0 8b c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Vundo_A_2147908980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vundo.A!MTB"
        threat_id = "2147908980"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 44 24 0c c7 44 24 0c 28 01 00 00 50 53 e8 ?? 22 00 00 85 c0 74 ?? 8b b4 24 38 01 00 00 8b 3d 58 70 00 10 8d 4c 24 30 56 51 ff ?? 85 c0 74 ?? 8d 54 24 0c 52 53 e8 ?? 22 00 00 85 c0 74 ?? 8d 44 24 30 56 50 ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

