rule Virus_Win32_Sality_2147600097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sality"
        threat_id = "2147600097"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 05 00 30 07 (80|fe c9) 5e 4e 0f (84 ?? ?? ?? ??|85) fe c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Sality_2147600097_1
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sality"
        threat_id = "2147600097"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b dd 33 c9 66 69 c1 ?? ?? d1 e9 2b c1 d1 e1 66 31 84 0d ?? ?? 00 00 41 41 3b ca 74 02 eb e5 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Sality_2147600097_2
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sality"
        threat_id = "2147600097"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 06 2b 0c 24 8d 7d 00 89 14 24 8d 49 ac}  //weight: 1, accuracy: High
        $x_1_2 = {33 db 53 4b 8d 40 73 f7 6c 24 68 52}  //weight: 1, accuracy: High
        $x_1_3 = {2f 6c 6f 67 6f [0-1] 2e 67 69 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Sality_AM_2147605602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sality.AM"
        threat_id = "2147605602"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 ff 00 00 00 8b 8d ?? ?? ff ff 81 e1 ff 00 00 00 0f af c1 05 38 04 00 00 66 a3 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 52 68 00 04 01 00 6a 00 6a 04 6a 00 6a ff ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Sality_AM_2147605906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sality.AM!corrupt"
        threat_id = "2147605906"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        info = "corrupt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "103"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 84 0d 16 10 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {8a a4 15 16 10 00 00}  //weight: 10, accuracy: High
        $x_10_3 = {88 84 15 16 10 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {88 a4 0d 16 10 00 00}  //weight: 10, accuracy: High
        $x_1_5 = {02 9c 15 16 10 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {02 9c 15 17 10 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {8a 84 15 16 10 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {8a 84 15 17 10 00 00}  //weight: 1, accuracy: High
        $x_10_9 = {8a ac 1d 16 10 00 00}  //weight: 10, accuracy: High
        $x_10_10 = {88 84 1d 16 10 00 00}  //weight: 10, accuracy: High
        $x_1_11 = {88 ac 15 16 10 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {88 ac 15 17 10 00 00}  //weight: 1, accuracy: High
        $x_10_13 = {8a 84 05 16 10 00 00}  //weight: 10, accuracy: High
        $x_10_14 = {89 54 0e 0c}  //weight: 10, accuracy: High
        $x_10_15 = {89 44 0e 08}  //weight: 10, accuracy: High
        $x_10_16 = {89 5c 0e 04}  //weight: 10, accuracy: High
        $x_50_17 = "SOSiTE_AVERI_SOSiTEEE.haha" ascii //weight: 50
        $x_30_18 = {2f 6c 6f 67 6f 73 2e 67 69 66 00}  //weight: 30, accuracy: High
        $x_30_19 = {2f 6c 6f 67 6f 68 2e 67 69 66 00}  //weight: 30, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_30_*) and 7 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_30_*) and 8 of ($x_10_*))) or
            ((2 of ($x_30_*) and 4 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_30_*) and 5 of ($x_10_*))) or
            ((1 of ($x_50_*) and 5 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_50_*) and 6 of ($x_10_*))) or
            ((1 of ($x_50_*) and 1 of ($x_30_*) and 2 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_30_*) and 3 of ($x_10_*))) or
            ((1 of ($x_50_*) and 2 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Sality_H_2147606086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sality.H"
        threat_id = "2147606086"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 50 00 00 6a 00 6a 00 6a 02 a1 ?? ?? 00 10 50 ff 15 ?? ?? 00 10 [0-32] 81 e1 ff 00 00 00 83 f9 02 75 27 8b 15 ?? ?? 00 10 33 c0 8a 02 3d 81 00 00 00 74 16 68 00 50 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 10 00 00 68 66 06 00 00 6a 00 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Sality_AN_2147606857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sality.AN"
        threat_id = "2147606857"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 ff 00 00 00 8b 8d ?? ?? ff ff 81 e1 ff 00 00 00 0f af c1 05 97 08 00 00 66 a3 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 52 68 00 54 01 00 6a 00 6a 04 6a 00 6a ff ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Sality_P_2147625827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sality.gen!P"
        threat_id = "2147625827"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 5d 81 ed 05 10 40 00 (8b 44 24 20 83 e8 05 89 44|58 2d ?? ?? ?? ??) 89 85 ?? ?? 40 00 80 bd ?? ?? 40 00 00 75 19 c7 85 ?? ?? 40 00 22 22 22 22 c7 85 ?? ?? 40 00 33 33 33 33 e9 82 00 00 00 33 db 64 67 8b 1e 30 00 85 db 78 0e 8b 5b 0c 8b 5b 1c 8b 1b 8b 5b 08 f8 eb 0a 8b 5b 34 8d 5b 7c 8b 5b 3c f8 66 81 3b 4d 5a 74 05 e9 ?? ?? 00 00 8b f3 03 76 3c 81 3e 50 45 00 00 74 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Sality_AT_2147632182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sality.AT"
        threat_id = "2147632182"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ed 05 10 40 00 8a 9d 73 27 40 00 84 db 74 13 81 c4 ?? ?? ?? ?? 2d ?? ?? ?? ?? 89 85 ?? 12 40 00 eb 19 c7 85 ?? 14 40 00 22 22 22 22 c7 85 ?? 14 40 00 33 33 33 33 e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Sality_AT_2147632187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sality.gen!AT"
        threat_id = "2147632187"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 6b 75 6b 75 [0-15] 2e 69 6e 66 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 69 6e 66 6f 2f 68 6f 6d 65 2e 67 69 66 00 68 74 74 70 3a 2f 2f [0-21] 2e 69 6e 66 6f 2f 68 6f 6d 65 2e 67 69 66}  //weight: 1, accuracy: Low
        $x_2_3 = {60 e8 00 00 00 00 08 01 01 01 01 01 01 01 01 58 59 5a 5b 5c 5d 5e 5f 81 ?? ?? ?? ?? ?? 08 01 01 01 01 01 01 01 01 50 51 52 53 54 55 56 57 [0-16] c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Sality_AT_2147632187_1
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sality.gen!AT"
        threat_id = "2147632187"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "purity_control" ascii //weight: 1
        $x_1_2 = {66 81 3a 4d 5a 0f 85 54 02 00 00 8b 42 3c 03 d0 66 81 3a 50 45 0f 85 44 02 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 6d 08 80 bd ?? ?? ?? ?? 01 0f 85 fb 00 00 00 8b 8d ?? ?? ?? ?? 49 85 c9 74 0f 41 8d b5 ?? ?? ?? ?? 8b bd ?? ?? ?? ?? f3 a4 89 ad ?? ?? ?? ?? 89 ad ?? ?? ?? ?? 89 ad ?? ?? ?? ?? 89 ad ?? ?? ?? ?? 89 ad ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 68 fe 01 00 00 50 6a 00 ff 95 ?? ?? ?? ?? 85 c0 74 2e 8b c8 48 83 bc 05 ?? ?? ?? ?? 00 74 10 80 bc 05 ?? ?? ?? ?? 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Sality_Q_2147632231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sality.gen!Q"
        threat_id = "2147632231"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 db 64 67 8b 1e 30 00 85 db 78 19 00 c7 85 ?? ?? ?? ?? 22 22 22 22 c7 85 ?? ?? ?? ?? 33 33 33 33 e9 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 fe 01 00 00 50 6a 00 ff 95 ?? ?? ?? ?? 85 c0 74 ?? 8b c8 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Sality_AU_2147636748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sality.AU"
        threat_id = "2147636748"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ed 05 10 40 00 8a 9d 73 27 40 00 84 db 74 13 81 c4 ?? ?? ?? ?? 2d ?? ?? ?? ?? 89 85 ?? 12 40 00 eb 19 c7 85 ?? 14 40 00 22 22 22 22 c7 85 ?? 14 40 00 33 33 33 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Sality_G_2147683028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sality.G"
        threat_id = "2147683028"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 4c 45 52 [0-6] 54 52 45 4e [0-6] 54 52 4f 4a [0-6] 41 4e 44 41}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 74 6a 63 [0-6] 2e 61 76 63 [0-6] 2e 6b 65 79 [0-6] 2e 76 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = {0f af c2 8b 8d ?? ?? ?? ?? d1 e1 2b c1 8b 55 ?? 66 8b 0c 55 ?? ?? ?? ?? 66 33 c8 8b 55 ?? 66 89 0c 55 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 83 e8 01 89 85 ?? ?? ?? ?? 8b 4d ?? 83 c1 01 89 4d ?? 83 bd ?? ?? ?? ?? 00 75 ?? 68 00 50 00 00 68 58 70 00 10 8b 15 ?? ?? ?? ?? 03 55 ?? 52 ff 15 70 6e 00 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Sality_AW_2147683980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sality.AW"
        threat_id = "2147683980"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ed 05 10 40 00 8a 9d a7 26 40 00 84 db 74 13 81 c4 ?? ?? ?? ?? 2d ?? ?? ?? ?? 89 85 ?? 12 40 00 eb 19 c7 85 ?? 14 40 00 22 22 22 22 c7 85 ?? 14 40 00 33 33 33 33 e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Sality_HNB_2147936832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sality.HNB!MTB"
        threat_id = "2147936832"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ba 00 00 00 00 60 00 [0-96] 60 [0-255] [0-255] c1}  //weight: 4, accuracy: Low
        $x_1_2 = {40 00 00 42 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 00 00 e0 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

