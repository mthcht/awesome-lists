rule Virus_Win32_Expiro_D_2147599151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.gen!D"
        threat_id = "2147599151"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 65 74 14 3c 79 74 10 3c 75 74 0c 3c 69 74 08 3c 6f 74 04 3c 61 75 04}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 d8 8a 84 05 d9 fe ff ff 3c 61 7e 11 3c 7a 7d 0d 8b 45 d8 8d 84 05 d9 fe ff ff 80 28 20 ff 45 d8 8b 45 d8 0f be 84 05 d9 fe ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 45 10 39 c7 72 ?? 8a 04 3e 3c 2f 74 ?? 3c 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_F_2147645063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.gen!F"
        threat_id = "2147645063"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6b 6b 71 76 78 5f 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_2_2 = {0f be 10 0f be ?? 02 31 ca 88 10 66 ff 45 ?? 0f b7 45 ?? 0f b7 55 ?? 39 d0 7c df}  //weight: 2, accuracy: Low
        $x_1_3 = {0f b7 49 06 f7 e1 89 85}  //weight: 1, accuracy: High
        $x_1_4 = {50 8b 38 ff 97 f8 00 00 00 89 (c3|c6)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Expiro_G_2147660415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.gen!G"
        threat_id = "2147660415"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6b 6b 71 76 78 5f 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_1_2 = {0f b7 45 fe 01 f0 0f be 10 0f b6 4d ?? 31 ca 88 10}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 0a 00 00 00 99 f7 f9 0f b6 14 15 ?? ?? ?? ?? 8b 7d ?? 31 d7 89 fa 8b 7d ?? 88 17 66 ff 45 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Expiro_CD_2147685148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.CD"
        threat_id = "2147685148"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a1 d0 30 1b 01 03 05 90 30 1b 01 83 e8 09}  //weight: 1, accuracy: High
        $x_1_2 = {e8 32 df ff ff e8 4d 91 ff ff e8 88 11 00 00 e8 c9 91 ff ff 68 0f 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_EA_2147708748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.EA!bit"
        threat_id = "2147708748"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d1 8b 11 85 d2 81 f2 ?? ?? ?? ?? 39 d1 89 10 42 41 4f 41 4f 4f 41 41 4f 81 c0 04 00 00 00 83 ff 00 74 05 e9 d7 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_EM_2147722965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.EM!bit"
        threat_id = "2147722965"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 57 52 29 c0 83 c0 30 64 8b 38 51 8b 4f 08 89 f8 83 c0 0c 8b 10 83 c2 0c 8b 3a 53 8b d7 83 c2 18 8b 02 85 c0 0f 84 25 00 00 00 89 fa 83 c2 30 8b 12 8b 1a 81 e3 df 00 df 00 8b 52 0c c1 e2 08 01 da 81 ea 4b 33 45 32 85 d2 0f 84 09 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8d 1a 8b 18 85 db 81 f3 ?? ?? ?? ?? 39 df 89 1f 8d 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_MH_2147729272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.MH!bit"
        threat_id = "2147729272"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4a 30 8b 31 81 e6 df 00 df 00 8b 49 0b 03 ce c1 e1 02 81 e9}  //weight: 1, accuracy: High
        $x_1_2 = {8b f0 8b 30 85 f6 81 f6 ?? ?? ?? ?? 39 f1 89 32 01 d6 49 83 c0 04 49 49 49 81 c2 04 00 00 00 83 f9 00 75 dc}  //weight: 1, accuracy: Low
        $x_1_3 = {89 c1 03 3c 91 89 7d e4 b8 24 00 00 00 99 f7 fb 8b 7d f4 8b 3c 87 89 7d dc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_MI_2147729319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.MI!bit"
        threat_id = "2147729319"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5f 30 8b 03 81 e0 df 00 df 00 8b 5b 0c c1 e3 08 03 d8 c1 eb 02 81}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 06 85 c3 35 ?? ?? ?? ?? 39 c7 89 07 29 d8 83 c6 04 4b 83 c7 04 4b 4b 4b 83 fb 00 74 05}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 0a 00 00 00 99 f7 fb 89 45 f0 8b 45 20 03 45 18 01 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_MJ_2147729416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.MJ!bit"
        threat_id = "2147729416"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 56 30 8b 0a 81 e1 df 00 df 00 8b 52 0b 03 d1 c1 ea 02 81 ea d2 4c 91 0c}  //weight: 1, accuracy: High
        $x_1_2 = {8b 0f 85 f2 81 f1 ?? ?? ?? ?? 39 ce 89 0e 8d 0f 81 c6 04 00 00 00 81 c7 04 00 00 00 83 ea 04 85 d2 75}  //weight: 1, accuracy: Low
        $x_1_3 = {89 c7 8b 75 9c 8b 5d 90 b9 ff 00 00 00 99 f7 f9 88 14 33 ff 45 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_MK_2147729897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.MK!bit"
        threat_id = "2147729897"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 83 c2 30 8b 12 8b 02 81 e0 df 00 df 00 8b 52 0c c1 e2 08 01 c2 c1 e2 02}  //weight: 1, accuracy: High
        $x_1_2 = {40 8b 06 85 c0 35 ?? ?? ?? ?? 39 c3 89 03 8d 06 4a 4a 4a 83 c3 04 81 c6 04 00 00 00 4a 85 d2 75 df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_ML_2147730055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.ML!bit"
        threat_id = "2147730055"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 f1 83 c1 30 8b 09 8b 01 81 e0 df 00 df 00 8b 49 0c c1 e1 08 01 c1}  //weight: 1, accuracy: High
        $x_1_2 = {40 8b 03 85 c1 35 ?? ?? ?? ?? 39 c3 89 06 8b c6 43 83 c6 04 83 e9 04 43 43 43 83 f9 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_MP_2147730255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.MP!bit"
        threat_id = "2147730255"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f3 83 c6 30 8b 36 8b 3e 81 e7 df 00 df 00 8b 76 0b 03 f7}  //weight: 1, accuracy: High
        $x_1_2 = {4f 8b 39 85 ff 81 f7 ?? ?? ?? ?? 3b df 89 3b 4f 4e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_BAA_2147730406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.BAA!bit"
        threat_id = "2147730406"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 83 c3 30 8b 1b 8b 0b 81 e1 df 00 df 00 8b 5b 0b 03 d9}  //weight: 1, accuracy: High
        $x_1_2 = {41 8b 0e 85 c3 81 f1 ?? ?? ?? ?? 3b d9 89 08 89 c1 4b 4b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_BAD_2147730427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.BAD!bit"
        threat_id = "2147730427"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b da 83 c3 30 8b 1b 8b 03 81 e0 df 00 df 00 8b 5b 0b 03 d8}  //weight: 1, accuracy: High
        $x_1_2 = {8d 03 8b 06 85 c3 35 ?? ?? ?? ?? 39 c6 89 02 29 d8 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_BAC_2147730766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.BAC!bit"
        threat_id = "2147730766"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 83 c0 30 8b 00 8b 38 81 e7 df 00 df 00 8b 40 0c c1 e0 08 03 c7}  //weight: 1, accuracy: High
        $x_1_2 = {4f 8b 3a 85 d8 81 f7 ?? ?? ?? ?? 3b c7 89 3b 8d 3a 48 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_AA_2147849666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.AA!MTB"
        threat_id = "2147849666"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 ?? 81 ?? 0c d0 08 00 ?? 00 00 00 00 ?? 81 ?? bc 03 00 00 43 00 3c 27 81 ?? a8 01 00 00 d2 2d cb 3b 81 ?? 70 03 00 00 b9 79 04 09 81 ?? 2c 02 00 00 5e 6f 7d 62 81 ?? 1c 03 00 00 a4 29 6f 54 81 ?? f8 02 00 00 d7 6e e6 30 81 ?? 7c 03 00 00 fc 56 85 02 81 ?? 18 03 00 00 7b 3a d1 35 81 ?? c0 02 00 00 fe 2c f8 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {04 f9 5d ee 18 81 ?? 88 00 00 00 79 6d d9 5c f7 ?? 38 03 00 00 81 ?? 58 31 6d 3f 09 81 ?? d4 03 00 00 1c 66 0e 75 81 ?? 00 04 00 00 81 ?? 00 04 00 00 81 ?? 00 c0 08 00}  //weight: 1, accuracy: Low
        $x_1_3 = "VEJCJUZNIPNRDMNPTWKBYXUZKMXQAQGHa1048d3edf26fed455c264c0" wide //weight: 1
        $x_1_4 = {7b 00 22 00 6f 00 70 00 22 00 3a 00 20 00 22 00 68 00 73 00 22 00 2c 00 20 00 22 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 22 00 3a 00 20 00 7b 00 22 00 62 00 69 00 64 00 22 00 3a 00 20 00 22 00 [0-64] 22 00 2c 00 20 00 22 00 68 00 69 00 64 00 22 00 3a 00 20 00 22 00 [0-64] 22 00 2c 00 20 00 22 00 4d 00 61 00 69 00 6e 00 49 00 44 00 22 00 3a 00 20 00 31 00 2c 00 20 00 22 00 53 00 75 00 62 00 73 00 69 00 64 00 69 00 61 00 72 00 79 00 49 00 44 00 22 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Virus_Win32_Expiro_NDP_2147850746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.NDP!MTB"
        threat_id = "2147850746"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 e8 00 00 00 00 ?? 81 ?? 0c ?? 08 00 ?? 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 04 00 00 81 ?? 00 04 00 00 81 ?? 00 c0 08 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 72 65 6c 6f 63 00 00 00 [0-21] 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_DB_2147851905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.DB!MTB"
        threat_id = "2147851905"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 f1 8b 0a 85 c8 81 f1 ?? ?? ?? ?? 3b f1 89 0e 49 48 48 81 c6 04 00 00 00 48 48 81 c2 04 00 00 00 85 c0 75 db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_DC_2147852147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.DC!MTB"
        threat_id = "2147852147"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 53 55 56 57 e8 ?? ?? ?? ?? 59 81 e9 ?? ?? ?? ?? bf ?? ?? ?? ?? 51 f7 91 f4 01 00 00 f7 91 d8 01 00 00 81 69 04 84 21 8d 64 81 b1 84 03 00 00 10 68 24 6a 81 b1 ?? ?? ?? ?? b3 02 c7 46 81 71 30 c1 14 44 57 f7 91 08 03 00 00 81 a9 c8 02 00 00 78 7a 6e 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_EM_2147852532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.EM!MTB"
        threat_id = "2147852532"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 83 3d 84 d0 44 00 01 75 05 e8 68 8c 0d 00}  //weight: 5, accuracy: High
        $x_5_2 = {8b f0 85 f6 75 0d 6a 12 e8 41 7e 0c 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Virus_Win32_Expiro_EM_2147852532_1
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.EM!MTB"
        threat_id = "2147852532"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {50 51 52 53 55 56 57 e8 00 00 00 00}  //weight: 2, accuracy: High
        $x_3_2 = {81 c6 00 04 00 00 81 c0 00 04 00 00 81 fe 00 c0 08 00 0f 85}  //weight: 3, accuracy: High
        $x_3_3 = {81 c6 00 04 00 00 81 c1 00 04 00 00 81 fe 00 c0 08 00 0f 85}  //weight: 3, accuracy: High
        $x_3_4 = {81 c7 00 04 00 00 81 c2 00 04 00 00 81 ff 00 c0 08 00 0f 85}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Expiro_EB_2147852592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.EB!MTB"
        threat_id = "2147852592"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 51 52 53 55 56 57 e8 00 00 00 00}  //weight: 2, accuracy: High
        $x_3_2 = {c0 08 00 0f 85 0f 00 81 ?? 00 04 00 00 81 ?? 00 04 00 00 81}  //weight: 3, accuracy: Low
        $x_3_3 = {c0 08 00 74 05 0f 00 81 ?? 00 04 00 00 81 ?? 00 04 00 00 81}  //weight: 3, accuracy: Low
        $x_3_4 = {c0 08 00 0f 84 0f 00 81 ?? 00 04 00 00 81 ?? 00 04 00 00 81}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Expiro_AB_2147888600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.AB!MTB"
        threat_id = "2147888600"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 43 20 2b ca 29 c1 c1 e9 01 8b c3 83 c0 24 8b 00 01 d0 01 c8 8b 08 81 e1 ?? ?? ?? ?? c1 e1 02 8b 43 1c 03 c1 01 d0 8b 08 bf ?? ?? ?? ?? 03 ca 52 8d 1d ?? ?? ?? ?? b8 00 40 09 00 56 03 de 51 54 57 50 53 ff d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_CCCF_2147892475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.CCCF!MTB"
        threat_id = "2147892475"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 54 50 57 51 ff d2}  //weight: 1, accuracy: High
        $x_1_2 = {42 8d 13 8b 12 85 f9 81 f2 ?? ?? ?? ?? 3b da 4a 89 17 29 ca 83 e9 04 83 c7 04 83 c3 04 85 c9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_EK_2147899592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.EK!MTB"
        threat_id = "2147899592"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 53 0f 84 89 00 00 00 0f 85 83 00 00 00 00 00 00 00 53 56 68 02 01 00 00 0f 84 90 00 00 00 0f 85 8a 00 00 00 0f 84 35 e1 ff ff 0f 85 60 c4 ff ff e9 0f 84 6c 01 00 00 89 c6 89 e0 50 0f 84 f7 01 00 00 0f 85 f1 01 00 00 00 00 00 00 5d c2 04 00}  //weight: 5, accuracy: High
        $x_5_2 = {13 0f 84 41 01 00 00 0f 84 95 01 00 00 0f 85 8f 01 00 00 e9 0f 84 9e 00 00 00 47 3b 7c 1e 18 0f 82 70 01 00 00 0f 84 88 00 00 00 0f 85 82 00 00 00 00 00 00 00 57 56 83 ec 40 8b 44 24 54 8b 68 08 8b 38}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_RPY_2147908372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.RPY!MTB"
        threat_id = "2147908372"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 01 ca 53 54 50 53 52 ff d7 5b 59 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_AEX_2147923468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.AEX!MTB"
        threat_id = "2147923468"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 83 24 02 00 00 74 7a 35 0c f7 93 24 01 00 00 81 83 8c 03 00 00 ff 74 aa 09 81 b3 e0 01 00 00 9a 6b aa 32 81 b3 38 02 00 00 cd 41 5a 63 81 ab e4 00 00 00 ce 46 82 1f 81 ab fc 00 00 00 91 44 39 28 81 b3 d8 03 00 00 0a 13 e7 57 81 ab 7c 02 00 00 cf 4b 75 30 81 b3 b4 00 00 00 51 0c 29 32 81 83 dc 03 00 00 6b 7b d8 1f 81 83 c4 00 00 00 f1 59 98 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_AER_2147928138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.AER!MTB"
        threat_id = "2147928138"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 45 f0 89 75 f8 50 8d 45 f4 89 75 f4 50 8d 45 f8 c7 45 f0 04 00 00 00 50 56 68 c8 45 40 00 ff 75 fc ff 15}  //weight: 2, accuracy: High
        $x_1_2 = {56 8d 45 f4 33 f6 50 68 19 00 02 00 56 68 60 43 40 00 68 02 00 00 80 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_HNE_2147928179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.HNE!MTB"
        threat_id = "2147928179"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 50 01 d8 54 52 57 50 ff d6 58 5b 52 04 00 40 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_HNT_2147931010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.HNT!MTB"
        threat_id = "2147931010"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 db 89 5d e4 8d 45 94 50 ff 15 0c 00 6a ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? (01|2d|09) 33 db}  //weight: 10, accuracy: Low
        $x_1_2 = {2e 72 65 6c 6f 63 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 00 e2}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 72 65 6c 6f 63 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 00 60}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Expiro_HNW_2147936833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.HNW!MTB"
        threat_id = "2147936833"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2e 73 79 6d 74 61 62 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_HNW_2147936833_1
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.HNW!MTB"
        threat_id = "2147936833"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2e 72 73 72 63 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 00 40 2e 72 65 6c 6f 63 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 00 e2 00 00 00 00 00 00 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Expiro_HNW_2147936833_2
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Expiro.HNW!MTB"
        threat_id = "2147936833"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "501"
        strings_accuracy = "Low"
    strings:
        $x_500_1 = {40 00 00 40 2e 72 65 6c 6f 63 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 00 e2 00 00 00 00 00 00 00 00 00 00}  //weight: 500, accuracy: Low
        $x_1_2 = {30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 30 ?? 30}  //weight: 1, accuracy: Low
        $x_1_3 = {31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 31 ?? 31}  //weight: 1, accuracy: Low
        $x_1_4 = {32 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 32 ?? 32}  //weight: 1, accuracy: Low
        $x_1_5 = {33 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 33 ?? 33}  //weight: 1, accuracy: Low
        $x_1_6 = {34 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 34 ?? 34}  //weight: 1, accuracy: Low
        $x_1_7 = {35 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 35 ?? 35}  //weight: 1, accuracy: Low
        $x_1_8 = {36 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 36 ?? 36}  //weight: 1, accuracy: Low
        $x_1_9 = {37 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 37 ?? 37}  //weight: 1, accuracy: Low
        $x_1_10 = {38 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 38 ?? 38}  //weight: 1, accuracy: Low
        $x_1_11 = {39 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 39 ?? 39}  //weight: 1, accuracy: Low
        $x_1_12 = {3a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 3a ?? 3a}  //weight: 1, accuracy: Low
        $x_1_13 = {3b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 3b ?? 3b}  //weight: 1, accuracy: Low
        $x_1_14 = {3c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 3c ?? 3c}  //weight: 1, accuracy: Low
        $x_1_15 = {3d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 3d ?? 3d}  //weight: 1, accuracy: Low
        $x_1_16 = {3e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 3e ?? 3e}  //weight: 1, accuracy: Low
        $x_1_17 = {3f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 3f ?? 3f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_500_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

