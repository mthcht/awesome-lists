rule Ransom_Win64_Basta_MK_2147837078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.MK!MTB"
        threat_id = "2147837078"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b 10 40 8a c7 40 8a cf 81 c7 ?? ?? ?? ?? c1 c7 ?? 41 02 04 11 d2 c0 41 88 04 11 49 ff c1 48 83 ee ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_ML_2147837079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.ML!MTB"
        threat_id = "2147837079"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b 10 40 8a cf 41 8a 04 12 d2 c8 40 02 c7 69 ff ?? ?? ?? ?? 41 88 04 12 49 ff c2 c1 cf 0d 48 83 ee ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_MN_2147837123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.MN!MTB"
        threat_id = "2147837123"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b 10 40 8a cf 41 8a 04 12 40 2a c7 69 ff ?? ?? ?? ?? d2 c0 41 88 04 12 49 ff c2 81 c7 ?? ?? ?? ?? 48 83 ee ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_SAA_2147837152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.SAA!MTB"
        threat_id = "2147837152"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 01 0f be 44 24 ?? 0f be 4c 24 ?? d3 e0 88 44 24 ?? 0f be 44 24 ?? 0f be 4c 24 ?? 0b c1 88 44 24 ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48}  //weight: 1, accuracy: Low
        $x_1_2 = "Disinclinatio impingemen" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_GG_2147837201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.GG!MTB"
        threat_id = "2147837201"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 09 33 c1 88 05 ?? ?? ?? ?? 0f be 44 24 ?? 0f be 0d ?? ?? ?? ?? d3 e0 88 84 24 ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 0f be 00 48 8b 8c 24 ?? ?? ?? ?? 0f be 09 0b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_WK_2147837202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.WK!MTB"
        threat_id = "2147837202"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b c8 8b c1 89 44 24 ?? 48 8b 44 24 ?? 48 8b 8c 24 ?? ?? ?? ?? 48 33 c8 48 8b c1 48 89 05 ?? ?? ?? ?? 48 8b 44 24 ?? 0f be 00 0f be 4c 24 ?? d3 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_SAB_2147837204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.SAB!MTB"
        threat_id = "2147837204"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "instructions_read_me.txt" ascii //weight: 1
        $x_1_2 = "Your network has been breached and all data was encrypted" ascii //weight: 1
        $x_1_3 = "killservices" ascii //weight: 1
        $x_1_4 = "onion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win64_Basta_AB_2147840459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.AB!MTB"
        threat_id = "2147840459"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 ab aa aa aa 41 f7 e7 d1 ea 8d 04 52 0f b6 54 24 ?? 44 2b f8 41 c1 e8 ?? 33 c0 41 0f be cf 33 4c 24 ?? 41 0b cc 39 4d ?? 0f 94 c0 33 c9 31 05 ?? ?? ?? ?? 8b 44 24 ?? 0b 45 f0 89 44 24 ?? 89 05 ?? ?? ?? ?? 85 c9 74}  //weight: 10, accuracy: Low
        $x_1_2 = "process call create \"powershell -executionpolicy bypass -nop -w hidden %s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_TD_2147841844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.TD!MTB"
        threat_id = "2147841844"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 20 83 c0 0e 89 44 24 20 48 8b 44 24 70 48 8b 40 10 48 89 44 24 30 48 8b 44 24 30 48 63 40 3c 48 8b 4c 24 70 48 03 41 10 48 89 44 24 38 8b 44 24 20 99 2b c2 d1 f8 89 44 24 20 48 8b 44 24 38 8b 40 28 48 8b 4c 24 70 48 03 41 10 48 89 44 24 40 48 8b 44 24 40 48 83 c4 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_AD_2147843123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.AD!MTB"
        threat_id = "2147843123"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "201"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {48 89 9c 24 80 00 00 00 44 0f be d1 33 db 41 0f b7 ca 66 c7 45 b8 ?? 00 66 83 f1 ?? 66 89 5d ea 41 0f b7 d2 66 89 4d be 66 83 f2 ?? 66 89 4d c6 41 0f b7 c2 66 89 55 c2 66 83 f0 ?? 66 89 55 d0 66 89 45 ba 45 0f b7 c2 66 41 83 f0 ?? 41 0f b7 ca 41 0f b7 d2 66 44 89 45 c8 66 83 f1 ?? 66 44 89 45 cc 66 83 f2 ?? 66 89 4d d6 41 0f b7 c2 66 89 55 da 66 83 f0 ?? 66 89 4d dc 66 89 45 bc 45 0f b7 ca 66 41 83 f1 ?? 66 44 89 45 e2 41 0f b7 c2 66 89 55 e8 66 83 f0 ?? 66 44 89 4d c4 66 89 45 c0 4c 8d 45 ba}  //weight: 100, accuracy: Low
        $x_100_3 = {41 0f b7 c2 66 44 89 4d ce 66 83 f0 ?? 66 44 89 4d e6 66 89 45 ca 33 d2 66 89 45 d2 b9 01 00 1f 00 41 0f b7 c2 66 83 f0 ?? 66 89 45 d4 41 0f b7 c2 66 83 f0 ?? 66 89 45 d8 41 0f b7 c2 66 83 f0 ?? 66 89 45 de 41 0f b7 c2 66 83 f0 ?? 66 41 83 f2 ?? 66 89 45 e0 66 44 89 55 e4 ff 15}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_AA_2147843125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.AA"
        threat_id = "2147843125"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {0f 57 c0 33 c0 48 89 45 70 0f 29 85 b0 00 00 00 f2 0f 10 45 70 f2 0f 11 85 c0 00 00 00 48 8d 95 b0 00 00 00 48 8d 4c 24 50 e8 ?? ?? ?? ?? 41 b8 3e 42 00 00 48 8d 15 ?? ?? ?? ?? 48 8d 4c 24 50 e8 ?? ?? ?? ?? 48 8d 4c 24 50 e8 ?? ?? ?? ?? 48 8d 4c 24 58 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_PG_2147843641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.PG!MTB"
        threat_id = "2147843641"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 48 01 d0 44 0f b6 08 8b 8d ?? ?? ?? ?? ba 83 be a0 2f 89 c8 f7 ea c1 fa 03 89 c8 c1 f8 1f 29 c2 89 d0 6b c0 2b 29 c1 89 c8 48 63 d0 48 8b 85 f0 02 00 00 48 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 fc 02 00 00 01}  //weight: 1, accuracy: Low
        $x_1_2 = "VisibleEntry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_PH_2147844289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.PH!MTB"
        threat_id = "2147844289"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {49 89 c8 89 c8 48 ff c1 4c 3b 44 24 ?? 4c 8b 4c 24 ?? 73 ?? 99 41 f7 fa 48 8d 05 ?? ?? ?? ?? 48 63 d2 8a 04 10 48 8b 54 24 40 42 32 04 02 43 88 04 01 eb}  //weight: 4, accuracy: Low
        $x_1_2 = "VisibleEntry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_PIC_2147847122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.PIC!MTB"
        threat_id = "2147847122"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 33 d0 8b 83 ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 0f af c1 48 63 8b ?? ?? ?? ?? 89 93 ?? ?? ?? ?? 0f b6 93 ?? ?? ?? ?? 44 89 8b ?? ?? ?? ?? 44 2b cf 44 01 4b 64 89 83 0c 01 00 00 41 0f b6 c2 0f af d0 48 8b 83 ?? ?? ?? ?? 88 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_AC_2147847398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.AC!MTB"
        threat_id = "2147847398"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b c3 4c 8d 0d [0-6] b8 ?? ?? ?? ?? 4d 8d 40 ?? f7 eb 8b cb ff c3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 0f b6 8c 08 ?? ?? ?? ?? 43 32 8c 08 ?? ?? ?? ?? 48 8b 44 24 ?? 41 88 4c 00 ?? 3b 9c 24 ?? ?? ?? ?? 72 ?? ff 54 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_AF_2147847938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.AF!MTB"
        threat_id = "2147847938"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f af c0 89 43 ?? 8b 43 ?? 35 ?? ?? ?? ?? 01 43 ?? 8b 83 ?? ?? ?? ?? 83 e8 ?? 01 83 ?? ?? ?? ?? 48 8b 83 ?? ?? ?? ?? 44 88 04 01 b8 ?? ?? ?? ?? ff 83 ?? ?? ?? ?? 8b 4b ?? 2b c1 01 43 ?? 8d 81 ?? ?? ?? ?? 01 83 ?? ?? ?? ?? 49 81 f9 ?? ?? ?? ?? 0f 8c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_AN_2147894439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.AN!MTB"
        threat_id = "2147894439"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Welcome to Bulls and Cows, a fun word game" ascii //weight: 1
        $x_1_2 = "I'm thinking of" ascii //weight: 1
        $x_1_3 = "Do you want to play again with the same hidden word (y/n)" ascii //weight: 1
        $x_1_4 = "WELL DONE - YOU WIN!" ascii //weight: 1
        $x_1_5 = "Release\\BullCowGame.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_AG_2147897734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.AG!MTB"
        threat_id = "2147897734"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "E:\\cpp\\git5\\x64\\dll\\SudSolver.pdb" ascii //weight: 1
        $x_1_2 = "VisibleEntry" ascii //weight: 1
        $x_1_3 = "Webcam Sudoku Solver Version" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_YZ_2147900882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.YZ!MTB"
        threat_id = "2147900882"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 8d 40 01 f7 eb c1 fa 02 8b c2 c1 e8 1f 03 d0 8b c3 ff c3 8d 0c d2 03 c9 2b c1 48 63 c8 48 8b 44 ?? ?? 42 0f b6 8c 09 ?? ?? ?? ?? 43 32 8c 08 ?? ?? ?? ?? 41 88 4c 00 ff 3b 9c 24 ?? ?? ?? ?? b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_SG_2147903622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.SG!MTB"
        threat_id = "2147903622"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 03 44 8d 47 ?? 48 8d 0c 07 41 0f b6 04 00 30 01 48 8b 03 0f b6 11 41 30 14 00 41 0f b6 0c 00 48 8b 03 30 0c 07 03 3d ?? ?? ?? ?? 3b 3d ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_GA_2147927356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.GA!MTB"
        threat_id = "2147927356"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c8 8b 05 30 7c 09 00 89 0d 4a 7c 09 00 48 8b 0d e7 7b 09 00 0f af 81 e8 00 00 00 89 05 16 7c 09 00 8b 81 d0 00 00 00 2b 46 74 2d 97 8f 48 01 31 41 4c 49 81 fa 38 f5 05 00 0f 8c}  //weight: 1, accuracy: High
        $x_1_2 = "VisibleEntry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_GB_2147929166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.GB!MTB"
        threat_id = "2147929166"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {31 81 90 00 00 00 b8 25 68 92 92 2b 83 8c 00 00 00 48 8b 0d 64 73 00 00 01 81 20 01 00 00 49 81 f9 a0 38 00 00 0f 8c c1 fe ff ff}  //weight: 3, accuracy: High
        $x_2_2 = "rundll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_ZXZ_2147936969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.ZXZ!MTB"
        threat_id = "2147936969"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f b6 d0 41 0f b6 c5 03 d2 03 c0 49 c1 ed 10 4d 33 4c d0 02 4d 33 0c c0 4c 31 4d b7 0f b6 c1 48 8d 0d ?? ?? ?? ?? 44 8d 04 00 41 0f b6 c5 4e 8b 4c c1}  //weight: 4, accuracy: Low
        $x_5_2 = {49 33 c4 48 89 41 28 49 8b 42 20 48 33 41 30 49 33 c5 48 89 41 30 49 8b 42 ?? 49 83 c2 40 48 33 41 38 48 33 c2 4c 89 55 ef 48 83 6d 77 01 48 8d 15 a3 d5 07 00 48 89 41 38 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Basta_VZT_2147939872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Basta.VZT!MTB"
        threat_id = "2147939872"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {66 03 d7 0f b7 ff 66 33 d1 0f b7 c2 0f af f8 b8 bf 00 00 00 ff 08 48 8b 44 24 28 44 0f b6 08 0f b6 84 24 ?? ?? ?? ?? 44 0f af c8 b8 0d 37 76 51 41 f7 e1 b8 bf 00 00 00 c1 ea 09 44 69 c2 49 06 00 00 48 8b 15 ?? ?? ?? ?? 45 2b c8 4c 63 00 46 23 0c 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

