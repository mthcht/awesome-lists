rule Ransom_Win32_Hive_MK_2147795540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hive.MK!MTB"
        threat_id = "2147795540"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hive"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 f2 89 4c 24 ?? c1 e2 ?? 31 f2 89 d6 c1 ee ?? 89 34 24 89 ce c1 e9 ?? 31 f1 33 ?? 24 89 ce 31 d6 8b 54 24 0c 89 50 ?? 89 70 ?? 01 d6 b2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Hive_ZZ_2147809008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hive.ZZ"
        threat_id = "2147809008"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ec 20 8d 05 ?? ?? ?? ?? 89 04 24 e8 ?? ?? ?? ?? 8b 44 24 04 89 44 24 14 c6 00 ?? 8d 0d ?? ?? ?? ?? 89 0c 24 e8 ?? ?? ?? ?? 8b 44 24 04 89 44 24 1c c7 00 00 00 00 00 8d 0d ?? ?? ?? ?? 89 0c 24 e8 ?? ?? ?? ?? 8b 44 24 04 89 44 24 18 8d 0d ?? ?? ?? ?? 89 0c 24 e8 ?? ?? ?? ?? 8b 44 24 04 8d 0d ?? ?? ?? ?? 89 08 8b 0d ?? ?? ?? ?? 85 c9 75 19 8b 4c 24 1c 89 48 04 8b 5c 24 14 89 58 08 8b 5c 24 18 89 58 0c 89 03 eb 31}  //weight: 10, accuracy: Low
        $x_10_2 = {83 ec 14 8b 44 24 18 89 04 24 e8 ?? ?? ?? ?? 8b 44 24 04 8b 4c 24 04 8b 54 24 08 85 c0 0f 85 a4 00 00 00 8b 44 24 18 89 04 24 e8 ?? ?? ?? ?? 8b 44 24 04 8b 4c 24 04 8b 54 24 08 85 c0 74 0c 89 4c 24 1c 89 54 24 20 83 c4 14 c3 89 4c 24 10 89 54 24 0c 8b 44 24 18 89 04 24 e8 ?? ?? ?? ?? 8b 44 24 18 89 04 24 e8 ?? ?? ?? ?? 8b 44 24 18 89 04 24 e8 ?? ?? ?? ?? 8b 44 24 18 89 04 24 e8 ?? ?? ?? ?? 8b 44 24 18 89 04 24 e8 ?? ?? ?? ?? 8b 44 24 18 89 04 24 e8 ?? ?? ?? ?? 8b 44 24 18 89 04 24 e8 ?? ?? ?? ?? 8b 44 24 18 89 04 24 e8 ?? ?? ?? ?? 8b 44 24 10 89 44 24 1c 8b 44 24 0c 89 44 24 20 83 c4 14 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Hive_SA_2147815655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hive.SA"
        threat_id = "2147815655"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_100_2 = "\\netlogon\\xxx.exe -u" wide //weight: 100
        $x_100_3 = "\\netlogon\\xxxx.exe -u" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Hive_SB_2147815656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hive.SB"
        threat_id = "2147815656"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_100_2 = {5c 00 6e 00 65 00 74 00 6c 00 6f 00 67 00 6f 00 6e 00 5c 00 [0-16] 2e 00 65 00 78 00 65 00 20 00 2d 00 75 00}  //weight: 100, accuracy: Low
        $x_100_3 = {5c 00 6e 00 65 00 74 00 6c 00 6f 00 67 00 6f 00 6e 00 5c 00 [0-16] 2e 00 64 00 6c 00 6c 00 [0-16] 2d 00 75 00 [0-48] 3a 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Hive_F_2147815857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hive.F"
        threat_id = "2147815857"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".key" ascii //weight: 1
        $x_1_2 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 ?? 61 6e 64 20 33 32 2d 62 79 74 65 20 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {65 78 65 4e 55 4c 63 6f 75 6c 64 6e 27 74 20 67 65 6e 65 72 61 74 65 20 72 61 6e 64 6f 6d 20 62 ?? 74 65 73 3a 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Hive_SC_2147818483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hive.SC"
        threat_id = "2147818483"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_100_2 = {5c 00 6e 00 65 00 74 00 6c 00 6f 00 67 00 6f 00 6e 00 5c 00 79 00 79 00 79 00 2e 00 64 00 6c 00 6c 00 [0-16] 2d 00 75 00 [0-48] 3a 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Hive_SD_2147824251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hive.SD"
        threat_id = "2147824251"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_100_2 = {5c 00 6e 00 65 00 74 00 6c 00 6f 00 67 00 6f 00 6e 00 5c 00 [0-16] 2e 00 65 00 78 00 65 00 20 00 2d 00 75 00}  //weight: 100, accuracy: Low
        $x_100_3 = {5c 00 6e 00 65 00 74 00 6c 00 6f 00 67 00 6f 00 6e 00 5c 00 [0-16] 2e 00 64 00 6c 00 6c 00 [0-16] 2d 00 75 00 [0-48] 3a 00}  //weight: 100, accuracy: Low
        $x_100_4 = {5c 00 73 00 68 00 61 00 72 00 65 00 24 00 5c 00 [0-16] 2e 00 65 00 78 00 65 00 20 00 2d 00 75 00}  //weight: 100, accuracy: Low
        $x_100_5 = {5c 00 73 00 68 00 61 00 72 00 65 00 24 00 5c 00 [0-16] 2e 00 64 00 6c 00 6c 00 [0-16] 2d 00 75 00 [0-48] 3a 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Hive_SE_2147827150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hive.SE"
        threat_id = "2147827150"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "106"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " -da " wide //weight: 1
        $x_1_2 = " -min-size " wide //weight: 1
        $x_1_3 = " -explicit-only " wide //weight: 1
        $x_1_4 = " -network-only " wide //weight: 1
        $x_1_5 = " -local-only " wide //weight: 1
        $x_1_6 = " -no-discovery " wide //weight: 1
        $x_1_7 = " -no-mounted " wide //weight: 1
        $x_1_8 = " -no-local " wide //weight: 1
        $x_1_9 = " -wmi " wide //weight: 1
        $x_5_10 = "rundll32" wide //weight: 5
        $x_5_11 = "cmd" wide //weight: 5
        $x_100_12 = " -u " wide //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 6 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Hive_ZX_2147839304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hive.ZX"
        threat_id = "2147839304"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ec 50 a1 ?? ?? ?? ?? 89 ce c7 45 f0 03 01 00 00 c7 45 f4 00 00 00 00 85 c0 74 40 89 d7 8d 4d f0 6a 00 6a 00 ff 75 0c ff 75 08 51 6a 00 6a 00 6a 00 52 ff d0 3d 03 01 00 00 75 12 6a ff 57 e8 ?? ?? ?? ?? 8b 45 f0 3d 03 01 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {31 f6 b9 46 02 00 00 46 89 f2 e8 ?? ?? ?? ?? b9 02 00 00 00 89 54 24 34 51 ?? 46 02 00 00 ?? 89 44 24 38 50 31 c0 50 e8 ?? ?? ?? ?? b9 46 02 00 00 89 f2 e8 ?? ?? ?? ?? 89 d6 b9 02 00 00 00 51 [0-5] 89 44 24 34 50 31 c0 50 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

