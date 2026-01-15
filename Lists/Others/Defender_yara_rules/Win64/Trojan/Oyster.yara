rule Trojan_Win64_Oyster_AA_2147908622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.AA!MTB"
        threat_id = "2147908622"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 d0 8b 85 ?? ?? ?? ?? 48 89 54 c5 ?? 83 85 ?? ?? ?? ?? 01 81 bd ?? ?? ?? ?? ?? ?? 00 00 76 ?? 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {48 63 d0 8b 85 ?? ?? ?? ?? 48 89 54 c5 ?? 83 85 ?? ?? ?? ?? 01 81 bd ?? ?? ?? ?? ?? ?? 00 00 0f 86 ?? ?? ?? ?? 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Oyster_A_2147913092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.A"
        threat_id = "2147913092"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 58 45 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 54 65 73 74 00 43 4f 4d 00 6f 70 65 6e 00 74 65 6d 70 00 25 73 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_YAD_2147953809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.YAD!MTB"
        threat_id = "2147953809"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "@USVWATAUAVAW" ascii //weight: 20
        $x_1_2 = {48 b8 24 07 c0 e9 03 48 c7 c3}  //weight: 1, accuracy: High
        $x_1_3 = {48 b8 72 17 de a6 5c 28 c7 56}  //weight: 1, accuracy: High
        $x_1_4 = {48 b8 6f 15 4a 89 86 dc 95 a1}  //weight: 1, accuracy: High
        $x_1_5 = {48 b8 a7 e0 9c fe 3f f0 5c cd}  //weight: 1, accuracy: High
        $x_1_6 = {48 b8 35 5b 03 93 e9 1f ad fe}  //weight: 1, accuracy: High
        $x_1_7 = {48 b8 4d 58 c1 08 47 6e 01 e1}  //weight: 1, accuracy: High
        $x_1_8 = {48 b8 08 91 12 09 60 74 52 ac}  //weight: 1, accuracy: High
        $x_1_9 = {48 b8 2d 13 71 8e 9d 75 9c 30}  //weight: 1, accuracy: High
        $x_1_10 = {48 b8 37 4a 89 16 31 10 10 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Oyster_Z_2147953906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.Z!MTB"
        threat_id = "2147953906"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 44 89 f8 41 ff c7 44 88}  //weight: 1, accuracy: High
        $x_1_2 = {48 b8 0f b6 07 41 c1 e2 08 ff}  //weight: 1, accuracy: High
        $x_1_3 = {49 bf 0f b6 07 41 c1 e2 08 41}  //weight: 1, accuracy: High
        $x_1_4 = {48 b8 89 d0 66 c1 e8 05 8d 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_ZA_2147953907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.ZA!MTB"
        threat_id = "2147953907"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8d 4c 24 48 c7 44 24 28 40 00 00 00 45 33 c0 48 c7 44 24 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_ZB_2147953908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.ZB!MTB"
        threat_id = "2147953908"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 53 50 48 85 d2 74 30 66 83 7b 48 00 76 29 41 b8 40 00 00 00 48 8d 4c 24 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_ZC_2147953909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.ZC!MTB"
        threat_id = "2147953909"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 89 44 5c 42 0f b6 01 84 c0 74 15 66 89 44 5c 44 48 83 c1 03 48 83 c3 03 48 83 fb 3f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_ZD_2147953912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.ZD!MTB"
        threat_id = "2147953912"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 44 24 50 45 33 c9 89 44 24 48 45 33 c0 89 44 24 40 33 d2 89 44 24 38 33 c9 89 44 24 30 48 89 44 24 28 89 44 24 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_ZF_2147953913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.ZF!MTB"
        threat_id = "2147953913"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 41 39 ff 73 13 48 8b 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_ZE_2147953914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.ZE!MTB"
        threat_id = "2147953914"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 48 8d 34 68 77 1a}  //weight: 1, accuracy: High
        $x_1_2 = "DllRegisterServer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_CC_2147953996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.CC!MTB"
        threat_id = "2147953996"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {45 33 c0 41 8b d5 48 8d 81 ?? ?? ?? ?? ff d0}  //weight: 3, accuracy: Low
        $x_2_2 = {b8 4d 5a 00 00 66 39 07}  //weight: 2, accuracy: High
        $x_1_3 = "KERNEL32.DLL" ascii //weight: 1
        $x_1_4 = "LoadLibraryA" ascii //weight: 1
        $x_1_5 = "GetProcAddress" ascii //weight: 1
        $x_1_6 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_GZZ_2147954000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.GZZ!MTB"
        threat_id = "2147954000"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 83 ec 28 ba ?? ?? ?? ?? 31 c9 41 b8 00 30 00 00 41 b9 40 00 00 00 ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {41 ff d6 48 89 c7 48 89 f1 ba 02 00 00 00 41 ff d7}  //weight: 5, accuracy: High
        $x_5_3 = {41 ff d7 48 89 c7 48 89 f1 ba 02 00 00 00 ff 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_YAB_2147954001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.YAB!MTB"
        threat_id = "2147954001"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 2b c8 48 03 cb 8a 44 0c 20 43 32 04 13 41 88 02 4d 03 d4}  //weight: 1, accuracy: High
        $x_1_2 = {49 63 c9 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 45 03 cc 48 f7 e1 48 c1 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_OSH_2147954005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.OSH!MTB"
        threat_id = "2147954005"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 48 8b 59 10 48 8b d3 48 8b 4a 60 45 8b ce 48 8b c1 66 44 39 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_C_2147954006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.C!MTB"
        threat_id = "2147954006"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 48 83 ec 20 48 8b 35 ?? ?? ?? ?? 48 8b 0e 48 8d ?? ?? ?? ?? 00 ba 01 00 00 00 45 31 c0 ff d0 b8 ?? ?? ?? ?? 48 03 06 48 83 c4 20 5e 48 ff e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_CB_2147954007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.CB!MTB"
        threat_id = "2147954007"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 03 01 ff d0 31 c0}  //weight: 3, accuracy: High
        $x_2_2 = {4b 45 52 4e 45 4c 33 32 2e 44 4c 4c 00 4c 6f 61 64 4c 69 62 72 61 72 79 41 00 45 78 69 74 50 72 6f 63 65 73 73 00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73}  //weight: 2, accuracy: High
        $x_1_3 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 00 00 00 4c 6f 61 64 4c 69 62 72 61 72 79 41 00 00 00 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_CD_2147954008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.CD!MTB"
        threat_id = "2147954008"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b c8 ff 15 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 05 ?? ?? ?? ?? ff d0 45 33 c9 45 33 c0 33 d2 33 c9}  //weight: 2, accuracy: Low
        $x_1_2 = {4b 00 45 00 52 00 4e 00 45 00 4c 00 33 00 32 00 2e 00 44 00 4c 00 4c}  //weight: 1, accuracy: High
        $x_1_3 = "LoadLibraryA" ascii //weight: 1
        $x_1_4 = "GetProcAddress" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_ZH_2147954042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.ZH!MTB"
        threat_id = "2147954042"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 44 24 58 48 8b 4c 24 28 0f b7 04 48 85 c0 74 6c 45 33 c0 33 d2 33 c9}  //weight: 1, accuracy: High
        $x_1_2 = "DllRegisterServer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_BB_2147954043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.BB!MTB"
        threat_id = "2147954043"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 6c 24 50 45 33 c9 89 6c 24 48 45 33 c0 89 6c 24 40 33 d2 89 6c 24 38 33 c9 89 6c 24 30 48 89 6c 24 28 89 6c 24 20}  //weight: 1, accuracy: High
        $x_1_2 = "DllRegisterServer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_BC_2147954044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.BC!MTB"
        threat_id = "2147954044"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fd 88 fb d4 7f 5b 90 51 07 06 ce bc ff 3b 41 c5 ac c1 ed 40 cc 0c af db 56 a5 17 35 6e fe 8b a3 0d a2 c4 cb 69 8a 02 f8 ef 3b e4 47 5e da 89 71 d2 48 6e f4 14 a1 49 c8 16 b4 73 c9 e8 b2 87 73 54 5c ec 78 f4 2e 8e b5 31 ee e0 24 3c 81 8f c3 53 2c 81 34 e8 57 1b 4d c2 97 46 19 e2 7c 61 57 c7 b6 9f 89 ca e7 5b 0e fd 63 06 89 0c 2d 9e e6 62 42 81 c6 34 92 8c fa 7c 8a ae e4 8f ff 2f 8a bb f4 64 8c 68 da 36 bd 07 8b e7 6f 84 36 75 34 90 4d ab 6e 94 ce f7 1f 60 da 02 08 6f e8 15 b9 9b a0 57 12 ab ed 98 4d 44 63 5c 12 62 08 6c c4 13 b7 15 83 c6}  //weight: 1, accuracy: High
        $x_1_2 = {bd a0 08 90 87 5b 9e 1e ad 55 9d b6 e4 4f 3a ed a7 2f fd 17 ce fe a4 4b 48 8b 33 c2 98 91 ab 67 06 1c c3 2c 24 e4 81 93 af 73 20 2c 52 2d 22 22 dc 68 3a 28 3f e8 8c 96 43 87 5f a1 59 bf ed 10}  //weight: 1, accuracy: High
        $x_1_3 = {88 fb d4 7f 5b 90 51 07 06 ce bc ff 3b 41 c5 ac c1 ed 40 cc 0c af db 56 a5 17 35 6e fe 8b a3 0d a2 c4 cb 69 8a 02 f8 ef 3b e4 47 5e}  //weight: 1, accuracy: High
        $x_1_4 = {3b 41 c5 ac c1 ed 40 cc 0c af db 56 a5 17 35 6e fe 8b a3 0d a2 c4 cb 69 8a 02 f8 ef 3b e4 47 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Oyster_CF_2147954270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.CF!MTB"
        threat_id = "2147954270"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 19 31 41 ?? 48 83 c1 08 48 39 d1 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_AC_2147954509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.AC!MTB"
        threat_id = "2147954509"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 20 00 30 00 00 4c 8d 8c 24 f0 00 00 00 45 33 c0 48 8d 94 24 98 00 00 00 48 c7}  //weight: 1, accuracy: High
        $x_1_2 = "DllRegisterServer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_CH_2147955425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.CH!MTB"
        threat_id = "2147955425"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 83 ec 28 48 8b 0d ?? ?? ?? ?? 45 33 c0 ba 01 00 00 00 48 8d 81 ?? ?? ?? ?? ff d0 48 8b 05 ?? ?? ?? ?? 48 05 ?? ?? ?? ?? 48 83 c4 28 48 ff e0}  //weight: 2, accuracy: Low
        $x_1_2 = "KERNEL32.DLL" ascii //weight: 1
        $x_1_3 = "LoadLibraryA" ascii //weight: 1
        $x_1_4 = "GetProcAddress" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_CP_2147961045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.CP!MTB"
        threat_id = "2147961045"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 b8 fd d5 0d cc c7 5a c7 92}  //weight: 2, accuracy: High
        $x_2_2 = {48 b8 2c 4d 5c 07 f6 66 f9 12}  //weight: 2, accuracy: High
        $x_2_3 = {48 b8 e6 e3 f7 c2 33 54 ec 8f}  //weight: 2, accuracy: High
        $x_2_4 = {48 b8 26 44 fb 3e 9d 19 39 39}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_CQ_2147961171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.CQ!MTB"
        threat_id = "2147961171"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4b 45 52 4e c7 45 ?? 45 4c 33 32 c7 45 ?? 2e 44 4c 4c}  //weight: 2, accuracy: Low
        $x_2_2 = {4c 69 62 72 c7 45 ?? 61 72 79 41}  //weight: 2, accuracy: Low
        $x_2_3 = "GetP" ascii //weight: 2
        $x_2_4 = {72 6f 63 41 c7 45 ?? 64 64 72 65 66 c7 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

