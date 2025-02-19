rule Trojan_Win32_RedLine_PY_2147829750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.PY!MTB"
        threat_id = "2147829750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 84 24 a8 01 00 00 ?? ?? ?? ?? b8 ?? ?? ?? ?? f7 a4 24 b4 00 00 00 8b 84 24 b4 00 00 00 81 84 24 a4 01 00 00 ?? ?? ?? ?? ff d7 6a 00 ff d3 81 fe 56 53 1c 00 7f ?? 46 81 fe 44 ad cd 13 0f 8c}  //weight: 1, accuracy: Low
        $x_1_2 = "seyoxededudibaruxufayuvi" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_PZ_2147829751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.PZ!MTB"
        threat_id = "2147829751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe f8 6a 1a 01 0f 8d ?? ?? ?? ?? c7 44 24 ?? 7b 83 66 09 c7 84 24 ?? ?? ?? ?? 43 a8 44 1c c7 84 24 ?? ?? ?? ?? 31 d7 5f 47 c7 44 24 ?? 75 45 68 6d c7 84 24 ?? ?? ?? ?? 22 e9 77 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_PZA_2147829752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.PZA!MTB"
        threat_id = "2147829752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e0 03 0f b6 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8d 82 ?? ?? ?? ?? 03 c1 83 e0 03 0f b6 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8d 86 ?? ?? ?? ?? 03 c1 83 e0 03 0f b6 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8d 87 ?? ?? ?? ?? 03 c1 83 e0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c8 83 e1 ?? 0f b6 89 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? 8d 8a ?? ?? ?? ?? 03 c8 83 e1 03 0f b6 89 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? 83 c0 02 3d 7e 07 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_RedLine_AE_2147829920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.AE!MTB"
        threat_id = "2147829920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c2 83 e0 03 0f b6 80 [0-4] 30 82 [0-4] 8d 86}  //weight: 2, accuracy: Low
        $x_2_2 = {03 c2 83 e0 03 0f b6 80 [0-4] 30 82 [0-4] 83 c2 04 81 fa 00 ac 01 00 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_AF_2147830033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.AF!MTB"
        threat_id = "2147830033"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 33 c1 8b 4d 08 03 4d fc 88 01 eb}  //weight: 4, accuracy: High
        $x_1_2 = "WkuxzgsX{t{jgu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_B_2147830213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.B!MTB"
        threat_id = "2147830213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 db f6 17 80 37 56 47 e2 f6}  //weight: 1, accuracy: High
        $x_1_2 = {f6 17 33 db 80 07 44 80 2f 86 f6 2f 47 e2 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_C_2147830214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.C!MTB"
        threat_id = "2147830214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 0c 24 b8 d1 05 00 00 01 04 24 8b 14 24 8a 04 32 8b 0d ?? ?? ?? ?? 88 04 31 81 c4 04 04 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_C_2147830214_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.C!MTB"
        threat_id = "2147830214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 c1 ea 05 03 54 24 24 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 d7 31 54 24 10 c7 05 ?? ?? ?? ?? ff ff ff ff 8b 44 24 10 29 44 24 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_D_2147830234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.D!MTB"
        threat_id = "2147830234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce c1 e9 05 03 4c 24 20 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 cf 31 4c 24 10 c7 05 ?? ?? ?? ?? ff ff ff ff 8b 44 24 10 29 44 24 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_T_2147831119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.T!MTB"
        threat_id = "2147831119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 f9 29 ce 81 c1 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? c1 e9 02 f3 a5 89 de 83 c3 01 c7 04 24 00 e0 52 00 89 5c 24 04 83 e6 03 e8 ?? ?? ?? ?? 0f b6 86 ?? ?? ?? ?? 30 83 ?? ?? ?? ?? 81 fb 00 ac 01 00 75 d3}  //weight: 10, accuracy: Low
        $x_10_2 = {89 c2 83 e2 03 0f b6 92 20 c4 52 00 30 90 20 18 51 00 83 c0 01 3d 00 ac 01 00}  //weight: 10, accuracy: High
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RedLine_RD_2147831855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RD!MTB"
        threat_id = "2147831855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 ed 56 57 39 6c 24 18 76 28 0f 1f 40 00 60 0a c1 03 c3 2b d9 85 c0 61 8b 4c 24 1c 8b c5 83 e0 03 8a 04 08 8b 4c 24 14 30 04 29 45 3b 6c 24 18 72 dc 5f 5e 5d 5b c2 10 00}  //weight: 1, accuracy: High
        $x_1_2 = "NDAdmin.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_BQ_2147832933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.BQ!MTB"
        threat_id = "2147832933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 dc 8b 5d d4 8b 7d d0 83 e7 03 8a 87 [0-4] 30 04 33 46 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "logging.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_BQ_2147832933_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.BQ!MTB"
        threat_id = "2147832933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {89 45 b4 8b 45 bc 33 d2 f7 75 b4 8b 4d 10 0f b6 14 11 0f b6 45 c3 33 c2 88 45 eb 8b 4d 08 03 4d bc 8a 55 eb 88 11 eb}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_DIS_2147833875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.DIS!MTB"
        threat_id = "2147833875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d f0 8b fe d3 e7 03 45 d4 89 55 ec 03 7d e0 33 f8 33 fa 89 7d e8 8b 45 e8 29 45 f8 8b 45 d8 29 45 fc ff 4d e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_DSD_2147834076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.DSD!MTB"
        threat_id = "2147834076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 f7 8a 1c 06 02 d3 88 55 13 0f b6 d2 0f b6 0c 02 88 0c 06 88 1c 02 0f b6 0c 06 0f b6 d3 03 d1 0f b6 ca 8b 55 08 0f b6 0c 01 30 0c 17 47 8a 55 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDS_2147834247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDS!MTB"
        threat_id = "2147834247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 8b 4d cc 8d 45 e4 89 7d f4 89 55 e4 e8 ?? ?? ?? ?? 8b 45 e4 33 c7 31 45 e0 89 35 ?? ?? ?? ?? 8b 45 e0 29 45 fc 81 45 e8 ?? ?? ?? ?? ff 4d dc 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDS_2147834247_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDS!MTB"
        threat_id = "2147834247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c0 01 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 d2 b9 00 01 00 00 f7 f1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f b6 80 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 33 d2 b9 00 01 00 00 f7 f1}  //weight: 2, accuracy: Low
        $x_2_2 = {49 81 c9 00 ff ff ff 41 8a 89 ?? ?? ?? ?? 88 4d fb 0f b6 45 fb 8b 0d ?? ?? ?? ?? 03 8d d0 fc ff ff 0f be 11 33 d0 a1 ?? ?? ?? ?? 03 85 d0 fc ff ff 88 10}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MR_2147834492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MR!MTB"
        threat_id = "2147834492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "So Go0d hCKJb14 xhVgs57" ascii //weight: 10
        $x_5_2 = {83 c4 04 89 85 54 ec ff ff c7 45 fc 00 00 00 00 83 bd 54 ec ff ff 00 74 ?? 83 ec 18 8b cc 89 a5 0c ec ff ff 68 ?? ?? ?? ?? e8}  //weight: 5, accuracy: Low
        $x_5_3 = {e0 00 02 01 0b 01 0e 20 00 5c 02 00 00 6a 03 00 00 00 00 00 a5 a8}  //weight: 5, accuracy: High
        $x_2_4 = "WaitForSingleObjectEx" ascii //weight: 2
        $x_2_5 = "GetCPInfo" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_BS_2147834571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.BS!MTB"
        threat_id = "2147834571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 6b c0 ?? 8b 55 ?? 03 55 ?? 0f b6 0a 33 c8 8b 55 ?? 03 55 ?? 88 0a eb}  //weight: 1, accuracy: Low
        $x_1_2 = "POV4hp3Hy7tF1r2m" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_BS_2147834571_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.BS!MTB"
        threat_id = "2147834571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 45 08 03 85 f4 fb ff ff 0f b6 00 8b 8d e4 f7 ff ff 33 84 8d f8 fb ff ff 8b 8d f0 fb ff ff 03 8d f4 fb ff ff 88 01 e9}  //weight: 3, accuracy: High
        $x_1_2 = "Exodus Web3 Wallet" ascii //weight: 1
        $x_1_3 = "KeePass Tusk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RedLine_BS_2147834571_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.BS!MTB"
        threat_id = "2147834571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 d0 c1 e0 05 32 45 ef 89 c3 0f b6 4d ef 8b 55 f0 8b 45 0c 01 d0 8d 14 0b 88 10 8b 55 f0 8b 45 0c 01 d0 0f b6 10 0f b6 5d ef 8b 4d f0 8b 45 0c 01 c8 29 da 88 10 83 45 f0 01 8b 45 f0 3b 45 10 72}  //weight: 1, accuracy: High
        $x_1_2 = "6G8L2pm3TY\\UMkEhYq3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RPG_2147834603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RPG!MTB"
        threat_id = "2147834603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ce f7 e6 8b c6 2b c2 d1 e8 03 c2 c1 e8 06 6b c0 5b 2b c8 c1 e9 02 0f be 81}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_BR_2147834829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.BR!MTB"
        threat_id = "2147834829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 d0 0f b6 00 c1 e0 05 32 45 f3 89 c2 0f b6 45 f3 8d 0c 02 8b 55 f4 8b 45 0c 01 d0 89 ca 88 10 8b 55 f4 8b 45 0c 01 d0 0f b6 00 89 c2 0f b6 45 f3 89 d1 29 c1 8b 55 f4 8b 45 0c 01 d0 89 ca 88 10 83 45 f4 01 8b 45 f4 3b 45 10 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_BR_2147834829_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.BR!MTB"
        threat_id = "2147834829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {c6 45 e7 cd c6 45 e8 46 c6 45 e9 90 c6 45 ea ee c6 45 eb 94 c6 45 ec 63 c6 45 ed bb c6 45 ee 0a c6 45 ef c0 c6 45 f0 9a c6 45 f1 50 c6 45 f2 f1 c6 45 f3 a9 c6 45 f4 a9 c6 45 f5 b0 c6 45 f6 69 c6 45 f7 1d c6 45 f8 85 c6 45 f9 04 c6 45 fa 58 c6 45 fb 9d 6a 40 68 00 30 00 00 68 00 00 a0 00 6a 00 ff 15}  //weight: 3, accuracy: High
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDC_2147835020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDC!MTB"
        threat_id = "2147835020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {88 4d bf 0f b6 4d bf 8b 45 c0 31 d2 f7 75 b8 0f b6 92 ?? ?? ?? ?? 31 d1 88 4d eb 8b 45 c0}  //weight: 2, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "kernel32" ascii //weight: 1
        $x_1_4 = "main.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDD_2147835021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDD!MTB"
        threat_id = "2147835021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 45 eb 05 33 c9 88 4d eb 0f b6 55 eb 83 fa 03 74 62 8b 45 c0 8a 88 ?? ?? ?? ?? 88 4d bf 0f b6 4d bf 8b 45 c0 33 d2 f7 75 b8}  //weight: 2, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "kernel32" ascii //weight: 1
        $x_1_4 = "main.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_2147835233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MT!MTB"
        threat_id = "2147835233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 f4 33 d2 f7 75 14 8b c2 33 d2 b9 ?? ?? ?? ?? f7 f1 8b 55 08 0f be 04 02 c1 e0 ?? 6b c0 ?? 99 b9 57 00 00 00 f7 f9 6b c0 36 99 83 e2 ?? 03 c2 c1 f8 ?? 8b 55 0c 03 55 f4 0f b6 0a 33 c8 8b 55 0c 03 55 f4 88 0a eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_BD_2147835331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.BD!MTB"
        threat_id = "2147835331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 83 0d ?? ?? ?? ?? ?? 8b c6 c1 e8 ?? 03 45 ?? 03 fe 31 7d ?? 50 89 45 ?? 8d 45 ?? 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_BD_2147835331_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.BD!MTB"
        threat_id = "2147835331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 45 f4 8a 88 [0-4] 88 4d f3 0f b6 4d f3 8b 45 f4 33 d2 f7 75 ec 0f b6 92 [0-4] 33 ca 88 4d fb 8b 45 f4 8a 88 [0-4] 88 4d f2 0f b6 55 fb 8b 45 f4 0f b6 88 [0-4] 03 ca 8b 55 f4 88 8a [0-4] 83 7d f4 64 76}  //weight: 4, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDE_2147835444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDE!MTB"
        threat_id = "2147835444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b9 01 00 00 00 c1 e1 00 0f be 54 0d c4 c1 e2 04 88 55 c2 0f be 45 c3 0f be 4d c2 03 c1 8b 55 98 03 55 c8 88 02 8b 45 c8 83 c0 01}  //weight: 2, accuracy: High
        $x_1_2 = "Irea Inno" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDF_2147835522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDF!MTB"
        threat_id = "2147835522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 45 0c 8b 4d f8 83 0d ?? ?? ?? ?? ?? 8b c1 c1 e8 05 03 45 ec 03 f3 33 f0 33 75 0c c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 08 89 75 e0 8b 45 e0 29 45 fc 81 45 f4 ?? ?? ?? ?? ff 4d f0 8b 45 fc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_LD_2147835919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.LD!MTB"
        threat_id = "2147835919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8b 40 04 ff 70 09 6a 00 8b 45 08 ff 50 24 89 45 f8 83 65 f4 ?? 6a 00 8d 45 f4 50 ff 75 f8 8b 45 08 8b 40 04 ff 30 ff 75 fc e8 ?? ?? ?? ?? 83 c4 14 8b 45 f8 89 45 fc 8b 45 08 8b 40 04 8b 4d f4 89 08 ff 65 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MU_2147836041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MU!MTB"
        threat_id = "2147836041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 f4 33 d2 f7 75 14 8b 4d 08 0f be 04 11 6b c0 47 99 b9 2d 00 00 00 f7 f9 6b c0 3d 99 b9 22 00 00 00 f7 f9 6b c0 1a 8b 55 0c 03 55 f4 0f b6 0a 33 c8 8b 55 0c 03 55 f4 88 0a eb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MV_2147836048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MV!MTB"
        threat_id = "2147836048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 08 03 45 e8 89 45 08 8b 45 f4 03 45 f8 89 45 fc 83 0d 0c 58 45 00 ff 8b c7 c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 0c 8b 45 e0 01 45 0c 8b 45 fc 31 45 08 8b 45 0c 31 45 08 ff 75 08 8d 45 f0 50 e8 ?? ?? ?? ?? 81 45 f8 ?? ?? ?? ?? ff 4d ec 8b 45 f0 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDH_2147837299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDH!MTB"
        threat_id = "2147837299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c6 d3 e8 89 45 fc 8b 45 d0 01 45 fc 8b 45 fc 33 45 f0 83 25 ?? ?? ?? ?? 00 31 45 f8 8b 45 f8 29 45 f4 81 45 e4 ?? ?? ?? ?? ff 4d e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDK_2147838557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDK!MTB"
        threat_id = "2147838557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c8 33 d2 8b c6 f7 f1 8a 82 ?? ?? ?? ?? 32 c3 88 04 2e 46 3b f7}  //weight: 2, accuracy: Low
        $x_1_2 = "vbc.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDM_2147839391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDM!MTB"
        threat_id = "2147839391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 0c 33 45 08 83 25 ?? ?? ?? ?? 00 2b f8 89 45 0c 8b c7 c1 e0 04 89 45 08 8b 45 ec 01 45 08 83 0d ?? ?? ?? ?? ff 8b c7 c1 e8 05 03 45 e8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 0c 8b 45 fc 03 c7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_CZ_2147841033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.CZ!MTB"
        threat_id = "2147841033"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 84 3c 10 01 00 00 88 84 34 10 01 00 00 88 8c 3c 10 01 00 00 0f b6 84 34 10 01 00 00 03 c2 0f b6 c0 8a 84 04 10 01 00 00 30 83 70 3a 43 00 43 81 fb ?? ?? ?? ?? 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RPQ_2147841277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RPQ!MTB"
        threat_id = "2147841277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 75 cc 3b f7 0f 83 81 00 00 00 8a 14 30 8b c6 83 e0 03 8a 88 ?? ?? ?? ?? 32 ca 0f b6 da 8d 04 19 8b 4d d0 88 04 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RPQ_2147841277_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RPQ!MTB"
        threat_id = "2147841277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 75 dc 3b f0 73 57 8b c6 83 e0 03 8a 88 ?? ?? ?? ?? 32 0c 37 0f b6 1c 37 8d 04 19 88 04 37}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 0c 28 1c 37 46 8b 45 d8 eb b9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RPQ_2147841277_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RPQ!MTB"
        threat_id = "2147841277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5c 24 10 0f b6 1c 03 32 18 83 c0 04 88 5c 28 fc 8b 5c 24 14 0f b6 1c 0b 32 58 fd 83 c1 04 88 59 fc 0f b6 58 fe 32 5f ff 83 c7 04 88 59 fd 0f b6 58 ff 32 5f fc 83 6c 24 18 01 88 59 fe 75 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDAL_2147841608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDAL!MTB"
        threat_id = "2147841608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 0c 03 45 e4 0f be 08 8b 45 e4 99 be 37 00 00 00 f7 fe 8b 45 08 0f be 04 10 6b c0 26 99 be 1d 00 00 00 f7 fe 83 e0 2b 33 c8 88 4d e3 0f be 4d e3 0f be 55 e3 03 ca 8b 45 0c 03 45 e4 88 08 0f be 4d e3 8b 55 0c 03 55 e4 0f be 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDAG_2147841626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDAG!MTB"
        threat_id = "2147841626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Explorer.exe" wide //weight: 1
        $x_2_2 = {4e 33 ce 33 ce 46 f7 d9 c1 c1 09 33 cc f7 de 21 05 b2 a7 40 00 46 b9 57 a4 04 00 03 cb 03 0d bf af 40 00 87 f7 0b 1d 13 ae 40 00 31 35 f6 a6 40 00 4b 31 0d df aa 40 00 33 0d 63 af 40 00 47 31 3d 9a a9 40 00 f7 d7 21 15 dc a8 40 00 33 15 34 ae 40 00 c1 c9 0d c1 c1 0d f7 d7 09 0d 9d a8 40 00 4f 89 05 0a ab 40 00 43 31 3d 13 aa 40 00 87 f7 2b cb f3 a4 f7 d6 33 f7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDAH_2147841627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDAH!MTB"
        threat_id = "2147841627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 75 dc 3b f0 73 52 8b c6 83 e0 03 8a 88 ?? ?? ?? ?? 32 0c 37 0f b6 1c 37 8d 04 19 88 04 37}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDAK_2147841630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDAK!MTB"
        threat_id = "2147841630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 75 dc 3b f0 73 ?? 8b c6 83 e0 03 8a 88 ?? ?? ?? ?? 32 0c 37 0f b6 1c 37 8d 04 19 88 04 37}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDAQ_2147841916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDAQ!MTB"
        threat_id = "2147841916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 75 d8 3b f7 73 ?? 8a 14 30 8b c6 83 e0 03 8a 88 ?? ?? ?? ?? 32 ca 0f b6 da 8d 04 19 8b 4d dc 88 04 31}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDAS_2147842398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDAS!MTB"
        threat_id = "2147842398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 fc 33 d2 f7 75 14 8b 45 08 0f be 04 10 6b c0 38 99 b9 24 00 00 00 f7 f9 6b c0 16 6b c0 13 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDAT_2147842399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDAT!MTB"
        threat_id = "2147842399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 fc 99 be 36 00 00 00 f7 fe 8b 45 08 0f be 14 10 6b d2 25 81 e2 86 03 00 00 33 ca 88 4d fb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RPX_2147842428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RPX!MTB"
        threat_id = "2147842428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 51 59 58 88 04 0b eb 05 d1 5d 29 f5 38 50 b8 b7 00 00 00 eb 19 4c 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RPX_2147842428_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RPX!MTB"
        threat_id = "2147842428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 c1 e9 05 03 4c 24 2c 8b d0 c1 e2 04 03 54 24 20 03 c3 33 ca 33 c8 2b f9 8b cf c1 e1 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RPX_2147842428_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RPX!MTB"
        threat_id = "2147842428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 55 d4 52 6a 40 8b 45 cc 50 68 ?? ?? ?? ?? ff 55 e8 89 45 d0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7d 08 33 db f6 17 80 37 ?? 47 e2 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RPX_2147842428_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RPX!MTB"
        threat_id = "2147842428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 44 24 1c 8b 44 24 1c 89 44 24 20 8b 4c 24 18 8b d6 d3 ea 03 54 24 30 89 54 24 14 8b 44 24 20 31 44 24 10 8b 44 24 10 33 44 24 14 2b f8 89 44 24 10 8d 44 24 24 89 7c 24 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RPX_2147842428_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RPX!MTB"
        threat_id = "2147842428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 8b 0e 8b 49 04 8b 4c 31 30 8b 49 04 89 4c 24 0c 8b 11 ff 52 04 8d 44 24 08 50 e8 ?? ?? ?? ?? 83 c4 04 8b 08 6a 0a 8b 51 30 8b c8 ff d2 8b 4c 24 0c 0f b7 f8 85 c9 74 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RPX_2147842428_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RPX!MTB"
        threat_id = "2147842428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 fb 0f be 4d fb 0f be 75 fb 8b 45 fc 99 bf 37 00 00 00 f7 ff 8b 45 08 0f be 04 10 69 c0 53 0b 00 00 99 bf 34 00 00 00 f7 ff 25 70 29 00 00 33 f0 03 ce 8b 55 0c 03 55 fc 88 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RPX_2147842428_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RPX!MTB"
        threat_id = "2147842428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 dc 83 c0 01 89 45 dc 8b 4d dc 3b 4d 10 73 30 8b 45 dc 99 b9 41 00 00 00 f7 f9 8b 45 08 0f be 0c 10 69 c9 19 14 00 00 83 e1 45 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01 eb bf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RPX_2147842428_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RPX!MTB"
        threat_id = "2147842428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 50 ff 74 24 50 ff 54 24 34 8b 44 24 18 47 8b 54 24 14 83 c6 28 0f b7 80 ?? ?? ?? ?? 3b f8 7c bc 8b 7c 24 2c 8b 74 24 1c 8b 86 a4 00 00 00 6a 00 6a 04 ff 74 24 44 83 c0 08 50 ff 74 24 50 ff 54 24 34 8b 4c 24 18 56 8b 81 ?? ?? ?? ?? 03 44 24 18 89 86 b0 00 00 00 ff 74 24 48 ff 54 24 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RPY_2147842429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RPY!MTB"
        threat_id = "2147842429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 8b c8 c1 ea 05 03 54 24 34 c1 e1 04 03 4c 24 24 03 c3 33 d1 33 d0 2b fa 8b cf c1 e1 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RPY_2147842429_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RPY!MTB"
        threat_id = "2147842429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2c ce 50 b8 ff 56 00 00 b8 52 2e 00 00 58 51 59 90 88 04 0b 52 52 5a ba 4f 75 00 00 52 eb 05 6e 92}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RPY_2147842429_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RPY!MTB"
        threat_id = "2147842429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 c1 cf 51 c1 ea ba 66 81 c3 8d 01 c1 d6 7a 42 66 0b c7 c1 d0 22 66 0d e8 01 66 4e 66 f7 ea c1 d1 fd 66 c1 db 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RPY_2147842429_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RPY!MTB"
        threat_id = "2147842429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 7c 24 10 c7 44 24 1c 00 00 00 00 8b 44 24 28 01 44 24 1c 8b 44 24 14 90 01 44 24 1c 8b 44 24 1c 89 44 24 20 8b 4c 24 18 8b 54 24 14 d3 ea 8b cb 8d 44 24 24 89 54 24 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_BZ_2147842499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.BZ!MTB"
        threat_id = "2147842499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 14 01 8b 44 24 ?? 03 54 24 ?? 8b 0c b8 8b 44 24 ?? 8a 04 01 8d 4c ?? 24 30 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_BZ_2147842499_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.BZ!MTB"
        threat_id = "2147842499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f be 04 10 69 c0 [0-4] 6b c0 ?? 99 bf [0-4] f7 ff 99 bf [0-4] f7 ff 83 e0 ?? 33 f0 03 ce 8b 55 0c 03 55 fc 88 0a 0f be 45 fb 8b 4d 0c 03 4d fc 0f b6 11 2b d0 8b 45 0c 03 45 fc 88 10 eb}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDAU_2147842629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDAU!MTB"
        threat_id = "2147842629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4f 81 cf 00 ff ff ff 47 8a 44 3d 10 88 44 35 10 88 4c 3d 10 0f b6 44 35 10 03 c2 0f b6 c0 8a 44 05 10 30 83 ?? ?? ?? ?? 43 81 fb 00 b2 02 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDAW_2147843067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDAW!MTB"
        threat_id = "2147843067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c6 83 e0 03 8a 88 ?? ?? ?? ?? 32 0c 33 0f b6 1c 33 8d 04 19 8b 4d d0 88 04 31}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDAY_2147843068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDAY!MTB"
        threat_id = "2147843068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c6 83 e0 03 8a 88 ?? ?? ?? ?? 32 0c 37 0f b6 1c 37 8d 04 19 88 04 37}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_EH_2147843531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.EH!MTB"
        threat_id = "2147843531"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6b c0 16 99 bf 25 00 00 00 f7 ff 6b c0 2c 83 e0 2c 33 f0 03 ce 8b 55 0c 03 55 dc 88 0a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDBA_2147843728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDBA!MTB"
        threat_id = "2147843728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 84 3c 8c 00 00 00 88 84 34 8c 00 00 00 88 8c 3c 8c 00 00 00 0f b6 84 34 8c 00 00 00 03 c2 0f b6 c0 8a 84 04 8c 00 00 00 30 83 ?? ?? ?? ?? 43 81 fb 00 bc 02 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDBB_2147843729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDBB!MTB"
        threat_id = "2147843729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 44 24 18 8b 44 24 18 89 44 24 1c 8b f7 c1 ee 05 03 f5 8b 44 24 1c 31 44 24 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDBD_2147844308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDBD!MTB"
        threat_id = "2147844308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c2 83 e0 03 8a 80 ?? ?? ?? ?? 30 04 32 42 3b d7 72 ed}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDBF_2147844563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDBF!MTB"
        threat_id = "2147844563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 74 24 1c 8b 54 24 14 8b 46 24 8d 04 68 0f b7 0c 10 8b 46 1c 8d 04 88 8b 34 10 83 fb 10 72 3e 8d 4b 01 8b c7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDBG_2147844949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDBG!MTB"
        threat_id = "2147844949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 43 3c 8b 44 18 78 03 c3 89 45 dc 8b 70 20 8b 40 18 03 f3 89 45 e0 85 c0 74 31 8b 06 8d 4d e4 03 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDBI_2147844951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDBI!MTB"
        threat_id = "2147844951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d0 83 e2 03 8a 8a ?? ?? ?? ?? 30 0c 38 40 3b c6 72 ed}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDBJ_2147845157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDBJ!MTB"
        threat_id = "2147845157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 75 14 8b 4d 10 0f b6 14 11 8b 45 08 03 45 cc 0f b6 08 2b ca 8b 55 08 03 55 cc 88 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDBL_2147845159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDBL!MTB"
        threat_id = "2147845159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 d7 c1 c0 01 87 d1 2b f0 2b 35 c9 3e 5f 00 03 c8 03 1d 07 3c 5f 00 31 05 ed 37 5f 00 0b 3d 42 3e 5f 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDBP_2147845702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDBP!MTB"
        threat_id = "2147845702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 dc 99 b9 41 00 00 00 f7 f9 8b 45 08 0f be 0c 10 69 c9 2f d1 ff ff 81 e1 ff 00 00 00 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBCI_2147845999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBCI!MTB"
        threat_id = "2147845999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 33 b2 3d 6e f7 64 24 68 8b 44 24 68 81 6c 24 68 b6 93 e6 65 81 44 24 68 db e8 e4 21 81 6c 24 68 9d c0 11 1f 81 44 24 68 91 88 05 3d b8 c1 04 90 7b f7 a4 24 8c 00 00 00 8b 84 24 8c 00 00 00 81 44 24 68 7b 3f f1 7a b8 32 b7 31 5b f7 a4 24 8c 00 00 00 8b 84 24 8c 00 00 00 b8 0c 61 e9 32 f7 64 24 30 8b 44 24 30 81 6c 24 68 62 29 f6 1a 81 6c 24 30 22 ef 9d 05 81 6c 24 68 a3 88 87 4f b8 ac 4f 2a 4b f7 a4 24 88 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDBT_2147846004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDBT!MTB"
        threat_id = "2147846004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 44 24 14 90 01 44 24 1c 8b 44 24 1c 89 44 24 20 8b 4c 24 14 c1 e9 05 89 4c 24 24 8b cb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDBV_2147846121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDBV!MTB"
        threat_id = "2147846121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 5d e8 0f b6 4c 1d 10 88 4c 3d 10 88 54 1d 10 0f b6 4c 3d 10 03 ce 0f b6 c9 0f b6 4c 0d 10 32 88}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBCJ_2147846385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBCJ!MTB"
        threat_id = "2147846385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kujohec xukesutidigayopulohetowamozaxac" wide //weight: 1
        $x_1_2 = "Wodiwafoluva" wide //weight: 1
        $x_1_3 = "jlexetexupuxoyosomik" wide //weight: 1
        $x_1_4 = "Sohilu huyejulupi nanuwal" wide //weight: 1
        $x_1_5 = "moxuniwerodikixazomajaseyowuvip" wide //weight: 1
        $x_1_6 = "gasomowu sinucicoto zodofarubuwuna cizebupotuhiraguhale" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_CAP_2147846561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.CAP!MTB"
        threat_id = "2147846561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 e2 c1 ea 06 8b c2 c1 e0 06 03 c2 8b d6 2b d0 0f b6 82 [0-4] b2 1c f6 ea 24 45 30 86 [0-4] 03 f3 81 fe 00 0c 02 00 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_CAP_2147846561_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.CAP!MTB"
        threat_id = "2147846561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 fc 99 b9 41 00 00 00 f7 f9 8b 45 08 0f be 04 10 6b c0 ?? 99 b9 [0-4] f7 f9 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_CAQ_2147846562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.CAQ!MTB"
        threat_id = "2147846562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 e2 c1 ea 06 8b c2 c1 e0 06 03 c2 8b d1 2b d0 0f b6 82 [0-4] b2 1c f6 ea 24 45 30 46 01 83 c1 02 81 f9 7e 07 00 00 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_CAQ_2147846562_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.CAQ!MTB"
        threat_id = "2147846562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Radedonicinaxa=Nedebemog weyenikevoh bon daj piyodihelix micat jivoleleyufek" wide //weight: 1
        $x_1_2 = "lXicuxuhiyijo bedu juzukuticumixa figuyotinoxene logisativadexel savizagacisuk delobihemaxali goxoyamuj bojup" wide //weight: 1
        $x_1_3 = "Sidarapi xexorebidawu" wide //weight: 1
        $x_1_4 = "0Hamusahiyucum duvugebubus fux yofilobuy sutuwura" wide //weight: 1
        $x_1_5 = "Javabomatago xelidemarohah9Yas nolaneronamux conasay haziwarocayi vovo mugacoy sakol" wide //weight: 1
        $x_1_6 = "Tecizisip hotave vihobag jepahir9Zihicuwejar keju wijejil netanidop jizirovodohim zet rura" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_CAR_2147846725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.CAR!MTB"
        threat_id = "2147846725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 fc 99 b9 [0-4] f7 f9 8b 45 08 0f be 0c 10 83 e1 ?? 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_CAR_2147846725_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.CAR!MTB"
        threat_id = "2147846725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {03 55 f8 8a 02 88 45 fe 0f b6 4d fe 8b 45 f8 33 d2 f7 75 10 0f b6 92 [0-4] 33 ca 88 4d ff 8b 45 08 03 45 f8 8a 08 88 4d fd}  //weight: 3, accuracy: Low
        $x_3_2 = {0f b6 4d fc 8b 55 08 03 55 f8 0f b6 02 2b c1 8b 4d 08 03 4d f8 88 01 e9}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_CAS_2147846799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.CAS!MTB"
        threat_id = "2147846799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 dc 99 b9 41 00 00 00 f7 f9 8b 45 08 0f be 04 10 6b c0 ?? 99 b9 ?? 00 00 00 f7 f9 8b 55 0c 03 55 dc 0f b6 0a 33 c8 8b 55 0c 03 55 dc 88 0a eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_CAS_2147846799_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.CAS!MTB"
        threat_id = "2147846799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 44 24 14 89 44 24 20 8b 44 24 28 01 44 24 20 8b 4c 24 1c 8b 54 24 14 d3 ea 8b 4c 24 3c 8d 44 24 2c c7 05 [0-4] ee 3d ea f4 89 54 24 2c e8 [0-4] 8b 44 24 20 31 44 24 10 81 3d [0-4] e6 09 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDBW_2147846889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDBW!MTB"
        threat_id = "2147846889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 84 3d e8 fe ff ff 03 c2 0f b6 c0 0f b6 84 05 e8 fe ff ff 32 86}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBCK_2147846892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBCK!MTB"
        threat_id = "2147846892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c6 33 c1 2b f8 89 44 24 10 8b c7 c1 e0 04 81 3d ?? ?? ?? ?? 8c 07 00 00 89 44 24 0c 75 16}  //weight: 1, accuracy: Low
        $x_1_2 = {31 74 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 14 81 3d ?? ?? ?? ?? 93 00 00 00 75 10}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c7 c1 e8 05 8d 34 3b c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ff ff ff ff 89 44 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBCM_2147847071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBCM!MTB"
        threat_id = "2147847071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 74 24 10 8b 44 24 14 31 44 24 10 2b 7c 24 10 81 3d ?? ?? ?? ?? 93 00 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 8d 34 2b c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ff ff ff ff 89 44 24 14 8b 44 24 20 01 44 24 14 81 3d ?? ?? ?? ?? 79 09 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_EM_2147847198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.EM!MTB"
        threat_id = "2147847198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 97 20 00 02 00 81 c1 00 01 00 00 c1 e1 08 03 cf 8a 04 0a 88 06}  //weight: 2, accuracy: High
        $x_2_2 = {80 f1 a3 80 f2 54 88 4c 24 04 0f b6 48 02 88 54 24 05 0f b6 50 03 f6 d1 80 f2 75 88 4c 24 06}  //weight: 2, accuracy: High
        $x_1_3 = {eb c4 3a 0d f1 c0 36 5e f1 c1 35 bb f1 c1 35 ff f1 c1 35 ff f1 c1 35 ff f1 c1 35 ff f1 c1 35 ff f0 c0 35 fe f1 c1 35 bb f0 c0 36 55 ff bf 3f 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBCN_2147847204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBCN!MTB"
        threat_id = "2147847204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kuyusixavoculo mosanimukufata" wide //weight: 1
        $x_1_2 = "Bifeluyasaru zege" wide //weight: 1
        $x_1_3 = "Nalobaz como sefevezohuruto fopuya sayap nitix fuyofuy labeme zuxupavuvuvi" wide //weight: 1
        $x_1_4 = "Tovareduzu zocagagar sah xiwacetizevoraz" wide //weight: 1
        $x_1_5 = "Goyivizuju wetiwakococe jem" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBCP_2147847219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBCP!MTB"
        threat_id = "2147847219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tutivodiri henolitej mimegojuhegeho vupinutovoganur" wide //weight: 1
        $x_1_2 = "Kuwutorebuvuvah" wide //weight: 1
        $x_1_3 = "Mazuhujujamo biwujasu bunububotunabim" wide //weight: 1
        $x_1_4 = "Meviv nuvorocufilu" wide //weight: 1
        $x_1_5 = "Beyulajekan rihi cuhukagezawahaw kobas" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBCQ_2147848646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBCQ!MTB"
        threat_id = "2147848646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d a7 00 00 00 88 44 24 1f 0f b6 4c 24 1f 31 c0 29 c8 88 44 24 1f 0f b6 44 24 1f 83 f0 ff 88 44 24 1f 8b 4c 24 20 0f b6 44 24 1f 01 c8 88 44 24 1f 0f b6 44 24 1f c1 f8 01 0f b6 4c 24 1f c1 e1 07 09 c8 88 44 24 1f 8a 4c 24 1f}  //weight: 1, accuracy: High
        $x_1_2 = "emzeuumvgwtgvddcdzwqrqxbdwgpjvwskuo" ascii //weight: 1
        $x_1_3 = "blzdoxltptjsqxaitedaopuoptezejqnsvcjximvpoqagivxdfqjrteemqipheulvdytaxkcxquzw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDBX_2147848765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDBX!MTB"
        threat_id = "2147848765"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b f0 8b ce c1 e1 04 89 44 24 14 89 4c 24 10 8b 44 24 28 01 44 24 10 8b 7c 24 18 8b c6 c1 e8 05 03 fe}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDBZ_2147848766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDBZ!MTB"
        threat_id = "2147848766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {04 08 04 8e 69 5d 91 07 08 07 8e 69 5d 91 61}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBED_2147848769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBED!MTB"
        threat_id = "2147848769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e1 01 09 c8 88 44 24 1f 8b 4c 24 20 0f b6 44 24 1f 29 c8 88 44 24 1f 0f b6 4c 24 1f 31 c0 29 c8 88 44 24 1f 8b 4c 24 20 0f b6 44 24 1f 29 c8 88 44 24 1f}  //weight: 1, accuracy: High
        $x_1_2 = {f6 17 80 2f 4a 47 e2}  //weight: 1, accuracy: High
        $x_1_3 = "nzjlcxloduqtjfgptqaaxcrytrzdfyhnddclizfkgwluiu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBEE_2147848783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBEE!MTB"
        threat_id = "2147848783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "K1JX8cxcS7zbl4jjwUAbJFjHqACDmt" ascii //weight: 1
        $x_1_2 = "nlahJYlawUZifyTpOnwPnuMFXFeZcSSNWY" ascii //weight: 1
        $x_1_3 = "qIbUyAZXsusycKWHeDdO" ascii //weight: 1
        $x_1_4 = "qrJuaZBbXMAAzUOojFZzWPvRSfFGwwzxmg" ascii //weight: 1
        $x_1_5 = "7iGkFBAR5cc134M2rdZj7oBfurozvDb" ascii //weight: 1
        $x_1_6 = "HYRUMNFu89eZ5hhXW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDCE_2147849160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDCE!MTB"
        threat_id = "2147849160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 85 47 fc ff ff 0f b6 8d 47 fc ff ff c1 f9 02 0f b6 95 47 fc ff ff c1 e2 06 0b ca 88 8d 47 fc ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDCG_2147849162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDCG!MTB"
        threat_id = "2147849162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 45 dc 0f b6 4d ee 8b 45 e8 33 d2 f7 75 e4 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ef}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDCI_2147849429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDCI!MTB"
        threat_id = "2147849429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 75 f4 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDCJ_2147849609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDCJ!MTB"
        threat_id = "2147849609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 8c 00 00 0a 25 08 6f 8d 00 00 0a 25 17 6f 8e 00 00 0a 25 18 6f 8f 00 00 0a 25 06 6f 90 00 00 0a 6f 91 00 00 0a 07 16 07 8e 69 6f 92 00 00 0a 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBEV_2147849751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBEV!MTB"
        threat_id = "2147849751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 17 80 07 58 fe 07 47 e2}  //weight: 1, accuracy: High
        $x_1_2 = "qvikrjqijxwklhvklrhakl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBFG_2147849985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBFG!MTB"
        threat_id = "2147849985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c1 2b f0 89 44 24 14 8b c6 c1 e0 04 89 44 24 10 8b 44 24 28 01 44 24 10}  //weight: 1, accuracy: High
        $x_1_2 = "fodajizitifuvuhaciluvesigizomo miwudoxipedogapo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDCK_2147850030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDCK!MTB"
        threat_id = "2147850030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c1 f7 74 24 10 8a 82 ?? ?? ?? ?? 30 04 31 41 3b 4c 24 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_KAN_2147850125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.KAN!MTB"
        threat_id = "2147850125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 33 d2 f7 f7 8a 82 ?? ?? ?? ?? 30 04 19 41 3b ce 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBFZ_2147850550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBFZ!MTB"
        threat_id = "2147850550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 1c 01 6c 24 10 03 fa d3 ea 89 7c 24 24 89 54 24 14 8b 44 24 34 01 44 24 14 8b 44 24 24 31 44 24 10 8b 4c 24 10 33 4c 24 14 8d 44 24 28 89 4c 24 10}  //weight: 1, accuracy: High
        $x_1_2 = {69 00 78 00 65 00 6d 00 61 00 79 00 69 00 6e 00 6f 00 72 00 6f 00 20 00 72 00 69 00 76 00 65 00 72 00 6f 00 63 00 69 00 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDCN_2147850791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDCN!MTB"
        threat_id = "2147850791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 8a 1c 3e 8b c6 f7 74 24 18 6a 00 6a 00 8a 82 ?? ?? ?? ?? 32 c3 02 c3 88 04 3e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDCN_2147850791_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDCN!MTB"
        threat_id = "2147850791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c1 ce 6c f7 d7 c1 df 36 f7 d8 42 0f c8 81 c7 ce 00 00 00 f7 e8 f7 d3 0f ce c1 d2 99 f7 d7 c1 d6 74 f7 da}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDCQ_2147851231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDCQ!MTB"
        threat_id = "2147851231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {32 04 3e 0f b6 1c 3e 8d 0c 18 88 0c 3e fe c9 88 0c 3e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDCR_2147851683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDCR!MTB"
        threat_id = "2147851683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {32 c3 fe c8 02 c7 88 04 3e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDCU_2147851729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDCU!MTB"
        threat_id = "2147851729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 cf 33 c2 33 c1 2b f0 8b d6 c1 e2 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBHG_2147851806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBHG!MTB"
        threat_id = "2147851806"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 14 8b 54 24 10 8b c1 c1 e8 05 03 44 24 20 03 d5 33 c2 03 cf 33 c1 2b f0 8b d6 c1 e2 04}  //weight: 1, accuracy: High
        $x_1_2 = {8b 7d 08 f6 17 80 37 76 47 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_RedLine_RDCS_2147851873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDCS!MTB"
        threat_id = "2147851873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {32 c3 fe c8 02 c7 88 04 0e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDCT_2147851874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDCT!MTB"
        threat_id = "2147851874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {32 c3 fe c8 02 c3 88 04 0e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBHL_2147852204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBHL!MTB"
        threat_id = "2147852204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d 08 f6 17 80 37 86 47 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBHM_2147852312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBHM!MTB"
        threat_id = "2147852312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d5 33 c0 33 d2 66 ?? ?? ?? ?? 33 c9 66 89 ?? ?? ?? 8d 44 24 3c 50 66 89 ?? ?? ?? 8b 4c 24 1c 51}  //weight: 1, accuracy: Low
        $x_1_2 = "numalihijuwufataramo volekaxoyufuyojotazuw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDCX_2147852454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDCX!MTB"
        threat_id = "2147852454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {32 c3 0f b6 1c 3e 8d 0c 18 88 0c 3e fe c9 88 0c 3e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBHN_2147852876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBHN!MTB"
        threat_id = "2147852876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5a 41 64 65 64 67 72 33 00 00 00 00 76 6a 78 68 55 69 73 61 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBII_2147889295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBII!MTB"
        threat_id = "2147889295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "savujoratebolizilabezohoyicukomo xiliwut" ascii //weight: 1
        $x_1_2 = "Tag vukuzolotitekez" ascii //weight: 1
        $x_1_3 = "tupipevijayigixifu" ascii //weight: 1
        $x_1_4 = "vilokemabezomawifo" ascii //weight: 1
        $x_1_5 = "cicokirafinibirozatuwaj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBIL_2147889511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBIL!MTB"
        threat_id = "2147889511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zaubpnthtcshkyfktpwllnphnynddeajtiyzgfehigahvrtipdltdpwgzrgbuegncuufmvalgd" ascii //weight: 1
        $x_1_2 = "xyvcafhxwlheuebxnppaxuplsotllsvvrnzjocmaunvwijpgcwnamyelsdhwhoflrbamlestseowtentphjzxnmflwuv" ascii //weight: 1
        $x_1_3 = "rpghxajywufpryesomvgzwufwkvuwashylqeeadhkzbhmtyoemzhnfnkyahagixqirjuohjhpmlejbonmlsdwxsve" ascii //weight: 1
        $x_1_4 = "ordvkmsafwbasypsirsomhilfkxrsvclmwsczwxjltvojxctk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBIM_2147889519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBIM!MTB"
        threat_id = "2147889519"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7b 12 d9 05 d0 68 41 00 d9 5d 84 d9 05 cc 68 41 00 d9 5d 84 d9 05 c8 68 41 00 d9 5d 84 d9 45 84 dc 1d d0 66 41 00 df e0 f6 c4}  //weight: 1, accuracy: High
        $x_1_2 = "rnwuxonpbzqoxiyzowwzckrzxeylcphklmpdasdjzrgbsxdqhjtmryrqrpagmtwqvjgulvrmtday" ascii //weight: 1
        $x_1_3 = "fiovpfbvyklgghdhelihxdyfaxhzflamipocijjatohxornicyodbpcxyejjxvuxo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDDG_2147891328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDDG!MTB"
        threat_id = "2147891328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 c1 eb 37 4b 43 66 2b f9 66 c1 c1 69 66 c1 df bb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDDH_2147891383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDDH!MTB"
        threat_id = "2147891383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 08 03 55 fc 0f b6 02 35 a2 00 00 00 8b 4d 08 03 4d fc 88 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_EC_2147892924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.EC!MTB"
        threat_id = "2147892924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f be 04 0a c1 e0 10 33 45 f8 89 45 f8 b9 01 00 00 00 c1 e1 00 8b 55 e0 0f be 04 0a c1 e0 08 33 45 f8 89 45 f8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_EC_2147892924_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.EC!MTB"
        threat_id = "2147892924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Daggerhashimoto 888" wide //weight: 1
        $x_1_2 = "extendkey.dat" wide //weight: 1
        $x_1_3 = "regkey.dat" wide //weight: 1
        $x_1_4 = "@.vm_sec" ascii //weight: 1
        $x_1_5 = ".winlice" ascii //weight: 1
        $x_1_6 = ".boot" ascii //weight: 1
        $x_1_7 = "CreateProcessA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_DB_2147894777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.DB!MTB"
        threat_id = "2147894777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be 06 33 c1 69 c0 91 e9 d1 5b 33 f8 8b c7 c1 e8 0d 33 c7 69 c0 91 e9 d1 5b 8b c8 c1 e9 0f 33 c8 74 06 3b 4c 24 54 74 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_EB_2147895881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.EB!MTB"
        threat_id = "2147895881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HOjicgUd9XEm998P1A6mkt1SoQQjyprkOb8DLNzqq5ggLI0QyN7mpyRqGLkI6m8T0" ascii //weight: 1
        $x_1_2 = "fYhacL6hYlVZwPkgXGF4Iuj3Yoow7eWWFvSseHiG40IkxGAheqPAcv0kxPn0u7EH6" ascii //weight: 1
        $x_1_3 = "/deactivate" ascii //weight: 1
        $x_1_4 = "Activation1307228306" ascii //weight: 1
        $x_1_5 = "evqweqwe" wide //weight: 1
        $x_1_6 = "SystemBiosVersion" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBEU_2147896511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBEU!MTB"
        threat_id = "2147896511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 4d db 0f b6 55 db f7 d2 88 55 db 0f b6 45 db f7 d8 88 45 db 0f b6 4d db 83 c1 3b 88 4d db 0f b6 55 db f7 d2 88 55 db 0f b6 45 db c1 f8 05 0f b6 4d db c1 e1 03 0b c1 88 45 db 0f b6 55 db 83 c2 7f 88 55 db 8b 45 dc 8a 4d db 88 4c 05 e8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_DX_2147896552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.DX!MTB"
        threat_id = "2147896552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 10 89 6c 24 10 8d 6c 24 10 2b e0 53 56 57 a1 04 73 4d 00 31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0 64 a3}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MBEZ_2147896623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MBEZ!MTB"
        threat_id = "2147896623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d8 33 f0 8b de 80 07 ?? 8b c0 8b f6 33 f0 33 de 33 db 8b f6 8b f6 33 c0 8b f6 80 2f ?? 8b c3 33 f0 33 de 33 db 8b f0 33 c6 8b c0 8b c0 8b db f6 2f 47}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_SPGA_2147896818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.SPGA!MTB"
        threat_id = "2147896818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lepesuvanosiz taxigutolamatenoyufupozuyari" wide //weight: 1
        $x_1_2 = "dibemisidagunokuta" wide //weight: 1
        $x_1_3 = "wumosewodebomelas" wide //weight: 1
        $x_1_4 = "zuriroginafagagahefilamac" wide //weight: 1
        $x_1_5 = "redaturuyeroreridosepobeyib" wide //weight: 1
        $x_1_6 = "pijoxudujocewapozafuhanam" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_RedLine_RDEC_2147896944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDEC!MTB"
        threat_id = "2147896944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KJGhyuxGAUIsaiuld" ascii //weight: 1
        $x_1_2 = "xbyuidgAYU7uikj" ascii //weight: 1
        $x_1_3 = "AppLaunch.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDED_2147897026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDED!MTB"
        threat_id = "2147897026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c1 e8 18 43 33 c6 69 c8 91 e9 d1 5b 33 e9 8b 4c 24 20 3b df}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_SPGQ_2147897423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.SPGQ!MTB"
        threat_id = "2147897423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hixozoxakukoluro powucavus" wide //weight: 1
        $x_1_2 = "fazenoyod mohohoyogadozu" wide //weight: 1
        $x_1_3 = "xomozowi rahirizazuwujot royivopagesepisoc" wide //weight: 1
        $x_1_4 = "jabanafuhinuzalamojacizadozit tuxuxanudefiran tanesusu hosajivifoyo" wide //weight: 1
        $x_1_5 = "wadejuvufubaguce duhuxetivifijutopawazatu naworabidakinohetisemiyunacus wefaxulegicejavivukozamolopi kun" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDEJ_2147899615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDEJ!MTB"
        threat_id = "2147899615"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 c6 8b 44 24 14 c7 04 24 00 00 00 00 89 e1 51 57 50 56 6a ff ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_SPDF_2147900798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.SPDF!MTB"
        threat_id = "2147900798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kdxhzrcbikmdeifsbbywunlcqnruwurfdispbzmtfasciag" ascii //weight: 1
        $x_1_2 = "pduqsbggirvgtheqjpofvgwhrtwsjtamozxnhuezdsvrj" ascii //weight: 1
        $x_1_3 = "kiskcurkkgxmfmanlrkqfqqrnesraogndtxowjqopaearbvffpmybtvxqkofvkyaxpxenwwppnruidbpmtpeqszfsnygfd" ascii //weight: 1
        $x_1_4 = "wwwlrnmekuqrtsdwwlfxsirgyptgajzdutaprhczylzmujypvsujndgisbidimwqbeoozxaatdbnsydqkakktnsjbtlik" ascii //weight: 1
        $x_1_5 = "rjbartpywgfvdmbwmowckualssabzqksnczmyqvvqbjxietuhowkthezflxebnqtqiimdnospgtqevnhgwvtnouwaozmx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDEN_2147900898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDEN!MTB"
        threat_id = "2147900898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 10 8b 45 0c 8b 45 08 8b 7d 08 8b 75 0c 8b 4d 10 f3 a4 89 45 f4 8b 45 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_SPXF_2147902376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.SPXF!MTB"
        threat_id = "2147902376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 ff 2d 75 0e 6a 00 6a 00 ff d5 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDES_2147908000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDES!MTB"
        threat_id = "2147908000"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 f1 73 80 e9 6c 80 f1 74 80 c1 4e 80 f1 70 80 e9 65 80 f1 22 80 e9 73 80 f1 2a 88 88}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_MAZ_2147914502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.MAZ!MTB"
        threat_id = "2147914502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5c 24 2c 8b 54 24 38 8b 0c b7 0f b6 04 33 30 04 11 8b 4c 24 ?? 83 f9 ?? 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_DDA_2147916779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.DDA!MTB"
        threat_id = "2147916779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 37 34 ac 2c 65 34 22 2c 73 68 ?? ?? ?? ?? 88 04 37 e8 ?? ?? ?? ?? 30 04 37 83 c4 1c 46 3b 75 18 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDFJ_2147924162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDFJ!MTB"
        threat_id = "2147924162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 54 24 48 8a 44 04 4c 30 04 0a 41 89 4c 24 3c 3b 0e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_EZ_2147925123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.EZ!MTB"
        threat_id = "2147925123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f6 d4 08 ca f6 d0 80 e4 3c 08 ec 30 d4 08 e0 88 04 37 b8 [0-4] 3d [0-4] 0f 8e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLine_RDFM_2147933846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLine.RDFM!MTB"
        threat_id = "2147933846"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {46 8a 44 34 60 88 44 3c 60 88 4c 34 60 0f b6 44 3c 60 03 c2 89 74 24 38 0f b6 c8 89 4c 24 3c 84 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

