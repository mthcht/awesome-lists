rule Ransom_Win32_TeslaCrypt_MK_2147811340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TeslaCrypt.MK!MTB"
        threat_id = "2147811340"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 84 24 34 01 00 00 35 [0-2] 00 00 8b 8c 24 14 01 00 00 c6 84 24 47 01 00 00 f3 8b 94 24 38 01 00 00 8b b4 24 3c 01 00 00 81 c2 c1 89 ff ff 83 d6 ff 89 94 24 38 01 00 00 89 b4 24 3c 01 00 00 39 c1 73 40 8b 84 24 14 01 00 00 c6 84 24 47 01 00 00 53 8b 8c 24 14 01 00 00 8a 94 04 1b 01 00 00 88 54 0c 14 8b 84 24 34 01 00 00 35 [0-2] 00 00 03 84 24 14 01 00 00 89 84 24 14 01 00 00 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_TeslaCrypt_PA_2147829675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TeslaCrypt.PA!MTB"
        threat_id = "2147829675"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "All of your files were protected by a strong encryption with RSA-2048" ascii //weight: 1
        $x_1_2 = "shadows /all /Quiet" ascii //weight: 1
        $x_1_3 = "%s\\restore_files_%s.html" wide //weight: 1
        $x_1_4 = {64 6a 64 6b 64 75 65 70 36 32 6b 7a 34 6e 7a 78 2e [0-32] 2f 69 6e 73 74 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_TeslaCrypt_RJ_2147850573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TeslaCrypt.RJ!MTB"
        threat_id = "2147850573"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 19 00 00 00 2b cb 69 c9 8a 00 00 00 b8 1f 85 eb 51 f7 e1 8b f2 c1 ee 05 46 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_TeslaCrypt_GZZ_2147905381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TeslaCrypt.GZZ!MTB"
        threat_id = "2147905381"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4c 24 7c 81 f1 5c 4b 00 00 03 4c 24 50 89 4c 24 50 2b 44 24 7c 39 44 24 50 ?? ?? 8a 44 24 34 0c 7e 88 84 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_TeslaCrypt_GZZ_2147905381_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TeslaCrypt.GZZ!MTB"
        threat_id = "2147905381"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 c7 89 f8 88 c1 8b 44 24 ?? 8b 7c 24 ?? 88 4c 24 ?? 29 c2 19 fe 89 54 24 ?? 89 74 24 ?? ?? ?? ?? ?? 8b 44 24 64 8a 4c 24 2f 88 08 e9 ?? ?? ?? ?? 8b 44 24 ?? 8b 4c 24 68 81 f1 0e 1c 00 00 39 c8 0f 87}  //weight: 10, accuracy: Low
        $x_1_2 = "Clwoo9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_TeslaCrypt_AA_2147907232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TeslaCrypt.AA!MTB"
        threat_id = "2147907232"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 8b 44 24 ?? c7 44 24 ?? ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? 66 35 ?? ?? 66 89 44 24 ?? 66 8b 44 24 ?? 66 35 ?? ?? 8b 4c 24 ?? 66 8b 54 24 ?? 89 4c 24 ?? 66 39 c2 77 ?? e9 ?? ?? ?? ?? b8 ?? ?? ?? ?? 8b 4c 24 ?? 0f be 4c 0c ?? 8b 54 24 ?? 8a 5c 24 ?? 2a 5c 24 ?? 29 d0 31 c1 88 cf 88 5c 24 ?? 8b 44 24 ?? 88 7c 04 ?? e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_TeslaCrypt_CCHW_2147909191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TeslaCrypt.CCHW!MTB"
        threat_id = "2147909191"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be 00 8b 4c 24 18 0f be 09 29 c8 83 f8 00 0f 95 c2 80 f2 ff 80 e2 01 88 54 24 27}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_TeslaCrypt_NM_2147911280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TeslaCrypt.NM!MTB"
        threat_id = "2147911280"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {38 ea 89 44 24 ?? 88 4c 24 2f 0f 87 ?? ?? ?? ?? e9 a6 00 00 00 8b 44 24}  //weight: 3, accuracy: Low
        $x_3_2 = {58 89 44 24 ?? e9 f6 00 00 00 8a 84 24 ?? ?? ?? ?? 34 b6 8b 4c 24 4c 8a 54 24 ?? 83 c1 01 89}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_TeslaCrypt_ARA_2147913777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TeslaCrypt.ARA!MTB"
        threat_id = "2147913777"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 57 04 02 d1 30 14 30 8b 0d ?? ?? ?? ?? 8a 49 02 0f b6 d1 40 81 c2 ?? ?? ?? ?? 3b c2 76 e1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_TeslaCrypt_MA_2147916153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TeslaCrypt.MA!MTB"
        threat_id = "2147916153"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 d2 be af c4 00 00 29 c6 89 d0 19 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_TeslaCrypt_GW_2147916280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TeslaCrypt.GW!MTB"
        threat_id = "2147916280"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 f1 69 3d 00 00 8b b4 24 d0 00 00 00 81 f6 1d 7e 00 00 8b 7c 24 40 29 f8 89 84 24}  //weight: 2, accuracy: High
        $x_2_2 = {80 c1 08 8b b4 24 d0 00 00 00 81 f6 69 3d 00 00 01 f2 89 54 24 5c 38 c8 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_TeslaCrypt_GPAA_2147916282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TeslaCrypt.GPAA!MTB"
        threat_id = "2147916282"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b 8c 24 ?? ?? ?? ?? 89 44 24 ?? 66 8b 54 24 ?? 66 81 f2 ?? ?? 66 89 94 24 ?? ?? ?? ?? 66 81 f9 ?? ?? 77 ad}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_TeslaCrypt_GPAC_2147916284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TeslaCrypt.GPAC!MTB"
        threat_id = "2147916284"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 54 24 44 33 54 24 44 8b 74 24 1c 89 54 24 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_TeslaCrypt_CCJD_2147916389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TeslaCrypt.CCJD!MTB"
        threat_id = "2147916389"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 38 21 c0 8b 4c 24 3c 21 c9 8b 94 24 e8 00 00 00 81 f2 4c 17 00 00 8b 74 24 54 01 d6 89 8c 24 f8 00 00 00 89 84 24 fc 00 00 00 89 74 24 54 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_TeslaCrypt_GNM_2147929201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TeslaCrypt.GNM!MTB"
        threat_id = "2147929201"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {31 c2 31 f1 09 d1 89 0c 24 0f 85}  //weight: 10, accuracy: High
        $x_1_2 = "Joyhv.pew" ascii //weight: 1
        $x_1_3 = "lohugvb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_TeslaCrypt_ERL_2147941305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TeslaCrypt.ERL!MTB"
        threat_id = "2147941305"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 8b 94 24 ba 00 00 00 8a 5c 24 2f 88 9c 24 b9 00 00 00 66 2b 8c 24 ba 00 00 00 66 29 d0 66 89 84 24 b2 00 00 00 66 39 8c 24 b2 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

