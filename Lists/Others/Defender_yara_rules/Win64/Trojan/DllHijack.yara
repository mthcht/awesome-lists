rule Trojan_Win64_DllHijack_DA_2147845629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.DA!MTB"
        threat_id = "2147845629"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 01 48 8d 49 01 04 4b ff c2 34 3f 2c 4b 88 41 ff 3b 54 24 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_DA_2147845629_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.DA!MTB"
        threat_id = "2147845629"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b 45 08 48 8d 50 f0 48 39 ca 76 ?? 48 89 c8 31 d2 4c 8b 4c 24 40 48 f7 74 24 48 49 8b 45 00 41 8a 14 11 32 54 08 10 89 c8 41 0f af c0 31 c2 88 14 0b 48 ff c1 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_AG_2147913606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.AG!MTB"
        threat_id = "2147913606"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f b6 08 0f b6 45 f7 48 8b 55 10 48 98 0f b6 54 02 02 4c 8b 45 ?? 48 8b 45 f8 4c 01 c0 31 ca 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 ?? 0f}  //weight: 4, accuracy: Low
        $x_1_2 = {b9 e8 03 00 00 48 8b 05 b1 50 01 00 ff d0 8b 05 ?? ?? ?? 00 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_GZT_2147922425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.GZT!MTB"
        threat_id = "2147922425"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4f b7 44 86 df 14 a2 5a 6a aa 00 2f 5b 33 f4 20 d1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_GZT_2147922425_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.GZT!MTB"
        threat_id = "2147922425"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5b 5d 9c 31 66 ab b6 2a 8b 64 ac 4a}  //weight: 5, accuracy: High
        $x_5_2 = {b0 02 6b 28 d4 2a 0e 31 d0}  //weight: 5, accuracy: High
        $x_1_3 = "eqf.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_ADH_2147924704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.ADH!MTB"
        threat_id = "2147924704"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d3 2a 45 3c 13 ab 65 ad 1b e3 0d a4 c3 ab ed 34 0b 43 35 2d 33 3a ad}  //weight: 5, accuracy: High
        $x_3_2 = {66 44 1b d7 4c 33 c7 45 8d 80 ?? ?? ?? ?? 45 0f b6 da 4a 8d 3c d5 ?? ?? ?? ?? 49 d1 f0 66 41 81 ea 87 39 66 41 c1 fa 24 41 0f 97 c2}  //weight: 3, accuracy: Low
        $x_2_3 = {51 41 53 f6 d3 8b 9c 1c ?? ?? ?? ?? 41 81 e0 11 b0 1b 67 81 f3 9a 5f 94 82 48 c1 cf a8 d1 c3 42 8d 9c 03 ?? ?? ?? ?? 41 87 fa 44 32 c7 41 50 f7 d3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_MKV_2147924865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.MKV!MTB"
        threat_id = "2147924865"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 d0 99 f7 f9 48 63 d2 0f b6 84 14 ?? ?? ?? ?? 42 32 04 07 42 88 44 05 00 49 83 c0 01 4c 39 c6 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_MKV_2147924865_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.MKV!MTB"
        threat_id = "2147924865"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 8b c0 4f 8d 44 c7 10 44 8b c8 46 0f b6 4c 0f ?? 44 8b d1 41 c1 fa 1f 41 83 e2 07 44 03 d1 41 83 e2 f8 41 2b ca c1 e1 03 49 d3 e1 4d 31 08 ff c0 3b d0 7f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_AMC_2147930142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.AMC!MTB"
        threat_id = "2147930142"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 8b 44 24 20 4c 8d 4c 24 20 ba 01 00 00 00 48 8b cf ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_ASJ_2147932688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.ASJ!MTB"
        threat_id = "2147932688"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 f7 f1 48 8b c2 0f b6 44 04 ?? 8b 4c 24 ?? 33 c8 8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_CCJU_2147935877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.CCJU!MTB"
        threat_id = "2147935877"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CreateBackdoor" ascii //weight: 2
        $x_2_2 = "QueryDeviceInformation" ascii //weight: 2
        $x_1_3 = "bindShell" ascii //weight: 1
        $x_1_4 = "rundll32 windowscoredeviceinfo.dll,CreateBackdoor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_BS_2147935906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.BS!MTB"
        threat_id = "2147935906"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 c3 0f b6 45 f8 ba 0e 00 00 00 89 c1 e8 ?? ?? ff ff 31 d8 48 8b 4d 20 8b 55 fc 48 63 d2 88 44 91 03 83 45 fc 01 83 7d fc 03 0f 8e}  //weight: 2, accuracy: Low
        $x_2_2 = {0f b6 45 ff 48 8b 55 10 48 01 d0 44 0f b6 00 0f b6 45 ff 48 8b 55 18 48 01 d0 0f b6 08 0f b6 45 ff 48 8b 55 10 48 01 c2 44 89 c0 31 c8 88 02 80 45 ff 01 80 7d ff 0f 76}  //weight: 2, accuracy: High
        $x_1_3 = "PrintUIEntryW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_ADL_2147939353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.ADL!MTB"
        threat_id = "2147939353"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 44 24 48 48 8d 84 24 80 00 00 00 48 89 44 24 40 48 89 74 24 38 48 89 74 24 30 c7 44 24 28 04 00 00 00 89 74 24 20 45 33 c9 45 33 c0 49 8b d6 33 c9}  //weight: 2, accuracy: High
        $x_3_2 = {8d 56 01 b9 ff ff 1f 00 ff 15 ?? ?? ?? ?? 48 8b f8 48 89 44 24 50 45 8b f4 c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 45 8b c4 33 d2 48 8b c8}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_BY_2147939768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.BY!MTB"
        threat_id = "2147939768"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {42 0f b6 0c 08 03 d1 81 e2 ff 00 00 80 7d 0a ff ca 81 ca 00 ff ff ff ff c2 48 63 c2 49 ff c2 42 0f b6 0c 08 41 30 4a ff 49 ff c8 0f 85}  //weight: 4, accuracy: High
        $x_1_2 = {0f b6 d1 43 0f b6 0c 0b 42 0f b6 04 0a 43 88 04 0b 42 88 0c 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_C_2147946500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.C!MTB"
        threat_id = "2147946500"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 8b 08 44 8b 0d ?? ?? ?? ?? 48 03 cf eb ?? 41 0f b7 4c 55 00 48 8b 85 ?? ?? ?? ?? 8b 04 88 48 03 c7 eb ?? 0f b6 c0 48 ff c1 46 8d 0c 48}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_KK_2147951029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.KK!MTB"
        threat_id = "2147951029"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b d1 4c 8d 44 17 10 0f b6 54 10 10 41 30 10 ff c1 44 3b f1 7f ea}  //weight: 20, accuracy: High
        $x_10_2 = {8b c6 48 0f af c8 48 c1 e9 ?? 6b c9 ?? 44 8b f6 44 2b f1 41 83 fe}  //weight: 10, accuracy: Low
        $x_10_3 = {8b c7 48 0f af c8 48 c1 e9 ?? 6b c9 ?? 44 8b f7 44 2b f1 41 83 fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_DllHijack_GVB_2147951939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.GVB!MTB"
        threat_id = "2147951939"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 89 c2 83 c2 01 0f b6 ca 0f b6 44 0c 20 48 89 ca 44 8d 04 38 45 0f b6 c0 46 0f b6 4c 04 20 4c 89 c7 44 88 4c 0c 20 42 88 44 04 20 02 44 0c 20 0f b6 c0 0f b6 44 04 20 42 32 04 16 4d 39 da 42 88 04 13 49 8d 42 01 75 b7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_GXT_2147954927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.GXT!MTB"
        threat_id = "2147954927"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 d0 89 85 ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? 89 c1 d3 e2 89 d0 66 89 85 ?? ?? ?? ?? 83 85 ?? ?? ?? ?? 01 0f b6 85 ?? ?? ?? ?? 39 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_AHB_2147955080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.AHB!MTB"
        threat_id = "2147955080"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 8b 06 48 8b 4e ?? 42 0f b7 04 68 8b 04 81 49 01 c6 4c 89 f7 48 89 f8}  //weight: 20, accuracy: Low
        $x_30_2 = {ff c2 80 3c 11 00 75 ?? 85 d2 74 ?? 48 63 d2 45 31 c0 46 0f b6 0c 01 41 8d 04 41 49 ff c0 4c 39 c2 75}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_GVC_2147956826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.GVC!MTB"
        threat_id = "2147956826"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 00 8b c0 48 8b 4d f8 48 c1 e1 05 48 8b 55 f8 48 c1 ea 02 48 33 ca 48 33 c1 48 89 45 f8 8b 45 f4 ff c0 89 45 f4 8b 45 f4 3b 45 28 0f 9c c0 0f b6 c0 89 45 f0 83 7d f0 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_HR_2147957784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.HR!MTB"
        threat_id = "2147957784"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8b e0 65 48 8b 04 25 60 00 00 00 4c 8b 78 18 49 83 c7 20 4d 8b 37 4d 3b f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_GDX_2147958563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.GDX!MTB"
        threat_id = "2147958563"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 d2 48 8d 05 ?? ?? ?? ?? 31 c9 49 39 d7 ?? ?? 44 8a 04 01 45 32 04 16 41 c0 c0 04 45 88 04 16 48 ff c2 ff c1 83 e1 0f}  //weight: 5, accuracy: Low
        $x_5_2 = {6a 40 41 59 31 c9 4c 89 fa 41 b8 00 30 00 00 ff 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllHijack_AB_2147959073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllHijack.AB!MTB"
        threat_id = "2147959073"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 20 48 8b 4c 24 60 0f be 04 01 89 44 24 28 33 d2 8b 44 24 20 b9 08 00 00 00 f7 f1 8b c2 8b c0 8b 4c 24 28 33 4c 84 30 8b c1 8b 4c 24 20 48 8b 54 24 68 88 04 0a eb b2}  //weight: 1, accuracy: High
        $x_1_2 = "genericloader.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

