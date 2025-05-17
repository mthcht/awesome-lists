rule Trojan_Win32_XWorm_NWR_2147890114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XWorm.NWR!MTB"
        threat_id = "2147890114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 49 ff ff ff 3b 43 20 75 ?? 33 c0 89 43 20 eb ?? 8b 43 1c e8 b9 67 fa ff 8b d0 8b c6 e8 ?? ?? ?? ?? 89 43 20 83 c3}  //weight: 5, accuracy: Low
        $x_1_2 = "shutdown.exe /f /s /t 0" wide //weight: 1
        $x_1_3 = "StartDDos" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_XWorm_AMAT_2147916822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XWorm.AMAT!MTB"
        threat_id = "2147916822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-30] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-30] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_2_3 = "EXECUTE ( \"A\" & \"sc(Str\" & \"ingM\" & \"id" ascii //weight: 2
        $x_2_4 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 [0-30] 28 00 22 00}  //weight: 2, accuracy: Low
        $x_2_5 = {45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 43 61 6c 6c 28 [0-30] 28 22}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_XWorm_FEM_2147920072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XWorm.FEM!MTB"
        threat_id = "2147920072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 c4 f0 b8 00 10 40 00 e8 01 00 00 00 9a 83 c4 10 8b e5 5d e9 43 c7 36 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_XWorm_PAYR_2147929391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XWorm.PAYR!MTB"
        threat_id = "2147929391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b 55 d8 3b d6 7f 2d 8b 4d e8 8b 59 0c 2b 59 14 8d 0c 13 8b 55 e4 8b 5a 0c 2b 5a 14 8b 55 dc 8a 14 13 30 11 ff 45 dc 39 45 dc 7e 03 89 7d dc ff 45 d8 eb cc}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_XWorm_NW_2147934129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XWorm.NW!MTB"
        threat_id = "2147934129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8d 8c 24 a4 00 00 00 51 ff d6 8b 54 24 4c 8b 32 8d 4c 24 58 83 c6 34 e8 29 f6 ff ff 8b 0e 50 8b 44 24 50 50 ff d1 8b 74 24 58 3b f3 75 0a 68 03 40 00 80 e8 cd 8a 00 00 8d 4c 24 54 e8 04 f6 ff ff 8b 16}  //weight: 3, accuracy: High
        $x_1_2 = "WmiPrvSE.exe" ascii //weight: 1
        $x_1_3 = "5Qiilccol52Xrrthd2.DAEyor4JDA0iewWKE2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_XWorm_AAG_2147935030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XWorm.AAG!MTB"
        threat_id = "2147935030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 0f b6 84 34 ?? ?? ?? ?? 88 84 1c ?? ?? ?? ?? 88 8c 34 ?? ?? ?? ?? 0f b6 84 1c ?? ?? ?? ?? 8b 4c 24 ?? 03 c2 0f b6 c0 89 74 24 ?? 0f b6 84 04 ?? ?? ?? ?? 30 04 0f 47 3b 7c 24 ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_XWorm_BSA_2147938306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XWorm.BSA!MTB"
        threat_id = "2147938306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {56 8b f1 8b 4e 24 85 c9 74 15 8b 11 3b ce 0f 95 c0 0f b6 c0 50 ff 52 10 c7 46 24 00}  //weight: 10, accuracy: High
        $x_5_2 = {8b 45 c0 8d 4d c0 6a 14 68 a8 7b 68 00 ff 10 8b 56 0c 8d 4d c0 e8 39 36 fb ff 8b f8 6a 09 68 9c 7b 68 00 8b 0f 8b 11 8b cf ff d2 8b 56 24}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_XWorm_GVB_2147938658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XWorm.GVB!MTB"
        threat_id = "2147938658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 1c 02 88 1c 01 83 c0 01 83 d6 00 3d d7 08 00 00 89 f7 83 df}  //weight: 2, accuracy: Low
        $x_1_2 = {89 f3 83 e3 07 8a 1c 1c 80 f3 4a 88 1c 32 83 c6 01 83 d7 00 39 ce 89 fb 19 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_XWorm_BAA_2147939311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XWorm.BAA!MTB"
        threat_id = "2147939311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 8b c7 f7 f6 03 cf 47 8a 44 15 ?? 8b 55 ?? 32 04 11 88 01 8b 4d ?? 3b fb 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_XWorm_AHB_2147941647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XWorm.AHB!MTB"
        threat_id = "2147941647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 50 1b 8b 74 24 30 80 f1 e7 80 f2 78 88 4c 24 1e 0f b6 48 1c 88 54 24 1f 0f b6 50 1d 80 f1 98 80 f2 e9 88 4c 24 20 0f b6 48 1e 88 54 24 21 0f b6 50 1f}  //weight: 10, accuracy: High
        $x_5_2 = {50 57 57 ff 15 ?? ?? ?? 00 85 c0 74 0c c7 05 ?? ?? ?? 00 01 00 00 00 eb 15 ff 15 ?? ?? ?? 00 83 f8 78 75 0a c7 05 ?? ?? ?? 00 02 00 00 00}  //weight: 5, accuracy: Low
        $x_5_3 = {0b 0b 0b 83 74 74 74 f8 b9 b9 b9 ff 00 73 e1 ff 00 7f f9 ff 00 7f f9 ff 00 49 f7 ff 00 49 f7 ff 00 49 f7 ff 00 49 f7 ff 00 16 f5 ff 00 16 f5 ff 00 04 f3 ff 00 04 f3 ff 00 04 f3 ff 00 00 f2 ff 00 00 f2 ff 00 00 f2 ff 00 00 f0 ff 00 00 f0 ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

