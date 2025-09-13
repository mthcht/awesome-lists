rule Trojan_Win64_Emotet_RF_2147742888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.RF"
        threat_id = "2147742888"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 89 c1 b8 00 a0 02 00 89 c2 41 b8 00 10 00 00 8b 84 24 a4 00 00 00 35 98 cd 20 38 41 89 c1 4c 8b 54 24 30 41 ff d2 48 89 44 24 68 48 8b 44 24 68 48 c7 84 24 98 00 00 00 00 00 00 00 48 83 f8 00 74 12 e9 2d ff ff ff}  //weight: 1, accuracy: High
        $x_2_2 = {c7 84 24 b4 00 00 00 ee 35 21 5f 8b 44 24 44 88 c1 d3 e0 48 8b 94 24 98 00 00 00 89 84 24 b4 00 00 00 48 89 d0 48 81 c4 c0 00 00 00 5e c3}  //weight: 2, accuracy: High
        $x_1_3 = {b8 81 54 22 73 48 b9 d9 c1 ab 55 fe ff ff ff 48 03 8c 24 b8 00 00 00 48 8b 54 24 68 44 8b 44 24 44 48 89 4c 24 28 44 89 c1 d3 e8 89 84 24 b4 00 00 00 48 89 d1 48 8b 54 24 50 e8 15 04 00 00 48 8b 4c 24 68 48 8b 54 24 68 4c 8b 4c 24 28 4c 01 c9 4c 8b 4c 24 58 49 89 91 a0 00 00 00 49 89 89 a8 00 00 00 48 8b 4c 24 38 48 31 c9 48 89 8c 24 a8 00 00 00 48 8b 4c 24 68 48 81 c1 56 26 00 00 48 89 8c 24 98 00 00 00 eb 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Emotet_PDA_2147758754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PDA!MTB"
        threat_id = "2147758754"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 4e 00 00 00 33 c9 41 b9 13 03 00 00 41 b8 dd 03 00 00 ff 15 ?? ?? ?? ?? 33 d2 48 8b c7 49 f7 f4 48 83 c7 01 0f b6 44 55 00 30 44 37 ff 48 3b fb 75}  //weight: 1, accuracy: Low
        $x_1_2 = "CsWxf89ocsSE5dSfRtqLeF2uKJ1YedjLt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_RTA_2147812227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.RTA!MTB"
        threat_id = "2147812227"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ilahmnpokpozoqlzp" ascii //weight: 1
        $x_1_2 = "hgrclqgdvddpjh" ascii //weight: 1
        $x_1_3 = "nmgohwoswwfmwam" ascii //weight: 1
        $x_1_4 = "svrmukezulntgava" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_AF_2147817211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.AF!MTB"
        threat_id = "2147817211"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {8b 0e 49 ff c3 48 8d 76 ?? 33 cd 0f b6 c1 66 41 89 00 0f b7 c1 c1 e9 10 66 c1 e8 08 4d 8d 40 ?? 66 41 89 40 ?? 0f b6 c1 66 c1 e9 ?? 66 41 89 40 ?? 66 41 89 48 ?? 4d 3b ?? 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PBF_2147817222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PBF!MTB"
        threat_id = "2147817222"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 8b c1 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 14 24 2b d1 8b ca 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 ca [0-96] 48 63 c9 48 8b 54 24 28 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PBF_2147817222_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PBF!MTB"
        threat_id = "2147817222"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ef ff c7 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 48 8d 0d [0-4] 8a 04 08 42 32 04 36 41 88 06 49 ff c6 3b fd 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ZZ_2147817265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ZZ"
        threat_id = "2147817265"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {8b cb 41 8b d0 d3 e2 41 8b cb d3 e0 03 d0 41 0f be ?? 03 d0 41 2b d0 49 ff ?? (44 8b c2|45 8a ?? 44)}  //weight: 10, accuracy: Low
        $x_10_3 = {41 8b c0 45 84 ?? 75 d8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PBG_2147817819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PBG!MTB"
        threat_id = "2147817819"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e6 8b c6 8b ce 2b c2 ff c6 d1 ?? 03 c2 c1 e8 ?? 6b c0 ?? 2b c8 48 63 c1 42 0f b6 04 10 43 32 44 07 ?? 41 88 40 ?? 41 3b f4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PBG_2147817819_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PBG!MTB"
        threat_id = "2147817819"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 03 c1 48 63 0d ?? ?? ?? ?? 48 03 c1 48 63 0d ?? ?? ?? ?? 48 03 4c 24 ?? 0f b6 04 01 03 44 24 ?? 8b 4c 24 ?? 33 c8 8b c1 8b 0d ?? ?? ?? ?? 8b 14 24 2b d1 8b ca}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_MFP_2147818089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.MFP!MTB"
        threat_id = "2147818089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 98 48 01 d0 48 c1 e0 06 48 89 c2 48 8b 85 38 01 00 00 48 01 d0 48 89 85 b0 00 00 00 48 8b 85 b0 00 00 00 8b 40 3c 48 63 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_AN_2147818535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.AN!MTB"
        threat_id = "2147818535"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {0f b6 5c 1c 20 32 5c 17 ff 88 5c 38 ff 48 81 ff 35 0b 00 00 74 16 89 f9 83 e1 0f 0f b6 4c 0c 20 32 0c 17 88 0c 38}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_AK_2147818552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.AK!MTB"
        threat_id = "2147818552"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {0f b6 04 01 8b 4c 24 48 33 c8 8b c1 8b 4c 24 24 8b 54 24 20 2b d1 8b ca 03 4c 24 24 48 63 c9 48 8b 54 24 30 88 04 0a}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_AK_2147818552_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.AK!MTB"
        threat_id = "2147818552"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {0f b6 04 01 8b 8c 24 fc 00 00 00 33 c8 8b c1 8b 4c 24 34 8b 54 24 30 2b d1 8b ca 03 4c 24 34 48 63 c9 48 8b 94 24 f0 00 00 00 88 04 0a}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_AK_2147818552_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.AK!MTB"
        threat_id = "2147818552"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {48 8b 44 24 08 48 63 4c 24 04 0f b6 04 08 89 04 24 48 8b 4c 24 20 48 63 44 24 04 31 d2 48 f7 74 24 50 8b 04 24 0f b6 0c 11 31 c8 88 c2 48 8b 44 24 10 48 63 4c 24 04 88 14 08}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_KD_2147818683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.KD!MTB"
        threat_id = "2147818683"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 84 24 f0 81 00 00 0f b6 bc 04 40 76 00 00 8b 84 24 f0 81 00 00 99 b9 ?? ?? ?? ?? f7 f9 48 63 ca 48 8b 05 ?? ?? ?? ?? 0f b6 04 08 8b d7 33 d0 48 63 8c 24 ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 88 14 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_AM_2147818696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.AM!MTB"
        threat_id = "2147818696"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {41 32 4c 32 fd 83 c5 03 88 4e fd 41 8d 48 ff f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 48 98 48 8d 0c 40}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_AM_2147818696_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.AM!MTB"
        threat_id = "2147818696"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {03 d0 8b c3 ff c3 6b d2 ?? 2b c2 48 63 c8 42 8a 04 19 43 32 04 01 41 88 00 49 ff c0 48 83 ef 01 74 09}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_AM_2147818696_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.AM!MTB"
        threat_id = "2147818696"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {8b 84 24 f0 0b 00 00 99 b9 ?? 00 00 00 f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 fc 0b 00 00 33 c8 8b c1}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PBH_2147818754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PBH!MTB"
        threat_id = "2147818754"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b c2 48 98 48 8b [0-6] 0f b6 04 01 8b 4c 24 ?? 33 c8 8b c1 8b 4c 24 ?? 8b 54 24 ?? 2b d1 8b ca 03 4c 24 ?? 48 63 c9 48 8b 54 24 ?? 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PBH_2147818754_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PBH!MTB"
        threat_id = "2147818754"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 03 d1 48 8b ca 48 2b 8c 24 [0-4] 48 03 c1 48 89 44 24 [0-4] 48 8b 8c 24 [0-4] e8}  //weight: 1, accuracy: Low
        $x_1_2 = "HGDFZFsatrw5434grhjgfHFZDr36gh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAH_2147818777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAH!MTB"
        threat_id = "2147818777"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 4c 24 48 33 c8 8b c1 8b 4c 24 24 8b 54 24 20 2b d1 8b ca 03 4c 24 24 48 63 c9 48 8b 54 24 40 88 04 0a eb 94 48 8d 0d ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAH_2147818777_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAH!MTB"
        threat_id = "2147818777"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 f7 ea c1 fa 02 89 c8 c1 f8 1f 29 c2 89 d0 c1 e0 03 01 d0 01 c0 29 c1 89 ca 48 63 c2 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 ?? ?? ?? ?? 01 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BA_2147818857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BA!MTB"
        threat_id = "2147818857"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb 48 8d 7f ?? f7 eb [0-4] ff c3 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 8b 05 ?? ?? ?? ?? 48 63 d1 0f b6 0c 02 32 4c 3e ?? 88 4f ?? 49 ff cf 75}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 ef c1 fa ?? 83 c7 ?? 8b c2 c1 e8 ?? 03 d0 48 8b 05 ?? ?? ?? ?? 48 63 d2 48 6b d2 ?? 48 03 d0 41 8a 04 10 41 32 04 34 88 06}  //weight: 1, accuracy: Low
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Emotet_BC_2147818873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BC!MTB"
        threat_id = "2147818873"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 f7 e7 48 c1 ea [0-21] 4c 89 f1 4c 89 e2 e8 ?? ?? ?? ?? 48 89 c1 e8 ?? ?? ?? ?? 48 [0-15] 42 32 04 2f 88 04 3e 48 83 c7 01 48 81 ff ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAI_2147818889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAI!MTB"
        threat_id = "2147818889"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 44 8b 45 ?? 41 f7 f8 4c 63 ca 42 0f b6 14 09 44 8b 55 ?? 41 31 d2 45 88 d3 48 8b 8d ?? ?? ?? ?? 4c 63 8d ?? ?? ?? ?? 46 88 1c 09 8b 85 ?? ?? ?? ?? 83 c0 01 89 85 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAI_2147818889_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAI!MTB"
        threat_id = "2147818889"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 43 08 21 84 8b cb 48 8d 7f 01 f7 eb 03 d3 ff c3 c1 fa 05 8b c2 c1 e8 1f 03 d0 6b c2 3e 2b c8 48 8b 05 ?? ?? ?? ?? 48 63 d1 0f b6 0c 02 32 4c 3e ff 88 4f ff 49 ff cf 75 b9 48 8d 0d 42 8e 02}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 89 88 88 88 f7 ef 03 d7 c1 fa 05 8b c2 c1 e8 1f 03 d0 8b c7 ff c7 6b d2 3c 2b c2 48 63 c8 42 8a 04 09 43 32 04 02 41 88 00 49 ff c0 48 ff ce 74 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_PAJ_2147818917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAJ!MTB"
        threat_id = "2147818917"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d2 31 c9 41 [0-4] 89 d8 99 f7 ff 48 8b 05 ?? ?? ?? ?? 48 63 d2 8a 14 10 32 14 1e 88 54 1d 00 48 ff c3 48 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAJ_2147818917_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAJ!MTB"
        threat_id = "2147818917"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 36 00 00 00 f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 fc 00 00 00 33 c8 8b c1 8b 4c 24 34 8b 54 24 30 2b d1 8b ca 03 4c 24 34 48 63 c9 48 8b 94 24 f0 00 00 00 88 04 0a e9 60 ff ff ff 48 8d 0d a4 e6 02 00 ff 94 24 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BD_2147818947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BD!MTB"
        threat_id = "2147818947"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 04 1f 42 32 04 27 41 88 44 3d 00 48 ff c7 48 81 ff ?? ?? ?? ?? 0f 85 5d ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BD_2147818947_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BD!MTB"
        threat_id = "2147818947"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 48 63 4c 24 ?? 48 8b 94 24 ?? ?? ?? ?? 88 04 0a e9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 8b 05 ?? ?? ?? ?? 48 63 d1 0f b6 0c 02 32 4c 2b ff 88 4b ff 48 83 ee 01 75}  //weight: 1, accuracy: Low
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Emotet_BE_2147818948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BE!MTB"
        threat_id = "2147818948"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e8 ?? 03 d0 8b c3 ff c3 6b d2 ?? 2b c2 48 63 d0 48 8b 05 ?? ?? ?? ?? 8a 14 02 41 32 [0-4] 88 17 48 ff c7 49 [0-4] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {ff c8 83 c8 ?? ff c0 48 63 d0 48 8b 05 ?? ?? ?? ?? ff c6 8a 14 02 41 32 14 1e 88 13 48 ff c3 49 ff cd 75}  //weight: 1, accuracy: Low
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Emotet_BE_2147818948_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BE!MTB"
        threat_id = "2147818948"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 32 4c 11 ?? b8 ?? ?? ?? ?? 41 88 4a ?? 41 8d 48 ?? f7 e9 8b cf c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 8b 05 ?? ?? ?? ?? ff c1 48 63 c9 0f b6 0c 01 b8 bf 3c b6 22 42 32 4c 16 ?? 41 88 4a}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 f9 48 63 ca 48 8b 05 ?? ?? ?? ?? 0f b6 04 08 41 8b d0 33 d0 8b 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 03 c1 2b 44 24 ?? 2b 44 24 ?? 03 44 24 ?? 48 63 c8 48 8b 84 24 ?? ?? ?? ?? 88 14 08 e9}  //weight: 1, accuracy: Low
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Emotet_PAK_2147818976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAK!MTB"
        threat_id = "2147818976"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ef 03 d7 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 0f b6 0c 00 44 8d 47 02 43 32 4c 11 fb b8 ?? ?? ?? ?? 41 88 4a fb 41 8d 48 ff f7 e9 03 d1 8b cf c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 1c 2b c8 48 8b 05 ?? ?? ?? ?? ff c1 48 63 c9 0f b6 0c 01 b8 93 24 49 92 42 32 4c 16 fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAK_2147818976_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAK!MTB"
        threat_id = "2147818976"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 f7 ea c1 fa 03 89 c8 c1 f8 1f 29 c2 89 d0 01 c0 01 d0 c1 e0 04 89 ca 29 c2 48 63 c2 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 0f 9c c0 84 c0 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c8 f7 ea d1 fa 89 c8 c1 f8 1f 89 d3 29 c3 89 d8 6b c0 37 89 ce 29 c6 89 f0 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 0f 9c c0 84 c0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_AH_2147818981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.AH!MTB"
        threat_id = "2147818981"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {42 32 4c 16 fb 41 88 4a fc 8b cf 41 f7 e8 83 c7 03 41 03 d0 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 1c 2b c8}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_AG_2147818994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.AG!MTB"
        threat_id = "2147818994"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b cb f7 eb ff c3 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 35 2b c8 48 63 c1 42 8a 0c 08 43 32 0c 02 41 88 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_AG_2147818994_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.AG!MTB"
        threat_id = "2147818994"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b cf f7 ef ff c7 d1 fa 8b c2 c1 e8 1f 03 d0 6b c2 37 2b c8 48 8b 05 ?? ?? ?? ?? 48 63 d1 0f b6 0c 02 41 32 0c 36 88 0e}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_SH_2147819001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.SH!MTB"
        threat_id = "2147819001"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 d1 0f b6 0c 02 41 32 0c 36 88 0e}  //weight: 1, accuracy: High
        $x_1_2 = {41 b9 00 30 00 00 48 8b c8 89 7c 24 28 4c 8b c5 89 5c 24 20 33 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_MA_2147819012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.MA!MTB"
        threat_id = "2147819012"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 f9 8b c2 48 98 48 6b c0 01 48 8b 0d ?? ?? ?? ?? 48 03 c8 48 8b c1 0f b6 00 8b 4c 24 ?? 33 c8 8b c1 48 63 4c 24 ?? 48 6b c9 01 48 8b 54 24 ?? 48 03 d1 48 8b ca 88 01}  //weight: 5, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PBI_2147819016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PBI!MTB"
        threat_id = "2147819016"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SC.EXE" wide //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PBI_2147819016_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PBI!MTB"
        threat_id = "2147819016"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 03 c8 48 8b c1 0f b6 00 8b 4c 24 ?? 33 c8 8b c1 48 63 4c 24 ?? 48 6b c9 01 48 8b 54 24 ?? 48 03 d1 48 8b ca 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PBJ_2147819058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PBJ!MTB"
        threat_id = "2147819058"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 eb 03 d3 c1 fa 05 8b c2 c1 e8 1f 03 d0 8b c3 6b d2 ?? 2b c2 48 [0-8] 48 63 c8 48 [0-8] 0f b6 0c 01 41 32 0c 3c 88 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_MB_2147819091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.MB!MTB"
        threat_id = "2147819091"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 eb c1 fa ?? 8b c2 c1 e8 1f 03 d0 8b c3 6b d2 ?? 2b c2 48 8d 15 ?? ?? ?? ?? 48 63 c8 48 8b 05 44 fd 04 00 8a 0c 01 41 32 0c 3e 88 0f}  //weight: 5, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_DA_2147819092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.DA!MTB"
        threat_id = "2147819092"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 f9 8b c2 48 98 48 8b 0d [0-4] 0f b6 04 01 8b 8c 24 [0-4] 33 c8 8b c1 48 63 8c 24 [0-4] 48 8b 94 24 [0-4] 88 04 0a e9}  //weight: 5, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_SHN_2147819095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.SHN!MTB"
        threat_id = "2147819095"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d 15 66 ?? ?? ?? 48 63 c8 48 8b 05 ?? ?? ?? ?? 8a 0c 01 41 32 0c 3e 88 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_LDR_2147819096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.LDR!MTB"
        threat_id = "2147819096"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 f7 75 10 49 8b 45 08 45 03 ca 8a 0c 02 42 32 0c 03 41 88 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_MC_2147819110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.MC!MTB"
        threat_id = "2147819110"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 eb 03 d3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c3 ff c3 6b d2 ?? 2b c2 48 63 d0 48 8b 05 ?? ?? ?? ?? 8a 14 02 41 32 14 3c 88 17}  //weight: 5, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAA_2147819184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAA!MTB"
        threat_id = "2147819184"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 fa 04 8b c2 c1 e8 1f 03 d0 8b c6 83 c6 03 6b d2 26 2b c2 83 c0 02 48 63 c8 48 8b [0-6] 0f b6 0c 01 41 32 4c 3b ?? 49 ff cc 88 4f ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAL_2147819246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAL!MTB"
        threat_id = "2147819246"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 e0 41 ?? ed 44 [0-8] c1 fa ?? 29 c2 b8 ?? ?? ?? ?? 0f af d0 48 8b 05 ?? ?? ?? ?? 41 29 d4 4d 63 e4 42 0f b6 04 20 32 04 2b 88 04 2e 48 83 c5 01 48 81 fd ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAL_2147819246_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAL!MTB"
        threat_id = "2147819246"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ef c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 8b cf 2b c8 48 63 d1 48 8b 0d ?? ?? ?? ?? 0f b6 14 0a 43 32 54 3d 00 41 88 17 ff c7 49 ff c7 49 ff cc}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 ee c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c6 ff c6 6b d2 ?? 2b c2 48 63 d0 48 8b 05 ?? ?? ?? ?? 8a 14 02 41 32 54 1d 00 88 13 48 ff c3 48 83 ef 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_PAB_2147819297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAB!MTB"
        threat_id = "2147819297"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 ea 41 2b d2 41 83 c2 ?? c1 fa ?? 8b c2 c1 e8 ?? 03 c2 48 98 48 6b c0 ?? 49 03 c0 0f b6 0c 01 43 32 4c 19 ?? 48 83 ee 01 41 88 4b ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAM_2147819346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAM!MTB"
        threat_id = "2147819346"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c2 c1 fa ?? c1 ea ?? 01 d0 83 e0 ?? 29 d0 48 98 4c 01 c8 0f b6 00 44 31 c0 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAM_2147819346_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAM!MTB"
        threat_id = "2147819346"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 eb c1 fa ?? 8b c2 c1 e8 1f 03 d0 8b c3 ff c3 8d 0c ?? c1 e1 ?? 2b c1 48 63 c8 42 8a 04 19 43 32 04 01 41 88 00 49 ff c0 48 83 ef 01 74}  //weight: 1, accuracy: Low
        $x_1_2 = {41 f7 ea c1 fa ?? 8b c2 c1 e8 ?? 03 c2 48 98 48 8d 14 80 49 63 c2 41 83 c2 ?? 48 03 c8 0f b6 04 d1 43 32 44 08 ff 48 83 ee ?? 41 88 41 ff 74 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_PAO_2147819428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAO!MTB"
        threat_id = "2147819428"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 03 d0 8b cb c1 fa 05 83 c3 03 8b c2 c1 e8 1f 03 d0 6b c2 38 2b c8 48 8b 05 ?? ?? ?? ?? 83 c1 02 48 63 c9 0f b6 0c 01 42 32 4c 0e ?? 41 88 49 ?? 49 ff ca 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAO_2147819428_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAO!MTB"
        threat_id = "2147819428"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ed 2b d5 83 c5 ?? c1 fa ?? 8b c2 c1 e8 ?? 03 c2 48 98 48 6b c0 ?? 49 03 c1 0f b6 04 08 41 8d 48 ff 41 32 44 32 fd 88 46 fd b8 ?? ?? ?? ?? f7 e9 2b d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAC_2147819458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAC!MTB"
        threat_id = "2147819458"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c7 03 d8 8b 44 24 ?? 83 c0 02 0f af c1 2b d8 a1 ?? ?? ?? ?? 8b d0 0f af d0 8b 44 24 ?? 2b da 03 de 2b 1d ?? ?? ?? ?? 8a 0c 2b 30 08 ff 44 24 ?? 8b 44 24 ?? 3b 44 24 ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {40 0f af c3 0f af c3 2b c1 8d 44 46 ?? 0f af c7 8d 0c 6a 8a 14 08 8b 44 24 ?? 8a 18 8b 4c 24 ?? 32 da 88 18 8b 44 24 ?? 40 3b c1 89 44 24 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_N_2147819657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.N!MTB"
        threat_id = "2147819657"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f7 ee c1 fa 03 8b c2 c1 e8 1f 03 d0 8b c6 ff c6 8d 0c d2 c1 e1 02 2b c1 48 63 c8 42 8a 04 09 43 32 04 02 41 88 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAD_2147819729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAD!MTB"
        threat_id = "2147819729"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb f7 eb ff c3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 8a 0c ?? 43 32 0c ?? 41 88 0b 49 ff c3 49 83 ee ?? 74 [0-4] 4c 8b [0-6] eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAP_2147819776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAP!MTB"
        threat_id = "2147819776"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d7 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 1d 8b cf 2b c8 48 63 d1 48 8b 05 ?? ?? ?? ?? 0f b6 0c 02 32 0c 2b 88 0b ff c7 48 8d 5b ?? 48 83 ee ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAP_2147819776_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAP!MTB"
        threat_id = "2147819776"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 eb c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c3 6b d2 ?? 2b c2 48 63 c8 48 8b 05 ?? ?? ?? ?? 8a 0c 01 41 32 0c 3c 88 0f 48 8d 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAG_2147819910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAG!MTB"
        threat_id = "2147819910"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 fa 04 8b c2 c1 e8 1f 03 d0 41 8b c3 41 83 c3 03 6b d2 ?? 2b c2 83 c0 02 48 63 c8 48 8b [0-6] 0f b6 0c 01 42 32 4c 16 ?? 41 88 4a ?? 49 ff ce 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_AL_2147819994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.AL!MTB"
        threat_id = "2147819994"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 04 1f 42 32 04 2f 88 04 3e 48 83 c7 01 48 81 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_RPA_2147820015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.RPA!MTB"
        threat_id = "2147820015"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 0f b6 14 09 44 8b 55 a8 41 31 d2 45 88 d3 48 8b 8d b0 0b 00 00 4c 63 4d fc 46 88 1c 09 8b 45 fc 83 c0 01 89 45 fc e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BF_2147820044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BF!MTB"
        threat_id = "2147820044"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c2 41 83 c3 ?? c1 e8 ?? 03 d0 8d 04 d2 c1 e0 ?? 2b c8 48 8b 05 ?? ?? ?? ?? 83 c1 ?? 48 63 c9 0f b6 0c 01 42 32 4c 16 ?? 41 88 4a ?? 49 ff ce 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EG_2147820089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EG!MTB"
        threat_id = "2147820089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 31 d2 45 88 d3 48 8b 8d ?? 0b 00 00 4c 63 4d ?? 46 88 1c 09 8b 45 ?? 83 c0 01 89 45 ?? e9 ?? ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EM_2147820090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EM!MTB"
        threat_id = "2147820090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 c8 f7 ea d1 fa 89 c8 c1 f8 1f 89 d3 29 c3 89 d8 6b c0 37 89 ce 29 c6 89 f0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EM_2147820090_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EM!MTB"
        threat_id = "2147820090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 29 d1 4d 63 c9 42 0f b6 04 08 32 04 0b 41 88 04 08 48 83 c1 01 4c 39 d9 75 c2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EM_2147820090_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EM!MTB"
        threat_id = "2147820090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 e1 c1 ea 04 89 55 ?? 81 45 ?? ?? ?? ?? ?? 81 75 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c1 65 ?? ?? 81 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EM_2147820090_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EM!MTB"
        threat_id = "2147820090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8b c7 8b cf 2b c2 ff c7 d1 e8 03 c2 c1 e8 05 6b c0 3f 2b c8 48 63 c1 42 0f b6 04 20 41 32 44 2e ff 41 88 46 ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EM_2147820090_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EM!MTB"
        threat_id = "2147820090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 32 44 0c 20 49 2b d2 4a 8d 0c 5d fe ff ff ff 49 0f af d1 49 2b d2 49 03 d3 48 0f af c1 48 03 c7 48 ff c7 48 8d 0c 50 46 88 04 31}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EM_2147820090_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EM!MTB"
        threat_id = "2147820090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 45 b4 44 89 c0 89 55 b0 99 44 8b 45 b4 41 f7 f8 4c 63 ca 42 0f b6 14 09 44 8b 55 b0 41 31 d2 45 88 d3 48 8b 8d d0 0b 00 00 8b 55 18 2b 55 1c 03 55 1c 4c 63 ca 46 88 1c 09}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EM_2147820090_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EM!MTB"
        threat_id = "2147820090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yzkENTmBV" ascii //weight: 1
        $x_1_2 = "zQnFkEsglvSmYtKlkFDTme" ascii //weight: 1
        $x_1_3 = "zdMhYw" ascii //weight: 1
        $x_1_4 = "OutputDebugStringW" ascii //weight: 1
        $x_1_5 = "CreateFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EM_2147820090_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EM!MTB"
        threat_id = "2147820090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vGZlfkkg?U^>+xzU5%Q_>8Sy12PwSDt0McRnq" ascii //weight: 2
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "JucQB2R1psZmtrZw==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BG_2147820164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BG!MTB"
        threat_id = "2147820164"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 6b c0 ?? 29 c1 89 c8 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 [0-6] 83 85 [0-6] 8b 85 [0-6] 3b 85 [0-6] 0f 8c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EF_2147820201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EF!MTB"
        threat_id = "2147820201"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {01 c2 89 c8 29 d0 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EF_2147820201_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EF!MTB"
        threat_id = "2147820201"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {01 d0 29 c1 89 ca 48 63 c2 4c 01 d0 0f b6 00 44 31 c8 41 88 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EK_2147820202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EK!MTB"
        threat_id = "2147820202"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {99 b9 27 00 00 00 f7 f9 48 63 ca 48 8b 05 ?? ?? ?? ?? 0f b6 04 08 41 8b d0 33 d0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EK_2147820202_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EK!MTB"
        threat_id = "2147820202"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 d3 29 c3 89 d8 6b c0 ?? 89 ce 29 c6 89 f0 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EK_2147820202_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EK!MTB"
        threat_id = "2147820202"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 8d 04 40 49 0f af c3 48 03 d0 49 8d 46 02 48 03 c7 48 0f af c6 48 8d 04 40 48 2b d0 48 8b 44 24 28 49 03 d5 49 ff c5 44 88 0c 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EK_2147820202_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EK!MTB"
        threat_id = "2147820202"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 f7 f8 4c 63 ca 4c 8b 55 b0 43 0f b6 14 0a 31 d1 41 88 cb 4c 8b 8d e8 0b 00 00 8b 4d 24 03 4d 28 2b 4d 28 48 63 f1 45 88 1c 31 8b 45 24 83 c0 01 89 45 24}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BH_2147820215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BH!MTB"
        threat_id = "2147820215"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 8d 40 01 f7 e7 8b cf ff c7 c1 ea 05 6b c2 2f 2b c8 48 63 c1 42 0f b6 04 10 43 32 44 07 ff 41 88 40 ff 41 3b fc 72 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BH_2147820215_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BH!MTB"
        threat_id = "2147820215"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 63 c9 0f b6 0c 01 42 32 8c 1c a2 00 00 00 49 83 c3 03 43 88 4c 11 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BH_2147820215_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BH!MTB"
        threat_id = "2147820215"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 63 ca 4c 8b 55 ?? 43 0f b6 14 0a 31 d1 41 88 cb 4c 8b 8d ?? ?? ?? ?? 48 63 75 ?? 45 88 1c 31 8b 45 ?? 83 c0 ?? 89 45 ?? e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BI_2147820241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BI!MTB"
        threat_id = "2147820241"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 0f b6 44 05 ?? 4c 8b 0d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 99 c1 ea ?? 01 d0 83 e0 ?? 29 d0 48 98 4c 01 c8 0f b6 00 44 31 c0 88 01 83 85 [0-5] 8b 85 [0-5] 3b 85 [0-5] 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAN_2147820389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAN!MTB"
        threat_id = "2147820389"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 01 c0 01 d0 c1 e0 ?? 89 ca 29 c2 48 63 c2 4c 01 d0 0f b6 00 44 31 c8 41 88 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ER_2147820459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ER!MTB"
        threat_id = "2147820459"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b c8 48 63 c1 42 0f b6 0c 00 43 32 4c 0b ff 41 88 49 ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ER_2147820459_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ER!MTB"
        threat_id = "2147820459"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {29 d0 89 ca 29 c2 48 63 c2 4c 01 d0 0f b6 00 44 31 c8 41 88 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ER_2147820459_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ER!MTB"
        threat_id = "2147820459"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 04 01 8b 4c 24 3c 33 c8 8b c1 48 63 4c 24 20 48 8b 54 24 50 88 04 0a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ER_2147820459_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ER!MTB"
        threat_id = "2147820459"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "yahavSoduku.txt" ascii //weight: 1
        $x_1_3 = "bTlZc3dSTDJPRzJjIU9" ascii //weight: 1
        $x_1_4 = "QPToIl" ascii //weight: 1
        $x_1_5 = "QnimQsCBkniy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ER_2147820459_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ER!MTB"
        threat_id = "2147820459"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JkDefrag.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "iXjctelCVBIblRazh2d2APwYS2j2M29S" ascii //weight: 1
        $x_1_4 = "XCaoNVhaVetd3Fx9i1oAfZ3jdqrL0cwaqtRAXtMAUgyuHZwersTSCjeXrmRvA4" ascii //weight: 1
        $x_1_5 = "HeapReAlloc" ascii //weight: 1
        $x_1_6 = "DeleteFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BJ_2147820500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BJ!MTB"
        threat_id = "2147820500"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 31 d2 45 88 d3 48 8b 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 2b 95 ?? ?? ?? ?? 4c 63 ca 46 88 1c 09 8b 85 ?? ?? ?? ?? 83 c0 ?? 89 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 83 c0 ?? 89 85 ?? ?? ?? ?? e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ES_2147821026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ES!MTB"
        threat_id = "2147821026"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b cf 2b c8 48 63 c1 42 0f b6 0c ?? 43 32 0c ?? 41 88 ?? ff c7 4d 8d ?? 01 48 83 eb 01 74 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EL_2147821027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EL!MTB"
        threat_id = "2147821027"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4c 8b c8 4c 8d 55 ?? 4c 2b d0 0f 1f 40 00 66 0f 1f 84 00 00 00 00 00 b8 ?? ?? ?? ?? f7 ef c1 fa ?? 8b c2 c1 e8 ?? 03 d0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ED_2147821051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ED!MTB"
        threat_id = "2147821051"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 8a 04 02 44 32 44 1c 50 44 88 04 33 48 ff c3 49 3b de 7c b4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ED_2147821051_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ED!MTB"
        threat_id = "2147821051"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {2b ca d1 e9 03 ca c1 e9 04 89 4c 24 68 8b 4c 24 68 f7 e1 c1 ea 06 89 54 24 68 49 8b d2 81}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ED_2147821051_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ED!MTB"
        threat_id = "2147821051"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {c1 6c 24 48 08 81 44 24 48 e7 d4 00 00 6b 44 24 48 0f 89 44 24 48 81 74 24 48 ff 94 0d 00 44 8b 44 24 48 8b 54 24 58}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ED_2147821051_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ED!MTB"
        threat_id = "2147821051"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {44 8b 4c 24 08 41 d3 e1 44 89 4c 24 3c 41 89 c1 44 89 ca 4c 8b 44 24 28 41 8a 0c 10 44 28 d9 4c 8b 54 24 18 41 88 0c 12 83 c0 20 44 8b 4c 24 24 44 39 c8 89 44 24 0c}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BK_2147821085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BK!MTB"
        threat_id = "2147821085"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 0c 01 32 4c 3e ff 49 ff cd 88 4f ff 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BK_2147821085_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BK!MTB"
        threat_id = "2147821085"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 0c 01 42 32 4c 16 fd 41 88 4a ff 49 ff ce 0f 85 48}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BK_2147821085_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BK!MTB"
        threat_id = "2147821085"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d1 e8 03 c2 8b d7 c1 e8 ?? ff c7 6b c0 ?? 2b d0 48 8b 05 ?? ?? ?? ?? 4c 63 c2 48 8b 15 ?? ?? ?? ?? 45 8a 0c 00 44 32 8c 1d ?? ?? ?? ?? 44 88 0c 13 48 ff c3 48 3b de 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BL_2147821229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BL!MTB"
        threat_id = "2147821229"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b c8 48 63 c1 42 0f b6 0c 00 43 32 4c 13 ff 41 88 4a ff 48 ff cb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BL_2147821229_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BL!MTB"
        threat_id = "2147821229"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {03 ca 48 63 c9 48 8b 15 ?? ?? ?? ?? 88 04 0a e9}  //weight: 3, accuracy: Low
        $x_2_2 = {03 f9 8b cf 03 d1 8b ca}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BL_2147821229_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BL!MTB"
        threat_id = "2147821229"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 e7 8b cf 4d 8d 49 ?? c1 ea ?? ff c7 6b c2 ?? 2b c8 48 63 c1 42 0f b6 0c 10 41 32 49 ?? 41 88 48 ?? 41 3b fb 7d ?? 4c 8b 15 ?? ?? ?? ?? eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BM_2147821230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BM!MTB"
        threat_id = "2147821230"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {42 32 4c 16 fb 41 88 4a fc 41 8b c9 41 f7 e8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BM_2147821230_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BM!MTB"
        threat_id = "2147821230"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 0c 01 41 32 4c 3d ff 49 ff cc 88 4f ff 75 be}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BM_2147821230_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BM!MTB"
        threat_id = "2147821230"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 63 c9 0f b6 0c 01 43 32 4c 0b fd 41 88 49 fd 49 83 ea 01 74 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BM_2147821230_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BM!MTB"
        threat_id = "2147821230"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4c 63 c0 ff c6 45 8a 04 10 45 32 04 1f 44 88 03 48 ff c3 48 ff cf 75 c7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BM_2147821230_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BM!MTB"
        threat_id = "2147821230"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 8a 0c 08 43 32 0c 02 41 88 08 49 ff c0 48 ff ce 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAQ_2147821774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAQ!MTB"
        threat_id = "2147821774"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 e8 48 d1 ?? 49 f7 e6 48 c1 ea ?? 48 6b fa ?? 48 89 d9 48 89 f2}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c1 e8 [0-4] 48 03 [0-6] 8a 44 3d ?? 42 32 44 25 ?? 41 88 44 2d ?? 48 ff c5 48 81 fd [0-4] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BN_2147822333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BN!MTB"
        threat_id = "2147822333"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c2 c1 e8 ?? 03 d0 6b c2 ?? 8b d3 ff c3 2b d0 48 8b 05 ?? ?? ?? ?? 4c 63 c2 41 8a 14 00 (41 32|32) 88 17 48 ff c7 49 ff (ce|cf) 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BO_2147822453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BO!MTB"
        threat_id = "2147822453"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c3 ff c3 8d 14 52 c1 e2 ?? 2b c2 48 63 d0 48 8b 05 ?? ?? ?? ?? 8a 14 02 41 32 14 3f 88 17 48 ff c7 49 ff ce 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_DD_2147822807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.DD!MTB"
        threat_id = "2147822807"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 d0 8b c3 ff c3 8d 14 d2 03 d2 2b c2 48 63 d0 48 8b 05 [0-4] 8a 14 02 32 14 3e 88 17 48 ff c7 49 ff cf 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BQ_2147822820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BQ!MTB"
        threat_id = "2147822820"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 8b 05 ?? ?? ?? ?? 83 c1 ?? 48 63 c9 0f b6 0c 01 43 32 4c 13 ?? 41 88 4a ?? 48 83 ef ?? 74}  //weight: 2, accuracy: Low
        $x_2_2 = {8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 8a 0c 08 43 32 0c 02 41 88 08 49 ff c0 49 83 eb ?? 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_BR_2147822835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BR!MTB"
        threat_id = "2147822835"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 ff c2 41 ff c0 0f b6 0c 08 41 32 4c 11 ff 88 4a ff 48 ff cb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BR_2147822835_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BR!MTB"
        threat_id = "2147822835"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 e8 1f 03 d0 8b c3 ff c3 6b d2 ?? 2b c2 48 63 c8 42 8a 04 09 43 32 04 02 41 88 00 49 ff c0 49 ff cb 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BS_2147823211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BS!MTB"
        threat_id = "2147823211"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c3 ff c3 8d 0c 52 c1 e1 ?? 2b c1 48 63 c8 48 8b 05 ?? ?? ?? ?? 0f b6 0c 01 41 32 4c 3e ?? 88 4f ?? 48 ff ce 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BT_2147823844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BT!MTB"
        threat_id = "2147823844"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c2 c1 e8 ?? 03 d0 6b c2 ?? 8b d3 ff c3 2b d0 48 8b 05 ?? ?? ?? ?? 4c 63 c2 41 8a 14 00 32 14 37 88 17 48 ff c7 49 ff cf 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BU_2147823983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BU!MTB"
        threat_id = "2147823983"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 03 d1 41 ff c1 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 0f b6 0c 00 43 32 4c 13 ?? 41 88 4a ?? 48 ff cb 74 09}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BU_2147823983_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BU!MTB"
        threat_id = "2147823983"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 ef c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c7 ff c7 6b d2 ?? 2b c2 48 98 32 0c 18 4c 3b e6 41 88 4c 2c ff 7d}  //weight: 2, accuracy: Low
        $x_2_2 = {f7 ef d1 fa 8b c2 c1 e8 ?? 03 d0 8b c7 ff c7 6b d2 ?? 2b c2 48 98 42 32 0c ?? 48 3b f3 42 88 4c 1e ff 7d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_BV_2147824271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BV!MTB"
        threat_id = "2147824271"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c2 c1 e8 ?? 03 d0 8b c6 ff c6 6b d2 ?? 2b c2 48 63 c8 42 0f b6 04 01 43 32 44 11 ?? 48 ff cb 41 88 42 ?? 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_DF_2147824361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.DF!MTB"
        threat_id = "2147824361"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 eb 8b cb 03 d3 ff c3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 0f b6 0c 00 43 32 4c 0a ?? 41 88 49 ?? 48 83 ef 01 74}  //weight: 1, accuracy: Low
        $x_1_2 = "tK9%6TYeCiN7R>R2w$gBS^1bHUf0N" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_DG_2147824362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.DG!MTB"
        threat_id = "2147824362"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 d0 41 8b c4 41 ff c4 6b d2 43 2b c2 48 63 d0 48 63 05 1c a4 06 00 48 0f af c8 48 63 05 21 a4 06 00 48 2b c8 48 8d 04 89 48 03 d0 48 8b 44 24 28 42 0f b6 8c 32 f0 f7 04 00 41 32 4c 00 ff 43 88 4c 18 ff 44 3b 64 24 20 72 98}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_DG_2147824362_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.DG!MTB"
        threat_id = "2147824362"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 eb 8b cb 03 d3 ff c3 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 1e 2b c8 48 8b 05 [0-4] 48 63 d1 0f b6 0c 02 32 4c 3e ff 88 4f ff 48 83 ed 01 75}  //weight: 1, accuracy: Low
        $x_1_2 = "8OqX>w6*BoseU8>!25aAFemv2L8Ox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAR_2147824384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAR!MTB"
        threat_id = "2147824384"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 ?? 2b c8 48 8b [0-6] 48 63 d1 0f b6 0c 02 32 4c 1e ?? 88 4b ?? 48 83 ed 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAS_2147824703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAS!MTB"
        threat_id = "2147824703"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d3 c1 fa 05 8b c2 c1 e8 1f 03 d0 6b d2 25 8b c3 2b c2 48 63 c8 48 8b [0-8] 0f b6 0c 01 32 0c 3e 88 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAT_2147824910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAT!MTB"
        threat_id = "2147824910"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b ce 2b c8 48 63 c1 8a 4c 04 ?? 48 8b 05 [0-4] 44 8a 14 02 ba [0-4] 8b 05 ?? ?? ?? ?? 44 32 d1 0f af [0-6] 2b d0 [0-160] 48 63 c8 44 88 14 19}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EN_2147824993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EN!MTB"
        threat_id = "2147824993"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 0c 01 32 0c 2b 88 0b 48 ff c3 48 83 ee 01 75 be}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EN_2147824993_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EN!MTB"
        threat_id = "2147824993"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8b 44 24 38 99 b9 41 00 00 00 f7 f9 8b c2 48 98 48 8b 4c 24 28 0f b6 04 01 8b 4c 24 40 33 c8 8b c1 48 63 4c 24 38 48 8b 54 24 30 88 04 0a}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EN_2147824993_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EN!MTB"
        threat_id = "2147824993"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VirtualAlloc" ascii //weight: 1
        $x_1_2 = "CreateMutexA" ascii //weight: 1
        $x_1_3 = "WaitForSingleObject" ascii //weight: 1
        $x_2_4 = "kL1Z7f4XSWZpbiIOdzaNwmVk" ascii //weight: 2
        $x_2_5 = "MnF3jpEpMXNysQhbtxabPSJVjf5l6Z6XceCr2kKtqIdl" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BX_2147825281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BX!MTB"
        threat_id = "2147825281"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 98 0f b6 44 04 ?? 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 8b 0d 50 00 03 05 ?? ?? ?? ?? 2b 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BY_2147825425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BY!MTB"
        threat_id = "2147825425"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 44 04 ?? 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_NY_2147825853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.NY!MTB"
        threat_id = "2147825853"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 48 63 ca 48 8b 05 ?? ?? ?? ?? 0f b6 04 08 41 8b d0 33 d0 8b 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {2b c1 48 63 c8 48 8b 84 24 ?? ?? ?? ?? 88 14 08 e9}  //weight: 1, accuracy: Low
        $x_1_3 = "^^0sk%Hsl+CiJLo^9EUfRLzXJ(DXNSgkpmkM7M+" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BZ_2147825914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BZ!MTB"
        threat_id = "2147825914"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 98 0f b6 7c 04 ?? 8b 84 24 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 48 63 ca 48 8b 05 ?? ?? ?? ?? 0f b6 04 08 8b d7 33 d0 8b 0d ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 03 c1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_NZ_2147826028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.NZ!MTB"
        threat_id = "2147826028"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 83 e2 0f 03 c2 83 e0 0f 2b c2 48 63 c8 48 8b 05 c5 82 00 00 0f b6 04 08 44 33 c0 8b 05}  //weight: 1, accuracy: High
        $x_1_2 = {33 3c 61 2a 44 63 55 32 52 55 6f 4f 28 48 79 00 57 6d 54 41 79 44 42 72 6b 6f 53 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_MD_2147826037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.MD!MTB"
        threat_id = "2147826037"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 98 49 8b c9 32 14 18 4b 8d 04 1b 49 0f af c9 49 0f af c8 49 2b cb 49 0f af c9 49 03 ca 48 2b c8 48 8d 04 4e 48 ff c6 48 03 c8 88 14 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_MD_2147826037_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.MD!MTB"
        threat_id = "2147826037"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a c2 48 83 c1 01 48 83 c2 01 83 e0 0f 42 0f b6 04 00 32 44 29 ff 48 83 ee 01 88 41 ff 75}  //weight: 10, accuracy: High
        $x_10_2 = {f7 f9 48 63 ca 48 8b 44 24 30 0f b6 04 08 41 8b d0 33 d0 48 63 4c 24 40 48 8b 44 24 38 88 14 08 eb}  //weight: 10, accuracy: High
        $x_10_3 = {49 ff c1 41 f7 e0 41 8b c0 41 ff c0 c1 ea 03 6b d2 0f 2b c2 48 63 c8 42 0f b6 04 11 41 32 44 29 ff 41 88 41 ff 45 3b c4 72}  //weight: 10, accuracy: High
        $x_10_4 = {f7 e6 8b c6 2b c2 d1 e8 03 c2 c1 e8 05 48 6b c0 27 48 2b c8 48 63 c6 83 c6 01 0f b6 0c 01 41 32 4c 2d ff 41 3b f6 88 4d ff 0f 82}  //weight: 10, accuracy: High
        $x_10_5 = {41 f7 e0 41 8b c0 41 83 c0 01 2b c2 d1 e8 03 c2 c1 e8 05 48 6b c0 ?? 48 2b c8 0f b6 04 19 ?? 32 44 ?? ff ?? 3b ?? 41 88 41 ff 72}  //weight: 10, accuracy: Low
        $x_10_6 = {f7 e6 48 63 c6 83 c6 01 c1 ea 03 48 8d 0c d2 48 8d 15 ?? ?? ?? ?? 48 c1 e1 02 48 2b d1 0f b6 0c 02 41 32 4c 2d ff 41 3b f6 88 4d ff 0f 82}  //weight: 10, accuracy: Low
        $x_1_7 = "k+)0zMXthEy1%8z" ascii //weight: 1
        $x_1_8 = "7(rKOHM^Gz1VQ9gPc" ascii //weight: 1
        $x_1_9 = "La%Jy<2&jB144o" ascii //weight: 1
        $x_1_10 = "IXO>OK&AOwt$(e6MLQy*&vUx&irCQOem3y!rNO" ascii //weight: 1
        $x_1_11 = "GPt5GXVB3*0J7hJFM?>Bjq8is^dm2l^(v6rQ?o757vD5" ascii //weight: 1
        $x_1_12 = "*J!u6x%C%U!A5*3ey02Rh0#@MUzhvXqrvq5u&ZO&&P7_lSdt6a8nm" ascii //weight: 1
        $x_1_13 = "@sEBg9<j$$a(9SL>_XLk^PYTG^UxiU2nGQ@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Emotet_EH_2147826164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EH!MTB"
        threat_id = "2147826164"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8a 14 02 43 32 14 0b 41 88 11 49 ff c1 48 83 ef 01 75 c6}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EH_2147826164_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EH!MTB"
        threat_id = "2147826164"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4b 8d 04 0a 48 03 c8 48 8d 04 49 49 8b cb 49 ff c3 48 2b c8 44 88 04 39}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EH_2147826164_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EH!MTB"
        threat_id = "2147826164"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {48 8d 76 01 f7 e7 8b cf ff c7 c1 ea 04 6b c2 34 2b c8 48 63 c1 42 0f b6 04 20 41 32 44 36 ff 88 46 ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EH_2147826164_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EH!MTB"
        threat_id = "2147826164"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {99 b9 2c 00 00 00 f7 f9 48 63 ca 48 8b 05 ?? ?? ?? ?? 0f b6 04 08 8b d7 33 d0 48 63 8c 24 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 88 14 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EH_2147826164_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EH!MTB"
        threat_id = "2147826164"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {48 83 ec 48 c7 44 24 58 fe 60 00 00 83 fa 64 0f 85 a4 00 00 00 c7 44 24 34 64 d5 00 00 4c 89 44 24 20 c1 6c 24 34 06 81 74 24 34 75 f9 0f 00 c7 44 24 30 1e ae 00 00}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_GL_2147828752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.GL!MTB"
        threat_id = "2147828752"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {99 b9 2f 00 00 00 f7 f9 48 63 ca 48 8b 05 ?? ?? ?? ?? 0f b6 04 08 8b d7 33 d0 48 63 8c 24 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 88 14 08 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAW_2147829354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAW!MTB"
        threat_id = "2147829354"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 41 89 09 c7 45 10 [0-4] 81 75 10 [0-4] 6b 45 10 [0-4] 89 45 10 c1 65 10 05 c1 6d 10 07 81 75 10 [0-4] 8b 45 10 89 45 10 8b 4d 28 8b 45 ?? 33 c8 41 89 0a c7 45 10 [0-4] 81 75 10 [0-4] c1 6d 10 04 81 75 10 [0-4] 8b 45 10 89 45 10 48 83 c4 ?? 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PAV_2147829495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAV!MTB"
        threat_id = "2147829495"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0b 49 ff c3 48 8d 5b 04 33 cd 0f b6 c1 66 41 89 00 0f b7 c1 c1 e9 10 66 c1 e8 08 4d 8d 40 08 66 41 89 40 ?? 0f b6 c1 66 c1 e9 08 66 41 89 40 ?? 66 41 89 48 ?? 4d 3b d9 72}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 0b 49 ff c3 48 8d 5b 04 33 cd 41 88 08 0f b7 c1 c1 e9 10 66 c1 e8 08 4d 8d 40 04 41 88 40 ?? 41 88 48 ?? 66 c1 e9 08 41 88 48 ?? 4d 3b d9 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_PAU_2147829650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PAU!MTB"
        threat_id = "2147829650"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 2b ca d1 e9 03 ca c1 e9 04 89 4c 24 ?? 81 44 24 [0-6] 81 74 24 [0-6] c1 6c 24 [0-6] 81 74 24 [0-6] c7 44 24 [0-6] 81 4c 24 [0-6] 81 74 24 [0-6] c7 44 24 [0-6] c1 6c 24 [0-6] 81 44 24 [0-6] c1 6c 24 [0-6] 81 74 24 [0-6] 8b 44 24 ?? 8b 54 24 ?? 8b 4c 24 ?? 89 44 24 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_F_2147830026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.F!MTB"
        threat_id = "2147830026"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 54 24 74 89 44 24 50 4c 8b 84 24 80 00 00 00 4d 89 c1 49 d3 e9 4c 89 8c 24 80 00 00 00}  //weight: 1, accuracy: High
        $x_2_2 = {48 8b 4c 24 48 48 8b 54 24 48 48 d3 e2 48 89 94 24 80 00 00 00 c7 44 24 54 01 00 00 00 89 44 24 40 8b 44 24 54}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_DK_2147831635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.DK!MTB"
        threat_id = "2147831635"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 89 c8 41 29 d0 4d 63 c0 4c 8b 0d [0-4] 47 0f b6 04 01 44 32 44 0c 20 45 88 04 0a 48 83 c1 01 48 81 f9 9d 0b 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_DK_2147831635_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.DK!MTB"
        threat_id = "2147831635"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 ef c1 fa 04 ff c7 8b c2 c1 e8 1f 03 d0 6b c2 26 2b c8 48 63 c1 48 8d 0d [0-4] 8a 04 08 42 32 04 36 41 88 06 49 ff c6 3b fd 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_DL_2147831735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.DL!MTB"
        threat_id = "2147831735"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 c8 99 41 f7 fa 48 8b 05 [0-4] 48 63 d2 44 8a 04 10 45 32 04 0b 45 88 04 09 48 ff c1 48 81 f9 9d 0b 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_DL_2147831735_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.DL!MTB"
        threat_id = "2147831735"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {49 ff c1 41 f7 e0 41 8b c0 41 ff c0 c1 ea 05 6b d2 29 2b c2 48 63 c8 42 0f b6 04 11 42 32 44 0e ff 41 88 41 ff 44 3b c5 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_DL_2147831735_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.DL!MTB"
        threat_id = "2147831735"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 ?? 48 6b c0 ?? 48 2b c8 48 2b cb 8a 44 0c ?? 43 32 04 0b 41 88 01 4c 03 ce 45 3b d4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ME_2147834446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ME!MTB"
        threat_id = "2147834446"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4c 8b c8 48 2b f0 b8 ?? ?? ?? ?? 41 f7 e8 c1 fa 03 8b c2 c1 e8 1f 03 d0 49 63 c0 41 83 c0 01 48 63 ca 48 6b c9 19 48 03 c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 42 32 04 0e 41 88 01 49 83 c1 01 44 3b c5 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ME_2147834446_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ME!MTB"
        threat_id = "2147834446"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 63 4c 24 30 48 8b 44 24 50 44 0f b6 04 08 8b 44 24 30 99 b9 ?? ?? ?? ?? f7 f9 48 63 ca 48 8b 44 24 20 0f b6 04 08 41 8b d0 33 d0 48 63 4c 24 30 48 8b 44 24 28 88 14 08 eb}  //weight: 10, accuracy: Low
        $x_10_2 = {41 f7 e8 c1 fa 03 8b c2 c1 e8 1f 03 d0 41 8b c0 41 ff c0 6b d2 1b 2b c2 48 63 c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 42 32 04 0e 41 88 01 49 ff c1 44 3b c5 72}  //weight: 10, accuracy: Low
        $x_10_3 = {41 f7 e8 41 03 d0 c1 fa 04 8b c2 c1 e8 1f 03 d0 41 8b c0 41 ff c0 6b d2 1e 2b c2 48 63 c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 42 32 04 0e 41 88 01 49 ff c1 44 3b c5 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_PBA_2147834490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PBA!MTB"
        threat_id = "2147834490"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 2e 00 00 00 f7 f9 48 63 ca 48 8b 44 24 ?? 0f b6 04 08 41 8b d0 33 d0 48 63 4c 24 ?? 48 8b 44 24 ?? 88 14 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PBB_2147834491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PBB!MTB"
        threat_id = "2147834491"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 e8 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 49 63 c0 41 83 c0 ?? 48 63 ca 48 6b c9 ?? 48 03 c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 42 32 04 0e 41 88 01 49 83 c1 ?? 44 3b c5 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_DH_2147834494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.DH!MTB"
        threat_id = "2147834494"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {49 8b ca 49 83 c1 01 49 83 c2 01 41 f7 e0 41 8b c0 41 83 c0 01 2b c2 d1 e8 03 c2 c1 e8 04 48 6b c0 13 48 2b c8 0f b6 04 19 41 32 44 29 ff 45 3b c4 41 88 41 ff 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_DI_2147834495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.DI!MTB"
        threat_id = "2147834495"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 63 4c 24 30 48 8b 44 24 60 44 0f b6 04 08 8b 44 24 30 99 b9 3f 00 00 00 f7 f9 48 63 ca 48 8b 44 24 20 0f b6 04 08 41 8b d0 33 d0 48 63 4c 24 30 48 8b 44 24 28 88 14 08 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PBD_2147834567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PBD!MTB"
        threat_id = "2147834567"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b ca 49 83 c1 ?? 49 83 c2 ?? 41 f7 e0 41 8b c0 41 83 c0 ?? 2b c2 d1 ?? 03 c2 c1 e8 ?? 48 6b c0 ?? 48 2b c8 0f b6 04 19 42 32 44 0e ?? 44 3b c5 41 88 41 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PBE_2147834608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PBE!MTB"
        threat_id = "2147834608"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b c8 48 2b f8 41 8b c0 41 83 c0 ?? 99 83 e2 ?? 03 c2 83 e0 ?? 2b c2 48 63 c8 48 8d 05 [0-4] 8a 04 01 42 32 04 0f 41 88 01 49 83 c1 ?? 44 3b c6 72}  //weight: 1, accuracy: Low
        $x_1_2 = {41 f7 e8 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 49 63 c0 41 83 c0 ?? 48 63 ca 48 6b c9 ?? 48 03 c8 48 8d 05 [0-4] 8a 04 01 42 32 04 0f 41 88 01 49 83 c1 ?? 44 3b c6 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_ZW_2147834618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ZW!MTB"
        threat_id = "2147834618"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 ff c1 41 f7 e0 41 8b c0 41 ff c0 c1 ea ?? 8d 0c 92 c1 e1 ?? 2b c1 48 63 c8 42 0f b6 04 11 41 32 44 29 ff 41 88 41 ff 45 3b c4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_DJ_2147834642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.DJ!MTB"
        threat_id = "2147834642"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 f9 8b c2 48 98 48 8b 4c 24 20 0f b6 04 01 8b 4c 24 38 33 c8 8b c1 48 63 4c 24 30 48 8b 54 24 28 88 04 0a eb}  //weight: 1, accuracy: High
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_SL_2147834647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.SL!MTB"
        threat_id = "2147834647"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b d7 33 c9 ff 15 0d b2 07 00 8b cf b8 31 0c c3 30 f7 ef ff c7 c1 fa 02 8b c2 c1 e8 1f 03 d0 6b c2 15 2b c8 48 63 c1 48 8d 0d 81 86 0b 00 8a 04 08 42 32 04 36 41 88 06 49 ff c6 3b fd 72 c1 48}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ACMMS_2147834665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ACMMS!MTB"
        threat_id = "2147834665"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b c8 48 2b f0 b8 ?? ?? ?? ?? 41 f7 e8 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 49 63 c0 41 83 c0 01 48 63 ca 48 6b c9 ?? 48 03 c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 42 32 04 0e 41 88 01 49 83 c1 01 44 3b c5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_AGBU_2147834668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.AGBU!MTB"
        threat_id = "2147834668"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c1 41 f7 e0 41 8b c0 41 ff c0 c1 ea ?? 8d 0c 92 c1 e1 ?? 2b c1 48 63 c8 42 0f b6 04 11 41 32 44 29 ff 41 88 41 ff 45 3b c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_SK_2147834677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.SK!MTB"
        threat_id = "2147834677"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 cf f3 3c cf 41 f7 e8 c1 fa 02 8b c2 c1 e8 1f 03 d0 49 63 c0 41 83 c0 01 48 63 ca 48 6b c9 15 48 03 c8 48 8d 05 45 dd 08 00 8a 04 01 42 32 04 0f 41 88 01 49 83 c1 01 44 3b c6 72 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ACMO_2147834723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ACMO!MTB"
        threat_id = "2147834723"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 48 6b c0 ?? 48 2b c8 0f b6 04 19 42 32 44 0e ff 44 3b c7 41 88 41 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_WW_2147834730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.WW!MTB"
        threat_id = "2147834730"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b ca 49 83 c1 ?? 49 83 c2 ?? 41 f7 e0 c1 ea ?? 41 83 c0 ?? 8b c2 48 6b c0 ?? 48 2b c8 0f b6 04 19 42 32 44 0e ff 44 3b c7 41 88 41 ff 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_MF_2147834769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.MF!MTB"
        threat_id = "2147834769"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 f7 e8 c1 fa 02 8b c2 c1 e8 1f 03 d0 41 8b c0 41 ff c0 8d 0c 52 c1 e1 03 2b c1 48 63 c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 42 32 04 0f 41 88 01 49 ff c1 44 3b c6 72}  //weight: 10, accuracy: Low
        $x_10_2 = {b8 9d 82 97 53 48 ff c5 f7 e6 8b c6 ff c6 c1 ea 04 6b d2 31 2b c2 48 63 c8 42 0f b6 04 39 41 32 44 2e ff 88 45 ff 41 3b f5 0f 82}  //weight: 10, accuracy: High
        $x_10_3 = {4c 8b c8 48 2b f8 41 8b c0 41 83 c0 01 99 83 e2 1f 03 c2 83 e0 1f 2b c2 48 63 c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 42 32 04 0f 41 88 01 49 83 c1 01 44 3b c6 72}  //weight: 10, accuracy: Low
        $x_10_4 = {b8 89 88 88 88 49 ff c1 41 f7 e0 41 8b c0 41 ff c0 c1 ea 03 6b d2 0f 2b c2 48 63 c8 42 0f b6 04 11 41 32 44 29 ff 41 88 41 ff 45 3b c4 72}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_NR_2147834805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.NR!MTB"
        threat_id = "2147834805"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c7 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 48 8d 0d ?? ?? ?? ?? 8a 04 08 42 32 04 36 41 88 06 49 ff c6 3b fd 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_MG_2147834828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.MG!MTB"
        threat_id = "2147834828"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 f7 e8 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 41 8b c0 41 ff c0 6b d2 ?? 2b c2 48 63 c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 42 32 04 0f 41 88 01 49 ff c1 44 3b c6 72}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b6 04 01 89 44 24 40 8b 44 24 38 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8b 4c 24 28 0f b6 04 01 8b 4c 24 40 33 c8 8b c1 48 63 4c 24 38 48 8b 54 24 30 88 04 0a eb}  //weight: 10, accuracy: Low
        $x_10_3 = {f7 ee 03 d6 ff c6 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 48 8d 0d ?? ?? ?? ?? 8a 04 08 41 32 04 2f 41 88 07 49 ff c7 41 3b f6 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_MH_2147834923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.MH!MTB"
        threat_id = "2147834923"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 ff c1 41 f7 e0 41 8b c0 41 ff c0 c1 ea ?? 6b d2 ?? 2b c2 48 63 c8 42 0f b6 04 11 42 32 44 0e ff 41 88 41 ff 44 3b c5 72}  //weight: 10, accuracy: Low
        $x_10_2 = {41 ff c0 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 48 8d 0d ?? ?? ?? ?? 8a 04 08 42 32 04 16 41 88 02 49 ff c2 44 3b c5 72}  //weight: 10, accuracy: Low
        $x_10_3 = {41 f7 e8 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 41 8b c0 41 ff c0 8d 0c 92 c1 e1 ?? 2b c1 48 63 c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 41 32 04 2a 41 88 02 49 ff c2 45 3b c6 72}  //weight: 10, accuracy: Low
        $x_10_4 = {4d 8d 40 01 f7 e7 8b cf ff c7 c1 ea ?? 6b c2 ?? 2b c8 48 63 c1 42 0f b6 04 10 43 32 44 07 ff 41 88 40 ff 41 3b fc 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_SAA_2147834924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.SAA!MTB"
        threat_id = "2147834924"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 ff c1 41 f7 e0 41 8b c0 41 ff c0 c1 ea ?? 6b d2 ?? 2b c2 48 ?? ?? 42 ?? ?? ?? ?? 42 ?? ?? ?? ?? 41 ?? ?? ?? 44 ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_SP_2147834943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.SP!MTB"
        threat_id = "2147834943"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 bf 3c b6 22 49 8b ca 49 83 c1 01 49 83 c2 01 41 f7 e0 c1 ea 03 41 83 c0 01 8b c2 48 6b c0 3b 48 2b c8 0f b6 04 19 42 32 44 0e ff 44 3b c7 41 88 41 ff 72 cb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_DN_2147834947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.DN!MTB"
        threat_id = "2147834947"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4d 8d 40 01 f7 e6 8b c6 ff c6 c1 ea 05 8d 0c 52 c1 e1 04 2b c1 48 63 c8 42 0f b6 04 11 43 32 44 07 ff 41 88 40 ff 41 3b f4 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_MI_2147834996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.MI!MTB"
        threat_id = "2147834996"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 48 8d 0d ?? ?? ?? ?? 8a 04 08 42 32 04 36 41 88 06 49 ff c6 3b fd 72}  //weight: 10, accuracy: Low
        $x_10_2 = {4d 8d 40 01 f7 e6 8b ce ff c6 c1 ea ?? 6b c2 ?? 2b c8 48 63 c1 42 0f b6 04 10 43 32 44 07 ff 41 88 40 ff 41 3b f4 72}  //weight: 10, accuracy: Low
        $x_10_3 = {41 f7 e8 41 03 d0 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 41 8b c0 41 ff c0 6b d2 ?? 2b c2 48 63 c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 42 32 04 16 41 88 02 49 ff c2 44 3b c5 72}  //weight: 10, accuracy: Low
        $x_10_4 = {4d 8d 40 01 f7 e6 8b c6 ff c6 c1 ea ?? 8d 0c d2 03 c9 2b c1 48 63 c8 42 0f b6 04 11 43 32 44 07 ff 41 88 40 ff 41 3b f4 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_DO_2147835001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.DO!MTB"
        threat_id = "2147835001"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 f7 e8 41 03 d0 41 ff c0 c1 fa 05 8b c2 c1 e8 1f 03 d0 6b c2 2f 2b c8 48 63 c1 48 8d 0d [0-4] 8a 04 08 41 32 04 2a 41 88 02 49 ff c2 45 3b c6 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ARA_2147835016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ARA!MTB"
        threat_id = "2147835016"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4d 8d 40 01 f7 e6 8b c6 ff c6 c1 ea 05 8d 0c 52 c1 e1 04 2b c1 48 63 c8 42 0f b6 04 11 43 32 44 07 ff 41 88 40 ff 41 3b f4 72 d0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ARA_2147835016_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ARA!MTB"
        threat_id = "2147835016"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 f7 e8 41 ff c0 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b c2 2c 2b c8 48 63 c1 48 8d 0d c9 60 08 00 8a 04 08 41 32 04 2a 41 88 02 49 ff c2 45 3b c6 72 c7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ARA_2147835016_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ARA!MTB"
        threat_id = "2147835016"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 41 8b c0 41 ff c0 8d 0c 92 c1 e1 03 2b c1 48 63 c8 48 8d 05 be 74 08 00 8a 04 01 41 32 04 2a 41 88 02 49 ff c2 45 3b c6 72 c4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ARA_2147835016_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ARA!MTB"
        threat_id = "2147835016"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 8b c0 41 83 c0 01 99 83 e2 1f 03 c2 83 e0 1f 2b c2 48 63 c8 48 8d 05 03 c8 08 00 8a 04 01 42 32 04 0f 41 88 01 49 83 c1 01 44 3b c6 72 d1}  //weight: 2, accuracy: High
        $x_2_2 = "sc.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ARA_2147835016_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ARA!MTB"
        threat_id = "2147835016"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 44 24 38 ff c0 89 44 24 38 8b 44 24 68 39 44 24 38 73 42 48 63 44 24 38 48 8b 4c 24 60 0f b6 04 01 89 44 24 40 8b 44 24 38 99 b9 2e 00 00 00 f7 f9 8b c2 48 98 48 8b 4c 24 28 0f b6 04 01 8b 4c 24 40 33 c8 8b c1 48 63 4c 24 38 48 8b 54 24 30 88 04 0a eb aa}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ARA_2147835016_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ARA!MTB"
        threat_id = "2147835016"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 8b c8 b8 79 78 78 78 41 f7 e8 41 ff c0 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b c2 11 2b c8 48 63 c1 48 8d 0d b7 de 07 00 8a 04 08 42 32 04 16 41 88 02 49 ff c2 44 3b c5 72 c7}  //weight: 10, accuracy: High
        $x_10_2 = {41 8b c8 b8 b7 60 0b b6 41 f7 e8 41 03 d0 41 ff c0 c1 fa 05 8b c2 c1 e8 1f 03 d0 6b c2 2d 2b c8 48 63 c1 48 8d 0d 04 f4 07 00 8a 04 08 42 32 04 16 41 88 02 49 ff c2 44 3b c5 72 c4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_EB_2147835057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EB!MTB"
        threat_id = "2147835057"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {49 2b c1 4c 63 c2 4d 6b c0 15 4c 03 c0 48 8b 44 24 28 41 8a 0c 08 41 32 0c 02 43 88 0c 1a 49 83 c2 01 44 3b 64 24 20}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EB_2147835057_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EB!MTB"
        threat_id = "2147835057"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 04 01 41 32 04 29 41 88 01 49 ff c1 45 3b c4 72 c4 49 8b c3 48 8b 5c 24 30 48 8b 6c 24 38 48 8b 74 24 40 48 8b 7c 24 48}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EB_2147835057_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EB!MTB"
        threat_id = "2147835057"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 04 08 41 32 04 2a 41 88 02 49 ff c2 45 3b c6 72 c7 49 8b c1 48 8b 5c 24 50 48 8b 6c 24 58 48 8b 74 24 60 48 8b 7c 24 68}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EB_2147835057_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EB!MTB"
        threat_id = "2147835057"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MTScratchpadRTStylus.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "PostQuitMessage" ascii //weight: 1
        $x_1_4 = "CryptStringToBinaryA" ascii //weight: 1
        $x_1_5 = "RtlLookupFunctionEntry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_MJ_2147835114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.MJ!MTB"
        threat_id = "2147835114"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 f7 e8 41 ff c0 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 48 8d 0d ?? ?? ?? ?? 8a 04 08 41 32 04 2a 41 88 02 49 ff c2 45 3b c6 72}  //weight: 10, accuracy: Low
        $x_10_2 = {48 8d 76 01 f7 e7 8b cf ff c7 c1 ea ?? 6b c2 ?? 2b c8 48 63 c1 42 0f b6 04 20 41 32 44 36 ff 88 46 ff 41 3b ff 72}  //weight: 10, accuracy: Low
        $x_10_3 = {41 f7 e8 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 41 8b c0 41 ff c0 6b d2 ?? 2b c2 48 63 c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 41 32 04 2a 41 88 02 49 ff c2 45 3b c6 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_MIA_2147835209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.MIA!MTB"
        threat_id = "2147835209"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xyuz" ascii //weight: 1
        $x_1_2 = "SC.EXE" ascii //weight: 1
        $x_1_3 = "yahavSoduku.txt" ascii //weight: 1
        $x_1_4 = "Board number:" ascii //weight: 1
        $x_1_5 = "Dll1.dll" ascii //weight: 1
        $x_1_6 = "u.txt" ascii //weight: 1
        $x_1_7 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_PBC_2147835252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.PBC!MTB"
        threat_id = "2147835252"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb 41 8b d0 d3 e2 41 8b cb d3 e0 03 d0 41 0f be c1 03 d0 41 2b d0 49 ff ?? 44 8b c2 45 8a ?? 41 8b c0 45 84 c9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_MK_2147835336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.MK!MTB"
        threat_id = "2147835336"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 ff c6 41 f7 e1 2b ca 41 8b c1 d1 e9 41 ff c1 03 ca c1 e9 ?? 6b c9 ?? 2b c1 48 63 c8 42 0f b6 04 11 32 46 ff 41 88 44 30 ff 44 3b cd 72}  //weight: 10, accuracy: Low
        $x_10_2 = {48 ff c3 41 f7 e3 41 8b c3 41 ff c3 c1 ea ?? 6b d2 ?? 2b c2 48 63 c8 42 0f b6 04 09 41 32 44 18 ff 88 43 ff 44 3b de 72}  //weight: 10, accuracy: Low
        $x_10_3 = {0f b6 04 01 89 44 24 2c 8b 44 24 20 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8b 4c 24 40 0f b6 04 01 8b 4c 24 2c 33 c8 8b c1 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 54 24 20 2b d1 8b ca}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotet_JD_2147835452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.JD!MTB"
        threat_id = "2147835452"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c2 d1 e8 03 c2 8b d1 c1 e8 ?? ff c1 6b c0 ?? 2b d0 43 8d 04 0e 4c 63 c2 48 63 d0 49 63 c1 47 0f b6 04 18 44 32 04 2a 44 88 04 38 3b ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_ML_2147835472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.ML!MTB"
        threat_id = "2147835472"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Emotet dummy DLL" ascii //weight: 10
        $x_10_2 = "Emotet loader bundle" ascii //weight: 10
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "dummy-dll.dll" ascii //weight: 1
        $x_1_5 = "hello_from_" ascii //weight: 1
        $x_1_6 = "loaded" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Emotet_MM_2147835661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.MM!MTB"
        threat_id = "2147835661"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ATszzPKoqNXTPfR" ascii //weight: 10
        $x_1_2 = "BeXFsAGUOmaQwfJCWyDzmzN" ascii //weight: 1
        $x_1_3 = "CCqmuqIKVWxSfpf" ascii //weight: 1
        $x_10_4 = "AFACEXqwUtHztuwmGbQwN" ascii //weight: 10
        $x_1_5 = "ANGMWkictcm" ascii //weight: 1
        $x_1_6 = "AeGFGFAktJisrfqm" ascii //weight: 1
        $x_10_7 = "xUuDQNpEBoKhFIMSb" ascii //weight: 10
        $x_1_8 = "yxazbtnIftyFUVFN" ascii //weight: 1
        $x_1_9 = "zDITzqqpmsghHOQFXnHUSgtj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Emotet_SAB_2147835695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.SAB!MTB"
        threat_id = "2147835695"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e8 ?? 03 d0 41 ?? ?? 41 ?? ?? 6b d2 ?? 2b c2 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 8a 0c 01 43 ?? ?? ?? 41 ?? ?? 49 ?? ?? 48 ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_NZB_2147835704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.NZB!MTB"
        threat_id = "2147835704"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c2 48 63 c8 48 63 05 ?? ?? ?? ?? 0f b6 14 39 48 63 0d ?? ?? ?? ?? 32 14 2b 49 0f af c9 49 2b c8 48 83 e9 02 48 0f af c8 48 63 05 ?? ?? ?? ?? 48 2b c8 49 2b c8 49 03 c9 48 8d 04 4b 48 ff c3 42 88 14 18 44 3b d6 72 95}  //weight: 1, accuracy: Low
        $x_1_2 = "<WyO4vHJNn2E<<1BJHLaF(Cy55NOw?<U" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_SAC_2147835718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.SAC!MTB"
        threat_id = "2147835718"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e8 ?? 03 d0 41 ?? ?? 41 ?? ?? 8d 0c d2 03 c9 2b c1 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 8a 0c 01 43 ?? ?? ?? 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_SAD_2147835719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.SAD!MTB"
        threat_id = "2147835719"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e8 ?? 03 d0 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? 48 ?? ?? 42 ?? ?? ?? ?? 43 ?? ?? ?? 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_SAE_2147837867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.SAE!MTB"
        threat_id = "2147837867"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b c2 48 98 48 ?? ?? ?? ?? ?? ?? ?? 0f b6 04 01 8b 4c 24 ?? 33 c8 8b c1 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_CB_2147839146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.CB!MTB"
        threat_id = "2147839146"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {48 8b 8c 24 30 03 00 00 0f b6 04 01 8b 8c 24 bc 03 00 00 33 c8 8b c1 48 63 8c 24 b8 03 00 00 48 8b 94 24 b0 03 00 00 88 04 0a e9 ea fc ff ff}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EC_2147840555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EC!MTB"
        threat_id = "2147840555"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 89 fe 48 c1 ee 3f 48 c1 ff 23 01 f7 89 fe c1 e6 05 01 fe 29 f3 48 63 db 8a 1c 0b 32 1c 02 48 8b 95 90 02 00 00 88 1c 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_EC_2147840555_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.EC!MTB"
        threat_id = "2147840555"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {81 74 24 48 9d 7c bb ff c7 44 24 58 62 7d 00 00 c1 6c 24 58 04 c1 64 24 58 06 81 74 24 58 28 0f 02 00 8b 54 24 58 8b 4c 24 48}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_CPP_2147841269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.CPP!MTB"
        threat_id = "2147841269"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 63 c4 41 83 c4 ?? 48 63 ca 48 6b c9 ?? 48 03 c8 48 8b 44 24 28 42 0f ?? ?? ?? ?? ?? ?? ?? 41 32 4c 00 ff 43 88 4c 18 ff 44 3b 64 24 20 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BP_2147842512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BP!MTB"
        threat_id = "2147842512"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 c8 48 8b 84 24 30 03 00 00 0f b6 04 08 8b d7 33 d0 48 63 8c 24 b8 03 00 00 48 8b 84 24 b0 03 00 00 88 14 08 e9 47 fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_CDQ_2147842768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.CDQ!MTB"
        threat_id = "2147842768"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4d 8d 40 01 f7 eb 8b cb [0-4] ff c3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 8b 44 24 40 48 63 d1 0f b6 8c 32 00 b2 04 00 41 32 4c 00 ff 48 8b 44 24 38 41 88 4c 00 ff 48 63 c3 48 3b 44 24 30 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_SAH_2147842907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.SAH!MTB"
        threat_id = "2147842907"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb f7 eb 03 d3 ff c3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 ?? ?? ?? ?? 48 ?? ?? 8a 8c 32 ?? ?? ?? ?? 41 ?? ?? ?? 48 ?? ?? ?? ?? 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_RDD_2147842987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.RDD!MTB"
        threat_id = "2147842987"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 63 c8 ff c3 48 8b 44 24 40 0f b6 8c 31 ?? ?? ?? ?? 32 0c 02 48 8b 44 24 38 88 0c 02 48 ff c2 48 63 c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_LK_2147842997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.LK!MTB"
        threat_id = "2147842997"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 04 24 c1 e8 0d 8b 0c 24 c1 e1 13 0b c1 89 04 24 48 8b 44 24 20 0f be 00 83 f8 61 7c 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_SAI_2147843091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.SAI!MTB"
        threat_id = "2147843091"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 d8 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 01 f7 6b ff ?? 29 fb 48 ?? ?? 8a 1c 0b 32 1c 02 48 ?? ?? ?? ?? ?? ?? 88 1c 02 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_RDC_2147843177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.RDC!MTB"
        threat_id = "2147843177"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b cb f7 eb 03 d3 ff c3 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 1e 2b c8 48 8b 44 24 40 48 63 d1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_RDE_2147844741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.RDE!MTB"
        threat_id = "2147844741"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 0f b6 08 4d 8d 40 01 8b d0 2a c8 81 e2 ff 03 00 00 ff c0 42 32 0c 0a 41 88 48 ff 3b c7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_BA_2147845278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.BA!MSR"
        threat_id = "2147845278"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Iposiogseogjseiojgei" ascii //weight: 2
        $x_2_2 = "PartitionWizardEntryPoint" ascii //weight: 2
        $x_2_3 = "opifoipw490fgsjgiseirhj" ascii //weight: 2
        $x_2_4 = "kmnEGlDVCccMkxBiCNufvqMJKx" ascii //weight: 2
        $x_2_5 = "mJiQlIvdMiLNEQsgdIKUdfRoi" ascii //weight: 2
        $x_2_6 = "INCcYxTSGrTLXrHGFyuVEO" ascii //weight: 2
        $x_2_7 = "mTuorCaOwefCeuJZmlomRkjNNGCVl" ascii //weight: 2
        $x_2_8 = "DinxPcSbSYkurjlEKJbng" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_CDL_2147846248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.CDL!MTB"
        threat_id = "2147846248"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 63 d8 48 69 fb ?? ?? ?? ?? 48 89 fe 48 c1 ee ?? 48 c1 ff ?? 01 f7 89 fe c1 e6 ?? 01 fe 29 f3 48 63 db 8a 1c 0b 32 1c 02 48 8b [0-5] 88 1c 02 48 ff c0 48 39 85 88 02 00 00 77}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_SN_2147902959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.SN!MTB"
        threat_id = "2147902959"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JJxcc354ghFXR" ascii //weight: 2
        $x_2_2 = "HGDFZFsatrw5434grhjgfHFZDr36gh" ascii //weight: 2
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_CCIK_2147912025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.CCIK!MTB"
        threat_id = "2147912025"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ZrA1C1aTjcTGwKtxKeZYeOPTpGIJrY65l4J0kjziYE3CNSaIKR" ascii //weight: 5
        $x_1_2 = "OzeS@*+b6TxoPP!boccnR*T" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotet_GB_2147926385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotet.GB!MTB"
        threat_id = "2147926385"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb 41 8b d0 d3 e2 41 8b cb d3 e0 03 d0 41 0f be ?? 03 d0 41 2b d0 49 ff c1 44 8b c2}  //weight: 1, accuracy: Low
        $x_1_2 = {44 8b c0 44 8b ?? 41 8b cb 41 d3 ?? 8b cb d3 e0 8b c8 8d 42 ?? 66 83 f8 ?? 0f b7 c2 77 ?? 83 c0 ?? 41 2b ?? 41 03 ?? 03 c1 49 83 [0-2] 41 0f b7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

