rule Trojan_Win32_Dapato_DSK_2147741341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dapato.DSK!MTB"
        threat_id = "2147741341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d f0 83 e9 08 89 4d f0 8b 55 f8 8b 4d f0 d3 fa 81 e2 ff 00 00 00 8b 45 f4 03 45 ec 88 10 8b 4d ec 83 c1 01 89 4d ec}  //weight: 2, accuracy: High
        $x_1_2 = "2#JNMHXFA@2*EDC1V}JZf3OLKXMtJ|U" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dapato_PVD_2147750182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dapato.PVD!MTB"
        threat_id = "2147750182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c9 fd 43 03 00 89 0d ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 81 3d ?? ?? ?? ?? a5 02 00 00 8b 35 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 1e 46 3b f7 7c 05 00 e8}  //weight: 1, accuracy: Low
        $x_2_3 = {8b 58 04 33 da 89 58 04 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 78 08 33 f9 89 78 08}  //weight: 2, accuracy: Low
        $x_2_4 = {8a 03 8a 54 14 18 32 c2 88 03 8b 44 24 10 43 48 89 44 24 10 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dapato_PVS_2147754412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dapato.PVS!MTB"
        threat_id = "2147754412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 1c 28 30 1c 31 40 41 3b c7 7c ?? 33 c0 3b ca 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dapato_BD_2147836924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dapato.BD!MTB"
        threat_id = "2147836924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f3 a5 1b f5 32 24 00 00 94 08 00 f0 00 a2 f3 1d 1b f5 33 24 00 00 94 08 00 f0 00 a2 f3 9d 1b f5 34 24 00 00 94 08 00 f0 00 a2 f3 f9 1a f5 35 24 00 00 94}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dapato_GPC_2147903870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dapato.GPC!MTB"
        threat_id = "2147903870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {6d 00 6f 00 6e 00 65 00 79 00 6d 00 6f 00 74 00 69 00 76 00 65 00 73 00 2e 00 63 00 63}  //weight: 4, accuracy: High
        $x_4_2 = {6c 00 6d 00 61 00 6f 00 2e 00 65 00 78 00 65}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dapato_ADA_2147905699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dapato.ADA!MTB"
        threat_id = "2147905699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be f8 93 8a 00 b8 38 93 8a 00 0f 45 f0 33 ff 80 3e 00 74 49 8b d6 8d 59 28 52 8d 4d d8}  //weight: 1, accuracy: High
        $x_1_2 = {8b ec 51 8d 45 fc 50 68 40 9f 7c 00 68 00 00 00 80 ff 15 74 70 7c 00 f7 d8 1a c0 fe c0 8b e5 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dapato_AMME_2147906181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dapato.AMME!MTB"
        threat_id = "2147906181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 6a 00 8d 85 bc fb ff ff 50 ff 15 ?? ?? ?? ?? 85 c0 74 0f 6a 02 8d 85 bc fb ff ff 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "%s\\ytool" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dapato_MKV_2147930116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dapato.MKV!MTB"
        threat_id = "2147930116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 80 40 57 46 00 8a 92 40 57 46 00 c0 f8 04 c0 e2 02 24 03 32 c2 8b d7 88 04 13 8b 55 ?? 43 83 fa 10 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dapato_BAA_2147940393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dapato.BAA!MTB"
        threat_id = "2147940393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 fe 81 ef ?? ?? ?? ?? 03 c7 31 03 83 45 ec 04 6a 00 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dapato_GVA_2147940499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dapato.GVA!MTB"
        threat_id = "2147940499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 fe 81 ef 89 15 00 00 03 c7 31 03 83 45 ec 04 6a 00}  //weight: 2, accuracy: High
        $x_1_2 = {8b 13 03 55 ec 2b d0 89 13 8b 45 d4 03 45 a4 03 45 ec 03 f0 bf 89 15 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dapato_GVB_2147941183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dapato.GVB!MTB"
        threat_id = "2147941183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5a 2b d0 31 13 83 45 ec 04 6a 00}  //weight: 2, accuracy: High
        $x_1_2 = {8b 13 03 55 ec 2b d0 89 13 8b 45 d4 03 45 a4 03 45 ec 03 f0 bf 89 15 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

