rule Trojan_Win32_Ekstak_G_2147742532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.G!MTB"
        threat_id = "2147742532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 57 57 ff 15 54 83 50 00 01 05 70 d9 50 00 68 48 a1 50 00 8d 55 dc 52 ff 15 64 d9 50 00 89 7d fc}  //weight: 1, accuracy: High
        $x_1_2 = {c7 05 a4 dc 50 00 50 72 6f 63 c7 05 a8 dc 50 00 65 73 73 33 c7 05 ac dc 50 00 32 46 69 72 66 c7 05 b0 dc 50 00 73 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_G_2147742532_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.G!MTB"
        threat_id = "2147742532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 45 ec 89 45 ?? 53 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 c1 a9 ?? ?? ?? ?? e9 0b 00 a1 ?? ?? ?? ?? 33 05}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 8b 00 a3 ?? ?? ?? ?? 3b 45 ?? 0f 95 c1 53 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 c1 a9 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_BS_2147742794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.BS!MTB"
        threat_id = "2147742794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b da c1 e3 04 8d 05 ?? ?? ?? ?? 89 00 83 e1 03 61 8b 4d 08 8a 81 ?? ?? ?? ?? 84 c0 75 ?? a1 ?? ?? ?? ?? 8b 55 0c 03 c1 03 c2 8a 15 ?? ?? ?? ?? 30 10 83 3d ?? ?? ?? ?? 03 7e ?? 41 89 4d 08 eb ?? cf 81 f9 b6 04 00 00 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_BA_2147742861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.BA!MTB"
        threat_id = "2147742861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e0 0f 85 c0 75 ?? 8b 4d ?? 83 e9 10 89}  //weight: 1, accuracy: Low
        $x_1_2 = {03 76 0b 8b 55 ?? 83 c2 01 89 55 ?? eb 02 ff e1 81 7d ?? 04 05 00 00 7e 04 33 c0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_BB_2147743114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.BB!MTB"
        threat_id = "2147743114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 11 88 0c ?? 8a 8a ?? ?? ?? ?? 84 c9 75 12 8b 0d ?? ?? ?? ?? 03 ca 03 c1 8a 0d ?? ?? ?? ?? 30 08 83 3d ?? ?? ?? ?? 03 76 03 42 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {60 2b f0 86 c3 83 fe 39 8d 3d ?? ?? ?? ?? 88 07 03 07 ba 0d 00 00 00 83 e6 3a 66 8b c3 83 f9 0e 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_BC_2147743117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.BC!MTB"
        threat_id = "2147743117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 03 c1 42 8a 1c 0e 8b 75 0c 88 1c 30 8a 81 ?? ?? ?? ?? 84 c0 75 ?? a1 ?? ?? ?? ?? 8a 1d ?? ?? ?? ?? 03 c1 03 c6 30 18 83 3d ?? ?? ?? ?? 03 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_BD_2147743295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.BD!MTB"
        threat_id = "2147743295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 08 8b 0d ?? ?? ?? ?? 8a 14 08 32 15 ?? ?? ?? ?? 8b 45 0c 03 45 08 8b 0d ?? ?? ?? ?? 88 14 08 83 3d ?? ?? ?? ?? 03 76 ?? 8b 55 08 83 c2 01 89 55 08 eb ?? cc 81 7d 08 04 05 00 00 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_BE_2147743426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.BE!MTB"
        threat_id = "2147743426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 8d 14 30 8b 45 0c 8a 0c 31 88 0c 02 8a 8e ?? ?? ?? ?? 84 c9 75 ?? 8b 15 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 03 d6 03 c2 30 08 83 3d ?? ?? ?? ?? 03 76}  //weight: 1, accuracy: Low
        $x_1_2 = {89 03 8d 05 ?? ?? ?? ?? 2b 30 83 e1 05 8a 82 ?? ?? ?? ?? 84 c0 75 ?? a1 ?? ?? ?? ?? 8b 4d 0c 03 c2 03 c1 8a 0d ?? ?? ?? ?? 30 08 83 3d ?? ?? ?? ?? 03 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_BF_2147743537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.BF!MTB"
        threat_id = "2147743537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 8d 34 10 8b 45 0c 8a 0c 11 88 0c 06 8a 8a ?? ?? ?? ?? 84 c9 75 ?? 8b 0d ?? ?? ?? ?? 03 ca 03 c1 8a 0d ?? ?? ?? ?? 30 08 83 3d ?? ?? ?? ?? 03 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_2147743867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak!MTB"
        threat_id = "2147743867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 03 c3 46 8a 14 19 88 14 38 20 00 8a 06 b9 ?? ?? ?? ?? a2 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 c8 03 c3 46 8a 14 19 88 14 38 8a 83 ?? ?? ?? ?? 84 c0 75 11 a1 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 03 c3 03 c7 30 08 83 3d ?? ?? ?? ?? ?? 76 03 43 eb 06 e8 ?? ?? ?? ?? cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_BG_2147744035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.BG!MTB"
        threat_id = "2147744035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ef 10 8a 07 b9 ?? ?? ?? ?? a2 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 c8 47 8d 14 18 8b 45 0c 8a 0c 19 88 0c 02 8a 8b ?? ?? ?? ?? 84 c9 75 ?? 8b 15 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 03 d3 03 c2 30 08 83 3d ?? ?? ?? ?? 03 76}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d9 03 c8 46 8a 1c 03 88 1c 39 8a 88 ?? ?? ?? ?? 84 c9 75 ?? 8b 0d ?? ?? ?? ?? 8a 1d ?? ?? ?? ?? 03 c8 03 cf 30 19 39 15 ?? ?? ?? ?? 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_CA_2147744753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CA!MTB"
        threat_id = "2147744753"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {84 c0 75 14 a1 ?? ?? ?? ?? 8b ?? 0c 03 ?? 03 ?? 8a ?? ?? ?? ?? ?? 30 ?? 83 3d ?? ?? ?? ?? 03 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_CB_2147744833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CB!MTB"
        threat_id = "2147744833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c6 8b f0 33 ?? 3d 4e e6 40 bb 74 0c f7 05 ?? ?? ?? ?? 00 00 ff ff 75 05 b8 4f e6 40 bb a3 ?? ?? ?? ?? f7 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_A_2147744913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.A!MTB"
        threat_id = "2147744913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\\\.\\avgSP_Open" ascii //weight: 2
        $x_2_2 = "\\\\.\\avgSP_Open" wide //weight: 2
        $x_5_3 = "\\BaseNamedObjects\\shell.{A48F1A32-A340-11D1-BC6B-00A0C90312E1}" ascii //weight: 5
        $x_5_4 = "\\BaseNamedObjects\\shell.{A48F1A32-A340-11D1-BC6B-00A0C90312E1}" wide //weight: 5
        $x_1_5 = " security " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_DSK_2147744914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.DSK!MTB"
        threat_id = "2147744914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {29 f8 5f 57 bf ?? ?? ?? ?? 81 f7 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 81 f7 ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 81 f7 ?? ?? ?? ?? 29 f8 5f 31 c3}  //weight: 2, accuracy: Low
        $x_2_2 = {31 d8 5b 51 b9 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? e9}  //weight: 2, accuracy: Low
        $x_2_3 = {29 c7 58 53 bb ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 31 df 5b 50}  //weight: 2, accuracy: Low
        $x_2_4 = {01 d9 5b 50 b8 ?? ?? ?? ?? 81 f0 ?? ?? ?? ?? 81 e8 ?? ?? ?? ?? 81 c0 ?? ?? ?? ?? 81 f0 ?? ?? ?? ?? 31 c1 58 52}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_CC_2147745085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CC!MTB"
        threat_id = "2147745085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 4e e6 40 bb 74 ?? f7 05 ?? ?? ?? ?? 00 00 ff ff 0f 85 ?? ?? ?? ?? b8 83 9a de cb}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 4e e6 40 bb 74 ?? f7 05 ?? ?? ?? ?? 00 00 ff ff 75 ?? b8 4f e6 40 bb}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 4e e6 40 bb 74 ?? f7 05 ?? ?? ?? ?? 00 00 ff ff 0f 85 ?? ?? ?? ?? b8 ?? ?? ?? ?? 81}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 4e e6 40 bb c6 44 24 ?? 74 c6 44 24 ?? 70 c6 44 24 ?? 72 c6 44 24 ?? 79 c6 44 24 ?? 2e c6 44 24 ?? 64 74 ?? a9 00 00 ff ff 74 ?? f7 d0}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 0a 58 50 ff 75 9c 56 56 ff 15 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 45 a0 50 e8 ?? ?? ?? ?? 8b 45 ec 8b 08 8b 09 89 4d 98 50 51 e8 ?? ?? ?? ?? 59 59 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ekstak_CE_2147745400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CE!MTB"
        threat_id = "2147745400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 36 3c ec ?? 81 c1 ff 09 d8 11 eb ?? 58 33 fe ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 33 c6 33 c7 5f 3d 4e e6 40 bb 0f 84 ?? ?? ?? ?? e9 ?? ?? ?? ?? 81 e9 16 64 52 57 29 c8 59 57}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 d2 e3 5b 84 81 e9 6e 44 93 59 81 c1 c6 14 8a 89 81 e9 a7 42 50 41 01 c8 59 29 c1 58 89 04 29 59 a1 ?? ?? ?? ?? 3d 4e e6 40 bb 74 ?? a9 00 00 ff ff 0f 85}  //weight: 1, accuracy: Low
        $x_2_3 = {6a 0a 58 50 ff 75 9c 56 56 ff 15 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 45 a0 50 e8 ?? ?? ?? ?? 8b 45 ec 8b 08 8b 09 89 4d 98 50 51 e8 ?? ?? ?? ?? 59 59 c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_CF_2147745512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CF!MTB"
        threat_id = "2147745512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d8 f1 dd 1d ?? ?? ?? ?? 8d 35 ?? ?? ?? ?? 8d 3d ?? ?? ?? ?? a5 81 7d ?? 4e e6 40 bb 74 ?? 8b 0d ?? ?? ?? ?? 81 e1 00 00 ff ff 85 c9 75 ?? c7 45 ?? 4f e6 40 bb}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 0a 58 50 ff 75 9c 56 56 ff 15 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 45 a0 50 e8 ?? ?? ?? ?? 8b 45 ec 8b 08 8b 09 89 4d 98 50 51 e8 ?? ?? ?? ?? 59 59 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_CH_2147745857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CH!MTB"
        threat_id = "2147745857"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b d3 58 0f ?? ?? ?? ?? ?? 81 7d e0 4e e6 40 bb 74 ?? 8b 15 ?? ?? ?? ?? 81 e2 00 00 ff ff 85 d2 75 ?? c7 45 ?? 4f e6 40 bb}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 0a 58 50 ff 75 9c 56 56 ff 15 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 45 a0 50 e8 ?? ?? ?? ?? 8b 45 ec 8b 08 8b 09 89 4d 98 50 51 e8 ?? ?? ?? ?? 59 59 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_PVD_2147746160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.PVD!MTB"
        threat_id = "2147746160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 4d ec 8b 55 ec 03 51 3c 89 55 fc b8 ?? ?? ?? ?? 3d ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? ba ?? ?? ?? ?? 81 fa ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 8b 45 fc 8b 4d ec 03 48 28 89 4d f0}  //weight: 3, accuracy: Low
        $x_3_2 = {33 d1 d3 e2 81 fa a3 de 43 e4 0f 84 b3 00 00 00 f7 c2 fc 0f a1 19 e9 0b 00 b9 ?? ?? ?? ?? 53 b8}  //weight: 3, accuracy: Low
        $x_3_3 = {33 d3 c1 ea 02 d3 d8 f7 c2 e7 c8 76 b3 0f 84 12 00 a5 b8 ?? ?? ?? ?? 50 3d ?? ?? ?? ?? 0f 84}  //weight: 3, accuracy: Low
        $x_3_4 = {a5 d3 c0 81 e2 ?? ?? ?? ?? c1 e2 03 85 d3 0f 92 c3 e9 06 00 8d 3d}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_CI_2147746240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CI!MTB"
        threat_id = "2147746240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 14 2e 5e 33 c3 33 c2 3d 4e e6 40 bb 74 ?? f7 05 ?? ?? ?? ?? 00 00 ff ff 0f 85 ?? ?? ?? ?? b8 2b 25 cd b5 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {31 c8 59 89 3c 28 58 5f 3d 4e e6 40 bb 0f 84 ?? ?? ?? ?? a9 00 00 ff ff e9 ?? ?? ?? ?? eb ?? 81 c2 73 54 c4 ea 31 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_GM_2147748593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GM!MTB"
        threat_id = "2147748593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {84 81 c2 5c b9 85 30 81 c2 69 9a 5b 8b 29 d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_S_2147756308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.S!MSR"
        threat_id = "2147756308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 56 2c 8a 0c 18 52 88 0d ?? ?? ?? 00 ff 57 08 8a 0d ?? ?? ?? 00 8a 54 24 18 02 c1 8b 0d ?? ?? ?? 00 32 c2 a2 ?? ?? ?? 00 88 04 19 8b 44 24 14 83 f8 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_SKR_2147759794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.SKR!MSR"
        threat_id = "2147759794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 03 cf 30 11 83 3d ?? ?? ?? 00 02 3d 44 07 00 00 1d 00 8a 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_SA_2147760152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.SA!MSR"
        threat_id = "2147760152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4e 2c 8a 1c 28 51 ff 57 08 8a 54 24 1c 02 c3 32 c2 8b 15 ?? ?? ?? 00 88 04 2a 8b 44 24 18 83 f8 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_SKA_2147760153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.SKA!MSR"
        threat_id = "2147760153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 02 88 14 39 8a 88 ?? ?? ?? 00 84 c9 75 12 8b 0d ?? ?? ?? 00 8a 15 ?? ?? ?? 00 03 c8 03 cf 30 11 40 3d 44 07 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_SM_2147773310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.SM!MSR"
        threat_id = "2147773310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c3 03 c1 6a 00 6a 00 6a 00 8a 08 6a 00 32 ca 6a 00 88 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_SM_2147773310_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.SM!MSR"
        threat_id = "2147773310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b7 03 2a fb a1 ?? ?? ?? 00 03 f8 66 33 c0 8a 65 f8 80 c7 14 0a c3 30 27}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_MR_2147778121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.MR!MTB"
        threat_id = "2147778121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "retry_uploadFile" ascii //weight: 1
        $x_1_2 = "PutPlan" ascii //weight: 1
        $x_1_3 = "localRoot" ascii //weight: 1
        $x_1_4 = "Detected WS_FTP server, using relative paths" ascii //weight: 1
        $x_1_5 = "SyncDeleteRemote" ascii //weight: 1
        $x_1_6 = "sendingCommand" ascii //weight: 1
        $x_1_7 = "epsv_reply" ascii //weight: 1
        $x_1_8 = "Malformed PASV reply" ascii //weight: 1
        $x_1_9 = "FtpCmdResp" ascii //weight: 1
        $x_1_10 = "TrustedPeople" ascii //weight: 1
        $x_1_11 = "pubKeyCurve" ascii //weight: 1
        $x_1_12 = "eccVerifyHashK" ascii //weight: 1
        $x_1_13 = "loadAnyEccAsn" ascii //weight: 1
        $x_1_14 = "loadEccPoint" ascii //weight: 1
        $x_1_15 = "shutdownChannel" ascii //weight: 1
        $x_1_16 = "DbgPrompt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_MS_2147780542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.MS!MTB"
        threat_id = "2147780542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DESTROYKEYDLG" ascii //weight: 1
        $x_1_2 = "PASSWORD_LOAD_DLG" ascii //weight: 1
        $x_1_3 = "Enter security password" ascii //weight: 1
        $x_1_4 = "t Explorer_Server" ascii //weight: 1
        $x_1_5 = "sqlite3.dll" ascii //weight: 1
        $x_1_6 = "_except_handler3" ascii //weight: 1
        $x_1_7 = "__getmainargs" ascii //weight: 1
        $x_1_8 = "__setusermatherr" ascii //weight: 1
        $x_1_9 = "__p__fmode" ascii //weight: 1
        $x_1_10 = "_controlfp" ascii //weight: 1
        $x_1_11 = "OffsetRect" ascii //weight: 1
        $x_1_12 = "SetCapture" ascii //weight: 1
        $x_1_13 = "DllInstall" ascii //weight: 1
        $x_1_14 = "CsrFreeCaptureBuffer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_AMK_2147787591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.AMK!MTB"
        threat_id = "2147787591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "borlndmm" ascii //weight: 3
        $x_3_2 = "Local\\FastMM_PID" ascii //weight: 3
        $x_3_3 = "should never get here" ascii //weight: 3
        $x_3_4 = "DHLLPPTTXX" ascii //weight: 3
        $x_3_5 = "SearchPathW" ascii //weight: 3
        $x_3_6 = "All Picture Files|*.bmp;*.wmf;*.emf;*.ico;*.dib;*.cur;*.gif;*" ascii //weight: 3
        $x_3_7 = "LoaderLock" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_DE_2147820427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.DE!MTB"
        threat_id = "2147820427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ac 30 41 00 14 05 50 55 49 4e 54 f8 10 40 00 02 00 00 00 00 c0 30 41 00 14 0a 50 4c 69 73 74 45 6e 74 72 79}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_HMQ_2147827646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.HMQ!MTB"
        threat_id = "2147827646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "duPAQp)" ascii //weight: 1
        $x_1_2 = "Z3u]e9N9" ascii //weight: 1
        $x_1_3 = "cY|g%[|o'~" ascii //weight: 1
        $x_1_4 = "waveInAddBuffer" ascii //weight: 1
        $x_1_5 = "kLoaderLock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_NH_2147827955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.NH!MTB"
        threat_id = "2147827955"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 fc 33 01 55 68 ?? ?? ?? ?? 01 ff 30 64 89 ?? 3b 01 7e}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b6 d3 88 01 17 b9 ?? ?? ?? ?? 01 c6 33 d2 f7 f1 89 01 4b 85 f6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_HLG_2147828591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.HLG!MTB"
        threat_id = "2147828591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 0c 53 56 57 e9 ?? ?? ?? 01}  //weight: 1, accuracy: Low
        $x_1_2 = "@.rigc" ascii //weight: 1
        $x_1_3 = "LdrUnlockLoaderLock" ascii //weight: 1
        $x_1_4 = "@GetProcAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_NEAA_2147836511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.NEAA!MTB"
        threat_id = "2147836511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 d2 8a 54 06 ff 8a 92 20 20 52 01 33 c9 8a 4c 07 ff 8a 00 20 20 52 00 3a ca 74 0c 33 c0 8a c2 33 01 8a d1 2b c2 eb 0b}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RB_2147838338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RB!MTB"
        threat_id = "2147838338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 68 90 40 65 00 e8 12 65 fb ff e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RB_2147838338_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RB!MTB"
        threat_id = "2147838338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 0c 53 56 57 e8 c2 ee f5 ff 89 45 fc e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RB_2147838338_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RB!MTB"
        threat_id = "2147838338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 0c 57 e8 84 ff ff ff b9 41 00 00 00 33 c0 bf 30 e6 4c 00 f3 ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RB_2147838338_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RB!MTB"
        threat_id = "2147838338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 56 68 54 4f 65 00 e8 92 63 fb ff 8b 45 08 83 c4 04 68 54 4f 65 00 50 e8 b1 64 fb ff e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RB_2147838338_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RB!MTB"
        threat_id = "2147838338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 10 53 56 57 8b 45 08 50 e8 ?? e8 f5 ff 83 c4 04 25 ff ff 00 00 89 45 fc e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RB_2147838338_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RB!MTB"
        threat_id = "2147838338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 08 56 57 ff 15 d8 c1 4b 00 68 ?? e0 4b 00 6a 01 6a 00 8b f8 ff 15 dc c1 4b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RB_2147838338_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RB!MTB"
        threat_id = "2147838338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f0 11 f7 d8 1b c0 40 83 c4 ?? c3 33 c0 5f 83 c4}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 56 e8 f6 69 fb ff e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RB_2147838338_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RB!MTB"
        threat_id = "2147838338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 08 a3 e0 ca 65 00 ff 15 54 95 65 00 a1 e0 ca 65 00 85 c0 74 13 68 a8 bb 45 01 56 ff 15 58 90 65 00 56 ff 15 54 90 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RB_2147838338_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RB!MTB"
        threat_id = "2147838338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 81 ec 04 01 00 00 56 57 b9 41 00 00 00 33 c0 8d bd fc fe ff ff f3 ab 8b 45 10 8d 8d fc fe ff ff 50 51 ff 15 60 40 4b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RB_2147838338_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RB!MTB"
        threat_id = "2147838338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 56 8b 75 14 56 6a 00 ff 15 50 67 65 00 56 e8 18 a1 20 00 e9}  //weight: 5, accuracy: High
        $x_1_2 = "Shredder.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RB_2147838338_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RB!MTB"
        threat_id = "2147838338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 56 ff 15 70 f0 46 00 8b 75 14 68 50 1c 27 01 56 ff 15 58 f0 46 00 e9}  //weight: 5, accuracy: High
        $x_1_2 = "ShutdownScheduler.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RB_2147838338_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RB!MTB"
        threat_id = "2147838338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 8b 45 14 50 ff 15 94 f0 46 00 ff 15 ?? f0 46 00 3d ?? ?? ?? ?? 75 05 e8 21 b1 01 00 e9}  //weight: 5, accuracy: Low
        $x_1_2 = "ShutdownScheduler.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 68 24 1f 65 00 e8 42 65 fb ff e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 0c 53 56 57 e8 d2 ee f5 ff 89 45 fc e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 10 53 56 57 e8 82 e8 f5 ff 89 45 fc e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 56 57 68 5f bf 65 00 e8 a0 55 fb ff 8b f0 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 10 53 56 57 e8 62 eb f5 ff 0f be c0 89 45 fc e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 04 50 ff 15 00 e0 64 00 8b 44 24 0c 8b 4c 24 10 0b c1 5e 83 f0 11 f7 d8 1b c0 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 0c 57 68 70 0a 4d 00 e8 1f ed fc ff b9 41 00 00 00 33 c0 bf 00 06 4d 00 f3 ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 56 8b 75 14 56 ff 15 a8 f0 46 00 56 ff 15 00 f2 46 00 85 c0 74 07 56 ff 15 a4 f0 46 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 33 c0 80 e2 3f 8a c2 0d c0 ff 00 00 83 c4 0c c3 90 90 90 90 55 8b ec ff 15 10 53 65 00 e8 82 ff ff ff e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 29 ff 15 a4 92 65 00 85 c0 a3 e0 ca 65 00 74 18 56 8b 75 14 68 a8 bb 45 01 56 ff 15 50 90 65 00 56 ff 15 4c 90 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 15 00 00 65 00 68 34 30 65 00 6a 00 8d 4c 24 10 6a 01 51 c7 44 24 18 0c 00 00 00 89 74 24 1c c7 44 24 20 00 00 00 00 ff 15 2c 02 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 f1 a3 ?? ?? ?? 00 e8 ?? 00 00 00 6a 00 6a 01 e8 19 00 6a 32 e8 ?? ?? ?? 00 01 05 ?? ?? ?? 00 e8 ?? ?? ?? 00 8b c8 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 46 07 00 00 59 a3 ?? 0b 08 01 e8 ?? 07 00 00 8b c8 33 d2 b8 ?? ?? ?? ?? f7 f1 31 05 7c 0b 08 01 e8 ?? 0d 00 00 33 c0 50 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 15 00 f0 64 00 68 34 00 65 00 6a 00 8d 4c 24 20 6a 01 51 c7 44 24 28 0c 00 00 00 89 74 24 2c c7 44 24 30 00 00 00 00 ff 15 38 f0 64 00 8b f0 ff 15 28 f2 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 03 c8 89 0d ?? ?? ?? 00 e8 ?? ?? ?? 00 8b c8 b8 ?? ?? ?? ?? 33 d2 8b 1d ?? ?? ?? 00 f7 f1 33 d8 89 1d ?? ?? ?? 00 e8 0d 00 6a 32 e8 ?? ?? ?? 00 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 56 8b 75 14 56 e8 6b a0 20 00 56 ff 15 54 66 65 00 ff 15 58 66 65 00 e9}  //weight: 5, accuracy: High
        $x_1_2 = "FoldAlyzer.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 56 8b 75 14 56 e8 a9 96 20 00 56 ff 15 a8 51 65 00 ff 15 ac 51 65 00 e9}  //weight: 5, accuracy: High
        $x_1_2 = "FileAlyzer.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 57 56 8b 7d 14 3b 7d 0c a9 00 00 80 00 57 e8 ?? 8d 06 00 e9}  //weight: 5, accuracy: Low
        $x_1_2 = "CJngBackup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RC_2147839298_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RC!MTB"
        threat_id = "2147839298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c0 5e 5d c3 8b c6 5e 5d c3 ?? ?? ?? ?? ?? 55 8b ec 56 8b 75 14 56 6a 00 ff 15 ?? 67 65 00 56 e8 ?? ?? 20 00 e9}  //weight: 5, accuracy: Low
        $x_1_2 = "Shredder.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RD_2147839482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RD!MTB"
        threat_id = "2147839482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 e8 97 65 fb ff e8 12 65 fb ff e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RD_2147839482_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RD!MTB"
        threat_id = "2147839482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 10 53 56 57 e8 e2 e9 f5 ff 89 45 fc e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RD_2147839482_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RD!MTB"
        threat_id = "2147839482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 68 34 2f 65 00 e8 c2 64 fb ff e8 8d 65 fb ff e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RD_2147839482_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RD!MTB"
        threat_id = "2147839482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6a 2c ff 15 d8 94 65 00 85 c0 74 14 e8 cf 54 fb ff e8 7a 02 00 00 e8 f5 5b 09 00 e8 00 b5 12 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RD_2147839482_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RD!MTB"
        threat_id = "2147839482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 b9 00 00 00 8b c8 b8 ?? ?? ?? ?? 33 d2 f7 f1 31 05 ?? ?? ?? ?? e8 ?? ?? 00 00 33 c0 50 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RD_2147839482_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RD!MTB"
        threat_id = "2147839482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 45 14 56 50 ff 15 30 94 46 00 3d ?? ?? ?? ?? 74 14 8b 35 f0 97 46 00 6a 00 48 50 68 bb 00 00 00 ff 75 14 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RD_2147839482_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RD!MTB"
        threat_id = "2147839482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 56 57 68 98 ?? 54 00 68 48 ?? 54 00 e8 cb ?? fa ff b9 41 00 00 00 33 c0 bf 50 ?? 54 00 f3 ab e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RD_2147839482_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RD!MTB"
        threat_id = "2147839482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce 8b 7d 04 03 cf 8b e8 03 00 0c 3b cd 75 05 ?? ?? ?? ?? 2a 8b ?? ?? ?? ?? 00 0c 24 8b 7b 08 03 7b 0c 2c f9 89 7c 24 04 2b 00 89 73 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RD_2147839482_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RD!MTB"
        threat_id = "2147839482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 f1 a3 ?? ?? ?? 00 e8 ?? 00 00 00 6a 00 6a 00 e8 19 00 6a 32 e8 ?? ?? ?? 00 01 05 ?? ?? ?? 00 e8 ?? ?? ?? 00 8b c8 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RD_2147839482_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RD!MTB"
        threat_id = "2147839482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 15 a4 80 65 00 e8 44 7b df ff e8 4f d7 da ff 68 ?? 03 00 00 e8 25 f6 ff ff 8b 15 e0 c4 65 00 03 d0 83 c4 04 89 15 e0 c4 65 00 e8 5f 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RD_2147839482_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RD!MTB"
        threat_id = "2147839482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 32 33 c2 a3 ?? ?? ?? 00 e8 ?? ?? ?? 00 01 05 ?? ?? ?? 00 e8 ?? ?? ?? 00 8b c8 b8 ?? ?? ?? ?? 33 d2 f7 f1 a3 ?? ?? ?? 00 e8 ?? ?? fe ff 8b 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 52 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RD_2147839482_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RD!MTB"
        threat_id = "2147839482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {55 8b ec 51 56 57 68 ?? cf 65 00 e8 ?? 55 fb ff 8b f0 e9}  //weight: 4, accuracy: Low
        $x_1_2 = {40 00 00 40 5f 65 63 6f 72 65 5f}  //weight: 1, accuracy: High
        $x_1_3 = {40 00 00 40 2e 65 63 6f 72 65}  //weight: 1, accuracy: High
        $x_1_4 = {40 00 00 40 5f 64 63 6f 72 65 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_RE_2147839483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RE!MTB"
        threat_id = "2147839483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 c0 5e 5d c3 8b c6 5e 5d c3 90 90 90 90 90 55 8b ec 8b 45 14 50 ff 15 e8 94 65 00 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RE_2147839483_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RE!MTB"
        threat_id = "2147839483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 53 56 e8 16 65 fb ff e9}  //weight: 1, accuracy: High
        $x_1_2 = {40 00 00 40 2e ?? 64 65 78 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RE_2147839483_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RE!MTB"
        threat_id = "2147839483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 4d b0 e8 f0 93 07 00 68 9c 20 6b 00 8d 4d b0 e8 43 94 07 00 b9 41 00 00 00 33 c0 bf a4 29 72 00 f3 ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RE_2147839483_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RE!MTB"
        threat_id = "2147839483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 5e 5d c3 8b c6 5e 5d c3 ?? ?? ?? ?? ?? 55 8b ec 56 8b 75 14 56 ff 15 ?? ?? 65 00 56 e8 ?? ?? 20 00 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RE_2147839483_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RE!MTB"
        threat_id = "2147839483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 56 e8 36 65 fb ff e9}  //weight: 1, accuracy: High
        $x_1_2 = {53 8b 1d e4 33 65 00 56 8b 74 24 0c 57 6a 00 6a 00 6a 00 8d 46 1c 83 cf ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RE_2147839483_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RE!MTB"
        threat_id = "2147839483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 56 57 68 71 69 4c 00 68 a4 30 4c 00 ff 15 3c 10 4c 00 50 e8 74 0d fd ff b9 41 00 00 00 33 c0 bf 00 65 4c 00 f3 ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RE_2147839483_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RE!MTB"
        threat_id = "2147839483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 4c 24 0c 66 33 c0 80 e1 3f 5e 8a c1 83 c8 c0 83 c4 10 c3 90 90 90 90 90 90 90 90 90 90 90 90 90 90 55 8b ec e8 58 ff ff ff e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RE_2147839483_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RE!MTB"
        threat_id = "2147839483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 f1 a3 ?? ?? ?? 00 e8 ?? ?? fe ff 8b 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 52 50 e8 19 00 6a 32 e8 ?? ?? ?? 00 01 05 ?? ?? ?? 00 e8 ?? ?? ?? 00 8b c8 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RF_2147840597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RF!MTB"
        threat_id = "2147840597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 53 56 57 b9 41 00 00 00 33 c0 bf 24 d4 4c 00 f3 ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RF_2147840597_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RF!MTB"
        threat_id = "2147840597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 15 04 b0 65 00 a1 04 15 66 00 50 ff 15 00 b0 65 00 b8 90 01 00 00 8b d0 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RF_2147840597_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RF!MTB"
        threat_id = "2147840597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 53 56 57 e8 75 ff ff ff 0f be d8 b9 41 00 00 00 33 c0 bf 54 f7 4c 00 f3 ab e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RF_2147840597_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RF!MTB"
        threat_id = "2147840597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a1 c8 2c 47 00 8b 4d 14 8b 15 a4 5e 48 00 50 51 52 6a 00 ff 15 ?? f5 46 00 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RF_2147840597_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RF!MTB"
        threat_id = "2147840597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 0c 8d 45 88 50 8d 85 88 fa ff ff ff d0 59 5f 5e 5b c9 c3 55 8b ec 56 e8 8c 63 e4 ff a3 70 6d 85 00 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RF_2147840597_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RF!MTB"
        threat_id = "2147840597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 c0 5e 5d c3 8b c6 5e 5d c3 90 90 90 90 90 55 8b ec 56 8b 75 14 56 e8 39 a1 20 00 56 ff 15 68 60 65 00 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RF_2147840597_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RF!MTB"
        threat_id = "2147840597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 56 8b 75 14 6a 00 6a 00 56 ff 15 ?? e4 46 00 56 ff 15 ?? e4 46 00 ff 15 ?? e4 46 00 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RF_2147840597_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RF!MTB"
        threat_id = "2147840597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 57 56 8b 7d 14 6a 03 e8 ?? ?? 04 00 59 e9 ?? ?? ?? 00}  //weight: 5, accuracy: Low
        $x_1_2 = ".img" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RF_2147840597_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RF!MTB"
        threat_id = "2147840597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 32 e8 18 10 20 00 83 c4 04 8b 0d b4 fd 64 00 03 c8 89 0d b4 fd 64 00 e8 22 dd 16 00 8b c8 b8 ?? ?? ?? ?? 33 d2 f7 f1 a3 98 fc 64 00 e8 3d 00 00 00 6a 00 6a 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RF_2147840597_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RF!MTB"
        threat_id = "2147840597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 46 07 00 00 59 a3 a0 0b 08 01 e8 9b 07 00 00 8b c8 33 d2 b8 ?? ?? ?? ?? f7 f1 31 05 7c 0b 08 01 e8 ?? 0c 00 00 33 c0 50 50 e8 68 00 00 00 a3 80 0b 08 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RF_2147840597_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RF!MTB"
        threat_id = "2147840597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 84 24 20 01 00 00 53 58 58 53 c7 84 24 20 01 00 00 53 58 58 53 c7 84 24 20 01 00 00 53 58 58 53 c7 84 24 20 01 00 00 53 58 58 53 c7 84 24 20 01 00 00 53 58 58 53 c3 55 8b ec 83 ec 03 83 e4 f8 83 c4 04 56 56 6a 03 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RF_2147840597_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RF!MTB"
        threat_id = "2147840597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c0 5e 5d c3 8b c6 5e 5d c3 ?? ?? ?? ?? ?? 55 8b ec 56 8b 75 14 56 e8 ?? 9f 20 00 ff 15 ?? ?? 65 00 e9}  //weight: 5, accuracy: Low
        $x_1_2 = "Smart Turn Off COMputer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RK_2147842777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RK!MTB"
        threat_id = "2147842777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 08 56 57 e8 e3 6d fb ff 8b f8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RK_2147842777_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RK!MTB"
        threat_id = "2147842777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 08 56 57 68 3e e1 64 00 e8 1e 6e fb ff 8b f8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RK_2147842777_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RK!MTB"
        threat_id = "2147842777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {55 8b ec 83 ec 08 56 57 e8 23 6e fb ff 8b f8 e9}  //weight: 4, accuracy: High
        $x_1_2 = {40 00 00 40 2e 47 49 46}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RK_2147842777_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RK!MTB"
        threat_id = "2147842777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {df 6c 24 04 dc 05 58 d0 65 00 dd 1d 58 d0 65 00 ff 15 b0 b2 65 00 a1 04 05 66 00 50 ff 15 0c b2 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RK_2147842777_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RK!MTB"
        threat_id = "2147842777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 05 7c 4b 08 01 68 ?? ?? ?? ?? e8 ?? 00 00 00 59 a3 ?? 4b 08 01 e8 ?? 00 00 00 8b c8 b8 ?? ?? ?? ?? 33 d2 f7 f1 31 05 ?? 4b 08 01 e8 ?? ?? 00 00 33 c0 50 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_EM_2147844976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.EM!MTB"
        threat_id = "2147844976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {55 8b ec 56 8b 75 14 56 e8 ?? ?? ?? ?? 68 38 9c 65 00 c7 05 38 9c 65 00 44 00 00 00 ff 15 ?? ?? ?? ?? e9}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_EM_2147844976_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.EM!MTB"
        threat_id = "2147844976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2a 01 00 00 00 81 7c 8b 00 a3 e0 87 00 00 be 0a 00 d4 bd 14 99 22 a4 87 00 00 d4 00 00 52 85 42 1a}  //weight: 5, accuracy: High
        $x_5_2 = {2a 01 00 00 00 a3 18 88 00 c5 7c 84 00 00 be 0a 00 d4 bd 14 99 66 40 84 00 00 d4 00 00 76 d1 33 f7}  //weight: 5, accuracy: High
        $x_5_3 = {2a 01 00 00 00 e9 56 87 00 0b bb 83 00 00 be 0a 00 d4 bd 14 99 91 7e 83 00 00 d4 00 00 b0 06 f5 c5}  //weight: 5, accuracy: High
        $x_1_4 = "SplitControlVB" wide //weight: 1
        $x_1_5 = "VBMailAgent" wide //weight: 1
        $x_1_6 = "VBScrollLIB" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_RG_2147845730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RG!MTB"
        threat_id = "2147845730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e0 46 00 ff d0 68 30 10 47 00 68 d4 1a 47 00 ff 15 ?? e0 46 00 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RG_2147845730_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RG!MTB"
        threat_id = "2147845730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 53 56 e8 c5 ff ff ff e9}  //weight: 1, accuracy: High
        $x_1_2 = {40 00 00 40 2e ?? 64 65 78 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RG_2147845730_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RG!MTB"
        threat_id = "2147845730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 53 56 57 e8 25 ff ff ff e8 60 ff ff ff 8b d8 b9 41 00 00 00 33 c0 bf 64 f7 4c 00 f3 ab e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RG_2147845730_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RG!MTB"
        threat_id = "2147845730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 e9 a4 65 00 8b f0 e8 9b ff ff ff 8b 7d 14 83 c4 04 85 f6 74 0b 8d 55 fc 52 57 ff 15 50 43 65 00 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RG_2147845730_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RG!MTB"
        threat_id = "2147845730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 56 e8 e7 ca f6 ff 68 38 b9 85 00 6a 00 ff 15 98 44 65 00 50 e8 d4 fe ff ff 31 05 78 ac 65 00 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RG_2147845730_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RG!MTB"
        threat_id = "2147845730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {dc 05 58 e0 65 00 dd 1d 58 e0 65 00 ff 15 a4 b4 65 00 68 64 e0 65 00 ff 15 88 b4 65 00 50 ff 15 84 b4 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RG_2147845730_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RG!MTB"
        threat_id = "2147845730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 56 8b 75 14 56 ff 15 ?? e4 46 00 ff 15 ?? e4 46 00 68 70 1c 47 00 ff 15 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RG_2147845730_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RG!MTB"
        threat_id = "2147845730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 0c 53 56 c7 45 f4 cc cc cc cc c7 45 f8 cc cc cc cc c7 45 fc cc cc cc cc e8 0c 64 fb ff 89 45 fc e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RG_2147845730_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RG!MTB"
        threat_id = "2147845730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 33 c0 80 e2 3f 8a c2 0d c0 ff 00 00 83 c4 0c c3 90 90 90 90 55 8b ec 8b 45 14 50 e8 4a 98 20 00 e8 7f ff ff ff e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RG_2147845730_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RG!MTB"
        threat_id = "2147845730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 15 00 40 65 00 68 44 70 65 00 6a 00 8d 4c 24 10 6a 01 51 c7 44 24 18 0c 00 00 00 89 74 24 1c c7 44 24 20 00 00 00 00 ff 15 a8 42 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RG_2147845730_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RG!MTB"
        threat_id = "2147845730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ff 15 58 82 46 00 6a 00 ff 15 40 86 46 00 85 c0 7d 12 3d 06 01 01 80 75 11 68 00 b1 46 00 ff d3 85 c0 74 06 ff 15 44 86 46 00 e9}  //weight: 5, accuracy: High
        $x_1_2 = "AcroBroker.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RH_2147848153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RH!MTB"
        threat_id = "2147848153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec a1 f0 d4 46 00 ff 75 14 ff d0 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RH_2147848153_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RH!MTB"
        threat_id = "2147848153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 68 84 a0 65 00 e8 45 57 fb ff 8b f0 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RH_2147848153_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RH!MTB"
        threat_id = "2147848153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 56 e8 b7 6a fb ff e9}  //weight: 5, accuracy: High
        $x_1_2 = {40 00 00 40 2e 6d 70 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RH_2147848153_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RH!MTB"
        threat_id = "2147848153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 56 57 68 04 01 00 00 6a 00 68 a8 ee 4c 00 e8 fc 01 00 00 83 c4 0c e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RH_2147848153_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RH!MTB"
        threat_id = "2147848153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 15 6c 32 65 00 8b f0 ff 15 00 33 65 00 85 c0 74 1a 8d 4c 24 04 51 50 ff 15 fc 32 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RH_2147848153_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RH!MTB"
        threat_id = "2147848153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 56 57 68 88 32 65 00 e8 90 62 fb ff e9}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 51 56 57 68 88 22 65 00 e8 90 62 fb ff e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_RH_2147848153_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RH!MTB"
        threat_id = "2147848153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 65 00 8d 55 f8 c7 45 f8 08 00 00 00 52 c7 45 fc 04 00 00 00 ff 15 ?? 30 65 00 c7 45 fc 00 00 00 00 ff 15 ?? 31 65 00 ff 15 ?? ?? 65 00 e9}  //weight: 5, accuracy: Low
        $x_1_2 = "DiskWriteCopy_Exe.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RI_2147848154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RI!MTB"
        threat_id = "2147848154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 08 56 e8 c4 6d fb ff e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RI_2147848154_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RI!MTB"
        threat_id = "2147848154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 10 53 56 57 6a 00 e8 70 0b f6 ff 89 45 fc e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RI_2147848154_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RI!MTB"
        threat_id = "2147848154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 56 e8 27 6a fb ff e9}  //weight: 5, accuracy: High
        $x_1_2 = {40 00 00 40 2e 73 63 61 72 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RI_2147848154_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RI!MTB"
        threat_id = "2147848154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 56 8b 75 14 56 ff 15 ?? e0 46 00 6a 00 e8 ?? 3b 04 00 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RI_2147848154_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RI!MTB"
        threat_id = "2147848154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 4d f8 51 50 ff 15 90 31 65 00 85 c0 74 0e 8b 45 14 8d 55 fc 52 50 ff 15 c4 30 65 00 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RJ_2147848155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RJ!MTB"
        threat_id = "2147848155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 08 56 68 0d ef 64 00 e8 cf 6d fb ff e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RJ_2147848155_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RJ!MTB"
        threat_id = "2147848155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a 00 e8 ?? 3b 04 00 8b 45 14 50 e8 ?? 3b 04 00 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RJ_2147848155_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RJ!MTB"
        threat_id = "2147848155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 4c 00 ff 15 ?? f3 4b 00 6a 4e ff 15 ?? f5 4b 00 6a 00 ff 15 ?? f3 4b 00 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GJT_2147849131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GJT!MTB"
        threat_id = "2147849131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 56 8b 75 14 56 e8 ?? ?? ?? ?? 56 6a 00 ff 15 ?? 81 65 00 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_BX_2147849581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.BX!MTB"
        threat_id = "2147849581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 56 8b 75 14 56 ff 15 d0 46 65 00 56 ff 15 44 40 65 00 56 ff 15 3c 47 65 00 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_BO_2147849627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.BO!MTB"
        threat_id = "2147849627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 56 68 28 eb 46 00 ff 15 [0-4] e9}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 83 ec 0c 53 56 57 8b 45 14 50 e8 b2 53 04 00 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_BP_2147849635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.BP!MTB"
        threat_id = "2147849635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 56 6a 19 6a 14 6a 0b 6a 0a 68 [0-3] 00 ff 15 [0-4] 8b 75 14 56 ff 15 [0-4] e9}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 56 68 28 ?? 46 00 ff 15 [0-4] e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_BQ_2147849636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.BQ!MTB"
        threat_id = "2147849636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 8b 45 14 50 e8 ?? ?? 04 00 a1 00 ?? ?? 00 6a 00 ff d0 e9}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 56 ff 15 9c c2 46 00 e9}  //weight: 5, accuracy: High
        $x_5_3 = {55 8b ec 56 8b 75 14 56 ff 15 00 ?? 46 00 56 e8 [0-4] e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_GMH_2147889138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GMH!MTB"
        threat_id = "2147889138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 53 ff 15 ?? ?? ?? ?? a1 ?? 00 47 00 89 35 ?? f9 46 00 8b fe 38 18}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 fc 83 c4 14 48 89 35 ?? f9 46 00 5f 5e}  //weight: 10, accuracy: Low
        $x_1_3 = "S4BAMPlayer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_BM_2147889507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.BM!MTB"
        threat_id = "2147889507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b e8 8b 4c 24 28 55 83 c1 04 89 4c 24 2c 8d 4c 24 20 51 53 ff 15 ?? ?? 65 00 55 ff 15 ?? ?? 65 00 8b 4c 24 20 83 c1 04 3b cf}  //weight: 1, accuracy: Low
        $x_1_2 = "pb825" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GMI_2147889545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GMI!MTB"
        threat_id = "2147889545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 fc 83 c4 14 48 89 35 9c fa 46 00 5f 5e a3 98 fa 46 00 5b c9 c3}  //weight: 10, accuracy: High
        $x_10_2 = {56 53 ff 15 ?? ?? ?? ?? a1 ?? 01 47 00 89 35 ?? fa 46 00 8b fe 38 18}  //weight: 10, accuracy: Low
        $x_1_3 = "S4BAMPlayer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_BN_2147890037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.BN!MTB"
        threat_id = "2147890037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 56 8b 74 24 0c 8d 4c 24 08 57 51 68 10 27 00 00 6a 03 6a 00 6a 00 56 50 8b f8 ff 15 ?? ?? ?? 00 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = "{165104d9-3477-4c8b-97cb-2bc29f404353}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_BR_2147890041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.BR!MTB"
        threat_id = "2147890041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 20 02 00 00 6a 20 8d 4c 24 38 6a 02 51 89 5c 24 3c 88 5c 24 40 88 5c 24 41 88 5c 24 42 88 5c 24 43 88 5c 24 44 c6 44 24 45 05 89 5c 24 30 ff 15 ?? ?? ?? 00 85 c0 75}  //weight: 2, accuracy: Low
        $x_1_2 = {8d 4c 24 08 51 68 0a 00 02 00 50 ff 15 ?? ?? ?? 00 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8b f0 33 f7 ff 15 ?? ?? ?? 00 8d 4c 24 10 8b f8 51 33 fe ff 15 ?? ?? ?? 00 8b 4c 24 14 8b 44 24 10 33 c8 8b c1 33 cf 5f 81 f9 4e e6 40 bb 5e 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GNT_2147895201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GNT!MTB"
        threat_id = "2147895201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 fc 83 c4 14 48 89 35 6c 6c 4d 00 5f 5e a3 68 6c 4d 00 5b c9 c3 55 8b ec 8b 4d 18 8b 45 14 53 56 83 21 00}  //weight: 10, accuracy: High
        $x_10_2 = {8b 45 fc 83 c4 14 48 89 35 6c 5c 4d 00 5f 5e a3 68 5c 4d 00 5b c9 c3 55 8b ec 8b 4d 18 8b 45 14 53 56 83 21 00}  //weight: 10, accuracy: High
        $x_1_3 = "@hac1030" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_GNU_2147895404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GNU!MTB"
        threat_id = "2147895404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 fc 83 c4 14 48 89 35 6c 4c 4d 00 5f 5e a3 68 4c 4d 00 5b c9 c3 55 8b ec 8b 4d 18 8b 45 14 53 56 83 21 00}  //weight: 10, accuracy: High
        $x_10_2 = {8b 45 fc 83 c4 14 48 89 35 6c 5c 4d 00 5f 5e a3 68 5c 4d 00 5b c9 c3 55 8b ec 8b 4d 18 8b 45 14 53 56 83 21 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_GNW_2147895517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GNW!MTB"
        threat_id = "2147895517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 fc 83 c4 14 48 89 35 dc 0c 4d 00 5f 5e a3 d8 0c 4d 00 5b c9 c3 55 8b ec 8b 4d 18 8b 45 14 53 56 83 21 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASDG_2147895721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDG!MTB"
        threat_id = "2147895721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 56 57 68 88 32 65 00 e8 c0 62 fb ff e9}  //weight: 1, accuracy: High
        $x_1_2 = "D:\\COLORREF\\pallet1171.plt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASDH_2147895963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDH!MTB"
        threat_id = "2147895963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 6a 14 6a 40 ff 15 ?? ?? 65 00 8b f0 6a 01 56 ff 15 ?? ?? 65 00 53 53 6a 01 56 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASDI_2147896634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDI!MTB"
        threat_id = "2147896634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 ec 0c 53 56 57 6a 14 6a 40 33 db ff 15 [0-4] 8b 74 24 1c 8b f8 39 5e 19 75}  //weight: 5, accuracy: Low
        $x_5_2 = {83 ec 10 53 55 56 57 ff 15 [0-3] 00 6a 14 6a 40 8b f0 32 db ff 15 [0-3] 00 8b f8 8d 44 24 10 50 56 ff 15 [0-3] 00 8b 74 24}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASDJ_2147897120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDJ!MTB"
        threat_id = "2147897120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4c 24 10 51 ff d3 56 8b f8 ff 15 [0-3] 00 50 56 57 ff 15 [0-3] 00 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = {5e 33 c0 5b 81 c4 14 04 00 00 c3 5f 5e b8 01 00 00 00 5b 81 c4 14 04 00 00 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GNB_2147897501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GNB!MTB"
        threat_id = "2147897501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 bd 4a 36 00 5a a9 32 00 00 da 0a 00 73 5b 0d ca bc 6d 32 00 00 d4 00 00 b3 cf 16 16}  //weight: 1, accuracy: High
        $x_1_2 = "VolumeUTIL Setup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GNC_2147897572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GNC!MTB"
        threat_id = "2147897572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2a 01 00 00 00 de ba 33 00 7b 19 30 00 00 da 0a 00 73}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GND_2147897582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GND!MTB"
        threat_id = "2147897582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 01 00 00 00 b4 94 ?? ?? ?? ?? 28 00 00 da 0a 00 ?? ?? 0d ca f2 cc 28 00 00 2a 01 00 71 27 49}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASDK_2147897643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDK!MTB"
        threat_id = "2147897643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 56 57 68 48 b1 4c 00 68 38 b1 4c 00 ff 15 [0-3] 00 8b 3d 04 93 4c 00 68 e8 b0 4c 00 8b f0 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASDL_2147897721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDL!MTB"
        threat_id = "2147897721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 34 10 65 00 6a 00 8d 4c 24 10 6a 01 51 c7 44 24 18 0c 00 00 00 89 74 24 1c c7 44 24 20 00 00 00 00 ff 15 [0-3] 00 a3 74 1d 65 00 5e 83 c4 10 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {68 34 10 65 00 6a 00 8d 44 24 18 6a 01 50 c7 44 24 20 0c 00 00 00 89 74 24 24 c7 44 24 28 00 00 00 00 ff 15 [0-3] 00 5f a3 74 1d 65 00 5e 83 c4 14 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_GAB_2147898664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GAB!MTB"
        threat_id = "2147898664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 01 00 00 00 e2 17 7b ?? 59 7c ?? 00 00 be ?? ?? ?? ?? 49 b9 ?? ?? ?? ?? 00 dc 01 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASDM_2147898769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDM!MTB"
        threat_id = "2147898769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 ec 80 01 00 00 53 55 56 57 b9 45 00 00 00 33 c0 8d 7c 24 7c f3 ab 8d 44 24 7c c7 44 24 7c 14 01 00 00 50 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GAD_2147898784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GAD!MTB"
        threat_id = "2147898784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 1f d4 71 00 96 ?? ?? ?? ?? be ?? ?? ?? ?? 49 b9 ?? ?? ?? ?? 00 dc 01 00 35 34 f5 b7 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GAD_2147898784_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GAD!MTB"
        threat_id = "2147898784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2a 01 00 00 00 54 4c 72 00 cb b0 6e 00 00 be 0a 00 0b 33 49 b9 9a 69 6e 00 00 dc 01 00 52 99 50}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASDO_2147898788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDO!MTB"
        threat_id = "2147898788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2a 01 00 00 00 45 90 86 00 d8 14 83 00 00 1e 0a 00 06 0e ea}  //weight: 5, accuracy: High
        $x_5_2 = {2a 01 00 00 00 19 51 85 00 35 bc 81 00 00 ae 0a 00 23 97}  //weight: 5, accuracy: High
        $x_5_3 = {2a 01 00 00 00 34 6c 73 00 ab d0 6f 00 00 be 0a 00 0b 33 49 b9 7c 56 6f 00 00 76 01 00 4b db}  //weight: 5, accuracy: High
        $x_5_4 = {2a 01 00 00 00 6e f5 7d 00 c7 d0 79 00 00 4c 0b 00 c1 20 b2 5d 6c a8 79 00 00 7c 01}  //weight: 5, accuracy: High
        $x_5_5 = {2a 01 00 00 00 91 44 47 00 9a b6 43 00 00 96 0a 00 e4 91 6b 05}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASDP_2147898814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDP!MTB"
        threat_id = "2147898814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2a 01 00 00 00 b0 [0-4] 89 6e 00 00 be [0-4] 49 b9 fb 41 6e 00 00 dc 01 00 e1}  //weight: 5, accuracy: Low
        $x_5_2 = {2a 01 00 00 00 1b 08 72 00 92 6c 6e 00 00 be 0a 00 0b 33 49 b9}  //weight: 5, accuracy: High
        $x_5_3 = {2a 01 00 00 00 74 c9 7a 00 eb 2d 77 00 00 be 0a 00 0b 33 49 b9}  //weight: 5, accuracy: High
        $x_5_4 = {2a 01 00 00 00 13 55 78 00 8a b9 74 00 00 be 0a 00 0b 33 49 b9 63 72 74}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASDQ_2147898886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDQ!MTB"
        threat_id = "2147898886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 44 24 1c 50 6a ff 55 6a 01 57 ff d3 55 8b b4 24 ?? ?? 00 00 56 ff 15 ?? ?? ?? 00 85 c0 0f 85}  //weight: 5, accuracy: Low
        $x_5_2 = {8b f0 8d 4c 24 08 81 e6 ff 00 00 00 51 83 fe 06 57 0f 93 c0 a2 ?? ?? ?? 00 ff 15 ?? ?? 4c 00 8b f8 e8}  //weight: 5, accuracy: Low
        $x_5_3 = {8b f0 81 e6 ff 00 00 00 83 fe 06 0f 93 c0 a2 ?? ?? ?? 00 e8 ?? ff ff ff 68 ?? ?? 65 00 ff 15 ?? ?? 65 00 83 fe 06 72}  //weight: 5, accuracy: Low
        $x_5_4 = {5f 5e 5d b8 01 00 00 00 5b 81 c4 20 06 00 00 c2 08 00 8d 44 24 14 50 57 ff 15 ?? ?? 65 00 8b 1d ?? ?? 65 00 56 8b f8 ff d3 85 ff 89 44 24 10 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASDN_2147898892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDN!MTB"
        threat_id = "2147898892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2a 01 00 00 00 d2 4a 6e 00 49 af 6a 00 00 be [0-4] 49 b9 11 68 6a 00 00 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASDR_2147899042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDR!MTB"
        threat_id = "2147899042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2a 01 00 00 00 aa 13 3a 00 1c 77 36 00 00 c0 0a 00 0d 15 b6 76 4f f4 35 00 00 d4 00 00 b5 26 7f 6c}  //weight: 5, accuracy: High
        $x_5_2 = {2a 01 00 00 00 1a 66 3a 00 8c c9 36 00 00 c0 0a 00 0d 15 b6 76 cf 46 36 00 00 d4 00 00 17 4b d1 ef}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASDS_2147899124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDS!MTB"
        threat_id = "2147899124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 54 24 04 56 56 8d 4c 24 10 56 51 56 52 c7 44 24 2c 02 00 00 00 c7 44 24 20 01 00 00 00 ff 15 ?? ?? 4c 00 8b f0 8b 44 24 04 f7 de 1b f6}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 46 24 8b 4c 24 0c 8b 56 20 03 c1 8b 4c 24 08 57 03 ca 8b 56 04 50 51 52 89 4c 24 18 89 44 24 1c ff 15 ?? ?? 4c 00 8b 4e 08 8d 44 24 10 50 51 89 7c 24 18 89 7c 24 1c ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_GAE_2147899193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GAE!MTB"
        threat_id = "2147899193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 01 00 00 00 bf ?? ?? ?? ?? 42 65 00 00 be 0a 00 d4 bd 14 99 ?? ?? 64 00 00 d4 00 00 dc d2 89}  //weight: 10, accuracy: Low
        $x_10_2 = {2a 01 00 00 00 a3 ?? ?? ?? ?? 66 66 00 00 be 0a 00 d4 bd 14 99 96 20 66 00 00 d4 00 00 b4 79}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASDU_2147899269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDU!MTB"
        threat_id = "2147899269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {56 57 6a 00 ff 15 ?? ?? 4c 00 8b f0 6a 5a 56 ff 15 ?? ?? 4c 00 56 6a 00 8b f8 ff 15 ?? ?? 4c 00 8b c7 5f 5e 59 c3}  //weight: 5, accuracy: Low
        $x_5_2 = {6a 00 56 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 00 00 cf 10 8d 44 24 2c 68 ?? ?? 4c 00 50 6a 00 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_GAF_2147899403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GAF!MTB"
        threat_id = "2147899403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 01 00 00 00 47 d5 69 00 ?? ?? ?? ?? 00 be 0a 00 d4 bd 14 99 ff f2 65 00 00 d4 00 00 ce 39 aa 43 00 00 01 00 04 00}  //weight: 10, accuracy: Low
        $x_10_2 = {2a 01 00 00 00 b7 ?? ?? ?? ?? 67 66 00 00 be 0a 00 d4 bd 14 99 92 21 66 00 00 d4 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_RPY_2147899487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RPY!MTB"
        threat_id = "2147899487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 d5 69 00 69 39 66 00 00 be 0a 00 d4 bd 14 99 ff f2 65 00 00 d4 00 00 ce 39 aa 43}  //weight: 1, accuracy: High
        $x_1_2 = "PRingTone" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RPY_2147899487_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RPY!MTB"
        threat_id = "2147899487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f2 9f 69 00 14 04 66 00 00 be 0a 00 d4 bd 14 99 c0 bd 65 00 00 d4 00 00 91 fb b8 1a}  //weight: 1, accuracy: High
        $x_1_2 = "PRingTone" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RPY_2147899487_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RPY!MTB"
        threat_id = "2147899487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 e6 68 00 4a 4a 65 00 00 be 0a 00 d4 bd 14 99 e2 03 65 00 00 d4 00 00 4a 13 13 bb}  //weight: 10, accuracy: High
        $x_10_2 = {2f f4 69 00 51 58 66 00 00 be 0a 00 d4 bd 14 99 f3 11 66 00 00 d4 00 00 60 0b c7 e8}  //weight: 10, accuracy: High
        $x_1_3 = "NetSchemeCAB" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_EK_2147899563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.EK!MTB"
        threat_id = "2147899563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2a 01 00 00 00 f5 ce 73 00 17 33 70 00 00 be 0a 00 d4 bd 14 99 c2 ec 6f 00 00 d4 00 00 95 b1 1d 1c}  //weight: 1, accuracy: High
        $x_1_2 = {2a 01 00 00 00 e7 e8 6d 00 09 4d 6a 00 00 be 0a 00 d4 bd 14 99 99 06 6a 00 00 d4 00 00 8b 03 dd e1}  //weight: 1, accuracy: High
        $x_1_3 = {2a 01 00 00 00 5d 4d 71 00 cf b0 6d 00 00 c0 0a 00 0d 15 b6 76 82 89 6d 00 00 d4 00 00 9a 16 78 7d}  //weight: 1, accuracy: High
        $x_1_4 = {2a 01 00 00 00 e8 ab 70 00 0a 10 6d 00 00 be 0a 00 d4 bd 14 99 8f d3 6c 00 00 d4 00 00 2e 44 4a 98}  //weight: 1, accuracy: High
        $x_1_5 = {2a 01 00 00 00 5d c8 71 00 7f 2c 6e 00 00 be 0a 00 d4 bd 14 99 4a 05 6e 00 00 d4 00 00 35 56 d3 b6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ER_2147899564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ER!MTB"
        threat_id = "2147899564"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2a 01 00 00 00 69 c5 6e 00 8b 29 6b 00 00 be 0a 00 d4 bd 14 99 0f e3 6a 00 00 d4 00 00 ef 12 a1 1a}  //weight: 5, accuracy: High
        $x_5_2 = {2a 01 00 00 00 61 29 6f 00 83 8d 6b 00 00 be 0a 00 d4 bd 14 99 ff 46 6b 00 00 d4 00 00 de c1 58 3a}  //weight: 5, accuracy: High
        $x_5_3 = {2a 01 00 00 00 85 1e 71 00 a7 82 6d 00 00 be 0a 00 d4 bd 14 99 2c 46 6d 00 00 d4 00 00 64 89 bf 96}  //weight: 5, accuracy: High
        $x_5_4 = {2a 01 00 00 00 45 b8 6e 00 67 1c 6b 00 00 be 0a 00 d4 bd 14 99 f0 d5 6a 00 00 d4 00 00 01 0e c0 b3}  //weight: 5, accuracy: High
        $x_5_5 = {2a 01 00 00 00 4e 30 6f 00 70 94 6b 00 00 be 0a 00 d4 bd 14 99 ee 4d 6b 00 00 d4 00 00 95 8e ae c9}  //weight: 5, accuracy: High
        $x_1_6 = "RButtonTRAY" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_ES_2147899583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ES!MTB"
        threat_id = "2147899583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2a 01 00 00 00 c2 53 6a 00 e4 b7 66 00 00 be 0a 00 d4 bd 14 99 8d 71 66 00 00 d4 00 00 ed 46 c5 3b}  //weight: 1, accuracy: High
        $x_1_2 = {2a 01 00 00 00 e5 fe 69 00 07 63 66 00 00 be 0a 00 d4 bd 14 99 a2 1c 66 00 00 d4 00 00 8d b6 cc 53}  //weight: 1, accuracy: High
        $x_1_3 = {2a 01 00 00 00 2e 0e 6a 00 50 72 66 00 00 be 0a 00 d4 bd 14 99 eb 2b 66 00 00 d4 00 00 e8 74 c7 2d}  //weight: 1, accuracy: High
        $x_1_4 = {2a 01 00 00 00 a8 27 6a 00 ca 8b 66 00 00 be 0a 00 d4 bd 14 99 60 45 66 00 00 d4 00 00 00 77 0a 7c}  //weight: 1, accuracy: High
        $x_1_5 = {2a 01 00 00 00 b3 2b 6a 00 d5 8f 66 00 00 be 0a 00 d4 bd 14 99 67 49 66 00 00 d4 00 00 95 ca c3 31}  //weight: 1, accuracy: High
        $x_1_6 = {2a 01 00 00 00 30 78 6a 00 52 dc 66 00 00 be 0a 00 d4 bd 14 99 05 96 66 00 00 d4 00 00 c8 53 d5 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_RPX_2147899593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RPX!MTB"
        threat_id = "2147899593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e4 f8 69 00 06 5d 66 00 00 be 0a 00 d4 bd 14 99 bc 16 66 00 00 d4 00 00 49 bd be 36}  //weight: 1, accuracy: High
        $x_1_2 = "NetSchemeCAB" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RPX_2147899593_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RPX!MTB"
        threat_id = "2147899593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {91 51 69 00 b3 b5 65 00 00 be 0a 00 d4 bd 14 99 54 6f 65 00 00 d4 00 00 dd 9a ed ec}  //weight: 10, accuracy: High
        $x_10_2 = {c0 0c 69 00 e2 70 65 00 00 be 0a 00 d4 bd 14 99 7a 2a 65 00 00 d4 00 00 62 4e 54 08}  //weight: 10, accuracy: High
        $x_1_3 = "NetSchemeCAB" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_RPZ_2147899594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RPZ!MTB"
        threat_id = "2147899594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ec 51 84 00 0e b6 80 00 00 be 0a 00 d4 bd 14 99 a6 79 80 00 00 d4 00 00 20 43 0b 58}  //weight: 1, accuracy: High
        $x_1_2 = "VBMailAgent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASDT_2147899597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDT!MTB"
        threat_id = "2147899597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 7f 05 69 00 a1 69 65 00 00 be}  //weight: 5, accuracy: High
        $x_5_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 18 bd 68 00 3a 21 65 00 00 be 0a 00 d4 bd 14 99}  //weight: 5, accuracy: High
        $x_5_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 8e bb 68 00 b0 1f 65 00 00 be 0a 00 d4 bd 14 99}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASDV_2147899598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDV!MTB"
        threat_id = "2147899598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ec 9f 66 00 0e 04 63 00 00 be 0a 00 d4 bd 14 99 a7 bd 62 00 00 d4 00 00 e4 01 7b}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASDW_2147899599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDW!MTB"
        threat_id = "2147899599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 e4 f8 69 00 06 5d 66 00 00 be 0a 00 d4 bd 14 99 bc 16 66 00 00 d4 00 00 49 bd be 36 00 00 01}  //weight: 5, accuracy: High
        $x_5_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 f2 9f 69 00 14 04 66 00 00 be 0a 00 d4 bd 14 99 c0 bd 65 00 00 d4 00 00 91 fb b8 1a 00}  //weight: 5, accuracy: High
        $x_5_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 d7 69 69 00 f9 cd 65 00 00 be 0a 00 d4 bd 14 99 9b 87 65 00 00 d4 00 00 ba fa 69 f9}  //weight: 5, accuracy: High
        $x_5_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 28 e6 68 00 4a 4a 65 00 00 be 0a 00 d4 bd 14 99 e2}  //weight: 5, accuracy: High
        $x_5_5 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 e5 fe 69 00 07 63 66 00 00 be 0a 00 d4 bd 14 99 a2}  //weight: 5, accuracy: High
        $x_5_6 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 2f f4 69 00 51 58 66 00 00 be 0a 00 d4 bd 14 99}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_GAN_2147899601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GAN!MTB"
        threat_id = "2147899601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6b 64 00 00 c0 0a 00 0d 15 b6 76 72 25 64 00 00 d4 00 00 57 93 06 be 00 00 01 00 04 00 10 10}  //weight: 10, accuracy: High
        $x_10_2 = {2a 01 00 00 00 0d 31 7c 00 7f 94 78 00 00 c0 0a 00 0d 15 b6 76 f3 4d 78 00 00 d4 00 00}  //weight: 10, accuracy: High
        $x_10_3 = {00 d0 88 60 00 6e 59 5a 00 00 fa 0e 00 a6 b9 6a 79 61 49 58 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {2a 01 00 00 00 9a d7 5f 00 38 a8 59 00 00 fa 0e 00 a6 b9 6a 79 ea 97 57 00 00 0e}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_GAN_2147899601_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GAN!MTB"
        threat_id = "2147899601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 01 00 00 00 67 53 80 00 89 b7 7c 00 00 be 0a 00 d4 bd 14 99 0c 7b ?? ?? 00 d4 00 00 1e}  //weight: 10, accuracy: Low
        $x_10_2 = {2a 01 00 00 00 2c 96 80 00 4e fa 7c 00 00 be 0a 00 d4 bd 14 99 ef bd ?? ?? 00 d4 00 00}  //weight: 10, accuracy: Low
        $x_10_3 = {2a 01 00 00 00 23 13 6b 00 45 77 67 00 00 be 0a 00 d4 bd 14 99 f4 30 67 00 00 d4 00 00 b4 21}  //weight: 10, accuracy: High
        $x_10_4 = {2a 01 00 00 00 d3 d7 6b 00 f5 3b 68 00 00 be 0a 00 d4 bd 14 99 77 f5 67 00 00 d4 00 00 df}  //weight: 10, accuracy: High
        $x_10_5 = {2a 01 00 00 00 30 0c 6b 00 52 70 67 00 00 be 0a 00 d4 bd 14 99 d8 29 67 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASDX_2147899603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDX!MTB"
        threat_id = "2147899603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 2c 96 80 00 4e fa 7c 00 00 be 0a 00 d4 bd 14 99 ef bd 7c 00 00 d4}  //weight: 5, accuracy: High
        $x_5_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 e7 df 71 00 59 43 6e 00 00 c0 0a 00 0d 15 b6 76 28 1c 6e 00 00 d4 00 00 c3 71}  //weight: 5, accuracy: High
        $x_5_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 fb cd 73 00 6d 31 70 00 00 c0 0a 00 0d 15 b6 76 1a 0a 70 00 00 d4 00 00 04 57 05 8a 00 00 01}  //weight: 5, accuracy: High
        $x_5_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 a6 6b 71 00 18 cf 6d 00 00 c0 0a 00 0d 15 b6 76 cf a7 6d 00 00 d4 00 00 ff 3c 5c bb 00 00 01 00}  //weight: 5, accuracy: High
        $x_5_5 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 67 53 80 00 89 b7 7c 00 00 be 0a 00 d4 bd 14 99 0c 7b 7c 00 00 d4 00 00 1e 3d 79 c6 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASDY_2147899622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDY!MTB"
        threat_id = "2147899622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 7d 13 81 00 9f 77 7d 00 00 be [0-4] 14 99 2c 3b 7d}  //weight: 5, accuracy: Low
        $x_5_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 45 e6 7f 00 67 4a 7c 00 00 be 0a 00 d4 bd 14 99 ed 0d 7c 00 00 d4 00 00 b3 8c d2 42}  //weight: 5, accuracy: High
        $x_5_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 56 4e 6b 00 78 b2 67 00 00 be [0-4] 14 99 02 6c 67}  //weight: 5, accuracy: Low
        $x_5_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 17 a4 6b 00 39 08 68 00 00 be [0-4] 14 99 db c1}  //weight: 5, accuracy: Low
        $x_5_5 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 c9 e0 6b 00 eb 44 68 00 00 be 0a 00 d4 bd 14 99 6b fe 67}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASDZ_2147899687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASDZ!MTB"
        threat_id = "2147899687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 57 8b 7c 24 10 85 ff 74 24 8b 74 24 0c 85 f6 74 1c e8 ?? ff ff ff 56 ff 15 ?? ?? 7e 00 83 c4 04 85 c0 74}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 44 24 10 6a 10 50 56 c7 44 24 1c 00 00 00 00 ff 15 00 83 7e 00 8b 4c 24 1c 83 c4 0c 85 c9 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASEA_2147899688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEA!MTB"
        threat_id = "2147899688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 85 cb 71 00 f7 2e 6e 00 00 c0 0a 00 0d 15 b6 76 a6 07 6e}  //weight: 5, accuracy: High
        $x_5_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 e2 e4 69 00 04 49 66 00 00 be 0a 00 d4 bd 14 99 a4 02 66 00 00 d4}  //weight: 5, accuracy: High
        $x_5_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 91 51 69 00 b3 b5 65 00 00 be 0a 00 d4 bd 14 99 54 6f 65 00 00 d4}  //weight: 5, accuracy: High
        $x_5_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 c0 0c 69 00 e2 70 65 00 00 be 0a 00 d4 bd 14 99}  //weight: 5, accuracy: High
        $x_5_5 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 6a 7f 69 00 8c e3 65 00 00 be 0a 00 d4 bd 14 99}  //weight: 5, accuracy: High
        $x_5_6 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 af [0-4] fb 65 00 00 be 0a 00 d4 bd 14 99}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASEB_2147899748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEB!MTB"
        threat_id = "2147899748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 6b c6 61 00 dd 29 5e 00 00 c0 0a 00 0d 15 b6 76 68}  //weight: 5, accuracy: High
        $x_5_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 3e bf 61 00 b0 22 5e 00 00 c0 0a 00 0d 15 b6 76 31}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASEB_2147899748_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEB!MTB"
        threat_id = "2147899748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 84 db 7b 00 f6 3e 78 00 00 c0 0a 00 0d 15 b6 76 a3 f8}  //weight: 5, accuracy: High
        $x_5_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 61 c8 7b 00 d3 2b 78 00 00 c0 0a 00 0d 15 b6 76 6f e5 77}  //weight: 5, accuracy: High
        $x_5_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 13 57 7c 00 85 ba 78 00 00 c0 0a 00 0d 15 b6 76 18 74}  //weight: 5, accuracy: High
        $x_5_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 71 fe 67 00 e3 61 64 00 00 c0 0a 00 0d 15 b6 76 4f 1b 64}  //weight: 5, accuracy: High
        $x_5_5 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 18 d9 7b 00 8a 3c 78 00 00 c0 0a 00 0d 15 b6 76 1b f6 77 00 00 d4 00 00 4c 46 7f}  //weight: 5, accuracy: High
        $x_5_6 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 db f5 67 00 4d 59 64 00 00 c0 0a 00 0d 15 b6 76 b5 12 64 00 00}  //weight: 5, accuracy: High
        $x_5_7 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 a6 05 68 00 18 69 64 00 00 c0 0a 00 0d 15 b6 76 7a 22 64 00 00 d4 00 00 6e e1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASEC_2147899961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEC!MTB"
        threat_id = "2147899961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d 4c 24 0c 8d 54 24 08 51 68 ?? ?? 4c 00 52 50 89 44 24 18 50 8b 44 24 18 c7 44 24 20 08 02 00 00 50 ff 15 ?? ?? 4c 00 85 c0 a3}  //weight: 4, accuracy: Low
        $x_4_2 = {81 ec bc 00 00 00 8d 44 24 00 56 57 50 ff 15 ?? ?? 65 00 68 4c 30 65 00 6a 00 68 01 00 1f 00 ff 15 ?? ?? 65 00 85 c0 74}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASED_2147899962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASED!MTB"
        threat_id = "2147899962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 53 cd e6 d7 7b 0b 2a 01 00 00 00 fc e1 3e 00 6e 45 3b 00 00 c0 0a 00 0d 15 b6 76 44 e2}  //weight: 5, accuracy: High
        $x_5_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 5d c4 61 00 cf 27 5e 00 00 c0 0a 00 0d 15 b6 76 45}  //weight: 5, accuracy: High
        $x_5_3 = {74 53 cd e6 d7 7b 0b 2a 01 00 00 00 e6 c3 40 00 b2 27 3d 00 00 c0 0a 00 03 8d 58 92 2b 17 3b 00 00 d4 00 00 a5 65 2e d1 00}  //weight: 5, accuracy: High
        $x_5_4 = {74 53 cd e6 d7 7b 0b 2a 01 00 00 00 9a a6 44 00 66 0a 41 00 00 c0 0a 00 03 8d 58 92 03 fa 3e 00 00 d4 00 00 f1 f5 d0 21}  //weight: 5, accuracy: High
        $x_5_5 = {74 53 cd e6 d7 7b 0b 2a 01 00 00 00 14 6c 45 00 e0 cf 41 00 00 c0 0a 00 03 8d}  //weight: 5, accuracy: High
        $x_5_6 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 d3 ba 61 00 45 1e 5e 00 00 c0 0a 00 0d 15 b6 76 b5 d7 5d 00 00 d4 00 00 dc 50 81 f5 00 00 01 00}  //weight: 5, accuracy: High
        $x_5_7 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 11 93 6e 00 83 f6 6a 00 00 c0 0a 00 0d 15 b6 76 e7}  //weight: 5, accuracy: High
        $x_5_8 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 9c 84 6e 00 0e e8 6a 00 00 c0 0a 00 0d 15 b6 76 78 a1}  //weight: 5, accuracy: High
        $x_5_9 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 d8 89 6e 00 4a ed 6a 00 00 c0 0a 00 0d 15 b6 76 d5}  //weight: 5, accuracy: High
        $x_5_10 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 4a c8 40 00 16 2c 3d 00 00 c0 0a 00 03 8d}  //weight: 5, accuracy: High
        $x_5_11 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 79 45 00 5c dd 41 00 00 c0 0a 00 03 8d}  //weight: 5, accuracy: High
        $x_5_12 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ed 74 45 00 b9 d8 41 00 00 c0 0a 00 03 8d 58 92 38 c8 3f 00 00 d4 00 00 09 b9 83 1c 00 00}  //weight: 5, accuracy: High
        $x_5_13 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 17 bb 61 00 89 1e 5e 00 00 c0 0a 00 0d 15 b6 76 f8}  //weight: 5, accuracy: High
        $x_5_14 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 bd 92 6e 00 2f f6 6a 00 00 c0 0a 00 0d 15 b6 76 9d}  //weight: 5, accuracy: High
        $x_5_15 = {74 53 cd e6 d7 7b 0b 2a 01 00 00 00 05 [0-4] ef 44 00 00 c0 0a 00 03 8d [0-4] 42 00 00 9e 04 00 a9 51 77 83 00 00 01 00 10 00 30 30 08}  //weight: 5, accuracy: Low
        $x_5_16 = {74 53 cd e6 d7 7b 0b 2a 01 00 00 00 0a c9 40 00 d6 2c 3d 00 00 c0 0a 00 03 8d [0-4] 3b 00 00 d4 00 00 c0 1b 0b 48}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASEE_2147899988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEE!MTB"
        threat_id = "2147899988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 ec bc 00 00 00 8d 44 24 00 56 57 50 ff 15 ?? ?? 4c 00 8d 4c 24 18 51 ff 15 ?? ?? 4c 00 8b 54 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RA_2147899991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RA!MTB"
        threat_id = "2147899991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 d8 67 fb ff eb 0d 8b 75 fc e8 ce 67 fb ff eb 03 8b 75 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RA_2147899991_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RA!MTB"
        threat_id = "2147899991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b c2 d1 f8 03 c1 8b 4d f0 89 86 c4 00 00 00 8b 45 f8 2b c1 2b 45 dc 99 2b c2 d1 f8 03 c1 89 86 c8 00 cc cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RA_2147899991_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RA!MTB"
        threat_id = "2147899991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 56 68 ?? 30 65 00 6a 01 6a 00 ff 15 ?? f3 64 00 8b f0 85 f6 74 2a ff 15 ?? f3 64 00 3d b7 00 00 00 75 13 56 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RA_2147899991_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RA!MTB"
        threat_id = "2147899991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {53 fb ff 8b f0 e9 04 00 56 57 e8}  //weight: 4, accuracy: Low
        $x_1_2 = {40 00 00 40 5f 62 63 6f 72 65}  //weight: 1, accuracy: High
        $x_1_3 = "Catalogic Book List" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASEF_2147900156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEF!MTB"
        threat_id = "2147900156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 c0 0a 00 03 8d 58}  //weight: 5, accuracy: Low
        $x_5_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? 61 00 ?? ?? 5e 00 00 c0 0a 00 0d 15 b6 76}  //weight: 5, accuracy: Low
        $x_5_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 [0-7] 00 00 c0 0a 00 0d 15 b6 76}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_GPA_2147900313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPA!MTB"
        threat_id = "2147900313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ec 75 67 00 0e da 63 00 00 be ?? ?? ?? ?? 14 99 d1 93}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASEG_2147900332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEG!MTB"
        threat_id = "2147900332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 83 ec 08 56 57 ff 15 ?? ?? 4b 00 68 ?? ?? 4b 00 6a 01 6a 00 8b f8 ff 15 ?? ?? 4b 00 8b f0 8d 45 fc 50 57 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASEH_2147900398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEH!MTB"
        threat_id = "2147900398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 51 56 68 ?? ?? ?? 00 6a 01 6a 00 ff 15 ?? ?? ?? 00 8b f0 85 f6 74 1b ff 15 ?? ?? ?? 00 3d b7 00 00 00 75 0e 56 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASEI_2147900399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEI!MTB"
        threat_id = "2147900399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {50 51 56 ff 15 ?? ?? ?? 00 8b e8 8a 44 24 60 89 6c 24 1c 84 c0 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASEJ_2147900500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEJ!MTB"
        threat_id = "2147900500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 44 24 04 bb 01 00 00 00 50 53 6a 00 68 ?? ?? ?? 00 68 00 00 00 80 c7 44 24 18 00 00 00 00 ff 15 ?? ?? ?? 00 85 c0 a3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASEK_2147900501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEK!MTB"
        threat_id = "2147900501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 d2 73 67 00 44 d7 63 00 00 c0 0a 00 0d 15 b6 76 bd 90 63 00 00 68 06}  //weight: 5, accuracy: High
        $x_5_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 69 36 70 00 db 99 [0-4] 0a 00 0d 15 b6 76 36 53}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASEL_2147900815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEL!MTB"
        threat_id = "2147900815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {51 57 ff 15 ?? ?? ?? 00 8b f8 a1 ?? ?? ?? 00 8b c8 48 83 f9 01 a3 ?? ?? ?? 00 73 4f 56 8b 35 ?? ?? ?? 00 68 ?? ?? ?? 00 ff d6 8d 54 24}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASEM_2147900909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEM!MTB"
        threat_id = "2147900909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 be 0a 00 df 2d d6 87 ?? ?? ?? 00 00 d4 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASEN_2147900988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEN!MTB"
        threat_id = "2147900988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 be 0a 00 df 2d d6 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASEO_2147901052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEO!MTB"
        threat_id = "2147901052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 ec 10 8d 44 24 00 6a 00 50 6a 00 68 19 00 02 00 6a 00 6a 00 6a 00 68 ?? ?? ?? 00 68 02 00 00 80 ff 15 ?? ?? ?? 00 8b 44 24}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASEP_2147901133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEP!MTB"
        threat_id = "2147901133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? 40 00 00 c0 0a 00 47 43 f4 14 ?? ?? 40 00 00 d4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GPB_2147901205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPB!MTB"
        threat_id = "2147901205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 c0 0a 00 0d 15 b6 76}  //weight: 4, accuracy: Low
        $x_4_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 73 5b 0d ca}  //weight: 4, accuracy: Low
        $x_4_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 be 0a 00 d4 bd 14 99}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASEQ_2147901646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEQ!MTB"
        threat_id = "2147901646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {51 c7 44 24 00 00 00 00 00 ff 15 [0-3] 00 85 c0 74 0c 8d 4c 24 00 51 50 ff 15 [0-3] 00 8b 44 24 00 59 c3}  //weight: 5, accuracy: Low
        $x_5_2 = {57 ff d3 68 [0-3] 00 57 89 86 ?? ?? 00 00 ff d3 68 [0-3] 00 57 89 86 ?? ?? 00 00 ff d3 8d 54 24 0c 89 86 ?? ?? 00 00 52 c7 44 24 10 14 01 00 00 ff 15}  //weight: 5, accuracy: Low
        $x_5_3 = {8b 54 24 04 52 ff 15 [0-3] 00 8b 44 24 0c 8b 7c 24 10 0b c7 5f 83 f0 11 f7 d8 1b c0 40 83 c4 14 c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASES_2147901716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASES!MTB"
        threat_id = "2147901716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 [0-3] 00 [0-3] 00 00 be 0a 00 1e 08 3c 94}  //weight: 5, accuracy: Low
        $x_5_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 [0-3] 00 [0-3] 00 00 be 0a 00 a0 a0 3d 6d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASET_2147901820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASET!MTB"
        threat_id = "2147901820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b f0 8d 44 24 0c 50 57 ff 15 ?? ?? ?? 00 85 f6 8b f8 74 0c 8d 4c 24 08 51 56 ff 15 ?? ?? ?? 00 85 ff 5f 5e 74 12 8b 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASEU_2147901933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEU!MTB"
        threat_id = "2147901933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 54 24 10 8b d8 52 55 ff 15 ?? ?? ?? 00 68 ?? ?? ?? 00 53 8b e8 ff 15 ?? ?? ?? 00 3b ef 89 86}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASEV_2147901948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEV!MTB"
        threat_id = "2147901948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 4c 24 14 c7 44 24 10 00 00 00 00 51 56 c7 44 24 14 00 00 00 00 c7 44 24 10 04 00 00 00 ff 15 ?? ?? ?? 00 8b 4c 24 04 8b f0 8d 54 24 08 8d 44 24 10 52 50 6a 00 6a 00 68 ?? ?? ?? 00 51 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASEW_2147902009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEW!MTB"
        threat_id = "2147902009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 44 24 08 50 ff 15 ?? ?? ?? 00 8d 4c 24 08 51 ff 15 ?? ?? ?? 00 8d 54 24 08 52 ff d7 56 8b f8 ff 15 ?? ?? ?? 00 50 56 57 ff 15 ?? ?? ?? 00 85 c0 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_KAA_2147902017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.KAA!MTB"
        threat_id = "2147902017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 c4 0a 00 05 30 e1 b4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASER_2147902146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASER!MTB"
        threat_id = "2147902146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b9 64 08 00 00 51 6a 08 e8 ?? ?? 26 00 50 e8 ?? ?? 26 00 0b c0 75 0a b8 fd 00 00 00 e8 ?? ?? ff ff 50 50 ff 35}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASEX_2147902147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEX!MTB"
        threat_id = "2147902147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {50 ff d6 8b 0d d8 ?? ?? 00 68 5c e0 4b 00 51 a3 c4 ?? ?? 00 ff d6 8b 15 d8 ?? ?? 00 68 48 e0 4b 00 52 a3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASEY_2147902301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEY!MTB"
        threat_id = "2147902301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 56 68 34 10 65 00 e8 ?? ?? ?? ff 83 c4 04 a3}  //weight: 5, accuracy: Low
        $x_5_2 = {e5 64 00 50 ff 15 ?? e5 64 00 f7 d8 1b c0 f7 d8 c3}  //weight: 5, accuracy: Low
        $x_5_3 = {50 ff d6 68 ?? ?? ?? 00 50 ff d7 8b 0d ?? ?? ?? 00 a3 ?? ?? ?? 00 51 ff d6 68 ?? ?? ?? 00 50 ff d7 5f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_GPD_2147902337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPD!MTB"
        threat_id = "2147902337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 b0 26 00 55 73 bd a6}  //weight: 4, accuracy: Low
        $x_4_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 b0 26 00 de ad c7 94}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_GPD_2147902337_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPD!MTB"
        threat_id = "2147902337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 c4 0a 00 67 cb 7b 78}  //weight: 4, accuracy: Low
        $x_4_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 c4 0a 00 e6 8e a9 02}  //weight: 4, accuracy: Low
        $x_4_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 c4 0a 00 a8 fb 33 28}  //weight: 4, accuracy: Low
        $x_4_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 c4 0a 00 18 08 ca 51}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_GPE_2147902394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPE!MTB"
        threat_id = "2147902394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {7e d1 24 00 c2 d1 24 00 b2 d1 24 00 a0 d1 24 00 90 d1 24 00 70 d1 24 00 5c d1 24}  //weight: 4, accuracy: High
        $x_4_2 = {ce d1 24 00 10 d2 24 00 fe d1 24 00 ee d1 24 00 dc d1 24 00 ba d1 24 00 a4 d1 24}  //weight: 4, accuracy: High
        $x_4_3 = {5e 19 25 00 72 19 25 00 82 19 25 00 a2 19 25 00 b4 19 25 00 c4 19 25 00 d6 19 25 00 e6 19 25 00 f6 19 25 00 04 1a 25 00 14 1a 25 00 28 1a 25}  //weight: 4, accuracy: High
        $x_4_4 = {a6 17 25 00 98 17 25 00 8a 17 25 00 78 17 25 00 68 17 25 00 56 17 25 00 42 17 25 00 2a 17 25 00 12 17 25 00 02 17 25 00 ee 16 25 00 e0 16 25}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASEZ_2147902416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASEZ!MTB"
        threat_id = "2147902416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 3f 12 44 00 ?? 71 40 00 00 c4 0a 00 1a 83 6e ?? 4d 29 40 00 00 d4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GZE_2147902470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GZE!MTB"
        threat_id = "2147902470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 57 89 65 e8 a0 ?? ?? ?? ?? 32 05 ?? ?? ?? ?? 24 ?? a2 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8d 14 4a 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 83 e2 03 33 db 8a d8 0f af d3 03 ca}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASFA_2147902778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFA!MTB"
        threat_id = "2147902778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 c4 0a 00 7a f3 50}  //weight: 5, accuracy: Low
        $x_5_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 c4 0a 00 aa 70 97}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASFB_2147902779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFB!MTB"
        threat_id = "2147902779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {50 55 ff 15 ?? ?? ?? 00 68 ?? ?? ?? 00 57 8b e8 ff d3 68 ?? ?? ?? 00 57 89 46 0c ff d3 68 ?? ?? ?? 00 57 89 46 10 ff d3 8b 4e 04 89 46 14 85 c9}  //weight: 5, accuracy: Low
        $x_5_2 = {ff d3 8b f0 8d 44 24 10 50 57 ff 15 ?? ?? ?? 00 85 f6 8b e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_GPH_2147902894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPH!MTB"
        threat_id = "2147902894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 62 0a 00 3c 87 da e7 bf}  //weight: 4, accuracy: Low
        $x_4_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 68 0a 00 b8 27 8e cd 33}  //weight: 4, accuracy: Low
        $x_4_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 68 0a 00 3b f3 a8 9a aa}  //weight: 4, accuracy: Low
        $x_4_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 62 0a 00 3c 87 da e7 79}  //weight: 4, accuracy: Low
        $x_4_5 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 68 0a 00 b8 27 8e cd c4}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASFC_2147902898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFC!MTB"
        threat_id = "2147902898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 4a 56 ff d7 5f eb ?? 68 ?? ?? 65 00 6a 01 6a 00 ff 15 ?? ?? 65 00 85 c0}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 81 ec ac 01 00 00 53 56 57 8d 85 ?? ?? ff ff 50 68 02 02 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASFC_2147902898_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFC!MTB"
        threat_id = "2147902898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b ec 83 ec 08 56 68 ?? ?? 65 00 e8 5f}  //weight: 5, accuracy: Low
        $n_10_2 = {57 00 61 00 6b 00 3f 00 58 00 62 00 6c 00 40 00 59 00 63 00 6d 00 41 00 5a 00 64 00 6e 00 42 00 5b 00 65 00 6f 00 43 00 5c 00 66 00 70 00 44 00 5d 00 67 00 71}  //weight: -10, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GPI_2147902934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPI!MTB"
        threat_id = "2147902934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 68 0a 00 b8 27 8e cd 33}  //weight: 4, accuracy: Low
        $x_4_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 68 0a 00 b8 27 8e cd 57}  //weight: 4, accuracy: Low
        $x_4_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 68 0a 00 3b f3 a8 9a 47}  //weight: 4, accuracy: Low
        $x_4_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 62 0a 00 3c 87 da e7 29}  //weight: 4, accuracy: Low
        $x_4_5 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 c4 0a 00 7d ab dd 6b 84}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASFD_2147902995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFD!MTB"
        threat_id = "2147902995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff d7 8d 4d fc 8b f0 51 68 00 00 00 02 56 ff 15 ?? ?? ?? 00 85 c0 74 ?? 8b 45 fc 8d 55 f8 6a 04 52 6a 18 50 ff 15 ?? ?? ?? 00 85 c0 74 12 8b 4d fc 51 ff 15 ?? ?? ?? 00 85 f6 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GPJ_2147903251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPJ!MTB"
        threat_id = "2147903251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 68 0a 00 3b f3 a8 9a d8}  //weight: 4, accuracy: Low
        $x_4_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 68 0a 00 5a 1a 83 5c 08}  //weight: 4, accuracy: Low
        $x_4_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 68 0a 00 5a 1a 83 5c 12}  //weight: 4, accuracy: Low
        $x_4_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 68 0a 00 3b f3 a8 9a cb}  //weight: 4, accuracy: Low
        $x_4_5 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 68 0a 00 5a 1a 83 5c 35}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASFE_2147903468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFE!MTB"
        threat_id = "2147903468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8b 74 24 08 57 8b 3d a8 15 4b 00 6a 10 c7 06 00 00 00 00 ff d7 66 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 83 ec 0c 53 56 57 68 ?? ?? 4b 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASFH_2147904039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFH!MTB"
        threat_id = "2147904039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {55 8b ec 83 ec 20 53 56 57 68 ?? ?? 4c 00 6a 01 6a 00 ff 15 ?? ?? 4c 00 85 c0}  //weight: 4, accuracy: Low
        $x_4_2 = {55 8b ec 83 ec 08 68 ?? ?? 65 00 6a 01 6a 00 ff 15 ?? ?? 65 00 85 c0}  //weight: 4, accuracy: Low
        $x_1_3 = "AnyMediaPlayer219" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_ASFI_2147904105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFI!MTB"
        threat_id = "2147904105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 00 6a 00 6a 01 56 ff 15 ?? ?? 65 00 68 ?? ?? 65 00 6a 00 8d 4c 24 10 6a 01 51 c7 44 24 18 0c 00 00 00 89 74 24 1c c7 44 24 20 00 00 00 00 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASFG_2147904262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFG!MTB"
        threat_id = "2147904262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {65 00 ff 15 ?? ?? 65 00 50 ff 15 ?? ?? 65 00 f7 d8 1b c0 f7 d8 c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASFG_2147904262_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFG!MTB"
        threat_id = "2147904262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 33 17 47 00 6c 74 43 00 00 d2 0a 00 df}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASFJ_2147904386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFJ!MTB"
        threat_id = "2147904386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 00 6a 00 6a 01 56 ff 15 ?? ?? 65 00 68 ?? ?? 65 00 6a 00 8d 44 24 18 6a 01 50 c7 44 24 20 0c 00 00 00 89 74 24 24 c7 44 24 28 00 00 00 00 ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {8d 4c 24 10 8d 54 24 20 51 8b 4c 24 1c 8d 44 24 18 52 50 6a 00 68 ?? ?? 65 00 51 89 6c 24 28 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASFK_2147904760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFK!MTB"
        threat_id = "2147904760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {51 ff d6 8b 15 ?? ?? ?? 00 68 ?? ?? ?? 00 52 a3 ?? ?? ?? 00 ff d6 a3 ?? ?? ?? 00 5e 59 c3 a1 ?? ?? ?? 00 68 ?? ?? ?? 00 50 ff d6 a3 ?? ?? ?? 00 5e 59 c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASFL_2147904761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFL!MTB"
        threat_id = "2147904761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 01 52 ff 15 ?? ?? ?? 00 8b c8 5e 41 f7 d9 1b c9 23 c8 33 c0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASFN_2147904762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFN!MTB"
        threat_id = "2147904762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 d2 0a 00 85 0d 45 b0 ?? ?? ?? 00 00 d4 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RP_2147904966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RP!MTB"
        threat_id = "2147904966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 0c 53 56 57 e8 f2 ee f5 ff 89 45 fc e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RP_2147904966_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RP!MTB"
        threat_id = "2147904966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 53 ff 15 b4 b4 64 00 8b d8 a1 24 fc 64 00 3b c7 75 7f 39 3d 28 fc 64 00 75 77 68 03 80 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RP_2147904966_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RP!MTB"
        threat_id = "2147904966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {56 e8 1a 72 fb ff 8b f0 e9}  //weight: 5, accuracy: High
        $x_1_2 = {40 00 00 40 5f 74 61 62 6c 65 5f}  //weight: 1, accuracy: High
        $x_1_3 = {40 00 00 40 2e 6d 70 65 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_RP_2147904966_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RP!MTB"
        threat_id = "2147904966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d9 45 08 d8 c8 d9 05 38 84 56 00 d8 4d 08 d8 05 3c 84 56 00 de c9 d8 05 40 84 56 00 d8 0d 44 84 56 00 d9 5d fc 9b eb 3b d9 45 08 d8 1d 40 84 56 00 9b df e0 9e 73 27 d9 05 48 84}  //weight: 1, accuracy: High
        $x_1_2 = {74 2e 8a 06 46 8a 27 47 38 c4 74 f2 2c 41 3c 1a 1a c9 80 e1 20 02 c1 04 41 86 e0 2c 41 3c 1a 1a c9 80 e1 20 02 c1 04 41 38 e0 74 d2 1a c0 1c ff 0f be c0 eb 78}  //weight: 1, accuracy: High
        $x_1_3 = "eSIM Client.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RP_2147904966_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RP!MTB"
        threat_id = "2147904966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0a c0 74 2e 8a 06 46 8a 27 47 38 c4 74 f2 2c 41 3c 1a 1a c9 80 e1 20 02 c1 04 41 86 e0 2c 41 3c 1a 1a c9 80 e1 20 02 c1 04 41 38 e0 74 d2 1a c0 1c ff 0f be c0 eb 78}  //weight: 5, accuracy: High
        $x_1_2 = "StudioLinePhoto.exe" wide //weight: 1
        $x_1_3 = "processlassolauncher.exe" wide //weight: 1
        $x_1_4 = "quickupgrade.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_GPK_2147905128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPK!MTB"
        threat_id = "2147905128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 ca 0a 00 67 f5 08 f4}  //weight: 4, accuracy: Low
        $x_4_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 96 0a 00 aa ed 2d a8}  //weight: 4, accuracy: Low
        $x_4_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 d2 0a 00 de 63 3f a6 c5 f4}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASFO_2147905227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFO!MTB"
        threat_id = "2147905227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 54 72 46 00 8e cf 42 00 00 d2 0a 00 58 94 5f 1e 4e 1e 42 00 00 d4 00 00 de 09 02}  //weight: 5, accuracy: High
        $x_5_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 64 45 46 00 92 a2 42 00 00 d2 0a 00 fa 3f 41 7d eb 10 42 00 00 d4 00 00 2a 8f 4c cf 00 00 01 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASFP_2147905335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFP!MTB"
        threat_id = "2147905335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 a1 14 51 00 d6 71 4d 00 00 d2 0a 00 ed db 3a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASFR_2147905863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFR!MTB"
        threat_id = "2147905863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {51 56 c7 44 24 04 00 00 00 00 ff 15 ?? ?? ?? 00 8b f0 ff 15 ?? ?? ?? 00 85 f6 a3 ?? ?? ?? 00 74 11 8d 44 24 04 50 56 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASFQ_2147905954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFQ!MTB"
        threat_id = "2147905954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ae 42 4a 00 f5 9f 46 00 00 d2 0a 00 1d 59 ee 99 a4 f8 45}  //weight: 5, accuracy: High
        $x_5_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 66 1d 4b 00 aa 7a 47 00 00 d2 0a 00 62 22 71 08 5a d3 46 00 00 d4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_AMME_2147905986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.AMME!MTB"
        threat_id = "2147905986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 da 0a 00 c8 21 20 bb 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_AMME_2147905986_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.AMME!MTB"
        threat_id = "2147905986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 96 0a 00 50 ef 5b 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_KAB_2147906070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.KAB!MTB"
        threat_id = "2147906070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 96 0a 00 46 59 ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GPL_2147906071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPL!MTB"
        threat_id = "2147906071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 ca 0a 00 69 33 b0}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GZZ_2147906089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GZZ!MTB"
        threat_id = "2147906089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AJAX DHTML Tracking" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GZZ_2147906089_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GZZ!MTB"
        threat_id = "2147906089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 7e 95 41 00 b1 f2 3d 00 00 ca 0a 00 6a d1}  //weight: 10, accuracy: High
        $x_10_2 = {6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 5f 64 42 00 92 c1 3e 00 00 ca 0a 00 ad d5 9e}  //weight: 10, accuracy: High
        $x_10_3 = {6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 96 10 43 00 c9 6d 3f 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_RL_2147906213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RL!MTB"
        threat_id = "2147906213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 08 56 57 68 9e cf 64 00 e8 ee 6e fb ff 8b f8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RL_2147906213_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RL!MTB"
        threat_id = "2147906213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 10 53 56 57 68 a9 3c 4c 00 e8 ed 07 f6 ff 89 45 fc e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RL_2147906213_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RL!MTB"
        threat_id = "2147906213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 00 8b c8 33 d2 81 e1 ff 00 00 00 8a d4 83 f9 05 8b c2 75 10 83 f8 01 73 18 c7 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RL_2147906213_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RL!MTB"
        threat_id = "2147906213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 08 56 57 68 0e df 64 00 e8 be 6f fb ff 8b f8 e9}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 83 ec 08 56 57 68 ee de 64 00 e8 ee 6f fb ff 8b f8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_RL_2147906213_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RL!MTB"
        threat_id = "2147906213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 08 56 57 68 ce c0 64 00 e8 8e 6e fb ff 8b f8 e9}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 83 ec 08 56 57 68 3e c1 64 00 e8 1e 6e fb ff 8b f8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASFS_2147906214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFS!MTB"
        threat_id = "2147906214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {51 56 ff 15 ?? ?? ?? 00 8b f0 ff 15 ?? ?? ?? 00 85 ff a3 ?? ?? ?? 00 74 27 85 f6 74 12 8b 15 ?? ?? ?? 00 68 ?? ?? ?? 00 52 ff 15 ?? ?? ?? 00 8d 44 24 08 50 57 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_KAC_2147906289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.KAC!MTB"
        threat_id = "2147906289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 be 0a 00 98 d4 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_KAD_2147906347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.KAD!MTB"
        threat_id = "2147906347"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 be 0a 00 ac 19}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GPM_2147906370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPM!MTB"
        threat_id = "2147906370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 d2 0a 00 d1 bb fe 58}  //weight: 4, accuracy: Low
        $x_4_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 d2 0a 00 52 15 41 3a}  //weight: 4, accuracy: Low
        $x_4_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 d2 0a 00 19 92 a2 e5}  //weight: 4, accuracy: Low
        $x_4_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 be 0a 00 eb e0 52 c6}  //weight: 4, accuracy: Low
        $x_4_5 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 d2 0a 00 3a ed b8 a6}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASFU_2147906607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFU!MTB"
        threat_id = "2147906607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b ec 83 ec 10 53 56 57 68 ?? 5e 4c 00 e8 ?? ec f5 ff 83 c4 04 89 45 fc}  //weight: 5, accuracy: Low
        $x_5_2 = {8b ec 83 ec 10 53 56 57 e8 ?? ?? ?? ff 89 45 f8 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASFT_2147907007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFT!MTB"
        threat_id = "2147907007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 be 0a 00 da 0e d9 3f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASFV_2147907008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFV!MTB"
        threat_id = "2147907008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 ec bc 00 00 00 8d 44 24 00 56 57 50 ff 15 ?? ?? ?? 00 8d 4c 24 18 51 ff 15 ?? ?? ?? 00 8b 54 24 10}  //weight: 5, accuracy: Low
        $x_5_2 = {6a 10 ff d7 66 85 c0 7d 06 81 0e 00 00 00 02 6a 05 e8 ad 01 20 00 6a 11 ff d7 66 85 c0 7d 06 81 0e 00 00 00 04 6a 12 ff d7 66 85 c0 7d 06 81 0e 00 00 00 08 8b c6 5f 5e c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_GZX_2147907102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GZX!MTB"
        threat_id = "2147907102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 39 bd 33 00 bc 1e 30 00 00 be ?? ?? ?? ?? ca fc 04 00 30}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RO_2147907140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RO!MTB"
        threat_id = "2147907140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 68 ef de 64 00 e8 45 6f fb ff 8b f0 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RO_2147907140_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RO!MTB"
        threat_id = "2147907140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {56 68 53 ff 64 00 e8 b5 71 fb ff 8b f0 e9}  //weight: 5, accuracy: High
        $x_5_2 = {56 68 2f df 64 00 e8 c5 71 fb ff 8b f0 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_RO_2147907140_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RO!MTB"
        threat_id = "2147907140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {56 68 01 ef 64 00 e8 a5 71 fb ff 8b f0 e9}  //weight: 5, accuracy: High
        $x_5_2 = {56 e8 ca 71 fb ff 8b f0 e9}  //weight: 5, accuracy: High
        $x_1_3 = {40 00 00 40 2e 74 61 62 6c 65}  //weight: 1, accuracy: High
        $x_1_4 = {40 00 00 40 5f 74 61 62 6c 65 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_RO_2147907140_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RO!MTB"
        threat_id = "2147907140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 0c 53 56 57 e8 ?? fe f5 ff 89 45 fc e9}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec 0c 53 56 57 68 c8 32 4c 00 e8 6d fe f5 ff 83 c4 04 89 45 fc e9}  //weight: 1, accuracy: High
        $x_5_3 = "FlappingWings" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_ASFW_2147907599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFW!MTB"
        threat_id = "2147907599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {51 53 56 57 ff 15 ?? ?? ?? ?? ?? ?? ?? ?? 00 8b f0 e8 ?? ?? ?? ff 83 c4 04 8d 44 24 0c 50 56 ff 15 ?? ?? ?? 00 8b f8 ff 15 ?? ?? ?? 00 8b d8 8b f3 81 e6 ff 00 00 00 85 ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASFX_2147907617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFX!MTB"
        threat_id = "2147907617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 01 ff 15 ?? ?? ?? 00 6a 05 e8 ?? ?? ?? 00 6a 00 ff 15 ?? ?? ?? 00 3b 05 ?? ?? ?? 00 74 05 a3 30 de 64 00 33 c0 a0}  //weight: 5, accuracy: Low
        $x_5_2 = {68 a5 00 00 00 ff 15 ?? ?? ?? 00 6a 05 e8 ?? ?? ?? 00 6a 00 ff 15 ?? ?? ?? 00 3b 05 ?? ?? ?? 00 74 05 a3 ?? ?? ?? 00 33 c0 a0}  //weight: 5, accuracy: Low
        $x_5_3 = {6a 2a ff 15 ?? ?? ?? 00 85 c0 75 10 5f 5e 5d b8 01 00 00 00 5b 81 c4 18 06 00 00 c3 8b 3d ?? ?? ?? 00 56 ff d7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASFY_2147907694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFY!MTB"
        threat_id = "2147907694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 54 24 04 56 56 8d 4c 24 10 56 51 56 52 c7 44 24 2c 02 00 00 00 c7 44 24 20 01 00 00 00 ff 15 ?? ?? ?? 00 8b f0 8b 44 24 04 f7 de 1b f6 50 f7 de ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {6a 00 52 6a 00 50 c7 44 24 ?? 02 00 00 00 c7 44 24 ?? 01 00 00 00 ff 15 ?? ?? ?? 00 8b 4c 24 08 8b f0 f7 de 1b f6 51 f7 de ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_SP_2147907934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.SP!MTB"
        threat_id = "2147907934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 c9 b2 80 84 94 0c 18 02 00 00 74 0f 66 8b 74 0c 10 66 3b b4 0c 20 04 00 00 75 1c 83 c0 02 83 c1 02 66 83 38 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASFZ_2147908411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASFZ!MTB"
        threat_id = "2147908411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 ec 0c 6a 05 c7 44 24 04 00 00 00 00 c7 44 24 08 08 00 00 00 e8 ?? ?? ?? 00 c7 44 24 08 00 00 00 00 ff 15 ?? ?? ?? 00 85 c0 74}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 01 51 ff 15 ?? ?? ?? 00 8b c8 41 f7 d9 1b c9 23 c8 33 c0 85 c9 0f 95 c0 83 c4 0c c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RM_2147908996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RM!MTB"
        threat_id = "2147908996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 10 53 56 57 e8 a2 07 f6 ff e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RM_2147908996_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RM!MTB"
        threat_id = "2147908996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 68 01 ef 64 00 e8 05 72 fb ff 8b f0 e9}  //weight: 1, accuracy: High
        $x_1_2 = {56 68 31 ef 64 00 e8 85 71 fb ff 8b f0 e9}  //weight: 1, accuracy: High
        $x_1_3 = {56 68 21 ef 64 00 e8 85 71 fb ff 8b f0 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_RN_2147908997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RN!MTB"
        threat_id = "2147908997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a7 64 00 6a 05 e8 ?? fa 1f 00 8b 4c 24 00 33 c0 85 c9 0f 95 c0 59}  //weight: 1, accuracy: Low
        $x_1_2 = {56 e8 2a 72 fb ff 8b f0 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASGA_2147909155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGA!MTB"
        threat_id = "2147909155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {56 ff d3 68 ?? ?? ?? 00 56 a3 ?? ?? ?? 00 ff d3 57 a3 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 f7 d8 1b c0 5f 5e 5b f7 d8 c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RR_2147909834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RR!MTB"
        threat_id = "2147909834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 8b 44 24 00 50 ff 15 4c a3 64 00 6a 00 ff 15 8c a0 64 00 6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 40 68 58 e0 64 00 ff 15 48 a3 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RS_2147910275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RS!MTB"
        threat_id = "2147910275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {56 e8 0a 74 fb ff 8b f0 e9}  //weight: 5, accuracy: High
        $x_1_2 = {40 00 00 40 5f 72 65 61 63 74 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RS_2147910275_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RS!MTB"
        threat_id = "2147910275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {90 90 90 90 56 e8 1a 72 fb ff 8b f0 e9}  //weight: 5, accuracy: High
        $x_1_2 = {40 00 00 40 2e 6d 61 69 6c}  //weight: 1, accuracy: High
        $x_1_3 = {40 00 00 40 2e 72 65 61 63 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_MBYH_2147910494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.MBYH!MTB"
        threat_id = "2147910494"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 a0 96 64 00 68 00 83 64 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RT_2147910495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RT!MTB"
        threat_id = "2147910495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 0c 53 56 57 e8 ?? fe f5 ff 89 45 fc e9}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec 0c 53 56 57 68 57 5c 4c 00 e8 1d ee f5 ff 89 45 fc e9}  //weight: 1, accuracy: High
        $x_1_3 = {55 8b ec 83 ec 0c 53 56 57 e8 12 f2 f5 ff 89 45 fc e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_RU_2147910529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RU!MTB"
        threat_id = "2147910529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {56 e8 fa 73 fb ff 8b f0 e9}  //weight: 5, accuracy: High
        $x_5_2 = {56 e8 3a 74 fb ff 8b f0 e9}  //weight: 5, accuracy: High
        $x_5_3 = {56 e8 0a 74 fb ff 8b f0 e9}  //weight: 5, accuracy: High
        $x_5_4 = {56 e8 1a 74 fb ff 8b f0 e9}  //weight: 5, accuracy: High
        $x_2_5 = {40 00 00 40 5f 6c 69 62 73 74 64}  //weight: 2, accuracy: High
        $x_2_6 = {40 00 00 40 2e 6c 69 62 73 74 64}  //weight: 2, accuracy: High
        $x_1_7 = "CoverCommander.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_ASGB_2147910548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGB!MTB"
        threat_id = "2147910548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b ec 83 ec 0c 53 56 57 e8 ?? ?? f6 ff 89 45 fc e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_HNA_2147910596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.HNA!MTB"
        threat_id = "2147910596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {67 57 06 d4 52 ad 92 1c fe f2 25 ea 43 4d 9e 0c e2 a1 55 0f 00 16 9b 15 81 b5 ae b9 59 88 e7 96}  //weight: 2, accuracy: High
        $x_2_2 = {bf f5 ce 5e 7e 96 92 14 ff 97 4f a2 6f e7 f2 c9 49 d0 0f d4 f7 00 4d a2 78 ec 07 d6 2b cc 63 49}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASGC_2147910847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGC!MTB"
        threat_id = "2147910847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 e8 03 00 00 68 e8 03 00 00 68 c9 04 00 00 56 ff d7 85 c0 7e 07 50 ff 15 ?? ?? ?? 00 6a 00 6a 00 6a 4a 56 ff d7}  //weight: 2, accuracy: Low
        $x_2_2 = {55 8b ec 83 ec 0c 53 56 57 68 ?? ?? 4c 00 e8 ?? ?? ?? ff 89 45 fc e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RV_2147910909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RV!MTB"
        threat_id = "2147910909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 51 56 68 ?? df 64 00 e8 01 74 fb ff e9}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 51 56 68 1f df 64 00 e8 f1 73 fb ff e9}  //weight: 5, accuracy: High
        $x_2_3 = {40 00 00 40 5f 6c 69 62 73 74 64}  //weight: 2, accuracy: High
        $x_2_4 = {40 00 00 40 2e 6c 69 62 73 74 64}  //weight: 2, accuracy: High
        $x_1_5 = "CoverCommander.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_ASGD_2147911087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGD!MTB"
        threat_id = "2147911087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4b 00 85 c0 74 0c 8d 4c 24 00 51 50 ff 15 ?? ?? 4b 00 8b 44 24 00 59 c3}  //weight: 2, accuracy: Low
        $x_2_2 = {55 8b ec 83 ec 0c 53 56 57 e8 ?? ?? f5 ff 89 45 fc e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_MBYK_2147911351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.MBYK!MTB"
        threat_id = "2147911351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 6a ff 68 b8 f9 4b 00 68 38 9a 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 e4 f3 4b 00 33 d2 8a d4 89 15 ?? 8d 4c 00 8b c8}  //weight: 2, accuracy: Low
        $x_2_2 = {55 8b ec 6a ff 68 b8 f9 4b 00 68 28 9a 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 e4 f3 4b 00 33 d2 8a d4 89 15 60 8d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d 5c 8d 4c 00 c1 e1 08 03 ca}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_RW_2147911360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RW!MTB"
        threat_id = "2147911360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 83 ec 0c 53 56 57 68 51 5c 4c 00 e8 fd ec f5 ff 83 c4 04 e9}  //weight: 5, accuracy: High
        $x_5_2 = {55 8b ec 83 ec 0c 53 56 57 e8 62 ec f5 ff 89 45 fc e9}  //weight: 5, accuracy: High
        $x_5_3 = {55 8b ec 83 ec 0c 53 56 57 e8 22 ed f5 ff 0f be c0 89 45 fc e9}  //weight: 5, accuracy: High
        $x_1_4 = {40 00 00 40 5f 66 6c 61 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_ASGE_2147911770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGE!MTB"
        threat_id = "2147911770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 ec 0c 56 57 ff 15 ?? ?? ?? 00 8b f0 8d 44 24 08 33 ff 50 68 19 00 02 00 57 68 ?? ?? ?? 00 68 00 00 00 80 ff 15 ?? ?? ?? 00 85 c0 74}  //weight: 2, accuracy: Low
        $x_2_2 = {8b ec 83 ec 0c 53 56 57 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 89 45 fc e9}  //weight: 2, accuracy: Low
        $x_2_3 = {51 6a 01 ff 15 ?? ?? ?? 00 68 ?? ?? ?? 00 a3 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 68 ?? ?? ?? 00 50 ff 15 ?? ?? ?? 00 8a 44 24 00 59 c3}  //weight: 2, accuracy: Low
        $x_2_4 = {55 8b ec 83 ec 0c 53 56 57 e8 ?? ?? ?? ff 0f be c0 89 45 fc e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ekstak_RY_2147911819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RY!MTB"
        threat_id = "2147911819"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 68 a0 c0 64 00 68 54 c0 64 00 e8 ?? ?? fb ff 8b f0 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASGF_2147912097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGF!MTB"
        threat_id = "2147912097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 40 68 ?? ?? ?? 00 8b f8 ff 15 ?? ?? ?? 00 8b f0 68 ?? ?? ?? 00 57 89 35}  //weight: 2, accuracy: Low
        $x_2_2 = {56 e8 0a 74 fb ff 8b f0 e9}  //weight: 2, accuracy: High
        $x_2_3 = {51 53 55 56 57 68 a5 00 00 00 ff 15 ?? ?? ?? 00 66 85 c0 75 20 6a 00 ff 15 ?? ?? ?? 00 3b 05}  //weight: 2, accuracy: Low
        $x_2_4 = {68 a5 00 00 00 8b f0 33 ed ff 15 ?? ?? ?? 00 66 85 c0 75 2b 6a 00 ff 15 ?? ?? ?? 00 3b 05}  //weight: 2, accuracy: Low
        $x_2_5 = {68 a5 00 00 00 8b f8 c7 44 24 14 00 00 00 00 ff 15 ?? ?? ?? 00 8b 35 ?? ?? ?? 00 66 85 c0 75 2d 6a 00 ff 15 ?? ?? ?? 00 3b 05}  //weight: 2, accuracy: Low
        $x_2_6 = {55 8b ec 83 ec 0c 53 56 57 e8 ?? ?? ?? ff 89 45 fc e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ekstak_RZ_2147912339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RZ!MTB"
        threat_id = "2147912339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 18 53 56 57 89 65 e8 9b 33 d2 89 55 fc e9 ?? ?? ?? ?? 20 10 00 00 00 00 00 00 00 43 56 20 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RZ_2147912339_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RZ!MTB"
        threat_id = "2147912339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 57 68 21 cf 64 00 e8 f4 73 fb ff 8b f0 e9}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 83 ec 0c 53 56 57 68 84 22 4c 00 e8 ?? ec f5 ff 83 c4 04 89 45 fc e9}  //weight: 1, accuracy: Low
        $x_1_3 = {55 8b ec 83 ec 0c 53 56 57 e8 82 ec f5 ff 89 45 fc e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASGH_2147912366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGH!MTB"
        threat_id = "2147912366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {51 56 ff 15 ?? ?? ?? 00 8b f0 c7 44 24 04 00 00 00 00 ff 15 ?? ?? ?? 00 68 ?? ?? ?? 00 a3 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 03 c8 85 f6 89}  //weight: 2, accuracy: Low
        $x_2_2 = {55 8b ec 83 ec 0c 53 56 57 e8 ?? ?? ?? ff 89 45 fc e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_KAE_2147912429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.KAE!MTB"
        threat_id = "2147912429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 a2 0a 00 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_HNC_2147912671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.HNC!MTB"
        threat_id = "2147912671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00}  //weight: 1, accuracy: High
        $x_1_2 = {20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 00 00 00 00 4a 00 15 00 01 00 46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 00 00 00 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00}  //weight: 1, accuracy: High
        $x_1_3 = {eb 7a 91 09 6f c7 74 c0 73 0a 2b c8 56 a6 69 fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GLX_2147912684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GLX!MTB"
        threat_id = "2147912684"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ec 6a ff 68 ?? 83 64 00 68 ?? 7d 64 00 64 a1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02}  //weight: 10, accuracy: Low
        $x_10_2 = {8b ec 6a ff 68 ?? 97 64 00 68 ?? 85 64 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02}  //weight: 10, accuracy: Low
        $x_1_3 = "Moon Codec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_PGAA_2147912799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.PGAA!MTB"
        threat_id = "2147912799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b ec 6a ff 68 ?? 97 64 00 68 ?? 84 64 00 64 a1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASGI_2147912860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGI!MTB"
        threat_id = "2147912860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 ec c0 00 00 00 8d 44 24 04 56 50 ff 15 ?? ?? 64 00 8b 35 ?? ?? 64 00 6a 00 ff d6 83 f8 07 75 04 6a 01 ff d6 c7 44 24 04 00 00 00 00 ff 15 ?? ?? 64 00 85 c0 5e 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASGJ_2147912929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGJ!MTB"
        threat_id = "2147912929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 51 a0 ?? ?? ?? 00 8a 0d ?? ?? ?? 00 32 c8 56 88 0d ?? ?? ?? 00 8a 0d ?? ?? ?? 00 80 c9 08 57 c0 e9 03 81 e1 ff 00 00 00 89 4d fc db 45 fc dc 3d}  //weight: 5, accuracy: Low
        $x_5_2 = {6a 00 8d 44 24 ?? 6a 01 50 c7 44 24 ?? 0c 00 00 00 89 74 24 ?? c7 44 24 28 00 00 00 00 ff 15 ?? ?? 64 00 5f a3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASGK_2147913313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGK!MTB"
        threat_id = "2147913313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b ec 83 ec 18 53 56 57 a1 ?? ?? 4c 00 c1 e0 03 0b 05 ?? ?? 4c 00 89 45 ec c7 45 f0 00 00 00 00 df 6d ec dd 1d ?? ?? 4c 00 8b 0d ?? ?? 4c 00 33 0d ?? ?? 4c 00 d1 e1}  //weight: 4, accuracy: Low
        $x_2_2 = {8b d8 85 db 74 2a ff 15 ?? ?? 65 00 6a 00 6a 00 68 ?? ?? 65 00 68 ?? ?? 85 00 a3 ?? ?? 65 00 ff d3 ff 15 ?? ?? 65 00 48 5b f7 d8 1b c0 f7 d8 c3}  //weight: 2, accuracy: Low
        $x_2_3 = "{cf5ebf46-e3b6-449a-b56b-43f568f87814}" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_ASGL_2147913462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGL!MTB"
        threat_id = "2147913462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {65 00 ff d6 68 ?? ?? 65 00 ff 15 ?? ?? 65 00 68 ?? ?? 65 00 50 ff d6 85 c0 5e 74 1d 6a 00 6a 00 68 ?? ?? 65 00 68 ?? ?? ?? 00 ff d0 ff 15 ?? ?? 65 00 48 f7 d8 1b c0 f7 d8 c3}  //weight: 2, accuracy: Low
        $x_2_2 = "{cf5ebf46-e3b6-449a-b56b-568f843f7814}" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASGM_2147913582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGM!MTB"
        threat_id = "2147913582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 6b 56 ff 15 ?? ?? ?? 00 8d 4c 24 04 89 44 24 1c 51 c7 44 24 2c 6d 00 00 00 c7 44 24 30 ?? ?? ?? 00 c7 44 24 28 00 00 00 00 ff 15 ?? ?? ?? 00 5e 83 c4 30 c3}  //weight: 5, accuracy: Low
        $x_4_2 = {83 ec 10 56 50 be 01 00 00 00 e8 ?? ?? ?? 00 8d 4c 24 08 51 68 19 00 02 00 6a 00 68 ?? ?? 65 00 68 02 00 00 80 ff 15 ?? ?? ?? 00 85 c0 75}  //weight: 4, accuracy: Low
        $x_1_3 = "Catalogic Book List" wide //weight: 1
        $x_4_4 = {6a 6b 50 c7 44 24 14 00 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 08 30 00 00 00 c7 44 24 0c 03 00 00 00 c7 44 24 10 ?? ?? ?? 00 89 44 24 1c ff 15 ?? ?? ?? 00 89 44 24 18 8d 44 24 00 50 c7 44 24 28 6d 00 00 00 c7 44 24 2c ?? ?? ?? 00 c7 44 24 24 00 00 00 00 ff 15 ?? ?? ?? 00 83 c4 30 c3}  //weight: 4, accuracy: Low
        $x_1_5 = "Free_Audio_Converter_32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_ASGN_2147913821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGN!MTB"
        threat_id = "2147913821"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {65 00 ff 15 ?? ?? 65 00 6a 00 66 ?? ?? 50 cf 65 00 7f 00 e8 ?? ?? ?? 00 01 05 ?? ?? 65 00 ff 15 ?? ?? 65 00 8b f0 81 e6 ff 00 00 00 83 fe 06 0f 93 c0 83 fe 06 a2 ?? ?? 65 00 72 5c 57 e8}  //weight: 4, accuracy: Low
        $x_1_2 = {50 ff d6 68 ?? ?? 65 00 50 ff d7 8b f0 5f 89 35 ?? ?? 65 00 68 ?? ?? 65 00 ff 15 ?? ?? 65 00 8b c6 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_CCIQ_2147913832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CCIQ!MTB"
        threat_id = "2147913832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 18 53 56 57 e8 ?? ?? de ff 89 45 fc e9 ?? ?? ?? ff 20 10 00 00 00 00 00 00 00 43 56 20 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_CCIQ_2147913832_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CCIQ!MTB"
        threat_id = "2147913832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 10 53 56 57 e8 ?? ?? f5 ff 89 45 fc e9}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 15 a4 f4 4b 00 68 ?? 59 4c 00 a3 ?? 5b 4c 00 ff 15 10 f0 4b 00 6a 00 66 c7 05 ?? 5c 4c 00 7f 00 e8 cf 13 0a 00 01 05 ?? 5b 4c 00 ff 15 0c f0 4b 00 8b f0 81 e6 ff 00 00 00 83 fe 06 0f 93 c0 83 fe 06 a2 ?? 5c 4c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_PMAA_2147913855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.PMAA!MTB"
        threat_id = "2147913855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 9a 65 00 68 ?? 8c 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_PQAA_2147913950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.PQAA!MTB"
        threat_id = "2147913950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 16 4c 00 68 ?? b3 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 8e 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 8e 4c 00 c1 e1 08 03 ca 89 0d ?? 8e 4c 00 c1 e8 10 a3 ?? 8e 4c 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASGO_2147914007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGO!MTB"
        threat_id = "2147914007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 00 ff 15 ?? ?? 65 00 6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 40 68 ?? ?? 65 00 ff 15 ?? ?? 65 00 a3 ?? ?? 65 00 c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_PUAA_2147914037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.PUAA!MTB"
        threat_id = "2147914037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 06 4c 00 68 ?? a3 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 7e 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 7e 4c 00 c1 e1 08 03 ca 89 0d ?? 7e 4c 00 c1 e8 10 a3 ?? 7e 4c 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? f6 4b 00 68 ?? 93 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4b 00 33 d2 8a d4 89 15 ?? 7e 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 7e 4c 00 c1 e1 08 03 ca 89 0d ?? 7e 4c 00 c1 e8 10 a3 ?? 7e 4c 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASGP_2147914107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGP!MTB"
        threat_id = "2147914107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {5f 5e 59 c3 68 ?? ?? ?? 00 6a 01 6a 00 ff 15 ?? ?? ?? 00 85 c0 74 e5 6a 00 ff 15 ?? ?? ?? 00 8b 74 24 08 6a 5a 56 ff 15 ?? ?? ?? 00 56 6a 00 8b f8 ff 15}  //weight: 4, accuracy: Low
        $x_1_2 = "StarsAudioConverter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GPN_2147914109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPN!MTB"
        threat_id = "2147914109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 11 76 c2 40}  //weight: 4, accuracy: Low
        $x_4_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 4a 1a 10 78}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASGR_2147914236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGR!MTB"
        threat_id = "2147914236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {56 57 6a 00 ff 15 ?? ?? 65 00 6a 00 ff 15 ?? ?? 65 00 8b f0 ff 15 ?? ?? 65 00 6a 5a 56 a3 ?? ?? 65 00 ff 15 ?? ?? 65 00 56 6a 00 8b f8 ff 15 ?? ?? 65 00 8b c7 5f 5e c3}  //weight: 3, accuracy: Low
        $x_3_2 = {56 57 6a 00 ff 15 ?? ?? 65 00 8b f0 6a 5a 56 ff 15 ?? ?? 65 00 56 6a 00 8b f8 ff 15 ?? ?? 65 00 8b c7 5f 5e c3}  //weight: 3, accuracy: Low
        $x_1_3 = "ExtremeZ-IP.exe" wide //weight: 1
        $x_1_4 = {56 57 e8 c9 53 fb ff 8b f0 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_QGAA_2147914436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.QGAA!MTB"
        threat_id = "2147914436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? f9 4b 00 68 ?? 9a 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4b 00 33 d2 8a d4 89 15 ?? 8d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 8d 4c 00 c1 e1 08 03 ca 89 0d ?? 8d 4c 00 c1 e8 10 a3 ?? 8d 4c 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GP_2147914455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GP!MTB"
        threat_id = "2147914455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ca ae 25 00 e2 ae 25 00 f4 ae 25 00 fe ae 25 00 1a af 25 00 30 af 25 00 4a af 25 00 5a af 25 00 7a af 25 00 88 af 25 00 9e af 25 00 b4 af 25}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_QHAA_2147914550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.QHAA!MTB"
        threat_id = "2147914550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 95 65 00 68 ?? 82 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_MBFI_2147914716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.MBFI!MTB"
        threat_id = "2147914716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 b8 85 65 00 68 10 73 65 00 64 a1 ?? ?? ?? ?? 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_QMAA_2147914738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.QMAA!MTB"
        threat_id = "2147914738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 89 65 00 68 ?? 7b 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_SPPD_2147914892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.SPPD!MTB"
        threat_id = "2147914892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 da 0a 00 ae 80 20 73 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_MBXC_2147914904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.MBXC!MTB"
        threat_id = "2147914904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 f8 e4 4b 00 68 ec 80 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 6a ff 68 58 89 65 00 68 90 7a 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_QPAA_2147914965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.QPAA!MTB"
        threat_id = "2147914965"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? e5 4b 00 68 ?? 81 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4b 00 33 d2 8a d4 89 15 ?? 5d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 5d 4c 00 c1 e1 08 03 ca 89 0d ?? 5d 4c 00 c1 e8 10 a3 ?? 5d 4c 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? f5 4b 00 68 ?? 91 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4b 00 33 d2 8a d4 89 15 ?? 6d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 6d 4c 00 c1 e1 08 03 ca 89 0d ?? 6d 4c 00 c1 e8 10 a3 ?? 6d 4c 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_STPD_2147915125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.STPD!MTB"
        threat_id = "2147915125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 da 0a 00 1c c3 13 b1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_QTAA_2147915182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.QTAA!MTB"
        threat_id = "2147915182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 88 65 00 68 ?? 78 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_SPVF_2147915205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.SPVF!MTB"
        threat_id = "2147915205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 af 52 5d 00 4a aa 59 00 00 da 0a 00 a7 ae 66 31 c7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GPO_2147915238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPO!MTB"
        threat_id = "2147915238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 e4 0c 00 a0 5f ba 6b}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GPO_2147915238_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPO!MTB"
        threat_id = "2147915238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 e8 99 70 1c}  //weight: 4, accuracy: Low
        $x_4_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 b3 f5 a2 24}  //weight: 4, accuracy: Low
        $x_4_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 be 40 73 d5}  //weight: 4, accuracy: Low
        $x_4_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 08 98 d7 a4}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_MBXG_2147915319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.MBXG!MTB"
        threat_id = "2147915319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? 87 65 00 68 ?? 76 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_MBXH_2147915335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.MBXH!MTB"
        threat_id = "2147915335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? 04 4c 00 68 ?? a0 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_KAF_2147915352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.KAF!MTB"
        threat_id = "2147915352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 5e 41}  //weight: 1, accuracy: Low
        $x_1_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 05 2d 06 55 bf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_RCAA_2147915516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RCAA!MTB"
        threat_id = "2147915516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 09 4c 00 68 ?? 9a 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 9d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 9d 4c 00 c1 e1 08 03 ca 89 0d ?? 9d 4c 00 c1 e8 10 a3 ?? 9d 4c 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASGU_2147915647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGU!MTB"
        threat_id = "2147915647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {53 56 8b 74 24 0c 57 c7 06 00 00 00 00 a1 ?? ?? 65 00 50 e8 ?? ?? 20 00 8b 3d ?? ?? 65 00 6a 12 a3 ?? ?? 65 00 ff d7 66 85 c0 6a 10 0f 95 c3 ff d7 66 85 c0 7d}  //weight: 4, accuracy: Low
        $x_1_2 = {55 8b ec 51 56 57 68 ?? ?? 65 00 e8 ?? ?? fb ff 8b f0 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GNM_2147915773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GNM!MTB"
        threat_id = "2147915773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {32 ca 8b 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 83 e1 ?? 83 e0 ?? 03 d1 8b 35 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 e2 ?? ?? ?? ?? 55 0f af c2 33 f0 57 8d 44 24 ?? 6a 50 50}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASGV_2147915798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGV!MTB"
        threat_id = "2147915798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {55 8b ec 83 ec 10 53 56 57 68 ?? ?? 4c 00 e8 ?? ?? f5 ff 83 c4 04 e9}  //weight: 4, accuracy: Low
        $x_1_2 = "Angular JS Editor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RIAA_2147915837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RIAA!MTB"
        threat_id = "2147915837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? f8 4b 00 68 ?? 98 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4b 00 33 d2 8a d4 89 15 ?? 7f 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 7f 4c 00 c1 e1 08 03 ca 89 0d ?? 7f 4c 00 c1 e8 10 a3 ?? 7f 4c 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? 08 4c 00 68 ?? a7 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 8f 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 8f 4c 00 c1 e1 08 03 ca 89 0d ?? 8f 4c 00 c1 e8 10 a3 ?? 8f 4c 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_KAG_2147915856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.KAG!MTB"
        threat_id = "2147915856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 7b}  //weight: 1, accuracy: Low
        $x_1_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 43}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_CCJC_2147915880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CCJC!MTB"
        threat_id = "2147915880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 56 8b 74 24 0c 57 c7 06 00 00 00 00 a1 ?? ?? 65 00 50 e8 ?? ?? 20 00 8b 3d ?? ?? 65 00 6a 12 a3 ?? ?? 65 00 ff d7 66 85 c0 6a 10 0f 95 c3 ff d7 66 85 c0 7d}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 56 57 68 ?? ?? 65 00 e8 ?? ?? fb ff 8b ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_KAH_2147915899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.KAH!MTB"
        threat_id = "2147915899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 ad}  //weight: 1, accuracy: Low
        $x_1_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 86}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_RMAA_2147916090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RMAA!MTB"
        threat_id = "2147916090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? f7 4b 00 68 ?? 98 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4b 00 33 d2 8a d4 89 15 ?? 7d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 7d 4c 00 c1 e1 08 03 ca 89 0d ?? 7d 4c 00 c1 e8 10 a3 ?? 7d 4c 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? 17 4c 00 68 ?? b8 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 9d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 9d 4c 00 c1 e1 08 03 ca 89 0d ?? 9d 4c 00 c1 e8 10 a3 ?? 9d 4c 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_3 = {55 8b ec 6a ff 68 ?? f7 4b 00 68 ?? 98 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4b 00 33 d2 8a d4 89 15 ?? 7e 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 7d 4c 00 c1 e1 08 03 ca 89 0d ?? 7d 4c 00 c1 e8 10 a3 ?? 7d 4c 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_4 = {55 8b ec 6a ff 68 ?? e7 4b 00 68 ?? 88 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4b 00 33 d2 8a d4 89 15 ?? 6d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 6d 4c 00 c1 e1 08 03 ca 89 0d ?? 6d 4c 00 c1 e8 10 a3 ?? 6d 4c 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_DSPD_2147916134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.DSPD!MTB"
        threat_id = "2147916134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 06 39 5e 00 ab 90 5a 00 00 da 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_CCJD_2147916145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CCJD!MTB"
        threat_id = "2147916145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {53 55 56 57 ff 15 ?? ?? 4c 00 8b 5c 24 14 68 64 50 4c 00 53 a3 ?? ?? 4c 00 ff 15 ?? ?? 4c 00 85 c0 74 09 6a 00 e8 ?? ?? ?? ?? eb 05 e8 ?? ?? ?? ?? 8b 0d ?? ?? 4c 00 8b 2d ?? ?? 4c 00 6a 00 6a 00 6a ff 53 03 c8}  //weight: 5, accuracy: Low
        $x_5_2 = {83 ec 08 8d 44 24 00 56 33 f6 50 68 19 00 02 00 56 68 74 30 4c 00 68 00 00 00 80 ff 15 ?? ?? ?? ?? 85 c0 74 09 33 c0 5e}  //weight: 5, accuracy: Low
        $x_1_3 = {55 8b ec 83 ec 10 53 56 57 68 ?? ?? 4c 00 e8 ?? ?? f5 ff 89 45 fc e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_RQAA_2147916194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RQAA!MTB"
        threat_id = "2147916194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 07 4c 00 68 ?? a7 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 8d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 8d 4c 00 c1 e1 08 03 ca 89 0d ?? 8d 4c 00 c1 e8 10 a3 ?? 8d 4c 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_RSAA_2147916203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.RSAA!MTB"
        threat_id = "2147916203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? e8 4b 00 68 ?? 88 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4b 00 33 d2 8a d4 89 15 ?? 6d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 6d 4c 00 c1 e1 08 03 ca 89 0d ?? 6d 4c 00 c1 e8 10 a3 ?? 6d 4c 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_MBXI_2147916278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.MBXI!MTB"
        threat_id = "2147916278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? 09 4c 00 68 ?? a9 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? 03 4c 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASGW_2147916279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGW!MTB"
        threat_id = "2147916279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {6a 01 56 ff 15 ?? ?? ?? 00 6a 00 6a 00 6a 01 56 ff 15 ?? ?? ?? 00 68 ?? ?? ?? 00 6a 00 8d 54 24 10 6a 01 52 c7 44 24 18 0c 00 00 00 89 74 24 1c c7 44 24 20 00 00 00 00 ff 15 ?? ?? ?? 00 a3 ?? ?? ?? 00 5e 83 c4 10 c3}  //weight: 4, accuracy: Low
        $x_1_2 = {56 8d 44 24 04 57 50 ff 15 ?? ?? ?? 00 8b 74 24 0c 8b 7c 24 08 33 f7 ff 15}  //weight: 1, accuracy: Low
        $x_4_3 = {8b 44 24 04 c7 00 00 00 00 00 ff 15 ?? ?? 65 00 6a 12 a3 ?? ?? 65 00 ff 15 ?? ?? 65 00 8b 44 24 04 c3}  //weight: 4, accuracy: Low
        $x_1_4 = {56 68 31 bf 65 00 e8 c5 55 fb ff 8b f0 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_ASGX_2147916364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGX!MTB"
        threat_id = "2147916364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 12 a3 7c bd 65 00 ff d7 66 85 c0 6a 10 0f 95 c3 ff d7 66 85 c0 7d 06 81 0e 00 00 00 02 6a 11 ff d7 66 85 c0 7d 06 81 0e 00 00 00 04 6a 00 ff 15 ?? ?? 65 00 84 db 74 06 81 0e ?? ?? ?? 00 8b c6 5f 5e 5b c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GPP_2147916422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPP!MTB"
        threat_id = "2147916422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 c4 0a 00 0b fd a3 65}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GPP_2147916422_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPP!MTB"
        threat_id = "2147916422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 39}  //weight: 4, accuracy: Low
        $x_4_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 d6}  //weight: 4, accuracy: Low
        $x_4_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 cf 8a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_MBXJ_2147916449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.MBXJ!MTB"
        threat_id = "2147916449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? 85 65 00 68 ?? 72 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GZM_2147916472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GZM!MTB"
        threat_id = "2147916472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 44 24 08 50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 01 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 14 6a 40 ff 15 ?? ?? ?? ?? 8b f8 6a 01 57}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_CCJE_2147916502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CCJE!MTB"
        threat_id = "2147916502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 ec 10 56 57 68 54 b0 65 00 6a 00 8d 44 24 14 6a 01 50 c7 44 24 1c 0c 00 00 00 c7 44 24 20 00 00 00 00 c7 44 24 24 00 00 00 00 ff 15 2c 82 65 00 8b 0d a0 bd 65 00 8b f0 51 c7 44 24 0c 00 00 00 00 ff 15 28 82 65 00 8d 54 24 08 52}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_SBAA_2147916527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.SBAA!MTB"
        threat_id = "2147916527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? f5 4b 00 68 ?? 93 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4b 00 33 d2 8a d4 89 15 ?? 6d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 6d 4c 00 c1 e1 08 03 ca 89 0d ?? 6d 4c 00 c1 e8 10 a3 ?? 6d 4c 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASGY_2147916622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGY!MTB"
        threat_id = "2147916622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 ec 10 a1 ?? ?? 65 00 56 57 50 e8 ?? ?? ?? 00 8d 54 24 0c c7 44 24 0c 0c 00 00 00 8b 4c 24 1c c7 44 24 10 00 00 00 00 51 6a 00 6a 01 52 c7 44 24 24 00 00 00 00 ff 15 ?? ?? 65 00 8b f0 a1 ?? ?? 65 00 50 c7 44 24 0c 00 00 00 00 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_KAJ_2147916731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.KAJ!MTB"
        threat_id = "2147916731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 52}  //weight: 1, accuracy: Low
        $x_1_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 0e}  //weight: 1, accuracy: Low
        $x_1_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_SLAA_2147916907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.SLAA!MTB"
        threat_id = "2147916907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? d5 4b 00 68 ?? 71 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4b 00 33 d2 8a d4 89 15 ?? 4d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 4d 4c 00 c1 e1 08 03 ca 89 0d ?? 4d 4c 00 c1 e8 10 a3 ?? 4d 4c 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? d5 4b 00 68 ?? 71 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4b 00 33 d2 8a d4 89 15 ?? 4d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 4c 4c 00 c1 e1 08 03 ca 89 0d ?? 4c 4c 00 c1 e8 10 a3 ?? 4c 4c 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_3 = {55 8b ec 6a ff 68 ?? d5 4b 00 68 ?? 71 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4b 00 33 d2 8a d4 89 15 ?? 4d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 4d 4c 00 c1 e1 08 03 ca 89 0d ?? 4c 4c 00 c1 e8 10 a3 ?? 4c 4c 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_4 = {55 8b ec 6a ff 68 ?? 08 4c 00 68 ?? a9 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 8d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 8d 4c 00 c1 e1 08 03 ca 89 0d ?? 8d 4c 00 c1 e8 10 a3 ?? 8d 4c 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_KAL_2147916976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.KAL!MTB"
        threat_id = "2147916976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 81 4a}  //weight: 1, accuracy: Low
        $x_1_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 d5}  //weight: 1, accuracy: Low
        $x_1_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_GPQ_2147916982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPQ!MTB"
        threat_id = "2147916982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 a3 37 e7 f9}  //weight: 4, accuracy: Low
        $x_4_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 8b 94}  //weight: 4, accuracy: Low
        $x_4_3 = {ec bd 25 00 fc bd 25 00 14 be 25 00 24 be 25 00 3c be 25 00 58 be 25 00 6a be 25 00 7c be 25 00 94 be 25 00 a2 be 25 00 b0 be 25 00 c0 be 25}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASGT_2147917039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGT!MTB"
        threat_id = "2147917039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 53 56 57 55 6a 00 6a 00 68 ?? ?? 4b 00 ff 75 08 e8 ?? ?? 00 00 5d 5f 5e 5b 8b e5 5d c3}  //weight: 2, accuracy: Low
        $x_2_2 = {55 8b ec 83 ec 10 53 56 57 68 ?? ?? 4c 00 e8 ?? ?? f5 ff 83 c4 04 89 45 fc e9}  //weight: 2, accuracy: Low
        $x_1_3 = "cmdfmt.exe" wide //weight: 1
        $x_1_4 = "AGP BUS Driver" wide //weight: 1
        $x_1_5 = "AFI CIO Print Driver" wide //weight: 1
        $x_1_6 = "Aero Sample" wide //weight: 1
        $x_1_7 = "wsgen.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_CCJF_2147917043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CCJF!MTB"
        threat_id = "2147917043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 10 b5 65 00 68 90 62 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 20 b2 65 00 33 d2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_SSAA_2147917142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.SSAA!MTB"
        threat_id = "2147917142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? b4 65 00 68 ?? 62 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 65 00 33 d2 8a d4 89 15 ?? 37 a6 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 37 a6 00 c1 e1 08 03 ca 89 0d ?? 37 a6 00 c1 e8 10 a3 ?? 37 a6 00 33 f6 56 e8}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? b5 65 00 68 ?? 62 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 65 00 33 d2 8a d4 89 15 ?? 37 a6 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 37 a6 00 c1 e1 08 03 ca 89 0d ?? 37 a6 00 c1 e8 10 a3 ?? 37 a6 00 33 f6 56 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_ASGZ_2147917333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASGZ!MTB"
        threat_id = "2147917333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d 14 09 8b 0d ?? ?? 65 00 0b d1 89 54 24 04 df 6c 24 04 dc 05 ?? ?? 65 00 dd 1d ?? ?? 65 00 ff 15 ?? ?? 65 00 a1 ?? ?? ?? 00 50 ff 15 ?? ?? 65 00 68 ?? ?? 65 00 ff 15 ?? ?? 65 00 b8 01 00 00 00 83 c4 08 c3}  //weight: 4, accuracy: Low
        $x_1_2 = {83 ec 08 a1 [0-9] 00 8b 0d 30 ?? ?? 00 50 c7 44 24 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_KAM_2147917475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.KAM!MTB"
        threat_id = "2147917475"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 8c 70}  //weight: 1, accuracy: Low
        $x_1_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_SZAA_2147917519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.SZAA!MTB"
        threat_id = "2147917519"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? f3 4b 00 68 ?? 8e 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4b 00 33 d2 8a d4 89 15 ?? 5d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 5d 4c 00 c1 e1 08 03 ca 89 0d ?? 5d 4c 00 c1 e8 10 a3 ?? 5d 4c 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? f3 4b 00 68 ?? 8d 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4b 00 33 d2 8a d4 89 15 ?? 5d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 5d 4c 00 c1 e1 08 03 ca 89 0d ?? 5d 4c 00 c1 e8 10 a3 ?? 5d 4c 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_TCAA_2147917671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.TCAA!MTB"
        threat_id = "2147917671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? c6 65 00 68 ?? 64 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 65 00 33 d2 8a d4 89 15 ?? 47 a6 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 47 a6 00 c1 e1 08 03 ca 89 0d ?? 47 a6 00 c1 e8 10 a3 ?? 47 a6 00 33 f6 56 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASHA_2147917812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASHA!MTB"
        threat_id = "2147917812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {81 ec 1c 06 00 00 53 55 56 57 ff 15 ?? ?? 4b 00 8b ac 24 ?? ?? 00 00 8b b4 24 ?? ?? 00 00 55 56 a3 ?? ?? 4c 00 ff 15}  //weight: 4, accuracy: Low
        $x_1_2 = {ff d3 8d 4c 24 ?? 51 6a ff 56 6a 04 57 ff d3 8d 94 24}  //weight: 1, accuracy: Low
        $x_4_3 = {83 ec 08 a1 ?? ?? 66 00 50 e8 ?? ?? ?? 00 8b 0d ?? ?? 65 00 50 c7 44 24 08 00 00 00 00 a3 ?? ?? 66 00 8d 14 09 8b 0d ?? ?? 65 00 0b d1 89 54 24 04 df 6c 24 04 dc 05 ?? ?? 65 00 dd 1d ?? ?? 65 00 ff 15 ?? ?? 65 00 a1 ?? ?? 66 00 50 ff 15 ?? ?? 65 00 b8 01 00 00 00 83 c4 08 c3}  //weight: 4, accuracy: Low
        $x_1_4 = "FFRestorer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_THAA_2147917824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.THAA!MTB"
        threat_id = "2147917824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? f4 4b 00 68 ?? 8e 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4b 00 33 d2 8a d4 89 15 ?? 5d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 5d 4c 00 c1 e1 08 03 ca 89 0d ?? 5d 4c 00 c1 e8 10 a3 ?? 5d 4c 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_MBXL_2147917865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.MBXL!MTB"
        threat_id = "2147917865"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? f6 4b 00 68 ?? 92 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_MBXM_2147917867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.MBXM!MTB"
        threat_id = "2147917867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? e6 4b 00 68 ?? 84 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? ?? ?? 33 d2 8a d4 89 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_TXAA_2147918452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.TXAA!MTB"
        threat_id = "2147918452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? b2 65 00 68 ?? 5d 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 65 00 33 d2 8a d4 89 15 ?? 27 a6 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 27 a6 00 c1 e1 08 03 ca 89 0d ?? 27 a6 00 c1 e8 10 a3 ?? 27 a6 00 33 f6 56 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GPS_2147918505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPS!MTB"
        threat_id = "2147918505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 60 e5 45 2c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GPT_2147918596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPT!MTB"
        threat_id = "2147918596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 de 62 ef db}  //weight: 4, accuracy: Low
        $x_4_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 e8 53 29 17}  //weight: 4, accuracy: Low
        $x_4_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 76 8c 99 45}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ekstak_KAN_2147918691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.KAN!MTB"
        threat_id = "2147918691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 d2 0a 00 1b d5 a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASHB_2147918722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASHB!MTB"
        threat_id = "2147918722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {55 8b ec 81 ec 14 05 00 00 8d 45 ec 56 50 ff 35 ?? ?? a6 00 ff 15 ?? ?? 65 00 83 f8 01 0f 85}  //weight: 3, accuracy: Low
        $x_2_2 = {ff d6 25 00 00 00 80 3d 00 00 00 80 74 06 ff d6 3c 04 77 06 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_CCJI_2147918897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CCJI!MTB"
        threat_id = "2147918897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 c8 b4 65 00 68 88 61 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 34 b2 65 00 33 d2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_ASHC_2147918979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.ASHC!MTB"
        threat_id = "2147918979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {51 56 ff 15 ?? ?? 4c 00 8b f0 c7 44 24 04 00 00 00 00 ff 15 ?? ?? 4c 00 68 ?? ?? 4c 00 a3 ?? ?? 4c 00 ff 15 ?? ?? 4c 00 8b 0d ?? ?? 4c 00 03 c8 85 f6 89 0d ?? ?? 4c 00 74 0c 8d 44 24 04 50 56 ff 15}  //weight: 3, accuracy: Low
        $x_2_2 = {03 c8 89 0d ?? ?? 4c 00 ff 15 ?? ?? 4c 00 6a 10 8b f8 ff 15 ?? ?? 4c 00 66 85 c0}  //weight: 2, accuracy: Low
        $x_3_3 = {ff d6 66 3d 04 08 74 07 68 ?? ?? 65 00 eb 05 68 ?? ?? 65 00 57 ff 15 ?? ?? 65 00 6a 0f ff 15 ?? ?? 65 00 5e b8 01 00 00 00 5f 81 c4 ac 00 00 00 c2 04 00 b8 01 00 00 00 5f 81 c4 ac 00 00 00 c2 04 00}  //weight: 3, accuracy: Low
        $x_2_4 = {81 ec ac 00 00 00 57 68 ?? ?? a6 00 ff 15 ?? ?? 65 00 8b bc 24 b4 00 00 00 85 ff 74 5c 8d 44 24 04 56 50 ff 15 ?? ?? 65 00 8b 35 ?? ?? 65 00 ff d6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_SDOD_2147919181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.SDOD!MTB"
        threat_id = "2147919181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 d2 0a 00 54 dc 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_UQAA_2147919756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.UQAA!MTB"
        threat_id = "2147919756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? c8 65 00 68 ?? 6c 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 65 00 33 d2 8a d4 89 15 ?? 5d a6 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 5d a6 00 c1 e1 08 03 ca 89 0d ?? 5d a6 00 c1 e8 10 a3 ?? 5d a6 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GNZ_2147923047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GNZ!MTB"
        threat_id = "2147923047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2a 01 00 00 00 69 bf 6b 00 f7 2d 68 00 00 a2 0a 00 06 15 a8 0e 36 d5 67 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_CCIO_2147924582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CCIO!MTB"
        threat_id = "2147924582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 1c 53 56 57 a0 48 f0 7c 00 32 05 49 f0 7c 00 a2 48 f0 7c 00 33 c9 8a 0d 43 f0 7c 00 c1 f9 03 83 c9 01 89 4d f0 db 45 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_MBXV_2147924746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.MBXV!MTB"
        threat_id = "2147924746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? f8 62 00 68 ?? 8e 62 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 62 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GPX_2147924801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GPX!MTB"
        threat_id = "2147924801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 48 0a 00 8d 50 e6 0b}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_AHC_2147924814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.AHC!MTB"
        threat_id = "2147924814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 83 ec 20 53 56 57 a1 ?? ?? ?? 00 c1 e0 03 0b 05 ?? ?? ?? 00 89 45 ec c7 45 f0 00 00 00 00 df 6d ec dd 1d ?? ?? ?? 00 8b 0d ?? ?? ?? 00 33 0d ?? ?? ?? 00 d1 e1 81 f9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GE_2147924829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GE!MTB"
        threat_id = "2147924829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {53 56 57 31 c9 31 ff 00 00 50 8b 00 8b 70 ?? 01 f6 74 14 66 8b 3e 83 00}  //weight: 5, accuracy: Low
        $x_5_2 = {53 56 57 89 cf 31 db 00 00 eb 02 8b 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_BAD_2147925761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.BAD!MTB"
        threat_id = "2147925761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 e2 08 c1 e1 04 23 f9 33 c9 8a 0d ?? ?? ?? ?? 6a 00 0f af d1 0b c2 89 3d ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 15 ?? ?? ?? 00 8b f0 e8 ?? ?? ?? ?? 6a 5a 56 ff 15 ?? ?? ?? ?? 56 6a 00 8b f8 ff 15}  //weight: 4, accuracy: Low
        $x_4_2 = {83 e2 08 81 e1 ff 00 00 00 0f af d1 0b c2 6a 00 a3 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 8b f0 e8 ?? ?? ?? ff 6a 5a 56 ff 15 ?? ?? ?? 00 56 6a 00 8b f8 ff 15 ?? ?? ?? 00 8b c7 5f 5e c3}  //weight: 4, accuracy: Low
        $x_1_3 = {55 8b ec 83 ec 18 53 56 57 e8 ?? ?? ?? ?? 89 45 fc e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_CCIP_2147926058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CCIP!MTB"
        threat_id = "2147926058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 0c 53 56 57 a0 34 ?? 7c 00 22 05 ?? ?? 7c 00 a2 34 ?? 7c 00 8a 0d 34 ?? 7c 00 80 c9 ?? 88 0d 34 ?? 7c 00 8b 15 2c ?? 7c 00 c1 e2 04 a1 28 ?? 7c 00 23 c2 a3 28 ?? 7c 00 33 c9 8a 0d 35 ?? 7c 00 8b 15 24 ?? 7c 00 83 e2 08 0f af ca a1 2c ?? 7c 00 0b c1 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_BAE_2147926497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.BAE!MTB"
        threat_id = "2147926497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 ec 08 a0 ?? ?? ?? 00 8a 0d ?? ?? ?? 00 32 c8 56 88 0d ?? ?? ?? 00 8a 0d ?? ?? ?? 00 80 c9 0c 68 ?? ?? ?? 00 c0 e9 02 81 e1 ff 00 00 00 89 4c 24 08}  //weight: 4, accuracy: Low
        $x_4_2 = {83 ec 08 a0 ?? ?? ?? 00 8a 0d ?? ?? ?? 00 32 c8 8d 54 24 00 88 0d ?? ?? ?? 00 8a 0d ?? ?? ?? 00 80 c9 0c 52 c0 e9 02 81 e1 ff}  //weight: 4, accuracy: Low
        $x_1_3 = {55 8b ec 83 ec 18 53 56 57 e8 ?? ?? ?? ff 89 45 fc e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ekstak_GNN_2147926503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GNN!MTB"
        threat_id = "2147926503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c8 8b c1 33 cf 5f 81 f9 ?? ?? ?? ?? 5e}  //weight: 5, accuracy: Low
        $x_5_2 = {32 c8 56 88 0d ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 80 c9 08 8b b4 24 ?? ?? ?? ?? c0 e9 03 81 e1 ?? ?? ?? ?? 6a 11 89 4c 24}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_CCJN_2147926601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CCJN!MTB"
        threat_id = "2147926601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 c8 8b c1 33 cf 5f 81 f9 ?? ?? ?? ?? 5e}  //weight: 3, accuracy: Low
        $x_2_2 = {32 c8 8b 44 24 58 88 0d ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 80 c9 08 c0 e9 03 81 e1 ?? ?? ?? ?? 89 4c 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_CCJM_2147926767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CCJM!MTB"
        threat_id = "2147926767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 c8 56 88 0d ?? ?? 4c 00 8a 0d 43 40 4c 00 80 c9 08 8b b4 24 b8 00 00 00 c0 e9 03 81 e1 ff 00 00 00 6a 05}  //weight: 2, accuracy: Low
        $x_1_2 = {32 c2 a2 46 40 4c 00 0c 30 c0 e8 04 25 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_CCJP_2147926983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CCJP!MTB"
        threat_id = "2147926983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {65 00 8a 0d ?? f0 65 00 32 c8 56 88 0d ?? f0 65 00 8a 0d ?? f0 65 00 80 c9 08 8b b4 24 b8 00 00 00 c0 e9 03 81 e1 ff}  //weight: 2, accuracy: Low
        $x_1_2 = {89 45 fc 8a 0d ?? f0 65 00 32 0d ?? f0 65 00 88 0d ?? f0 65 00 33 d2 8a 15 ?? f0 65 00 c1 fa 03 83 ca 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_CCJQ_2147927187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CCJQ!MTB"
        threat_id = "2147927187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c2 32 c1 8b 0d ?? ?? ?? ?? 24 ?? 68 ?? ?? ?? ?? a2 ?? ?? ?? ?? 8b c6 d1 e8 03 c8 33 c0 89 0d ?? ?? ?? ?? 83 e1 07 8a c2 57 0f af c8 03 f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_GTC_2147927296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.GTC!MTB"
        threat_id = "2147927296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a c1 32 c2 8b d7 24 ?? 68 ?? ?? ?? ?? a2 ?? ?? ?? ?? a1 ?? ?? ?? ?? d1 ea 03 c2 33 d2 a3 ?? ?? ?? ?? 83 e0 ?? 8a d1 56 0f af c2 03 f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_AMCO_2147927390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.AMCO!MTB"
        threat_id = "2147927390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af ca a1 ?? ?? ?? ?? 0b c1 a3 00 e8 ?? ?? ?? ?? 89 45 fc 8a 0d ?? ?? ?? ?? 32 0d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 33 d2 8a 15 ?? ?? ?? ?? c1 fa 03 83 ca 01 89 55 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_CCJR_2147927493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CCJR!MTB"
        threat_id = "2147927493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c1 32 c2 8b d6 24 ?? a2 ?? ?? ?? ?? a1 ?? ?? ?? ?? d1 ea 03 c2 33 d2 a3 ?? ?? ?? ?? 83 e0 07 8a d1 0f af c2 03 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_CCJS_2147929711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CCJS!MTB"
        threat_id = "2147929711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d1 8b 3d 34 e0 4c 00 22 d0 a1 30 e0 4c 00 80 f2 ?? 56 88 15 ?? e0 4c 00 8b d0 c1 ea 05 23 fa 33 d2 83 e0 08 8a d1 0f af c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_CCJT_2147929712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.CCJT!MTB"
        threat_id = "2147929712"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d1 8b f8 a1 30 e0 4c 00 22 d3 8b 1d 34 e0 4c 00 80 f2 ?? 88 15 45 e0 4c 00 8b d0 c1 ea 05 23 da 33 d2 83 e0 08 8a d1 0f af c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_MBW_2147938193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.MBW!MTB"
        threat_id = "2147938193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 6a ff 68 ?? e5 60 00 68 ?? 8e 60 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? e3 60 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_MBY_2147939471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.MBY!MTB"
        threat_id = "2147939471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? e5 65 00 68 ?? 7d 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? e1 65 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ekstak_NE_2147952189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ekstak.NE!MTB"
        threat_id = "2147952189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekstak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 ff 3b c1 75 30 8d 44 89 50 c1 e0 02 50 ff 35 64 2e a6 00 57 ff 35 88 30 a6 00 ff 15 e4 c1 65 00 3b c7 74 61 83 05 50 2e a6 00 10 a3 64 2e a6 00 a1 60 2e a6 00}  //weight: 2, accuracy: High
        $x_1_2 = {83 4e 08 ff 89 3e 89 7e 04 ff 05 60 2e a6 00 8b 46 10 83 08 ff 8b c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

