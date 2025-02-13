rule Trojan_Win32_Cutwail_AQ_2147612675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cutwail.AQ"
        threat_id = "2147612675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c 11 c1 e2 02 03 da 8b 1b 68 ?? ?? ?? ?? b8 ?? ?? ?? ?? 8d 14 52 03 c2 8f 45 f8 29 55 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {31 03 83 e9 04 7e 14 03 45 f8 03 45 fc 81 c3 ?? ?? ?? 00 2b 5d 10 f7 5d fc eb e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cutwail_A_2147677736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cutwail.A"
        threat_id = "2147677736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 7d fc 8b 77 24 03 75 f4 03 75 08 33 c0 66 8b 06 c1 e0 02 8b 75 fc 8b 76 1c 03 75 08 03 f0 8b 06 03 45 08}  //weight: 2, accuracy: High
        $x_2_2 = {ff 50 8b c9 58 8b c9 50 2b f6 58 8b c9 68 83 ea 23 01 8b c9 8f 45 fc 8b d0 eb 24}  //weight: 2, accuracy: High
        $x_1_3 = "sdlthq0r73495" ascii //weight: 1
        $x_1_4 = "imssystem" ascii //weight: 1
        $x_1_5 = "dth34905y345o" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Cutwail_A_2147679573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cutwail.gen!A"
        threat_id = "2147679573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b d2 28 0f be 82 ?? ?? ?? ?? 83 f8 30 7c 31 8b 8d ?? ?? ?? ?? 6b c9 28 1e 00 6a 19 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {40 73 33 6a ff e8 ?? ?? ?? ?? 83 c4 04 69 c0 0d 66 19 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6b c9 28 81 c1 ?? ?? ?? ?? 51 68 ?? ?? ?? ?? 8d 95 ?? ?? ?? ?? 52 ff 15 ?? ?? ?? ?? 83 c4 10 eb 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Cutwail_GAT_2147835745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cutwail.GAT!MTB"
        threat_id = "2147835745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 0c 0f 01 d9 81 ee ?? ?? ?? ?? 81 f6 ?? ?? ?? ?? 21 f1 8b 75 ec 8b 5d c4 8a 34 1e 32 34 0f 8b 4d e8 88 34 19 8b 4d c0 8b 75 f0 39 f1 8b 4d b8 8b 75 c0 8b 7d b0 89 4d dc 89 7d d4 89 75 d8 0f 84}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cutwail_GBY_2147837734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cutwail.GBY!MTB"
        threat_id = "2147837734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 cb 01 fb 8b 7d e8 89 4d c8 8a 0c 0f 0f b6 f9 88 4d c7 8b 4d d0 01 cf 8b 4d ec 0f b6 14 11 01 d7 81 f6 ?? ?? ?? ?? 89 f8 99 f7 fe 8b 75 e8 8a 0c 16 8b 7d c8 88 0c 3e 8a 4d c7 88 0c 16 8b 4d cc 81 c1 ?? ?? ?? ?? 39 cb 89 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cutwail_MK_2147842540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cutwail.MK!MTB"
        threat_id = "2147842540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 d0 8a 18 8b 45 ?? be ?? ?? ?? ?? 99 f7 fe 89 d0 03 45 ?? 8a 00 31 d8 88 01 ff 45 ?? 8b 55 ?? 8b 45 ?? 39 c2 0f 92 c0 84 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cutwail_RDA_2147843301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cutwail.RDA!MTB"
        threat_id = "2147843301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 04 0a c1 f8 05 89 c2 89 c8 c1 f8 1f 29 c2 89 d0 c1 e0 03 01 d0 c1 e0 02 01 d0 29 c1 89 ca 8b 45 e0 01 d0 0f b6 00 31 f0 88 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cutwail_RPZ_2147845331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cutwail.RPZ!MTB"
        threat_id = "2147845331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 34 6a 40 81 c2 ?? ?? ?? ?? 52 ff 76 60 6a 00 ff d0 89 86 a8 00 00 00 eb 80 33 c0 8b 12 8b c8 8b 72 30 0f be 1c 31 8d 7b bf 83 ff 19 8d 43 20 0f be c0 0f 46 d8 3a 5c 0c 30 75 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cutwail_ARA_2147847493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cutwail.ARA!MTB"
        threat_id = "2147847493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c1 99 6a 37 5f f7 ff 8a 82 ?? ?? ?? ?? 8b 55 8c 32 04 11 88 04 31 41 3b 4d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cutwail_CRHV_2147847962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cutwail.CRHV!MTB"
        threat_id = "2147847962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 c2 8b d0 c1 e2 ?? 2b d0 8b c1 2b c2 8a 90 28 2b 42 00 32 91 b8 bd 46 00 8b 44 24 10 88 14 01 41 3b 4c 24 14 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cutwail_CRUT_2147848042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cutwail.CRUT!MTB"
        threat_id = "2147848042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ee 03 d6 c1 fa ?? 8b c2 c1 e8 ?? 03 c2 8b c8 c1 e1 ?? 2b c8 8b c6 2b c1 46 8a 88 ?? ?? ?? ?? 32 8e ?? ?? ?? ?? 8b 45 fc 88 4c 06 ff 3b 75 0c 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cutwail_DAN_2147850604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cutwail.DAN!MTB"
        threat_id = "2147850604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 14 16 8b 75 dc 8b 7d d4 0f b6 34 37 31 f2 88 d3 8b 55 ec 8b 75 e8 88 1c 16 8b 45 ec 89 45 c8 8b 45 c8 05 01 00 00 00 89 45 ec eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cutwail_ACW_2147891218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cutwail.ACW!MTB"
        threat_id = "2147891218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d 08 03 4d f0 0f be 11 83 ea 30 0f af 55 f4 03 55 fc 89 55 fc 8b 45 f4 6b c0 0a 89 45 f4 8b 4d f0 83 e9 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cutwail_NCW_2147894993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cutwail.NCW!MTB"
        threat_id = "2147894993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 c6 0f fc ff ff 8d 81 ?? ?? ?? ?? 81 f7 ea 0d 00 00 89 74 24 ?? 81 f5 f9 0b 00 00 3b d8 0f 8f 3b 01 00 00 8b c7 35 ?? ?? ?? ?? 3b d8 0f 8d 2c 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cutwail_PADE_2147901493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cutwail.PADE!MTB"
        threat_id = "2147901493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 47 78 8b da 0f af c6 3b d0 74 25 8b 6f 40 69 c2 32 0a 00 00 89 44 24 1c 8b d0 2b ea 83 c3 03 89 6f 40 8b 47 78 0f af c6 3b d8 75 ee 8b 54 24 10 8b 47 2c 83 c1 03 33 c6 3b c8 76 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

