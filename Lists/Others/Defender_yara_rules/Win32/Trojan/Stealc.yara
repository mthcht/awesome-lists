rule Trojan_Win32_Stealc_CF_2147841872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.CF!MTB"
        threat_id = "2147841872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f be 04 37 8a 80 ?? ?? ?? ?? 0f be 5c 37 01 8a 9b 08 f8 40 00 c0 eb ?? c0 e0 ?? 0a c3 88 01}  //weight: 5, accuracy: Low
        $x_5_2 = {0f be 44 37 02 0f be 5c 37 01 8a 9b ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? c0 e3 ?? c0 e8 ?? 0a c3 88 41 01}  //weight: 5, accuracy: Low
        $x_5_3 = {0f be 5c 37 02 0f be 44 37 03 8a 9b 08 f8 40 00 c0 e3 ?? 0a ?? ?? ?? ?? ?? 83 c6 ?? 88 59 02 83 c1 ?? 3b 75 08 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_GKA_2147849495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.GKA!MTB"
        threat_id = "2147849495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 4c 05 ?? c1 f9 02 03 d1 8b 45 e8 03 45 f8 88 10 8b 4d f8 83 c1 01 89 4d f8 ba ?? ?? ?? ?? 6b c2 ?? 0f be 4c ?? f4 83 f9 ?? 0f 84}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_RTF_2147849567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.RTF!MTB"
        threat_id = "2147849567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d0 88 45 ?? 0f b6 45 bb 0f b6 84 05 ?? ?? ?? ?? 88 45 ba 8b 55 bc 8b 45 e4 01 d0 0f b6 00 32 45 ba 88 45 ?? 8b 55 bc 8b 45 e0 01 c2 0f b6 45 ?? 88 02 83 45 ?? ?? 8b 45 dc 3b 45 ?? 0f 8f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_RTT_2147849671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.RTT!MTB"
        threat_id = "2147849671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 3c 40 7e ?? 8b 45 08 0f b6 00 3c 5a 7f ?? 8b 45 08 0f b6 00 83 c8 20 0f be c0 eb ?? 8b 45 08 0f b6 00 0f be c0 31 45 f0 83 45 08 01 83 45 f4 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_GKI_2147849683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.GKI!MTB"
        threat_id = "2147849683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4d f4 03 4d fc 8b 55 08 03 55 f8 8a 02 88 01 8b 4d f8 83 c1 01 89 4d f8 8b 45 fc 33 d2 f7 35 ?? ?? ?? ?? 85 d2 75 ?? 8b 55 f8 03 15 ?? ?? ?? ?? 89 55 f8 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_GKJ_2147849953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.GKJ!MTB"
        threat_id = "2147849953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c1 89 45 e8 69 c0 ?? ?? ?? ?? 2b c1 66 89 45 ec 69 c0 ?? ?? ?? ?? 2b c1 33 d2 69 c0 ?? ?? ?? ?? 2b c1 88 44 15 f0 42 83 fa}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_GMF_2147888595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.GMF!MTB"
        threat_id = "2147888595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yQcuh7NqBj6habksskz9BIdfHfiT" ascii //weight: 1
        $x_1_2 = "ikQ8zOYsTBs=" ascii //weight: 1
        $x_1_3 = "tU47yuAxYTOpb4wnkBGkUesYbfU=" ascii //weight: 1
        $x_1_4 = "w189kaA0QHXhYq0=" ascii //weight: 1
        $x_1_5 = "pQ0U7vczUiilZ5wpohmU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_MA_2147891156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.MA!MTB"
        threat_id = "2147891156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 35 e0 f1 47 00 8b 7d f4 8b 4d f8 8d 04 3b d3 ef 89 45 ec c7 05 [0-9] 03 7d d4 8b 45 ec 31 45 fc 33 7d fc 81 3d ?? ?? ?? ?? 13 02 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_MB_2147891327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.MB!MTB"
        threat_id = "2147891327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 7d f0 8b 45 f8 8b 4d f4 03 c7 d3 ef 89 45 ec c7 05 ?? ?? ?? ?? ee 3d ea f4 03 7d ?? 8b 45 ec 31 45 fc 33 7d fc 81 3d ?? ?? ?? ?? 13 02 00 00 75 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_MB_2147891327_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.MB!MTB"
        threat_id = "2147891327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 85 1c ff ff ff c1 e8 05 89 45 74 8b 45 74 03 85 14 ff ff ff 8b 95 3c ff ff ff 03 d6 33 c2 33 c1 2b f8 83 3d 6c d2 45 02 0c c7 05 64 d2 45 02 ee 3d ea f4 89 45 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_RPX_2147891409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.RPX!MTB"
        threat_id = "2147891409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 04 3e 46 3b f3 7c f3 5e 83 fb 2d 75 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_RPX_2147891409_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.RPX!MTB"
        threat_id = "2147891409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 55 d8 8b 45 ec 31 45 fc 33 55 fc 89 55 d4 8b 45 d4 83 45 f8 64 29 45 f8 83 6d f8 64 8b 55 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_RPX_2147891409_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.RPX!MTB"
        threat_id = "2147891409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 f6 8b c3 c1 e0 04 03 44 24 30 8b d3 c1 ea 05 03 54 24 28 8d 0c 2b 33 c1 89 54 24 14 89 44 24 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_RPX_2147891409_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.RPX!MTB"
        threat_id = "2147891409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 dc 01 45 fc 8b 4d f8 8d 04 13 d3 ea 89 45 f4 03 55 d4 8b 45 f4 31 45 fc 31 55 fc 8b 45 fc 29 45 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_RPX_2147891409_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.RPX!MTB"
        threat_id = "2147891409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 00 00 00 00 58 89 45 f0 81 45 f0 cb 07 00 00 8b 45 08 8b 4d f0 89 48 04 8b 45 f0 83 c0 3d 8b 4d 08 89 41 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_RPX_2147891409_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.RPX!MTB"
        threat_id = "2147891409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 ff d3 ff d6 4f 75 e3 5f 5e 33 c0 5b c2 10 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 54 24 10 8b 4c 24 14 41 89 4c 24 14 3b 8c 24 20 08 00 00 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_RPX_2147891409_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.RPX!MTB"
        threat_id = "2147891409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 8b 15 30 00 00 00 81 c2 00 0f 00 00 89 55 e8 b8 04 00 00 00 d1 e0 8b 4d e8 8b 94 05 e0 fe ff ff 89 11 b8 04 00 00 00 6b c8 03 8b 55 e8 8b 84 0d e0 fe ff ff 89 42 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_DW_2147891479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.DW!MTB"
        threat_id = "2147891479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 0c 28 34 ?? 88 84 0c f4 00 00 00 41 3b ce 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {c0 f1 c0 db c7 44 24 ?? c6 db d1 d3 c7 44 24 ?? de e1 d7 d1 c7 ?? 24 44 c6 db dd dc}  //weight: 1, accuracy: Low
        $x_1_3 = "Desktop\\stealer_morph\\Nh3ZoGSZDjgH1Ht\\stealer" ascii //weight: 1
        $x_1_4 = "CreditCards/%ls_%ls.txt" wide //weight: 1
        $x_1_5 = "Autofills/%ls_%ls.txt" wide //weight: 1
        $x_1_6 = "Wallets/%ls_%ls_%ls" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_MC_2147891980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.MC!MTB"
        threat_id = "2147891980"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 55 f0 8b 4d f8 8d 04 13 d3 ea 89 45 ec c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 e0 8b 45 ec 31 45 fc 33 55 fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 55 ec 75 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_MD_2147892234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.MD!MTB"
        threat_id = "2147892234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 08 88 0a eb 27 8b 55 08 03 95 ?? ?? ?? ?? 0f b6 02 8b 8d ?? ?? ?? ?? 33 84 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 88 02 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_RPZ_2147892673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.RPZ!MTB"
        threat_id = "2147892673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 0c 6a 00 6a 00 6a 00 6a 00 ff d6 ff d7 4b 75 e8 b9 73 00 00 00 ba 6d 00 00 00 66 89 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_RPZ_2147892673_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.RPZ!MTB"
        threat_id = "2147892673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 f8 8b 4d f8 8b 51 04 33 55 ec 89 55 d0 8b 45 f8 8b 08 33 4d ec 89 4d 9c 8b 55 bc 03 55 9c 89 55 f0 8d 45 ac}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_RG_2147892797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.RG!MTB"
        threat_id = "2147892797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 4c 24 30 91 e9 d1 5b 83 c4 0c 69 ed 91 e9 d1 5b 83 c6 04 8b c1 c1 e8 18 33 c1 69 c0 91 e9 d1 5b 33 e8 89 44 24 24 83 ef 01 75 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_RG_2147892797_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.RG!MTB"
        threat_id = "2147892797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "adYvLqOrSqymsmkxMGehp" ascii //weight: 1
        $x_1_2 = "QldkjYZqXRYUtVagMbPIzqREB" ascii //weight: 1
        $x_1_3 = "mReYEVpArlaWvtwPtAhepehldwz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_ME_2147893127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.ME!MTB"
        threat_id = "2147893127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 7d f0 8b 4d f4 8d 04 37 d3 ee 89 45 ec c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 ?? 8b 45 ec 31 45 fc 33 75 fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 75 ec 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_DY_2147893171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.DY!MTB"
        threat_id = "2147893171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 0c 0c 34 ?? 0f b6 c0 66 89 84 4c ?? ?? ?? ?? 41 3b ce 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 44 0c 1c 04 ?? 88 84 0c ?? ?? ?? ?? 41 3b ca 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_SE_2147894230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.SE!MTB"
        threat_id = "2147894230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b d8 81 c3 3c 11 00 00 8b 45 d4 31 18 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 af}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_RD_2147894280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.RD!MTB"
        threat_id = "2147894280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 08 89 4d f8 8b 55 08 03 55 fc 0f b6 02 33 45 f4 8b 4d 08 03 4d fc 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_DZ_2147895047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.DZ!MTB"
        threat_id = "2147895047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c5 8d 0c 37 33 c1 89 54 24 18 89 44 24 10 89 1d [0-4] 8b 44 24 18 01 05 [0-4] 8b 15 [0-4] 89 54 24 38 89 5c 24 18 8b 44 24 38 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 44 24 18 89 44 24 18 8b 44 24 18 29 44 24 14 8b 4c 24 14 c1 e1 04 89 4c 24 10 8b 44 24 2c 01 44 24 10 81 3d [0-4] be 01 00 00 8b 44 24 14 8d 1c 07 75}  //weight: 1, accuracy: Low
        $x_1_2 = "kesozubexazaxahifahuvutozitucep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_GNT_2147895324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.GNT!MTB"
        threat_id = "2147895324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 4d fc 8b 45 08 30 0c 07 47 3b fb ?? ?? 5e 5f 83 fb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_GNT_2147895324_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.GNT!MTB"
        threat_id = "2147895324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c8 b8 4f ec c4 4e f7 e1 c1 ea 03 6b c2 e6 03 c8 0f be 4c 0c 40 66 89 4c 75 00 46 3b 74 24 74}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_RPY_2147895427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.RPY!MTB"
        threat_id = "2147895427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 ca a6 60 31 ca a6 60 31 ca a6 60 31 ca a6 60 31 ca a6 60 31 ca a6 76 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_RPY_2147895427_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.RPY!MTB"
        threat_id = "2147895427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 44 24 34 89 7c 24 1c 8b 44 24 34 01 44 24 1c 8b 44 24 10 33 44 24 1c 89 44 24 1c 8b 4c 24 1c 89 4c 24 1c 8b 44 24 1c 29 44 24 14 8b 54 24 14 c1 e2 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_MBEO_2147895462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.MBEO!MTB"
        threat_id = "2147895462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 61 62 65 6c 61 79 69 73 69 74 75 20 6e 6f 72 00 00 00 00 62 61 7a 6f 70 61 63 69 74 6f 7a 65 76 65 73 65 67 6f 67 69 78 69 00 00 00 00 00 00 74 6f 77 69 73 75 79 69 6c 61 77 61 62 6f 62 61 68 61 6d 6f 6b 69 6e 61 78 61 63 20 76 61 76 75 72 69 20 73 61 6d 61 78 61 6e 61 63 20 79 75 6c 69 79 6f 79 61 64 69 6c 6f 6b 6f 76 75 64 65 79 20 62 61 6e 69 77 75}  //weight: 1, accuracy: High
        $x_1_2 = {6a 6f 7a 6f 77 6f 6c 75 76 69 76 61 72 6f 67 61 73 69 77 6f 20 63 6f 6e 61 78 6f 6a 61 73 65 78 20 7a 65 63 6f 68 6f 73 69 62 69 63 6f 7a 75 78 65 72 75 63 75 6c 65 77 65 6d 75 77 20 6b 69 76 69 74 75 66 65 20 6c 65 6b 75 67 69 78 6f 6d 65 6d 75 6d 6f 78 75 72 6f 68 75 64 6f 6d 00 00 00 63 61 64 61 68 69 73 65 67 6f 68 6f 68 69 77 75 73 69 74 65 74 6f 79 65 73 69 70 65 6c 20 6c 6f 64 75 63 61 77 61 64 65 6c 65 78 75 68 00 00 00 72 75 72 6f 74 6f 76 75 76 65 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Stealc_GPAA_2147895583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.GPAA!MTB"
        threat_id = "2147895583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Q29udGVudC1UeXBlOiBtdWx0aXBhcnQvZm9ybS1kYXRhOyBib3VuZGFyeT0tLS0t" ascii //weight: 2
        $x_2_2 = "aHR0cDovL3JvYmVydGpvaG5zb24udG9w" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_FA_2147896442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.FA!MTB"
        threat_id = "2147896442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 89 54 24 18 03 cd 8d 14 06 33 ca 89 4c 24 10 89 3d [0-4] 8b 44 24 18 01 05 [0-4] a1 [0-4] 89 44 24 34 89 7c 24 18 8b 44 24 34 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 4c 24 18 89 4c 24 18 8b 44 24 18 29 44 24 14 8b 44 24 14 8b c8 c1 e1 04 03 cb 81 3d [0-4] be 01 00 00 89 4c 24 10 8d 3c 06 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 cf 89 4c 24 10 8b 44 24 18 31 44 24 10 8b 44 24 10 29 44 24 1c a1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_CA_2147897406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.CA!MTB"
        threat_id = "2147897406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 8b 7d f0 8b d3 d3 ea 8d 04 1f 89 45 ec c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 d4 8b 45 ec 31 45 fc 33 55 fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 55 ec 75 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_FB_2147898326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.FB!MTB"
        threat_id = "2147898326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Zaze xuho xupuhagavumu bemozediwatiric bek" ascii //weight: 1
        $x_1_2 = "Xilomik recofuwesetidup vasifisok bezesecokise yicexaj" ascii //weight: 1
        $x_1_3 = "Batuyurutusey zoruhikeje gicozasizehe herarikonanodo" ascii //weight: 1
        $x_1_4 = "luyanezif xofiteyuxapovuhesenokitiluponede yel cifivosijiyebokeduwemubefoni" ascii //weight: 1
        $x_1_5 = "Titugazamuw des jiziga koguyitaku jogekexofonega" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_NCS_2147899072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.NCS!MTB"
        threat_id = "2147899072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {75 05 e8 e1 1e 00 00 8b 35 ?? ?? ?? ?? 33 ff 8a 06 3a c3 74 12 3c ?? 74 01 47 56 e8 f5 f5 ff ff 59 8d 74 06 ?? eb e8 8d 04 bd}  //weight: 5, accuracy: Low
        $x_1_2 = "vcapi.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_MF_2147899082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.MF!MTB"
        threat_id = "2147899082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 fc 3b 45 0c 73 ?? 8b 4d 08 03 4d fc 0f b6 11 89 55 f8 8b 45 08 03 45 fc 0f b6 08 33 4d f4 8b 55 08 03 55 fc 88 0a 8b 45 f8 89 45 f4 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_MG_2147899983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.MG!MTB"
        threat_id = "2147899983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 31 a2 00 00 01 85 b0 da ff ff a1 ?? ?? ?? ?? 03 85 b4 da ff ff 8b 8d b0 da ff ff 03 8d b4 da ff ff 8a 09 88 08 81 3d ?? ?? ?? ?? ab 05 00 00 75 19}  //weight: 2, accuracy: Low
        $x_2_2 = {30 04 39 83 fb 0f 75 1e 0f 00 8b 8d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_MH_2147900074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.MH!MTB"
        threat_id = "2147900074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 31 a2 00 00 01 85 a0 da ff ff a1 ?? ?? ?? ?? 03 85 a4 da ff ff 8b 8d a0 da ff ff 03 8d a4 da ff ff 8a 09 88 08 81 3d ?? ?? ?? ?? ab 05 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {30 04 33 83 ff 0f 75 12}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_AMBI_2147900154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.AMBI!MTB"
        threat_id = "2147900154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 75 e0 8b 45 ec 31 45 fc 33 75 fc 89 75 dc 8b 45 dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_MI_2147900647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.MI!MTB"
        threat_id = "2147900647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 31 a2 00 00 01 85 5c ef ff ff a1 ?? ?? ?? ?? 03 85 60 ef ff ff 8b 8d 5c ef ff ff 03 8d 60 ef ff ff 8a 09 88 08 81 3d ?? ?? ?? ?? ab 05 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_KAC_2147900810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.KAC!MTB"
        threat_id = "2147900810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 fc 33 c6 89 45 ?? 2b f8 8d 45}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_EX_2147901773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.EX!MTB"
        threat_id = "2147901773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 4d ec 8b 4d f0 d3 e8 03 45 d8 8b c8 8b 45 ec 31 45 fc 31 4d fc 2b 5d fc 8b 45 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_FC_2147904763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.FC!MTB"
        threat_id = "2147904763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {30 04 33 83 ff 0f 75}  //weight: 3, accuracy: High
        $x_1_2 = "zudazehebujayicetapodohunekehote" ascii //weight: 1
        $x_1_3 = "Gihipuhapubiyon maf" wide //weight: 1
        $x_2_4 = "xacakeluhirilolajajadijazuduza" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Stealc_MBFW_2147905666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.MBFW!MTB"
        threat_id = "2147905666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f0 89 45 ?? 8b c6 89 75 ?? c1 e0 ?? 89 45 ?? 8b 45}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 ea 03 55 ?? 89 55 ?? 33 55 ?? 33 c2 89 5d ?? 2b f8 89 45}  //weight: 1, accuracy: Low
        $x_1_3 = {01 45 ec 8b 45 ec 31 45 e8 8b 45 f4 33 45 e8 2b f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Stealc_FK_2147910242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.FK!MTB"
        threat_id = "2147910242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 c4 04 8b 44 24 ?? 83 c0 64 89 44 24 ?? 83 6c 24 ?? 64 8a 4c 24 ?? 30 0c 3e 46 3b f3}  //weight: 3, accuracy: Low
        $x_1_2 = "meyoluzihe yeyobis" ascii //weight: 1
        $x_1_3 = "lovoxodazuf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_YZ_2147912196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.YZ!MTB"
        threat_id = "2147912196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 4d fc 30 0c 1f 47 3b 7d ?? 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_YZ_2147912196_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.YZ!MTB"
        threat_id = "2147912196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_ASGH_2147912565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.ASGH!MTB"
        threat_id = "2147912565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 65 fc 00 83 65 f8 00 8d 4d f8 e8 ?? ?? ?? ?? 8b 45 f8 83 c0 ?? 89 45 fc 83 6d fc ?? 8b 45 08 8a 4d fc 03 c2 30 08 42 3b 55 0c 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_ASGI_2147912812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.ASGI!MTB"
        threat_id = "2147912812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "silagek bisehakuhirabadacoye" ascii //weight: 1
        $x_1_2 = "vacejazulufapesu" wide //weight: 1
        $x_1_3 = "Vajepufupa sumive bavuxucawux" wide //weight: 1
        $x_1_4 = "biyuzucuzem0Wof sad velesuca yurotutavavecug jezutujuxeyawaj" wide //weight: 1
        $x_1_5 = "Merina tupom bilikog" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_AMAI_2147914518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.AMAI!MTB"
        threat_id = "2147914518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 8b 45 d8 31 18 6a 00 e8 [0-40] 83 45 ec 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_AMAJ_2147920439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.AMAJ!MTB"
        threat_id = "2147920439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 55 ff 83 c2 01 81 e2 ff 00 00 00 88 55 ff 0f b6 45 ff 8b 4d f8 0f b6 14 01 0f b6 45 fe 03 d0 81 e2 ff 00 00 00 88 55 fe 0f b6 4d ff 8b 55 f8 8a 04 0a 88 45 fd 0f b6 4d fe 0f b6 55 ff 8b 45 f8 8b 75 f8 8a 0c 0e 88 0c 10 0f b6 55 fe 8b 45 f8 8a 4d fd 88 0c 10 0f b6 55 ff 8b 45 f8 0f b6 0c 10 0f b6 55 fe 8b 45 f8 0f b6 14 10 03 ca 81 e1 ff 00 00 00 8b 45 f8 0f b6 0c 08 8b 55 08 03 55 f4 0f b6 02 33 c1 8b 4d 08 03 4d f4 88 01}  //weight: 2, accuracy: High
        $x_1_2 = {6a 04 68 00 30 00 00 8b 4d ec 51 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_OKA_2147920951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.OKA!MTB"
        threat_id = "2147920951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 0f fc 1a 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_ASGJ_2147924808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.ASGJ!MTB"
        threat_id = "2147924808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {0f be 04 33 89 44 24 08 8b 44 24 04 31 44 24 08 8a 4c 24 08 88 0c 33 83 ff 0f 75}  //weight: 4, accuracy: High
        $x_1_2 = {ff d7 6a 00 ff d3 81 fe 0f 4c 02 00 7f 09 46 81 fe d3 b6 0e 00 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_AMAA_2147925768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.AMAA!MTB"
        threat_id = "2147925768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 04 33 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8a 4c 24 ?? 88 0c 33 83 ff 0f 75 0f 6a 00 8d 54 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_AHEA_2147926913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.AHEA!MTB"
        threat_id = "2147926913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 6c 24 14 46 8b 4c 24 ?? 0f be 14 39 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b b4 24 ?? ?? ?? ?? 8a 44 24 ?? 88 04 39 83 fe 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_ANEA_2147927068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.ANEA!MTB"
        threat_id = "2147927068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {46 0f be 04 32 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 83 bc 24 ?? ?? ?? ?? 0f 8a 4c 24 ?? 88 0c 32 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_AJFA_2147927782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.AJFA!MTB"
        threat_id = "2147927782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 75 fc 89 75 dc 8b 45 dc 29 45 f8 81 c7 47 86 c8 61 83 6d ?? 01 0f 85 8f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_EAB_2147927988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.EAB!MTB"
        threat_id = "2147927988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b c3 c1 e8 05 89 45 fc 8b 45 e8 01 45 fc 8b f3 c1 e6 04 03 75 ec 8d 0c 1f 33 f1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_AVFA_2147928079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.AVFA!MTB"
        threat_id = "2147928079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff 8b 44 24 ?? 83 c0 46 89 44 24 ?? 83 6c 24 ?? 46 8a 44 24 ?? 30 04 1f 47 3b fd 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_EABA_2147930129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.EABA!MTB"
        threat_id = "2147930129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 84 3a 4b 13 01 00 8b 0d ?? ?? ?? ?? 88 04 39 81 3d ?? ?? ?? ??}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealc_AB_2147945015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealc.AB!MTB"
        threat_id = "2147945015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 ba 65 00 00 00 b8 6e 00 00 00 68 d0 63 51 00 66 89 0d e8 63 51 00 66 89 15 d2 63 51 00 66 a3 d6 63 51 00 ff 15 ?? ?? ?? ?? 68 b8 dd 43 00 50 c6 05 ba dd 43 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

