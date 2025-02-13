rule Trojan_Win32_Raccoon_BB_2147786259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.BB!MTB"
        threat_id = "2147786259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 31 06 c2 04 00 33 44 24 04 c2 04 00 81 00 ae 36 ef c6 c3 01 08 c3 29 08 c3}  //weight: 1, accuracy: High
        $x_1_2 = {89 55 fc b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 72 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_A_2147787406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.A!MTB"
        threat_id = "2147787406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 44 24 04 c2 04 00 81 00 ae 36 ef c6 c3 01 08 c3 29 08 c3}  //weight: 10, accuracy: High
        $x_10_2 = {8b 4d f4 d3 ee 89 45 f0 03 75 e0 33 f0 2b fe}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_M_2147793757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.M!MTB"
        threat_id = "2147793757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 44 24 24 50 6a 00 ff d6 6a 00 8d 4c 24 64 51 ff d7 8d 54 24 48 52 ff d3 33 c9 33 c0 8d 54 24 1c 52 66 89 44 24 24 66 89 4c 24 26 8b 44 24 24 50 51}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_M_2147793757_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.M!MTB"
        threat_id = "2147793757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {51 c7 04 24 02 00 00 00 8b 44 24 0c 01 04 24 83 2c 24 02 8b 44 24 08 8b 0c 24 31 08 59 c2 08 00 8b 4c 24 04 8b 01 89 44 24 04 8b 44 24 08 90 01 44 24 04 8b 54 24 04 89 11 c2 08 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_M_2147793757_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.M!MTB"
        threat_id = "2147793757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3 [0-4] 33 44 24 04 c2 04 00 81 00 cc 36 ef c6 c3 [0-4] 01 08 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f6 81 3d ?? ?? ?? ?? 34 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 94 01 3b 2d 0b 00 88 14 30 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_N_2147793758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.N!MTB"
        threat_id = "2147793758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 36 23 01 00 01 45 fc [0-5] 03 45 08 8b 4d fc 03 4d 08 8a 11 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 8b 08 33 4d 0c 8b 55 08 89 0a}  //weight: 1, accuracy: High
        $x_1_3 = {83 e9 14 88 0d ?? ?? ?? ?? 0f be 15 ?? ?? ?? ?? 83 ea 14 88 15 ?? ?? ?? ?? 0f be 05 ?? ?? ?? ?? 83 e8 14 a2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_U_2147795124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.U!MTB"
        threat_id = "2147795124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3 [0-3] 33 44 24 04 c2 04 00 81 00 fe 36 ef c6 c3 01 08 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {89 55 fc b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_BQ_2147795513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.BQ!MTB"
        threat_id = "2147795513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d}  //weight: 10, accuracy: High
        $x_10_2 = {31 06 c9 c2 04 00 33 44 24 04 c2 04 00 81 00 ?? ?? ?? ?? c3 01 08 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_BM_2147796264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.BM!MTB"
        threat_id = "2147796264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c1 8b 75 08 33 d2 f7 f7 8a 04 32 30 04 19 41 3b 4d 10 72 eb}  //weight: 10, accuracy: High
        $x_10_2 = {50 33 c0 0f 9b c0 52 57 33 ff 0f 9b c0 52 56 33 f6 0f 9b c0 52 33 d0 c1 e2 02 66 c1 e0 62}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_AH_2147796266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.AH!MTB"
        threat_id = "2147796266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e0 04 89 01 c3 31 08 c3 81 3d ?? ?? ?? ?? e6 01}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 4d fc 03 ca c1 ea 05 89 55 f8 8b 45 e0 01 45 f8 8b 45 ec 51 03 c7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_ET_2147797090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.ET!MTB"
        threat_id = "2147797090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 ec 29 45 f4 8b 4d f4 c1 e1 04 89 4d e4 8b 45 f8 01 45 e4 8b 45 f4 03 45 e8 89 45 f0}  //weight: 10, accuracy: High
        $x_10_2 = {d3 e8 89 45 ec 8b 4d ec 03 4d d4 89 4d ec 8b 55 e4 33 55 f0 89 55 e4 8b 45 ec 31 45 e4 8b 45 e4 29 45 d0 c7 45 c4 00 00 00 00 8b 45 d8 01 45 c4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_BA_2147797611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.BA!MTB"
        threat_id = "2147797611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 08 c6 05 ?? ?? ?? ?? 88 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 60 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 74 [0-32] 7f c6 05 ?? ?? ?? ?? 86 c6 05 ?? ?? ?? ?? 88 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 76 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 65}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 89 45 ec 8b 4d ec 03 4d d4 89 4d ec 8b 55 e4 33 55 f0 89 55 e4 8b 45 ec 31 45 e4 8b 45 e4 29 45 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccoon_ADN_2147797954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.ADN!MTB"
        threat_id = "2147797954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 e0 04 89 01 c3 33 44 24 04 89 01 c2 04 00 33 44 24 04 c2 04 00 81 00 a4 36 ef c6 c3 01 08 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_ES_2147797992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.ES!MTB"
        threat_id = "2147797992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qwdemuvefsfmca" ascii //weight: 1
        $x_1_2 = "FifthDimensionAscension" ascii //weight: 1
        $x_1_3 = "mueaewcsd" ascii //weight: 1
        $x_1_4 = "Coremdimens" ascii //weight: 1
        $x_1_5 = "qantumsymetric" ascii //weight: 1
        $x_1_6 = "TheGreatAwakening" ascii //weight: 1
        $x_1_7 = "TIPOFDAY.TXT" wide //weight: 1
        $x_1_8 = "Zeta Debugger" wide //weight: 1
        $x_1_9 = "Rock Debugger" wide //weight: 1
        $x_1_10 = "uiaodoemkceamfiwefs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_AC_2147798147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.AC!MTB"
        threat_id = "2147798147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 44 24 04 c2 04 00 81 00 ae 36 ef c6 c3 01 08 c3}  //weight: 10, accuracy: High
        $x_10_2 = {8b 4d f4 89 45 f8 8b c6 d3 e8 03 45 d8 33 45 f8 2b f8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_AD_2147798255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.AD!MTB"
        threat_id = "2147798255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {51 c7 04 24 02 00 00 00 8b 44 24 08 90 01 04 24 83 2c 24 02 8b 04 24 31 01 59 c2 04 00}  //weight: 10, accuracy: High
        $x_10_2 = {c1 e8 05 05 12 c9 23 00 89 01 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_AD_2147798255_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.AD!MTB"
        threat_id = "2147798255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 0c 33 44 24 1c c7 05 ?? ?? ?? ?? 00 00 00 00 31 44 24 10 89 44 24 0c 8b 44 24 10 01 05 ?? ?? ?? ?? 8b 44 24 10 29 44 24 14 8b 54 24 14 c1 e2 04 89 54 24 0c 8b 44 24 ?? 01 44 24 0c 8b 44 24 14 03 44 24 20}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 54 24 1c 31 54 24 0c c1 e9 05 03 [0-3] c7 05 ?? ?? ?? ?? b4 02 d7 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 4c 24 10 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_AM_2147798588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.AM!MTB"
        threat_id = "2147798588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {51 c7 04 24 02 00 00 00 8b 44 24 08 90 01 04 24 83 2c 24 02 8b 04 24 31 01 59 c2 04 00}  //weight: 10, accuracy: High
        $x_10_2 = {8b 44 24 14 29 44 24 18 8b 4c 24 18 c1 e1 04 89 4c 24 10 8b 44 24 2c 01 44 24 10 8b 44 24 18 03 44 24 20}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_AQ_2147798737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.AQ!MTB"
        threat_id = "2147798737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 44 24 04 c2 04 00 81 00 4a 36 ef c6 c3 01 08 c3}  //weight: 10, accuracy: High
        $x_10_2 = {c1 e0 04 89 01 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_AF_2147798993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.AF!MTB"
        threat_id = "2147798993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 10 33 44 24 18 c7 05 ?? ?? ?? ?? 00 00 00 00 33 f0 89 44 24 10 89 74 24 1c 8b 44 24 1c 01 05 ?? ?? ?? ?? 8b 44 24 1c 29 44 24 14 8b 4c 24 14 c1 e1 04 89 4c 24 10 8b 44 24 28 01 44 24 10 8b 44 24 14 03 44 24 20 89 44 24 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_AW_2147799366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.AW!MTB"
        threat_id = "2147799366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {51 c7 04 24 02 00 00 00 8b 44 24 08 90 01 04 24 83 2c 24 02 8b 04 24 31 01 59 c2 04 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_QV_2147806180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.QV!MTB"
        threat_id = "2147806180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 45 f0 f6 d0 30 44 0d f1 41 83 f9 0e 72 f1}  //weight: 10, accuracy: High
        $x_10_2 = {30 8c 15 21 fd ff ff 42 83 fa 07 73 08 8a 8d 20 fd ff ff eb eb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_QA_2147806300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.QA!MTB"
        threat_id = "2147806300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 75 f4 89 75 f0 8b 45 f0 01 05 ?? ?? ?? ?? 8b 55 ec 2b fe 8b cf c1 e1 04 03 4d e4 03 d7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_DE_2147807260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.DE!MTB"
        threat_id = "2147807260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2b f1 8b ce c1 e1 04 03 4d e8 8b c6 c1 e8 05 03 45 ec 03 fe 33 cf 33 c8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_DE_2147807260_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.DE!MTB"
        threat_id = "2147807260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 e1 04 03 4d dc 89 4d fc 8d 0c 03 c1 e8 05 03 45 d8 89 4d ec 89 45 f8 8b 45 ec 31 45 fc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_DE_2147807260_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.DE!MTB"
        threat_id = "2147807260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 44 24 04 c2 04 00 81 00 dc 35 ef c6 c3}  //weight: 10, accuracy: High
        $x_10_2 = {8b 4d f4 8b df d3 eb 03 5d dc 33 c3 89 45 ec 83 fa 27}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_DE_2147807260_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.DE!MTB"
        threat_id = "2147807260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "mirela" ascii //weight: 3
        $x_3_2 = "Filudujovava" ascii //weight: 3
        $x_3_3 = "CopyFileW" ascii //weight: 3
        $x_3_4 = "SystemTimeToTzSpecificLocalTime" ascii //weight: 3
        $x_3_5 = "ReleaseMutex" ascii //weight: 3
        $x_3_6 = "OutputDebugStringA" ascii //weight: 3
        $x_3_7 = "MoveFileA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_WE_2147807323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.WE!MTB"
        threat_id = "2147807323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4d f8 8b 5d fc 8b d1 c1 e2 04 8b c1 c1 e8 05 03 45 e4 03 d7 03 d9 33 d3 33 d0 89 55 ec}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_EC_2147807449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.EC!MTB"
        threat_id = "2147807449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {39 f0 4e 89 30 2b f2 41 83 c0 04 41 41 83 ea 04 41 83 fa 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_FD_2147808835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.FD!MTB"
        threat_id = "2147808835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rozovejusec" ascii //weight: 3
        $x_3_2 = "xogoruleyowukimutoxul" ascii //weight: 3
        $x_3_3 = "zasibif_fag53" ascii //weight: 3
        $x_3_4 = "fezusekuzu.pdb" ascii //weight: 3
        $x_3_5 = "GetNamedPipeHandleStateW" ascii //weight: 3
        $x_3_6 = "ReleaseMutex" ascii //weight: 3
        $x_3_7 = "GetProcessPriorityBoost" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_CE_2147809306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.CE!MTB"
        threat_id = "2147809306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "mirela" ascii //weight: 3
        $x_3_2 = "Filudujovava" ascii //weight: 3
        $x_3_3 = "CopyFileW" ascii //weight: 3
        $x_3_4 = "ReleaseMutex" ascii //weight: 3
        $x_3_5 = "OutputDebugStringA" ascii //weight: 3
        $x_3_6 = "MoveFileA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_CE_2147809306_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.CE!MTB"
        threat_id = "2147809306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "dfokjgnsdfjing" ascii //weight: 3
        $x_3_2 = "mehugisaj" ascii //weight: 3
        $x_3_3 = "GetNamedPipeInfo" ascii //weight: 3
        $x_3_4 = "FillConsoleOutputCharacterW" ascii //weight: 3
        $x_3_5 = "IsDebuggerPresent" ascii //weight: 3
        $x_3_6 = "GetFullPathNameW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_DG_2147809788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.DG!MTB"
        threat_id = "2147809788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 e0 04 03 45 dc 89 45 fc 8b 45 f8 03 c3 89 45 ec 8b c3 c1 e8 05 03 45 d8 89 45 f4 8b 45 ec 31 45 fc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_DR_2147809978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.DR!MTB"
        threat_id = "2147809978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c1 8b 75 08 33 d2 f7 f7 8a 04 32 30 04 19 41 3b 4d 10}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_DGE_2147809979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.DGE!MTB"
        threat_id = "2147809979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 e1 04 03 4d e0 8b c3 c1 e8 05 03 45 e4 8d 14 1f 33 ca 33 c8 29 4d f4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_DEM_2147810487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.DEM!MTB"
        threat_id = "2147810487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 8b ec 51 83 65 fc 00 8b 45 10 01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 8b 44 24 04 8b 4c 24 08 31 08 c2 08 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_DEN_2147810488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.DEN!MTB"
        threat_id = "2147810488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 8d 1c fe ff ff 8b d1 c1 e2 04 03 95 0c fe ff ff 8b c1 c1 e8 05 03 85 10 fe ff ff 03 cb 33 d1 33 d0 89 45 f4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_DM_2147810746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.DM!MTB"
        threat_id = "2147810746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b cf c1 e1 04 03 8d 10 fe ff ff 8b c7 c1 e8 05 03 85 08 fe ff ff 03 d7 33 ca 33 c8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_DER_2147811070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.DER!MTB"
        threat_id = "2147811070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 45 f0 8b c7 c1 e8 05 89 45 f8 8b 85 08 fe ff ff 01 45 f8 8b c7 c1 e0 04 03 85 10 fe ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_CR_2147811257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.CR!MTB"
        threat_id = "2147811257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 85 18 fe ff ff 03 c3 89 45 f4 8b c3 c1 e8 05 89 45 f8 8b 85 08 fe ff ff 01 45 f8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_CP_2147811319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.CP!MTB"
        threat_id = "2147811319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4c 24 04 8b 01 89 44 24 04 8b 44 24 08 01 44 24 04 8b 54 24 04 89 11}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_CJ_2147811420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.CJ!MTB"
        threat_id = "2147811420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2b f1 8b ce c1 e1 04 03 4d ec 8b c6 c1 e8 05 03 45 f0 8d 14 37 33 ca 33 c8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_MC_2147814736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.MC!MTB"
        threat_id = "2147814736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 51 83 65 fc 00 8b 45 0c 01 45 fc 8b 45 fc 31 45 08 8b 45 08 c9 c2 08 00}  //weight: 5, accuracy: High
        $x_5_2 = {01 08 c3 29 08 c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_MD_2147814737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.MD!MTB"
        threat_id = "2147814737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 44 24 10 3d a1 06 00 00 74 12 40 3d 86 76 13 01 89 44 24 10 0f 8c f8 fe ff ff eb 0c}  //weight: 5, accuracy: High
        $x_5_2 = {8d 44 24 20 50 6a 00 ff d6 6a 00 8d 8c 24 ?? ?? ?? ?? 51 ff d7 8d 54 24 24 52 ff d3 6a 00 ff d5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_MV_2147814904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.MV!MTB"
        threat_id = "2147814904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {81 00 47 86 c8 61 c3 81 00 eb 34 ef c6 c3 01 08 c3 29 08 c3}  //weight: 5, accuracy: High
        $x_5_2 = {c7 45 f4 02 00 00 00 83 45 f4 03 8b 8d 24 fd ff ff 8b c2 c1 e0 04 89 85 2c fd ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_CA_2147815000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.CA!MTB"
        threat_id = "2147815000"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8d 44 24 20 50 6a 00 ff d6 6a 00 8d 8c 24 50 0c 00 00 51 ff d7 8d 54 24 24 52 ff d3 6a 00 ff d5 6a 00 8d 84 24 50 10 00 00 50 6a 00 6a 00 6a 00 6a 00}  //weight: 5, accuracy: High
        $x_5_2 = {33 d2 33 c9 8d 44 24 1c 50 66 89 4c 24 1c 66 89 54 24 1e 8b 4c 24 1c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RC_2147827887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RC!MTB"
        threat_id = "2147827887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 33 c1 8b 4d 08 03 4d fc 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RC_2147827887_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RC!MTB"
        threat_id = "2147827887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 [0-37] 01 45 fc 8b 45 08 8b 4d ?? 31 08 c9 c2 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RC_2147827887_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RC!MTB"
        threat_id = "2147827887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {cc cc 81 01 e1 34 ef c6 c3 cc cc}  //weight: 1, accuracy: High
        $x_1_2 = {89 44 24 14 8b 44 24 ?? 01 44 24 14 8b 4c 24 14 33 4c 24 28 8b 44 24 10 [0-16] 33 c1 2b f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RC_2147827887_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RC!MTB"
        threat_id = "2147827887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 10 01 45 fc 8b 45 0c 33 45 fc 89 45 fc 8b 45 08 8b 4d fc 89 08 c9 c2 0c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RC_2147827887_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RC!MTB"
        threat_id = "2147827887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 dd 96 53 81 45 ?? 38 dd 96 53 8b 4d ?? 8b c6 d3 e0 [0-21] 03 c6 89 45 ?? 8b c6 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RC_2147827887_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RC!MTB"
        threat_id = "2147827887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 e8 89 44 24 10 8b 44 24 4c 01 44 24 10 8b 4c 24 28 33 ca 89 4c 24 38 89 5c 24 30 8b 44 24 38 89 44 24 30 8b 44 24 10 31 44 24 30}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 14 01 44 24 28 8b 44 24 18 c1 e8 05 89 44 24 10 8b 44 24 10 33 74 24 28 03 44 24 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RC_2147827887_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RC!MTB"
        threat_id = "2147827887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 00 e1 34 ef c6 c3 01 08 c3}  //weight: 1, accuracy: High
        $x_1_2 = {ee 3d ea f4 89 45 [0-16] 33 7d ?? 31 7d [0-80] 81 6d ?? 36 dd 96 53 81 45 ?? 3a dd 96 53 8b 45 ?? 8b 4d [0-10] d3 e8 [0-32] 8b c6 d3 e0 03 45 ?? 33 45 ?? 33 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RC_2147827887_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RC!MTB"
        threat_id = "2147827887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 00 47 86 c8 61 c3 81 00 e1 34 ef c6 c3 01 08 c3 01 08 c3}  //weight: 1, accuracy: High
        $x_1_2 = {ee 3d ea f4 89 45 [0-16] 33 75 ?? 31 75 [0-80] 81 6d ?? 36 dd 96 53 81 45 ?? 3a dd 96 53 [0-16] d3 e8 [0-32] d3 e2 [0-8] 03 55 ?? 33 55 ?? 33 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RC_2147827887_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RC!MTB"
        threat_id = "2147827887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 00 e1 34 ef c6 c3 01 08 c3}  //weight: 1, accuracy: High
        $x_1_2 = {ee 3d ea f4 89 45 [0-16] 33 7d ?? 31 7d [0-80] 81 6d ?? 36 dd 96 53 81 45 ?? 3a dd 96 53 8b 45 ?? 8b 4d ?? 03 c6 8b d6 d3 e2 [0-16] d3 e8 [0-16] 01 45 ?? 8b 45 ?? 33 45 [0-10] 33 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RC_2147827887_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RC!MTB"
        threat_id = "2147827887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b1 6c b0 6d [0-8] 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 73 c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 32 a2 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 67 88 0d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 ff 15 ?? ?? ?? ?? c3 cc cc 81 01 e1 34 ef c6 c3 cc cc}  //weight: 1, accuracy: Low
        $x_1_2 = {81 6c 24 24 36 dd 96 53 81 44 24 24 3a dd 96 53 [0-32] d3 e2 [0-32] c1 e8 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RD_2147827932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RD!MTB"
        threat_id = "2147827932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 55 f8 89 4d fc 8b 45 f8 c1 e0 04 8b 4d fc 89 01 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 e4 33 55 f0 89 55 e4 8b 45 e4 33 45 ec 89 45 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RD_2147827932_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RD!MTB"
        threat_id = "2147827932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 45 fc 83 6d fc 02 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 8b 44 24 04 8b 4c 24 08 01 08 c2 08 00 8b 44 24 08 8b 4c 24 04 c1 e0 04 89 01 c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RD_2147827932_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RD!MTB"
        threat_id = "2147827932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 10 01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RD_2147827932_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RD!MTB"
        threat_id = "2147827932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 83 65 fc 00 8b 45 0c 01 45 fc 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 0c 33 45 fc 89 45 fc 8b 45 08 8b 4d fc 89 08 c9 c2 0c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RB_2147827954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RB!MTB"
        threat_id = "2147827954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 54 24 04 b8 3b 2d 0b 00 01 44 24 04 8b 44 24 04 8a 04 30 88 04 0e 46 3b 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RB_2147827954_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RB!MTB"
        threat_id = "2147827954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 8b 45 90 33 d2 f7 f1 8b 45 88 8b 4d 80 57 8a 04 02 32 04 19 88 03 8d 45 94}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RB_2147827954_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RB!MTB"
        threat_id = "2147827954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 c2 08 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b c6 c1 e0 04 03 45 ?? 33 45 ?? 33 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RB_2147827954_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RB!MTB"
        threat_id = "2147827954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 c1 e1 04 03 4c 24 ?? 89 4c 24 ?? 8d 0c 07 c1 e8 05 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 c1 33 44 24 [0-18] 2b f0 89 44 24 ?? 8b c6 c1 e0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RB_2147827954_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RB!MTB"
        threat_id = "2147827954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 83 65 fc 00 8b 45 10 01 45 fc 8b 45 0c 33 45 fc 89 45 fc 8b 45 08 8b 4d fc 89 08 c9 c2 0c 00 [0-37] 55 8b ec 51 c7 45 fc 02 00 00 00 83 45 fc 02 8b 4d fc 8b 45 0c d3 e0 8b 4d 08 89 01 c9 c2 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RE_2147828046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RE!MTB"
        threat_id = "2147828046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 f9 8b 55 0c 03 55 f4 0f b6 0a 33 c8 8b 55 0c 03 55 f4 88 0a eb b2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RE_2147828046_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RE!MTB"
        threat_id = "2147828046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 55 8b ec 8b 45 08 8b 4d 0c 31 08 5d c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RE_2147828046_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RE!MTB"
        threat_id = "2147828046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {af 9e 1b 2c c7 44 24 ?? 30 2e 52 49 c7 84 24 ?? 00 00 00 7a cd 12 6e c7 84 24 ?? ?? ?? ?? c5 53 ef 46 b8 64 cb bc 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RE_2147828046_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RE!MTB"
        threat_id = "2147828046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 55 8b ec 51 83 65 fc 00 8b 45 0c [0-2] 01 45 fc 8b 45 08 8b 4d 0c 31 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RE_2147828046_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RE!MTB"
        threat_id = "2147828046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 4c 24 2c 89 35 ?? ?? ?? ?? 31 4c 24 10 8b 44 24 10 29 44 24 1c 8b 44 24 40 29 44 24 18}  //weight: 1, accuracy: Low
        $x_1_2 = {81 01 e1 34 ef c6 c3 [0-21] 01 11 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RE_2147828046_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RE!MTB"
        threat_id = "2147828046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wallet.dat" wide //weight: 1
        $x_1_2 = "mozzzzzzzzzzz" wide //weight: 1
        $x_1_3 = "sstmnfo_" ascii //weight: 1
        $x_1_4 = {40 8a 0c 85 ?? ?? ?? ?? 8b 45 08 32 0c 03 a1 ?? ?? ?? ?? 88 0c 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RE_2147828046_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RE!MTB"
        threat_id = "2147828046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 00 e1 34 ef c6 c3 01 08 c3 01 08 c3}  //weight: 1, accuracy: High
        $x_1_2 = {d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 [0-213] 36 dd 96 53 81 45 ?? 3a dd 96 53 8b 55 ?? 8b 4d ?? 8b c2 d3 e0 [0-32] d3 ea 8b 4d ?? 8d 45 [0-16] 8b 45 ?? 33 ?? 31 45 ?? 89 ?? ?? ?? ?? ?? 8b 45 [0-16] 29 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RE_2147828046_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RE!MTB"
        threat_id = "2147828046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 00 47 86 c8 61 c3 81 00 e1 34 ef c6 c3 ?? 08 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 [0-21] 56 c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 63 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RF_2147828286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RF!MTB"
        threat_id = "2147828286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 d8 8b 45 d8 31 18 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 0f 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RF_2147828286_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RF!MTB"
        threat_id = "2147828286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 c0 8b 55 e4 8d 4d f8 89 0c 24 8b 4d 14 8b 5d 0c 33 99 20 01 00 00 89 5c 24 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RF_2147828286_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RF!MTB"
        threat_id = "2147828286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 33 d2 8b c7 f7 f1 8b 45 0c 8b 4d 08 8a 04 02 32 04 31 47 88 06 3b 7d 10 72 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RF_2147828286_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RF!MTB"
        threat_id = "2147828286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 0c 01 45 fc 8b 45 08 8b 4d fc 31 08 c9 c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RF_2147828286_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RF!MTB"
        threat_id = "2147828286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 04 8b 4c 24 08 29 08 c2 08 00 8b 44 24 04 8b 4c 24 08 29 08 c2 08 00 8b 44 24 08 33 44 24 0c 8b 4c 24 04 89 01 c2 0c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RF_2147828286_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RF!MTB"
        threat_id = "2147828286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 c7 04 24 00 00 00 00 8b 44 24 0c 89 04 24 8b 44 24 08 31 04 24 8b 04 24 89 01 59 c2 08 00 [0-8] 81 00 e1 34 ef c6 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RF_2147828286_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RF!MTB"
        threat_id = "2147828286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 f7 f1 8b 45 fc 8a 0c 02 8d 14 33 8a 04 17 32 c1 43 88 02}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 fc f7 f1 8a 0e 8b 45 fc 32 8a ?? ?? ?? ?? 40 88 0c 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RF_2147828286_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RF!MTB"
        threat_id = "2147828286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 08 89 55 f8 89 4d fc 8b 45 f8 c1 e0 04 8b 4d fc 89 01 8b e5 5d c3 [0-32] 8b 08 81 e9 1f cb 10 39 8b 55 fc 89 0a 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RF_2147828286_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RF!MTB"
        threat_id = "2147828286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 dd 96 53 81 44 24 ?? 38 dd 96 53 8b c6 [0-64] 8b d6 d3 ea 03 d5 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 31 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RF_2147828286_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RF!MTB"
        threat_id = "2147828286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 dd 96 53 81 45 ?? 38 dd 96 53 8b 4d ?? 8b c7 d3 e0 89 5d ?? 03 45 [0-32] 8b c7 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RF_2147828286_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RF!MTB"
        threat_id = "2147828286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 45 fc 83 6d fc 02 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 8b 44 24 04 8b 4c 24 08 01 08 c2 08 00 55 8b ec 51 83 65 fc 00 83 45 fc 04 8b 4d fc 8b 45 0c d3 e0 8b 4d 08 89 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RF_2147828286_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RF!MTB"
        threat_id = "2147828286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 dd 96 53 81 44 24 ?? 38 dd 96 53 8b c6 [0-48] 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 8b c6 d3 e8 8b 4c 24 ?? 31 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RF_2147828286_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RF!MTB"
        threat_id = "2147828286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 dd 96 53 81 45 ?? 38 dd 96 53 8b 4d ?? 8b c7 d3 e0 [0-48] 8b c7 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RF_2147828286_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RF!MTB"
        threat_id = "2147828286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 dd 96 53 81 44 24 ?? 38 dd 96 53 8b 4c 24 ?? 8b d6 d3 e2 [0-53] 8b c6 d3 e8 03 c5 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 31 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RF_2147828286_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RF!MTB"
        threat_id = "2147828286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 dd 96 53 81 44 24 ?? 38 dd 96 53 8b c6 [0-48] 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 8b d6 d3 ea 03 d5 89 54 24 ?? 8b 44 24 ?? 31 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RF_2147828286_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RF!MTB"
        threat_id = "2147828286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 dd 96 53 81 44 24 ?? 38 dd 96 53 8b c6 [0-64] 8b 54 24 ?? 31 54 24 ?? 8b c6 d3 e8 03 c3 [0-48] 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_PA_2147828938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.PA!MTB"
        threat_id = "2147828938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 89 18 6a 00 e8 ?? ?? ?? ?? 8b 5d ?? 03 5d ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 83 45 ec ?? 6a 00 e8 ?? ?? ?? ?? bb 04 00 00 00 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RG_2147828939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RG!MTB"
        threat_id = "2147828939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RG_2147828939_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RG!MTB"
        threat_id = "2147828939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 09 8b 85 ?? ?? ff ff 99 be 26 00 00 00 f7 fe 8b 85 ?? ?? ff ff 0f b6 14 10 33 ca 8b 85 ?? ?? ff ff 03 85 ?? ?? ff ff 88 08 eb aa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RG_2147828939_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RG!MTB"
        threat_id = "2147828939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 08 89 54 24 04 c7 04 24 00 00 00 00 8b 44 24 0c 89 04 24 8b 44 24 04 31 04 24 8b 04 24 89 01 83 c4 08 c2 04 00 [0-16] 81 01 e1 34 ef c6 c3 [0-16] 29 11 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RG_2147828939_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RG!MTB"
        threat_id = "2147828939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 00 e1 34 ef c6 c3 01 08 c3}  //weight: 1, accuracy: High
        $x_1_2 = {36 dd 96 53 81 45 ?? 38 dd 96 53 8b 4d ?? 8b c6 d3 e0 [0-32] 8b c6 d3 e8 89 55 ?? 89 3d ?? ?? ?? ?? 03 45 ?? 33 c2 31 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RG_2147828939_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RG!MTB"
        threat_id = "2147828939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 dd 96 53 81 44 24 ?? 38 dd 96 53 8b 4c 24 ?? 8b d6 d3 e2 [0-48] 8b c6 d3 e8 03 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 31 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RG_2147828939_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RG!MTB"
        threat_id = "2147828939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 7c f6 ff ff 83 c0 01 89 85 7c f6 ff ff 8b 8d 7c f6 ff ff 3b 0d ?? ?? ?? ?? 73 27 0f b6 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 85 7c f6 ff ff 0f b6 08 33 ca 8b 15 ?? ?? ?? ?? 03 95 7c f6 ff ff 88 0a eb bc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RG_2147828939_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RG!MTB"
        threat_id = "2147828939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 dd 96 53 81 45 ?? 38 dd 96 53 8b 4d ?? 8b c6 d3 e0 [0-16] 8b 45 ?? 03 c6 89 45 ?? 8b c6 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 [0-10] 31 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RH_2147828963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RH!MTB"
        threat_id = "2147828963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 44 24 7c 8e ac 58 26 81 44 24 60 66 92 e6 2b 81 44 24 30 e5 ae fc 48 8a 9c 02 3b 2d 0b 00 88 1c 30 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RH_2147828963_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RH!MTB"
        threat_id = "2147828963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c2 08 00 81 01 e1 34 ef c6 c3}  //weight: 1, accuracy: High
        $x_1_2 = {d3 e8 89 45 f4 8b 45 d4 01 45 f4 8b 45 f4 33 45 e8 89 35 ?? ?? ?? ?? 31 45 fc 2b 5d fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RH_2147828963_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RH!MTB"
        threat_id = "2147828963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 0f 00 00 c7 04 24 f0 43 03 00 75 08 6a 00 ff 15 ?? ?? ?? ?? 56 83 44 24 04 0d a1 ?? ?? ?? ?? 0f af 44 24 04 05 c3 9e 26 00 81 3d ?? ?? ?? ?? 81 13 00 00 a3 ?? ?? ?? ?? 0f b7 35 ?? ?? ?? ?? 75 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RH_2147828963_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RH!MTB"
        threat_id = "2147828963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c2 01 89 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 3b 05 ?? ?? ?? ?? 73 ?? 0f b6 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ff ff 0f b6 02 33 c1 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ff ff 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RH_2147828963_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RH!MTB"
        threat_id = "2147828963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e8 05 [0-16] 89 45 ?? 8b 45 ?? 01 45 ?? 03 f3 33 75 ?? 33 75}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_PB_2147829147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.PB!MTB"
        threat_id = "2147829147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 83 45 ec ?? 6a 00 e8 ?? ?? ?? ?? bb 04 00 00 00 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 01 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_R_2147830069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.R!MTB"
        threat_id = "2147830069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 10 01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 55 8b ec 51 c7 45 fc 02 00 00 00 8b 45 0c 01 45 fc 83 6d fc 02 8b 45 08 8b 4d 0c 31 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RA_2147830366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RA!MTB"
        threat_id = "2147830366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 04 8b 4c 24 08 29 08 c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 10 01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RA_2147830366_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RA!MTB"
        threat_id = "2147830366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 04 8b 4c 24 08 29 08 c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 10 90 01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RA_2147830366_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RA!MTB"
        threat_id = "2147830366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 fc 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 [0-48] 55 8b ec 8b 4d 08 8b 01 89 45 08 8b 45 0c 01 45 08 8b 45 08 89 01 5d c2 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RA_2147830366_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RA!MTB"
        threat_id = "2147830366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 72 e4 8d 44 24 08 c7 44 24 08 00 00 00 00 50 6a 40 68 7e 07 00 00 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RA_2147830366_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RA!MTB"
        threat_id = "2147830366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 dd 96 53 81 45 ?? 38 dd 96 53 8b 4d ?? 8b ?? d3 e0 89 45 ?? 8b 45 ?? 01 45}  //weight: 1, accuracy: Low
        $x_1_2 = {81 00 e1 34 ef c6 c3 01 08 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_PC_2147830383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.PC!MTB"
        threat_id = "2147830383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 89 45 ?? 6a 00 [0-14] 2b d8 [0-14] 2b d8 8b 45 ?? 31 18 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_PD_2147830384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.PD!MTB"
        threat_id = "2147830384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8d 4c 24 ?? 89 44 24 ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 33 4c 24 ?? 89 35 ?? ?? ?? ?? 31 4c 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 4b 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_PG_2147830731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.PG!MTB"
        threat_id = "2147830731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 [0-10] 2b d8 8b 45 ?? 31 18 6a 00 [0-10] 8b 5d e8 83 c3 04 2b d8 [0-10] 2b d8 6a 00 [0-8] 2b d8 89 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RJ_2147831073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RJ!MTB"
        threat_id = "2147831073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 55 8b ec 51 [0-16] 8b 45 0c [0-16] 01 45 fc 83 6d fc 02 8b 45 08 8b 4d ?? 31 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RJ_2147831073_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RJ!MTB"
        threat_id = "2147831073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c2 08 00 81 01 e1 34 ef c6 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b c3 d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 45 cc 89 45 f8 8b 45 e8 31 45 fc 8b 45 fc 31 45 f8 81 3d ?? ?? ?? ?? 6e 0c 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RJ_2147831073_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RJ!MTB"
        threat_id = "2147831073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 00 47 86 c8 61 c3 81 00 e1 34 ef c6 c3 01 08 c3}  //weight: 1, accuracy: High
        $x_1_2 = {03 c6 89 45 ?? 8b c6 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RJ_2147831073_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RJ!MTB"
        threat_id = "2147831073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 ?? 8b 45 ?? 01 45 ?? 83 65 ?? 00 8b c6 c1 e0 ?? 03 45 ?? 33 45 ?? 33 c1 2b f8 8b 45 ?? 01 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RJ_2147831073_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RJ!MTB"
        threat_id = "2147831073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 75 ?? 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ?? 0f b6 45 ?? 8b 4d ?? 0f b6 91 ?? ?? ?? ?? 03 d0 8b 45 ?? 88 [0-32] 2b c8 88 4d [0-21] 2b ca 8b 55 ?? 88 8a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RJ_2147831073_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RJ!MTB"
        threat_id = "2147831073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 00 e1 34 ef c6 c3 01 08 c3}  //weight: 1, accuracy: High
        $x_1_2 = {36 dd 96 53 81 45 ?? 38 dd 96 53 8b 4d ?? 8b c6 d3 e0 [0-32] 8b d6 d3 ea 03 c6 89 45 ?? 03 55 ?? 8b 45 ?? 31 45 ?? 31 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RK_2147831079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RK!MTB"
        threat_id = "2147831079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 c2 08 00 55 8b ec 8b 4d 08 8b 01 89 45 08 8b 45 0c 01 45 08 8b 45 0c 01 01 5d c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RK_2147831079_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RK!MTB"
        threat_id = "2147831079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 11 c3 cc [0-21] 81 01 e1 34 ef c6 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {01 44 24 20 8b 44 24 20 89 44 24 28 8b 44 24 18 8b 4c 24 1c d3 e8 89 44 24 14 8b 44 24 40 01 44 24 14 8b 4c 24 14 33 4c 24 28 8b 44 24 10 33 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_EA_2147831190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.EA!MTB"
        threat_id = "2147831190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 75 e4 33 f7 2b de 8b 45 ec 29 45 fc 83 6d f4 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_EA_2147831190_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.EA!MTB"
        threat_id = "2147831190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {55 8b ec 51 c7 45 fc 04 00 00 00 8b 45 0c 83 6d fc 02 90 01 45 fc 83 6d fc 02 8b 45 08 8b 4d fc 31 08 c9 c2 08 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RI_2147832808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RI!MTB"
        threat_id = "2147832808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 c7 45 fc 04 00 00 00 8b 45 0c 83 6d fc 04 01 45 fc 8b 45 08 8b 4d fc 31 08 c9 c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RI_2147832808_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RI!MTB"
        threat_id = "2147832808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 0c 90 01 45 fc 8b 45 08 8b 4d fc 31 08 c9 c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RI_2147832808_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RI!MTB"
        threat_id = "2147832808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 10 01 45 fc 8b 45 08 8b 4d fc 89 08 c9 c2 0c 00 c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RI_2147832808_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RI!MTB"
        threat_id = "2147832808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c2 08 00 81 01 e1 34 ef c6 c3}  //weight: 1, accuracy: High
        $x_1_2 = {d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 [0-112] 81 6d ?? 36 dd 96 53 81 45 ?? 3a dd 96 53 8b 45 ?? 8b 4d ?? d3 e0 [0-48] d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 [0-9] 31 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RL_2147832930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RL!MTB"
        threat_id = "2147832930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 01 e1 34 ef c6 c3}  //weight: 1, accuracy: High
        $x_1_2 = {ee 3d ea f4 [0-16] 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 81 3d ?? ?? ?? ?? 6e 0c 00 00 [0-96] 81 6d ?? 36 dd 96 53 81 45 ?? 3a dd 96 53 8b 4d ?? 8b d6 d3 e2 [0-37] 8b c6 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 33 4d [0-8] 31 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RM_2147833189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RM!MTB"
        threat_id = "2147833189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e1 34 ef c6 c3}  //weight: 1, accuracy: High
        $x_1_2 = {ee 3d ea f4 [0-16] 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 [0-96] 81 6d ?? 36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-53] 89 45 ?? 8b 45 ?? 01 45 ?? 8b ?? ?? 33 [0-9] 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RM_2147833189_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RM!MTB"
        threat_id = "2147833189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 00 e1 34 ef c6 c3}  //weight: 1, accuracy: High
        $x_1_2 = {ee 3d ea f4 89 45 [0-16] 33 5d ?? 31 5d ?? 81 3d [0-96] 81 6d ?? 36 dd 96 53 81 45 ?? 3a dd 96 53 8b 45 ?? 8b 4d ?? 03 c7 8b d7 d3 e2 [0-16] d3 e8 [0-16] 01 45 ?? 8b 45 ?? 33 45 [0-8] 33 d0 [0-8] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RN_2147833335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RN!MTB"
        threat_id = "2147833335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 34 af 03 f0 45 53 51 b9 4d 6f 61 64 83 e9 02 8b d9 59 83 c3 01 39 1e 5b 75 e5 53 60 0a ed 66 83 d8 2a 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RN_2147833335_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RN!MTB"
        threat_id = "2147833335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 [0-37] 55 8b ec 8b 45 0c 8b 4d 08 c1 e0 04 89 01 5d c2 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RPB_2147833441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RPB!MTB"
        threat_id = "2147833441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 d0 8b 85 7c ff ff ff 89 04 0a b9 04 00 00 00 6b d1 00 8b 45 d0 8b 8d 7c ff ff ff 89 0c 10 ba 04 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RP_2147833596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RP!MTB"
        threat_id = "2147833596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 fc 8b 45 0c 33 45 fc 89 45 fc 8b 45 08 8b 4d fc 89 08 c9 c2 0c 00 [0-48] 55 8b ec 8b 45 0c 8b 4d 08 c1 e0 04 89 01 5d c2 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RO_2147833962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RO!MTB"
        threat_id = "2147833962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 34 af 03 f0 45 53 51 b9 ?? 6f 61 64 [0-6] 8b d9 59 83 c3 01 39 1e 5b 75 ?? 53 60 0a ed 66 83 d8 2a 61 bb 62 72 79 41 83 eb 02 83 c3 01 39 5e 08 5b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RPQ_2147834934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RPQ!MTB"
        threat_id = "2147834934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 33 d2 8b c3 f7 f1 8b 45 f8 8a 0c 02 8d 14 33 8b 45 fc 8a 04 10 32 c1 43 88 02 3b df 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RPU_2147835040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RPU!MTB"
        threat_id = "2147835040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8b c6 f7 f3 8a 0c 0a 30 0c 3e 46 8b 4d fc 3b 75 0c 72 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_MP_2147835462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.MP!MTB"
        threat_id = "2147835462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 25 00 8b 4d 04 81 c5 08 00 00 00 3b ed f9 89 08 81 ef 04 00 00 00 c0 d4 7d 8b 07 33 c3 85 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RPI_2147836594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RPI!MTB"
        threat_id = "2147836594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c6 01 8a 46 ff 68 ?? ?? ?? ?? 83 c4 04 32 02 68 ?? ?? ?? ?? 83 c4 04 aa 68 ?? ?? ?? ?? 83 c4 04 83 c2 01 68 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? 83 c4 04 49}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_CG_2147841193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.CG!MTB"
        threat_id = "2147841193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {59 50 56 ff d3 6a ?? ba ?? ?? ?? ?? a3 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59}  //weight: 6, accuracy: Low
        $x_1_2 = "GetObjectW" ascii //weight: 1
        $x_1_3 = "CoDecodeProxy" ascii //weight: 1
        $x_1_4 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_5 = "*.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_NEAA_2147842641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.NEAA!MTB"
        threat_id = "2147842641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f7 ff 83 e0 2c 33 f0 03 ce 8b 55 0c 03 55 fc 88 0a 0f be 45 fb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_NEAB_2147842644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.NEAB!MTB"
        threat_id = "2147842644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 44 24 0c 83 2c 24 04 01 04 24 8b 44 24 08 8b 0c 24 31 08 59}  //weight: 5, accuracy: High
        $x_5_2 = {8b 44 24 10 01 04 24 8b 44 24 0c 33 04 24 89 04 24 8b 44 24 08 8b 0c 24 89 08}  //weight: 5, accuracy: High
        $x_2_3 = "IsProcessorFeaturePresent" ascii //weight: 2
        $x_2_4 = "TerminateProcess" ascii //weight: 2
        $x_2_5 = "IsDebuggerPresent" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RPY_2147843543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RPY!MTB"
        threat_id = "2147843543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4f f7 d6 03 f3 c1 ce 08 f7 d2 03 c4 4f 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_CREC_2147847281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.CREC!MTB"
        threat_id = "2147847281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 33 d2 8b 45 08 f7 f1 8b 45 f8 8a 0c 02 8b 55 08 8b 45 fc 03 d7 68 ?? ?? ?? ?? 8a 04 10 32 c1 88 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_GJT_2147848912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.GJT!MTB"
        threat_id = "2147848912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 94 15 ?? ?? ?? ?? 8b 45 10 03 45 f0 0f b6 08 33 ca 8b 55 10 03 55 f0 88 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_MBHJ_2147851970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.MBHJ!MTB"
        threat_id = "2147851970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0d 30 a1 41 02 8a 94 31 4b 13 01 00 8b 0d ?? ?? ?? ?? 88 14 31 3d a8 00 00 00 75 ?? 6a 00 ff d7 a1 ?? ?? ?? ?? 46 3b f0 72}  //weight: 1, accuracy: Low
        $x_1_2 = {6c 6f 63 69 79 75 6a 61 76 65 67 69 62 65 79 00 4c 61 63 6f 6b 65 6b 75 20 72 61 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_MKZ_2147852733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.MKZ!MTB"
        threat_id = "2147852733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 cb 0f b6 c1 88 8d eb fc ff ff 8d 8d ec fc ff ff 03 c8 0f b6 01 88 02 88 19 0f b6 12 8b 8d ?? ?? ?? ?? 0f b6 c3 03 d0 0f b6 c2 0f b6 84 05 ?? ?? ?? ?? 30 04 0e 46 8a 8d eb fc ff ff 3b f7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_MKY_2147853014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.MKY!MTB"
        threat_id = "2147853014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 06 83 c4 08 0f b6 0f 03 c8 0f b6 c1 8b 8d f8 fe ff ff 8a 84 05 fc fe ff ff 30 81 ?? ?? ?? ?? 41 89 8d f8 fe ff ff 81 f9 00 ca 00 00 8b 8d f4 fe ff ff 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_MKW_2147853015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.MKW!MTB"
        threat_id = "2147853015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 33 d2 8b 45 fc f7 f1 8a 0e 8b 45 fc 32 8a ?? ?? ?? ?? 40 88 0c 33 46 89 45 fc 83 f8 40 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_AHB_2147890107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.AHB!MTB"
        threat_id = "2147890107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 33 d2 8b 45 fc f7 f1 8a 0f 32 8a d4 4e 41 00 88 0c 3e 8b 4d fc 41 47 89 4d fc 83 f9 40 72 cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_NNW_2147891492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.NNW!MTB"
        threat_id = "2147891492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 33 d2 8b 45 f4 f7 f1 8a 0e 8b 45 f8 32 8a ?? ?? ?? ?? 88 0c 30 8b 4d f4 41 46 89 4d f4 83 f9 40 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_CCBM_2147891710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.CCBM!MTB"
        threat_id = "2147891710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sgnl_" ascii //weight: 1
        $x_1_2 = "tlgrm_" ascii //weight: 1
        $x_1_3 = "grbr_" ascii //weight: 1
        $x_1_4 = "dscrd_" ascii //weight: 1
        $x_1_5 = "wlts_" ascii //weight: 1
        $x_1_6 = "scrnsht_" ascii //weight: 1
        $x_1_7 = "URL:%s" ascii //weight: 1
        $x_1_8 = "USR:%s" ascii //weight: 1
        $x_1_9 = "PASS:%s" ascii //weight: 1
        $x_1_10 = "machineId=" ascii //weight: 1
        $x_1_11 = "&configId=" ascii //weight: 1
        $x_1_12 = "Login Data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_RPZ_2147894732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.RPZ!MTB"
        threat_id = "2147894732"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 c7 17 49 c1 c0 13 03 fa 09 0d ?? ?? ?? ?? 2b fa c1 c8 13 41 c1 cf 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_MKQ_2147895550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.MKQ!MTB"
        threat_id = "2147895550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 33 d2 8b 45 fc f7 f1 8a 0f 8b 45 fc 32 8a 9c 39 41 00 40 88 0c 3e 47 89 45 fc 83 f8 40 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_MZZ_2147918918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.MZZ!MTB"
        threat_id = "2147918918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 c9 c1 ea 18 8b b4 8f ?? ?? ?? ?? 8b c8 03 74 97 48 8b 55 f4 c1 e9 08 0f b6 c9 33 b4 8f 48 08 00 00 0f b6 c8 03 b4 8f 48 0c 00 00 8b 4d 0c 33 34 0a 83 6d fc 01 8b 4d 08 89 34 0a 8b 4d 0c 8b 75 08 89 04 0a 75}  //weight: 5, accuracy: Low
        $x_5_2 = {8d 4f 44 89 44 32 04 8b 07 31 04 32 8b 45 f8 40 89 45 f8 3b 45 10 0f 82 68 ff ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccoon_EAXA_2147928695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoon.EAXA!MTB"
        threat_id = "2147928695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b f0 d3 e0 c1 ee 05 03 b4 24 d8 02 00 00 03 84 24 d0 02 00 00 89 74 24 10}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

