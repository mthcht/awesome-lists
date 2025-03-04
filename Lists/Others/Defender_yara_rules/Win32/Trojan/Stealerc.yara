rule Trojan_Win32_Stealerc_GJD_2147846835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.GJD!MTB"
        threat_id = "2147846835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 0c 03 85 ?? ?? ?? ?? 0f b6 08 8b 95 ?? ?? ?? ?? 0f b6 84 15 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 0f b6 94 15 ?? ?? ?? ?? 03 c2 25 ff 00 00 80 79 ?? 48 0d ?? ?? ?? ?? 40 0f b6 84 05 ?? ?? ?? ?? 33 c8 8b 55 f8 03 95 ?? ?? ?? ?? 88 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_GJK_2147848026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.GJK!MTB"
        threat_id = "2147848026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 04 11 83 f0 0d 8b 8d ?? ?? ?? ?? c1 e1 00 8d 95 ?? ?? ?? ?? 88 04 11 8b 85 ?? ?? ?? ?? c1 e0 00 8d 8d ?? ?? ?? ?? 0f b6 14 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_GKH_2147849586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.GKH!MTB"
        threat_id = "2147849586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 50 01 8b 85 ?? ?? ?? ?? 01 c2 8b 85 ?? ?? ?? ?? 83 e8 01 2b 85 ?? ?? ?? ?? 0f b6 84 05 ?? ?? ?? ?? 88 84 15 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 83 e8 01 2b 85 ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? 88 94 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_YAA_2147853420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.YAA!MTB"
        threat_id = "2147853420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb 8d 04 1f c1 e1 04 81 c1 ?? ?? ?? ?? 33 c8 8b c3 c1 e8 05 2d ?? ?? ?? ?? 33 c8 2b f1 8b ce c1 e1 04 81 e9 ?? ?? ?? ?? 8d 04 37 33 c8 8d bf ?? ?? ?? ?? 8b c6 c1 e8 05 2d ?? ?? ?? ?? 33 c8 2b d9 83 ed 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_GME_2147888196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.GME!MTB"
        threat_id = "2147888196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d4 cc c8 de 66 c7 84 24 ?? ?? ?? ?? c9 c8 8a 84 0c ?? ?? ?? ?? 34 bb 88 44 0c ?? 41 83 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_GMG_2147888764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.GMG!MTB"
        threat_id = "2147888764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ca 66 c7 44 24 ?? ?? ?? 66 c7 44 24 ?? ?? ?? 8a 44 0c 58 34 ae 88 44 0c 60 41 83 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_G_2147888814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.G!MTB"
        threat_id = "2147888814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 f0 8b 45 f0 89 45 ec 8b 55 f8 8b 4d f4 8b c2 d3 e8 8b 4d fc 81 c7 ?? ?? ?? ?? 89 7d e8 03 45 d0 33 45 ec 33 c8 2b f1 83 eb 01 89 4d fc 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_GPD_2147890490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.GPD!MTB"
        threat_id = "2147890490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f b6 0f 8b 74 24 ?? 03 c8 0f b6 c1 8a 84 04 ?? ?? 00 00 30 85 ?? ?? ?? ?? 45 81 fd 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_GMF_2147891312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.GMF!MTB"
        threat_id = "2147891312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 c6 2b df c1 c2 f9 c1 ca 0d 66 c1 db 77 41 66 f7 eb 66 f7 e8 bb f8 00 00 00 66 c1 ce b9 03 cb 66 f7 e7 41 c1 e3 5a 23 c3 66 40 66 33 fb 66 c1 d1 fd}  //weight: 10, accuracy: High
        $x_1_2 = {30 00 00 00 8b 7f 0c 8b 77 0c 8b 06}  //weight: 1, accuracy: High
        $x_1_3 = {5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c [0-32] 5c 41 70 70 4c 61 75 6e 63 68 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_GMC_2147891728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.GMC!MTB"
        threat_id = "2147891728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b f8 8a 15 ?? ?? ?? ?? 83 c4 0c 69 c9 ?? ?? ?? ?? 80 ea 60 80 f2 d1 88 0d ?? ?? ?? ?? 85 ff 74 ?? 8a c2 80 e9 48 80 ca 75 88 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_GPA_2147891922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.GPA!MTB"
        threat_id = "2147891922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8a 84 0c 8c 00 00 00 34 bb 88 44 0c 14 41 83 f9 16 7c ed}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_EM_2147892361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.EM!MTB"
        threat_id = "2147892361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 8a 42 0c 32 45 08 88 41 0c 5d e9 b6 00 00 00 55 8b ec 8a 42 19 32 45 08 88 41 19 5d e9 92 00 00 00 55 8b ec 8a 42 09 32 45 08 88 41 09 5d e9 6e 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_AMAB_2147892702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.AMAB!MTB"
        threat_id = "2147892702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 44 24 30 03 0a 55 54 c7 44 24 34 48 02 0a 0a 8a 44 0c 2c 34 ?? 88 84 0c fc 00 00 00 41 83 f9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_GPAE_2147892930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.GPAE!MTB"
        threat_id = "2147892930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8a 44 24 22 30 44 0c 23 41 83 f9}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_GMX_2147893297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.GMX!MTB"
        threat_id = "2147893297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 6a 00 80 34 28 ?? ff d6 6a 00 ff d7 6a 00 ff d3 8b 44 24 ?? 6a 00 6a 00 80 34 28 ?? ff d6 6a 00 ff d7 6a 00 ff d3 8b 44 24 ?? 6a 00 6a 00 80 04 28}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_NS_2147893375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.NS!MTB"
        threat_id = "2147893375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff d6 e8 25 04 00 00 8b f0 39 3e 74 13 56 e8 ?? ?? ?? ?? 59 84 c0 74 08 ff 36 e8 ?? ?? ?? ?? 59 e8 28 05 00 00 0f b7 f0 e8 d5 53 00 00 56}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_MBKL_2147894270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.MBKL!MTB"
        threat_id = "2147894270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 00 65 00 78 00 65 00 00 00 41 38 37 39 31 68 62 78 37 38 69 55 41}  //weight: 1, accuracy: High
        $x_1_2 = "GYAUs87atedyuw3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_AMBA_2147895791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.AMBA!MTB"
        threat_id = "2147895791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 f4 b8 ?? ?? ?? ?? 8b 5d f4 b9 ?? ?? ?? ?? 35 ?? ?? ?? ?? 25 ?? ?? ?? ?? 0d ?? ?? ?? ?? 89 03 01 cb 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_MBEU_2147896900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.MBEU!MTB"
        threat_id = "2147896900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 8b f0 8b f0 33 db 33 f6 33 f6 8b de 8b db 33 f3 80 07 ?? 8b c0 8b c0 33 c6 8b f0 8b f6 33 f6 8b db 8b f6 33 c3 f6 2f 47 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_AMBH_2147897647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.AMBH!MTB"
        threat_id = "2147897647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 ec 31 45 fc 33 55 fc 89 55 ec 8b 45 ec 83 45 f4 64 29 45 f4 83 6d f4 64 83 3d ?? ?? ?? ?? 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_AMBH_2147897647_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.AMBH!MTB"
        threat_id = "2147897647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d f4 8b 45 ec 31 45 fc d3 ee 03 75 d8 81 3d ?? ?? ?? ?? 03 0b 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = "Lewipadomunifuc hihokeyilo fex" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_AMBH_2147897647_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.AMBH!MTB"
        threat_id = "2147897647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 74 24 1c 8b 44 24 2c 01 44 24 1c 8b 44 24 10 33 44 24 1c 89 44 24 1c 8b 54 24 1c 89 54 24 1c 8b 44 24 1c 29 44 24 14 8b 4c 24 14 8b c1 c1 e0 04 03 44 24 30 81 3d ?? ?? ?? ?? be 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 28 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 54 24 18 89 54 24 18 8b 44 24 18 29 44 24 14 8b 4c 24 14 8b c1 c1 e0 04 03 44 24 2c 81 3d ?? ?? ?? ?? be 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Stealerc_GAA_2147898263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.GAA!MTB"
        threat_id = "2147898263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 20 69 f6 ?? ?? ?? ?? 69 0c b8 ?? ?? ?? ?? 47 8b c1 c1 e8 18 33 c1 69 c8 ?? ?? ?? ?? 8b 44 24 2c 33 f1 3b f8 7c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_GAB_2147898279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.GAB!MTB"
        threat_id = "2147898279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 f9 02 33 c1 0f b7 15 ?? ?? ?? ?? c1 fa 03 33 c2 0f b7 0d ?? ?? ?? ?? c1 f9 05 33 c1 83 e0 01 a3 ?? ?? ?? ?? 0f b7 15 ?? ?? ?? ?? d1 fa a1 ?? ?? ?? ?? c1 e0 0f 0b d0 66 89 15 ?? ?? ?? ?? 0f b7 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_AMMB_2147904677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.AMMB!MTB"
        threat_id = "2147904677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://185.172.128.90/cpa/ping.php" wide //weight: 2
        $x_2_2 = "/SILENT" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_RP_2147906315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.RP!MTB"
        threat_id = "2147906315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 3d cb d9 0b 00 75 06 81 c1 ?? ?? 00 00 40 3d 3d a6 15 00 7c eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_RP_2147906315_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.RP!MTB"
        threat_id = "2147906315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 8c 38 4b 13 01 00 a1 ?? ?? ?? ?? 88 0c 38 8b 0d ?? ?? ?? ?? 81 f9 ?? 04 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_RP_2147906315_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.RP!MTB"
        threat_id = "2147906315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 01 44 24 10 8b 54 24 10 8a 04 32 8b 0d ?? ?? ?? ?? 88 04 31 81 3d ?? ?? ?? ?? ?? ?? 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_RP_2147906315_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.RP!MTB"
        threat_id = "2147906315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 57 ff 15 7c a0 41 00 ff 15 14 a0 41 00 57 ff 15 a4 a0 41 00 81 fe ?? ?? ?? 00 7f 09 46 81 fe ?? ?? ?? 00 7c da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_RP_2147906315_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.RP!MTB"
        threat_id = "2147906315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 08 ba 61 2a 07 c7 44 24 20 9c 16 00 48 c7 44 24 10 4d 4f 3f 0a c7 44 24 18 da 50 d8 1b c7 44 24 0c ca b6 35 54 c7 44 24 24 65 58 8c 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_RP_2147906315_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.RP!MTB"
        threat_id = "2147906315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 61 2a 07 [0-4] 9c 16 00 48 [0-4] 4d 4f 3f 0a [0-4] da 50 d8 1b [0-4] ca b6 35 54 [0-4] 65 58 8c 69 [0-4] 52 8b 07 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_RP_2147906315_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.RP!MTB"
        threat_id = "2147906315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xajipixukujujevomiragivilup" ascii //weight: 1
        $x_1_2 = "sotaxonovigazo" ascii //weight: 1
        $x_1_3 = "Xiyuf" ascii //weight: 1
        $x_1_4 = "besohakexuxak" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_RP_2147906315_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.RP!MTB"
        threat_id = "2147906315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 0c ba 61 2a 07 c7 44 24 24 9c 16 00 48 c7 44 24 14 4d 4f 3f 0a c7 44 24 1c da 50 d8 1b c7 44 24 10 ca b6 35 54 c7 44 24 28 65 58 8c 69 c7 44 24 5c 52 8b 07 25 c7 44 24 58 50 b5 81 09 c7 44 24 34 8e 34 a6 6e c7 44 24 30 52 f3 6c 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_RP_2147906315_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.RP!MTB"
        threat_id = "2147906315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DgasyudguygiuxHIA" ascii //weight: 1
        $x_1_2 = "XcPUCXlXkRnyAdQ" ascii //weight: 1
        $x_1_3 = "ZtrbobDfRVDVSYJDbiTjJYMtnApmznZIIGm" ascii //weight: 1
        $x_1_4 = "dYuVXzkLLVWbcxpNkzwMQNycwFrMShzJDdw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_RP_2147906315_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.RP!MTB"
        threat_id = "2147906315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sicop ruhi kiteGJotosukamuhi" wide //weight: 1
        $x_1_2 = "osojigowam lavosuziga tinolihahuro" wide //weight: 1
        $x_1_3 = "vigivemiyiyic9Fiwacixi xegizezibeneki" wide //weight: 1
        $x_1_4 = "Feyixafufab dozameceyowanu dig gogapiwek liwibumewabuya" wide //weight: 1
        $x_1_5 = "Juzajimosoyezo" wide //weight: 1
        $x_1_6 = "fakohahukojobebizifogufefufir" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Stealerc_ZA_2147908532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.ZA!MTB"
        threat_id = "2147908532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0d ec d9 45 00 69 c9 fd 43 03 00 81 c1 c3 9e 26 00 89 0d ec d9 45 00 8a 15 ee d9 45 00 30 14 1e 83 ff 0f 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_ZB_2147908623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.ZB!MTB"
        threat_id = "2147908623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 14 1e 83 ff 0f}  //weight: 1, accuracy: High
        $x_1_2 = {46 3b f7 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_AMMH_2147909693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.AMMH!MTB"
        threat_id = "2147909693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 14 30 83 bc 24 ?? ?? ?? ?? 0f 75 ?? 6a 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {33 db 33 4d [0-20] 33 c1 [0-20] 81 f9 13 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Stealerc_AMMF_2147911245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.AMMF!MTB"
        threat_id = "2147911245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 83 fe 0a 7c ?? 8b 44 24 ?? 8d 4c 24 ?? 8a 44 04 ?? 30 04 2f e8 ?? ?? ?? ?? 8b 54 24 ?? 47 3b bc 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_AMAG_2147913660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.AMAG!MTB"
        threat_id = "2147913660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 0f b6 c0 0f b6 44 04 ?? 30 81 ?? ?? ?? ?? 41 89 4c 24 ?? 81 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_AMAI_2147913845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.AMAI!MTB"
        threat_id = "2147913845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 0f b6 44 3c ?? 88 44 34 ?? 88 4c 3c ?? 0f b6 44 34 ?? 03 c2 0f b6 c0 0f b6 44 04 ?? 30 83 ?? ?? ?? ?? 43 81 fb ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_PAFL_2147919661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.PAFL!MTB"
        threat_id = "2147919661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 65 fc 00 8d 75 fc e8 ?? ?? ?? ?? 8b 45 08 8a 4d fc 30 0c 38 47 3b fb 7c e6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealerc_APFA_2147927998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealerc.APFA!MTB"
        threat_id = "2147927998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 75 fc 89 75 dc 8b 45 dc 29 45 f8 81 c7 47 86 c8 61 83 6d ?? 01 0f 85}  //weight: 3, accuracy: Low
        $x_2_2 = {8b c3 c1 e8 05 89 45 fc 8b 45 e8 01 45 fc 8b f3 c1 e6 04 03 75 ec 8d 0c 1f 33 f1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

