rule Trojan_Win32_BunituCrypt_KMG_2147773064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.KMG!MTB"
        threat_id = "2147773064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b 85 ?? ?? ?? ?? 03 f8 8b 85 ?? ?? ?? ?? 03 c6 33 f8 31 7d ?? 33 ff 81 3d ?? ?? ?? ?? e6 06 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_GKM_2147774290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.GKM!MTB"
        threat_id = "2147774290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 7a 14 00 00 6a 00 e8 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_GKM_2147774290_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.GKM!MTB"
        threat_id = "2147774290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_GKM_2147774290_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.GKM!MTB"
        threat_id = "2147774290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 8b 45 ?? 05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 6a 00 e8 ?? ?? ?? ?? 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_GKM_2147774290_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.GKM!MTB"
        threat_id = "2147774290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_GKM_2147774290_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.GKM!MTB"
        threat_id = "2147774290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 45 ?? 03 d8 68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_GKM_2147774290_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.GKM!MTB"
        threat_id = "2147774290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 45 ?? 03 d8 68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_GKM_2147774290_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.GKM!MTB"
        threat_id = "2147774290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 8b 55 ?? 8b 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 3b 45 ?? 73 ?? 8b 55 ?? 03 55 ?? 8b 45 ?? 03 45 ?? 8b 4d ?? e8 ?? ?? ?? ?? 68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 45 ?? 01 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 01 45 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RBE_2147775138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RBE!MTB"
        threat_id = "2147775138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_DLL_2147776604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.DLL!MTB"
        threat_id = "2147776604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 4f 0c 00 00 6a 00 e8 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RF_2147776783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RF!MTB"
        threat_id = "2147776783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 31 0c 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 8b 15 ?? ?? ?? ?? 81 c2 8a a5 08 00 03 15 ?? ?? ?? ?? 33 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RF_2147776783_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RF!MTB"
        threat_id = "2147776783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 18 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 72 ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RF_2147776783_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RF!MTB"
        threat_id = "2147776783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 ?? e8 [0-14] a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 01 10 a1 [0-22] 31 02 83 05 ?? ?? ?? ?? 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RF_2147776783_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RF!MTB"
        threat_id = "2147776783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 10 33 c0 [0-10] 8b d8 [0-5] 83 c0 04 [0-10] 2b d8 01 [0-10] 83 c0 04}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 10 00 00 [0-5] 83 45 ec 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RF_2147776783_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RF!MTB"
        threat_id = "2147776783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 c7 [0-5] 0e 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 10 00 00 83 c0 04 70 00 [0-32] 31 [0-10] 04 [0-10] 04 [0-55] a1 [0-9] 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RF_2147776783_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RF!MTB"
        threat_id = "2147776783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 ?? 6a [0-30] e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 01 10 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RF_2147776783_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RF!MTB"
        threat_id = "2147776783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 a1 [0-23] 2b d8 a1 ?? ?? ?? ?? 89 18 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 83 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RF_2147776783_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RF!MTB"
        threat_id = "2147776783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 00 03 05 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 89 18 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RF_2147776783_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RF!MTB"
        threat_id = "2147776783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 0f 83 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 55 ?? 01 10 8b 45 ?? 03 45 ?? 03 45 ?? 8b 15 ?? ?? ?? ?? 31 02 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RF_2147776783_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RF!MTB"
        threat_id = "2147776783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 68 74 2d 4b 00 e8 ?? ?? ?? ?? 68 74 2d 4b 00 e8 ?? ?? ?? ?? 68 74 2d 4b 00 e8 ?? ?? ?? ?? 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RF_2147776783_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RF!MTB"
        threat_id = "2147776783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 01 5d ?? 8b ?? ?? 01 ?? ?? eb ?? 8b ?? ?? 3b ?? ?? 73 ?? 8b ?? ?? 8b ?? ?? 01 02 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b ?? ?? 03 ?? ?? 03 ?? ?? 8b ?? ?? 31 02 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RF_2147776783_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RF!MTB"
        threat_id = "2147776783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 68 2e 16 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 31 18 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 05 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {05 8a a5 08 00 03 45 ?? 03 d8 68 2e 16 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RTU_2147776816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RTU!MTB"
        threat_id = "2147776816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 5a 16 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 8b 15 ?? ?? ?? ?? 81 c2 8a a5 08 00 03 55 ?? 33 c2 03 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 c7 [0-14] 6a}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 0f}  //weight: 2, accuracy: Low
        $x_1_2 = {03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 18 33 c0 89 45 ?? 8b 45 ?? 83 c0 04 01 45 ?? 8b 45 ?? 83 c0 04}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 33 05 [0-20] 8b 15 [0-26] 83 [0-10] 04 83 [0-10] 04 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f [0-25] 2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 [0-10] e3 14 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d8 8b 45 ?? 31 18 83 45 ?? 04 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 8b 45 ?? 89 18 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 8d 85 ?? ?? ?? ?? 33 c9 ba 3c 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 0f ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 01 10 a1 ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 31 02 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 18 89 1d ?? ?? ?? ?? 6a 00 [0-50] a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 6a 00 [0-10] 83 c3 04}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 10 00 00 [0-20] 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 10 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 10 00 00 [0-10] 83 05 [0-5] 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 02 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 ?? ?? ?? ?? c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 18 8b 45 ?? 05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 [0-10] 8a a5 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = {89 18 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 6a 00 e8 ?? ?? ?? ?? 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 02 83 05 ?? ?? ?? ?? 04 83 ?? ?? ?? ?? ?? 04 6a [0-5] e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 72 [0-4] a1 ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? 2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 18 89 5d ?? 8b 45 ?? 8b 55 ?? 89 10 6a 01 e8 ?? ?? ?? ?? 8b d8 83 c3 04}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 10 00 00 [0-5] 83 45 [0-5] 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 b0 8a a5 08 00 [0-8] 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 6a 00 e8 ?? ?? ?? ?? 8b d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 10 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 ?? 8b 45 ?? 03 45 ?? 2d 00 10 00 00 [0-5] 83 45 [0-5] 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 33 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 6a 0c e8 ?? ?? ?? ?? 8b d8 83 c3 04}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 10 00 00 [0-10] 83 [0-5] 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 73}  //weight: 5, accuracy: Low
        $x_1_2 = {31 02 83 05 ?? ?? ?? ?? 04 83 ?? ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 72 ?? a1 ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? 2d 00 10 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {31 02 83 05 ?? ?? ?? ?? 04 e8 ?? ?? ?? ?? 8b d8 83 c3 04 e8 ?? ?? ?? ?? 2b d8 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 0f 83}  //weight: 1, accuracy: Low
        $x_1_2 = {10 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_21
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 6a ?? e8 ?? ?? ?? ?? 8b d8 83 c3 04}  //weight: 1, accuracy: Low
        $x_1_2 = {8a a5 08 00 33 c0 89 ?? ?? 33 c0 89 ?? ?? 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_22
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73}  //weight: 1, accuracy: Low
        $x_1_2 = {31 18 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 00 e8 ?? ?? ?? ?? 2b d8 01 1d ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_23
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 45 ?? 05 8a a5 08 00 03 45 ?? 03 d8 68 61 1e 00 00 6a}  //weight: 1, accuracy: Low
        $x_1_2 = {68 61 1e 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_24
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 4f 0c 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 4f 0c 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18}  //weight: 1, accuracy: Low
        $x_1_2 = {89 18 68 4f 0c 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 8b 45 ?? 05 8a a5 08 00 03 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_25
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 ?? 6a}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 00 03 05 ?? ?? ?? ?? 03 d8 6a ?? e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 89 18 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_26
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 00 03 05 ?? ?? ?? ?? 03 d8 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 89 18 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 d8 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_27
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 73}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 6a ?? e8 ?? ?? ?? ?? 2b d8 8b 45 ?? 31 18 83 ?? ?? 04 83 ?? ?? 04 8b ?? ?? 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_28
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a a5 08 00 8b ?? ?? 3b ?? ?? 0f}  //weight: 5, accuracy: Low
        $x_1_2 = {2b d8 8b 45 ?? 89 18 8b ?? ?? 03 ?? ?? 03 ?? ?? 8b ?? ?? 31 02 83 ?? ?? 04 83 ?? ?? 04}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d8 8b 45 ?? 03 ?? ?? 03 ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b ?? ?? 31 18 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BunituCrypt_RM_2147776981_29
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RM!MTB"
        threat_id = "2147776981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f}  //weight: 5, accuracy: Low
        $x_1_2 = {8b d8 83 c3 04 e8 ?? ?? ?? ?? 2b d8 01 1d ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 0e 00 2b d8 a1 ?? ?? ?? ?? 31 18 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d8 83 c3 04 e8 ?? ?? ?? ?? 2b d8 15 00 03 d8 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BunituCrypt_RTH_2147779171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RTH!MTB"
        threat_id = "2147779171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 10 33 c0 [0-20] 83 c0 04 01 [0-20] 83 c0 04}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RTH_2147779171_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RTH!MTB"
        threat_id = "2147779171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 10 8b 45 ?? 03 45 ?? 03 45 ?? 8b 15 ?? ?? ?? ?? 31 02 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RTH_2147779171_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RTH!MTB"
        threat_id = "2147779171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 ?? 6a [0-30] a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 01 02 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RTH_2147779171_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RTH!MTB"
        threat_id = "2147779171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 6a ?? e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 a1}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RTH_2147779171_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RTH!MTB"
        threat_id = "2147779171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 8b 45 ?? 3b 45 ?? 73 ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {89 18 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RTH_2147779171_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RTH!MTB"
        threat_id = "2147779171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d8 01 5d ?? 8b 45 ?? 01 45 ?? eb ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RTH_2147779171_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RTH!MTB"
        threat_id = "2147779171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? 8b 45 ?? 3b 05 ?? ?? ?? ?? 73 ?? a1 ?? ?? ?? ?? 8b 55 ?? 01 10 a1 ?? ?? ?? ?? 05 8a a5 08 00 03 45 ?? 8b 15 ?? ?? ?? ?? 31 02 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RTH_2147779171_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RTH!MTB"
        threat_id = "2147779171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a a5 08 00 [0-9] 0e 00 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {31 02 83 45 [0-5] 04 83 [0-5] 04 [0-10] 0f [0-18] 2d 00 10 00 00 ?? ?? 04}  //weight: 1, accuracy: Low
        $x_1_3 = {31 02 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 00 e8 ?? ?? ?? ?? 2b d8 01 5d e4 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BunituCrypt_RTH_2147779171_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RTH!MTB"
        threat_id = "2147779171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 8b 15 ?? ?? ?? ?? 03 55 ?? 03 55 ?? 33 c2 03 d8 68 d7 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 d7 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 d7 11 00 00 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d8 68 d7 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 d7 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 89 18 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RT_2147779782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RT!MTB"
        threat_id = "2147779782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 7c 30 00 00 03 45 ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RT_2147779782_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RT!MTB"
        threat_id = "2147779782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 0e 00 00 03 [0-12] e8 ?? ?? ?? ?? 2b [0-8] a1 ?? ?? ?? ?? 31 18 83 [0-5] 04 83 [0-5] 04 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RT_2147779782_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RT!MTB"
        threat_id = "2147779782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 7c 30 00 00 03 05 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 6a 00 e8 ?? ?? ?? ?? 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RT_2147779782_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RT!MTB"
        threat_id = "2147779782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 02 83 05 ?? ?? ?? ?? 04 83 ?? ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 0f ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? 2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RT_2147779782_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RT!MTB"
        threat_id = "2147779782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 18 89 5d ?? 8b 45 ?? 8b 55 ?? 89 10 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RT_2147779782_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RT!MTB"
        threat_id = "2147779782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 01 10 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RT_2147779782_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RT!MTB"
        threat_id = "2147779782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 00 10 00 00 83 c0 04 a3}  //weight: 1, accuracy: High
        $x_1_2 = {8b d8 83 c3 04 e8 ?? ?? ?? ?? 2b d8 01 1d ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 83 c3 04 e8 ?? ?? ?? ?? 2b d8 01 ?? ?? ?? ?? ?? 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RT_2147779782_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RT!MTB"
        threat_id = "2147779782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 00 e8 ?? ?? ?? ?? 2b d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RT_2147779782_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RT!MTB"
        threat_id = "2147779782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 73}  //weight: 2, accuracy: Low
        $x_2_2 = {2b d8 03 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 18 a1 ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 31 02 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RT_2147779782_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RT!MTB"
        threat_id = "2147779782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 ec 31 18 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 8b 45 ?? 05 8a a5 08 00 03 45 ?? 03 d8 68 ?? ?? ?? ?? 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RT_2147779782_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RT!MTB"
        threat_id = "2147779782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 67 2b 00 00 03 ?? ?? 8b ?? ?? 31 02 83 ?? ?? 04 83 ?? ?? 04 [0-10] 72}  //weight: 1, accuracy: Low
        $x_1_2 = {2d f2 05 00 00 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45 ?? 04 8b 45 a0 99}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_BunituCrypt_RT_2147779782_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RT!MTB"
        threat_id = "2147779782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 [0-5] 0e 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {31 02 83 45 ?? 04 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 00 e8 ?? ?? ?? ?? 2b d8 01 ?? ?? 8b ?? ?? 3b ?? ?? 0f [0-20] 2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RT_2147779782_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RT!MTB"
        threat_id = "2147779782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 c7 ?? ?? e3 14 00 00 c7 ?? ?? 9f 0a 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 89 45 ?? 8b 45 ?? 8b 55 ?? 01 10 8b 45 ?? 03 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RT_2147779782_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RT!MTB"
        threat_id = "2147779782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 68 4f 0c 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 8b 45 ?? 05 8a a5 08 00 03 45 ?? 03 d8 68 4f 0c 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 4f 0c 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d8 68 4f 0c 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 4f 0c 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ?? 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunituCrypt_RT_2147779782_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RT!MTB"
        threat_id = "2147779782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 [0-5] 0e 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {31 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 ?? 8b 45 ?? 03 45 ?? 2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: Low
        $x_1_3 = {31 18 83 45 ?? 04 83 45 ?? 04 8b [0-5] 3b [0-5] 0f [0-25] 2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_BunituCrypt_RT_2147779782_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunituCrypt.RT!MTB"
        threat_id = "2147779782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunituCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f}  //weight: 5, accuracy: Low
        $x_1_2 = {31 02 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 00 e8 ?? ?? ?? ?? 2b d8}  //weight: 1, accuracy: Low
        $x_1_3 = {31 18 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 00 e8 ?? ?? ?? ?? 2b d8}  //weight: 1, accuracy: Low
        $x_1_4 = {03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 83 ?? ?? ?? ?? ?? 04 83 ?? ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

