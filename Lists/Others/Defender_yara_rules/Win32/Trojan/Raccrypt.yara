rule Trojan_Win32_Raccrypt_GQ_2147787294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GQ!MTB"
        threat_id = "2147787294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? [0-4] 8b 4c 24 ?? 33 ?? 24 ?? 03 4c 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GQ_2147787294_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GQ!MTB"
        threat_id = "2147787294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 0c 02 40 3b 05}  //weight: 1, accuracy: High
        $x_10_2 = {03 c8 c1 e8 05 89 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b 55 ?? 33 d1 33 d3 8d 8d ?? ?? ?? ?? 89 55 ?? 29 11 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GQ_2147787294_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GQ!MTB"
        threat_id = "2147787294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f0 2c cb 49 c7 [0-5] b9 61 c2 1b c7 [0-5] 13 f9 47 7a c7 [0-5] 21 47 ef 5f c7 [0-5] a9 4e 9a 0f c7 [0-5] 0c 04 b3 5e}  //weight: 1, accuracy: Low
        $x_1_2 = {a4 94 77 17 c7 [0-5] a3 af d2 0e c7 [0-5] 8f 06 8d 6a c7 [0-5] 5d 9f f4 68 c7 [0-5] 72 83 38 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GQ_2147787294_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GQ!MTB"
        threat_id = "2147787294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b4 21 e1 c5 [0-6] c7 05 ?? ?? ?? ?? ff ff ff ff [0-10] 55 8b ec 8b 45 08 8b 4d 0c 31 08 5d c2 08 00}  //weight: 10, accuracy: Low
        $x_10_2 = {b4 21 e1 c5 [0-6] c7 05 ?? ?? ?? ?? ff ff ff ff [0-5] e8 ?? ?? ?? ?? 8b [0-3] 29 [0-5] 81 ?? 47 86 c8 61 ff [0-5] 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GQ_2147787294_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GQ!MTB"
        threat_id = "2147787294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 9b c6 a0 04 8b [0-20] c1 ?? 04 03 [0-30] c1 ?? 05 03 [0-15] 31}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 9b c6 a0 04 8b [0-20] c1 ?? 05 03 [0-30] c1 ?? 04 03 [0-15] 31}  //weight: 1, accuracy: Low
        $x_1_3 = {bb 9b c6 a0 04 8b [0-20] c1 ?? 05 89 [0-30] c1 ?? 04 03 [0-15] 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GQ_2147787294_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GQ!MTB"
        threat_id = "2147787294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 b3 6c 68 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 32 88 1d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 6b c6 05 ?? ?? ?? ?? 65 88 1d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 88 1d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {b0 74 88 1d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 6f a2 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 63 a2 ?? ?? ?? ?? a2 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GQ_2147787294_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GQ!MTB"
        threat_id = "2147787294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b4 21 e1 c5 [0-13] c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 05 [0-15] c7 05 [0-30] 02 01 01 31 33}  //weight: 1, accuracy: Low
        $x_1_2 = {b4 21 e1 c5 [0-13] c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 04 [0-15] c7 05 [0-30] 02 01 01 31 33}  //weight: 1, accuracy: Low
        $x_1_3 = {b4 21 e1 c5 [0-13] c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 05 [0-15] c7 05 1e 00 02 01 01 31 33}  //weight: 1, accuracy: Low
        $x_1_4 = {b4 21 e1 c5 [0-13] c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 04 [0-15] c7 05 1e 00 02 01 01 31 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GQ_2147787294_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GQ!MTB"
        threat_id = "2147787294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b4 21 e1 c5 [0-13] c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 05 03 [0-15] 02 01 01 31 33 [0-20] c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {b4 21 e1 c5 [0-13] c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 04 03 [0-15] 02 01 01 31 33 [0-20] c7 05}  //weight: 1, accuracy: Low
        $x_1_3 = {b4 21 e1 c5 [0-13] c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 05 03 0f 00 02 01 01 31 33 [0-20] c7 05}  //weight: 1, accuracy: Low
        $x_1_4 = {b4 21 e1 c5 [0-13] c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 04 03 0f 00 02 01 01 31 33 [0-20] c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GR_2147787785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GR!MTB"
        threat_id = "2147787785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b4 21 e1 c5 [0-5] e8 ?? ?? ?? ?? 8b [0-3] 29 [0-5] 81 [0-2] 47 86 c8 61 ff [0-5] 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GR_2147787785_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GR!MTB"
        threat_id = "2147787785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 9b c6 a0 04 8b [0-20] c1 ?? 04 [0-30] c1 ?? 05 03 [0-15] 02 01 01 31 33}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 9b c6 a0 04 8b [0-20] c1 ?? 05 03 [0-30] c1 ?? 04 [0-15] 02 01 01 31 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GR_2147787785_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GR!MTB"
        threat_id = "2147787785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 02 88 01 8b e5 5d c2}  //weight: 1, accuracy: High
        $x_10_2 = {d3 ea 89 55 ?? 8b 45 ?? 50 8d 4d ?? 51 e8 [0-4] 8b 55 ?? 33 55 ?? 89 55 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 50 8d 4d ?? 51 e8 [0-4] 8b 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GR_2147787785_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GR!MTB"
        threat_id = "2147787785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 56 8b f0 33 74 24 0c 8b 44 24 08 89 30 5e c2 08 00 81 00 a4 36 ef c6 c3}  //weight: 10, accuracy: Low
        $x_5_2 = {33 74 24 0c 8b 44 24 08 89 30 5e c2 08 00 81 00 a4 36 ef c6 c3}  //weight: 5, accuracy: High
        $x_5_3 = {25 bb 52 c0 5d 8b [0-2] 8b [0-4] c1 ?? 04 03 [0-6] 33 [0-8] c1 [0-1] 05 03}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Raccrypt_GR_2147787785_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GR!MTB"
        threat_id = "2147787785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 00 6c 00 [0-6] ff 15 46 00 57 66 [0-6] c7 05 ?? ?? ?? ?? 2e 00 64 00 c7 05 ?? ?? ?? ?? 72 00 6e 00 c7 05 ?? ?? ?? ?? 33 00 32 00 c7 05 ?? ?? ?? ?? 6b 00 65 00 c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 c7 05 ?? ?? ?? ?? 64 00 6c 00 c7 05 ?? ?? ?? ?? 65 00 6c 00 c7 05 ?? ?? ?? ?? 65 00 72 00 [0-13] ff 15 46 00 6c 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GR_2147787785_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GR!MTB"
        threat_id = "2147787785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 9b c6 a0 04 8b [0-20] c1 ?? 04 03 [0-30] c1 ?? 05 03 0f 00 02 01 01 31 33}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 9b c6 a0 04 8b [0-20] c1 ?? 05 03 [0-30] c1 ?? 04 03 0f 00 02 01 01 31 33}  //weight: 1, accuracy: Low
        $x_1_3 = {bb 9b c6 a0 04 8b [0-20] c1 ?? 05 89 [0-30] c1 ?? 04 03 0f 00 02 01 01 31 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GR_2147787785_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GR!MTB"
        threat_id = "2147787785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-30] c1 ?? 05 03 [0-15] 33 ?? 33}  //weight: 1, accuracy: Low
        $x_1_2 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-30] c1 ?? 05 03 [0-15] 31 ?? 31}  //weight: 1, accuracy: Low
        $x_1_3 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-30] c1 ?? 05 03 0f 00 33 ?? 33}  //weight: 1, accuracy: Low
        $x_1_4 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-30] c1 ?? 05 03 0f 00 31 ?? 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GS_2147788143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GS!MTB"
        threat_id = "2147788143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 45 08 8b 45 08 c9 c2 08 00 81 00 eb 34 ef c6 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GS_2147788143_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GS!MTB"
        threat_id = "2147788143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 0c 32 83 3d ?? ?? ?? ?? 33}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 31 81 bc 24 ?? ?? ?? ?? 91 05 00 00 46 3b b4 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GS_2147788143_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GS!MTB"
        threat_id = "2147788143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 89 1a 60 c7 44 24 ?? b8 38 69 0e c7 44 24 ?? 7d 00 8d 51 c7 44 24 ?? d2 fb 1a 43 c7 44 24 ?? 2c 31 1b 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GS_2147788143_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GS!MTB"
        threat_id = "2147788143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 23 01 00 8b 0d [0-4] 88 04 0f 81 3d [0-4] 66 0c 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 04 8b 4c 24 08 31 08 c2 08 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 44 24 08 8b 4c 24 04 c1 e0 04 89 01 c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GS_2147788143_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GS!MTB"
        threat_id = "2147788143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 72 00 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 72 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GS_2147788143_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GS!MTB"
        threat_id = "2147788143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 f8 40 00 00 00 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 7c c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
        $x_1_2 = "kernel32.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GS_2147788143_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GS!MTB"
        threat_id = "2147788143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 81 ec ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 88 c6 05 ?? ?? ?? ?? 79 c6 05 ?? ?? ?? ?? 92 c6 05 ?? ?? ?? ?? 6a 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? c7 85}  //weight: 10, accuracy: Low
        $x_2_2 = {b8 36 23 01 00 01 45 fc 8b [0-5] 03 ?? 08 8b ?? fc 03 ?? 08 8a ?? 88 ?? 8b ?? 5d c2 04 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Raccrypt_GT_2147793918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GT!MTB"
        threat_id = "2147793918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? [0-4] 8b ?? 24 ?? 33 ?? 24 ?? 03 ?? 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GT_2147793918_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GT!MTB"
        threat_id = "2147793918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 0a 81 bc 24 ?? ?? ?? ?? 91 05 00 00 41 3b 8c 24 ?? ?? ?? ?? 89 4c 24 ?? 0f 8c}  //weight: 1, accuracy: Low
        $x_1_2 = {91 05 00 00 75 56 14 00 8b 4c 24 ?? 30 04 ?? 81 bc 24 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GT_2147793918_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GT!MTB"
        threat_id = "2147793918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 72 00 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 72 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GT_2147793918_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GT!MTB"
        threat_id = "2147793918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 2d 0b 00 8b 0d ?? ?? ?? ?? 88 04 ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {25 bb 52 c0 5d 8b [0-6] 8b [0-4] c1 ?? 04 03 [0-8] c1 [0-1] 05 03 [0-40] 8b 45 ?? 29 45 ?? 81 ?? 47 86 c8 61 [0-5] 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {33 44 24 04 c2 04 00 81 00 a4 36 ef c6 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Raccrypt_GT_2147793918_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GT!MTB"
        threat_id = "2147793918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e aa cd 04 c7 [0-5] d2 a3 3a 6a c7 [0-5] 68 3f 01 6b c7 [0-5] 3f 5d 8e 10 c7 [0-5] 5b fd 46 4a c7 [0-5] d7 99 ac 7c c7 [0-5] b5 0d 96 5f c7 [0-5] b3 6b 51 02 c7 [0-5] 65 51 93 0b c7 [0-5] 8b 68 36 7d c7 [0-5] 32 a9 23 7a c7 [0-5] 00 2b 5a 11 c7 [0-5] b9 af 00 62 c7 [0-5] 4e 0b 44 74 c7 [0-5] 12 65 93 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GT_2147793918_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GT!MTB"
        threat_id = "2147793918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {47 00 65 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
        $x_2_2 = "kernel32.dll" wide //weight: 2
        $x_2_3 = {b8 36 23 01 00 01 45 ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 8b 45 ?? 03 45 ?? 8a 08 88 0a 8b e5 5d c2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Raccrypt_GT_2147793918_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GT!MTB"
        threat_id = "2147793918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-30] c1 ?? 05 03 [0-20] 33}  //weight: 1, accuracy: Low
        $x_1_2 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-30] c1 ?? 05 03 [0-20] 31}  //weight: 1, accuracy: Low
        $x_1_3 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-30] c1 ?? 05 03 14 00 33}  //weight: 1, accuracy: Low
        $x_1_4 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-30] c1 ?? 05 03 14 00 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GT_2147793918_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GT!MTB"
        threat_id = "2147793918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-30] c1 ?? 05 89 [0-40] 33}  //weight: 1, accuracy: Low
        $x_1_2 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-30] c1 ?? 05 89 [0-40] 31}  //weight: 1, accuracy: Low
        $x_1_3 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-30] c1 ?? 05 89 28 00 33}  //weight: 1, accuracy: Low
        $x_1_4 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-30] c1 ?? 05 89 28 00 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GT_2147793918_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GT!MTB"
        threat_id = "2147793918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {65 63 c6 05 ?? ?? ?? ?? 74 66 c7 05 ?? ?? ?? ?? 61 6c c6 05 ?? ?? ?? ?? 74 66 c7 05 ?? ?? ?? ?? 72 74 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 69 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 44 24 04 8b 4c 24 08 31 08 c2 08 00 8b 44 24 04 8b 4c 24 08 01 08 c2 08 00 8b 44 24 08 8b 4c 24 04 c1 e0 04 89 01 c2 08 00}  //weight: 10, accuracy: High
        $x_10_3 = {b4 21 e1 c5 [0-5] e8 ?? ?? ?? ?? 8b [0-3] 29 [0-5] 81 [0-2] 47 86 c8 61 ff [0-5] 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GU_2147794080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GU!MTB"
        threat_id = "2147794080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 04 31 83 3d ?? ?? ?? ?? 33 46 3b 35}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 31 81 bc 24 ?? ?? ?? ?? 91 05 00 00 46 3b b4 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GU_2147794080_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GU!MTB"
        threat_id = "2147794080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 bb 52 c0 5d 8b [0-6] 8b [0-4] c1 ?? 04 03 [0-30] c1 [0-1] 05 03 [0-40] 8b 45 ?? 29 45 ?? 81 ?? 47 86 c8 61 [0-5] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GU_2147794080_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GU!MTB"
        threat_id = "2147794080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 6a 40 ff 35 82 00 6c c6 05 ?? ?? ?? ?? 6c [0-6] c6 05 ?? ?? ?? ?? 6b c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 33 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GU_2147794080_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GU!MTB"
        threat_id = "2147794080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 65 00 00 00 66 a3 ?? ?? ?? ?? b8 6c 00 00 00 8b c8 66 89 0d ?? ?? ?? ?? b9 72 00 00 00 66 89 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 66 a3 ?? ?? ?? ?? a3 ?? ?? ?? ?? 51 b8 6b 00 00 00 6a 00 c7 05 ?? ?? ?? ?? 33 00 32 00 c7 05 ?? ?? ?? ?? 2e 00 64 00 c7 05 ?? ?? ?? ?? 6e 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GU_2147794080_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GU!MTB"
        threat_id = "2147794080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 81 fa ?? ?? ?? ?? 8b 45 ?? 8b 4d ?? 03 c6 33 c8 31 4d ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
        $x_2_2 = {03 c3 50 8b c3 d3 e0 03 45 ?? e8}  //weight: 2, accuracy: Low
        $x_2_3 = "fudkagata" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GY_2147794719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GY!MTB"
        threat_id = "2147794719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 bb 52 c0 5d 8b [0-10] c1 ?? 04 03 [0-25] c1 [0-1] 05 03 [0-10] 02 01 01 31 33 [0-20] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GY_2147794719_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GY!MTB"
        threat_id = "2147794719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8f fb 24 5e c7 85 ?? ?? ?? ?? 76 96 cc 13 c7 85 ?? ?? ?? ?? 68 e3 5c 14 c7 85 ?? ?? ?? ?? aa e4 a4 53 c7 85 ?? ?? ?? ?? cc 54 04 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GY_2147794719_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GY!MTB"
        threat_id = "2147794719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {23 29 9b 47 c7 85 ?? ?? ?? ?? 06 80 e6 6a c7 85 ?? ?? ?? ?? 07 b5 1f 11 c7 85 ?? ?? ?? ?? c8 cc 51 4b c7 85 ?? ?? ?? ?? 82 1b a6 1f c7 85 ?? ?? ?? ?? c9 ba ac 1b c7 85 ?? ?? ?? ?? d6 f7 22 3f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GY_2147794719_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GY!MTB"
        threat_id = "2147794719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 e8 46 32 c7 85 ?? ?? ?? ?? 25 bd b1 77 c7 85 ?? ?? ?? ?? d3 29 2d 6c c7 85 ?? ?? ?? ?? a2 b9 cd 19 c7 85 ?? ?? ?? ?? fb d0 9d 68 c7 85 ?? ?? ?? ?? dc c0 69 54 c7 85 ?? ?? ?? ?? 98 c3 e4 01 c7 85 ?? ?? ?? ?? be 14 4a 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GY_2147794719_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GY!MTB"
        threat_id = "2147794719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec b8 6e 00 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 72 c3 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GY_2147794719_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GY!MTB"
        threat_id = "2147794719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 6a 72 66 a3 ?? ?? ?? ?? 58 6a 6c 66 a3 ?? ?? ?? ?? 58 6a 32 66 a3 ?? ?? ?? ?? 58 6a 2e 66 a3 ?? ?? ?? ?? 58 6a 6e 66 a3 ?? ?? ?? ?? 58 6a 65 66 a3 ?? ?? ?? ?? 58 6a 64 66 a3 ?? ?? ?? ?? 58 6a 33 66 a3 ?? ?? ?? ?? 58 6a 65 66 a3 ?? ?? ?? ?? 58 68 ?? ?? ?? ?? 66 a3 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GY_2147794719_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GY!MTB"
        threat_id = "2147794719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 f8 40 00 00 00 [0-7] c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
        $x_1_2 = "kernel32.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GY_2147794719_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GY!MTB"
        threat_id = "2147794719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 c7 05 ?? ?? ?? ?? 64 00 6c 00 c7 05 ?? ?? ?? ?? 72 00 6e 00 c7 05 ?? ?? ?? ?? 6b 00 65 00 c7 05 ?? ?? ?? ?? 33 00 32 00 c7 05 ?? ?? ?? ?? 6c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {74 00 c7 05 ?? ?? ?? ?? 56 69 72 74 c7 05 ?? ?? ?? ?? 75 61 6c 50 c7 05 ?? ?? ?? ?? 72 6f 74 65 c6 05 ?? ?? ?? ?? 63 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GY_2147794719_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GY!MTB"
        threat_id = "2147794719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6c 66 c7 05 ?? ?? ?? ?? 65 63 c6 05 ?? ?? ?? ?? 74 66 c7 05 ?? ?? ?? ?? 72 74 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 69 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {f6 56 ff 35 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 69 ff 15}  //weight: 10, accuracy: Low
        $x_10_3 = {81 ec 2c 05 00 00 56 c6 05 ?? ?? ?? ?? 6b c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GZ_2147795113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GZ!MTB"
        threat_id = "2147795113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 [0-10] c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 44 24 [0-10] 02 01 01 31 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GZ_2147795113_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GZ!MTB"
        threat_id = "2147795113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 b3 5a 22 c7 45 ?? be a4 bb 7e c7 45 ?? 6a f5 d1 22 c7 45 ?? ce 4d 4a 5f c7 45 ?? 6f e9 1a 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GZ_2147795113_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GZ!MTB"
        threat_id = "2147795113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 f1 1a 2b c7 44 24 ?? f9 0b 2b 23 c7 44 24 ?? 54 d6 ab 00 c7 44 24 ?? d1 f0 0d 7b c7 44 24 ?? 68 17 ab 44}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GZ_2147795113_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GZ!MTB"
        threat_id = "2147795113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f6 56 ff 35 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 69 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GZ_2147795113_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GZ!MTB"
        threat_id = "2147795113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 f8 40 00 00 00 [0-14] c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 63}  //weight: 10, accuracy: Low
        $x_1_2 = "kernel32.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GZ_2147795113_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GZ!MTB"
        threat_id = "2147795113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 6a 72 66 a3 ?? ?? ?? ?? 58 6a 6c 66 a3 [0-15] 58 6a 32 66 a3 ?? ?? ?? ?? 58 6a 2e 66 a3 ?? ?? ?? ?? 58 6a 6e 66 a3 ?? ?? ?? ?? 58 6a 65 66 a3 ?? ?? ?? ?? 58 6a 64 66 a3 ?? ?? ?? ?? 58 6a 33 66 a3 ?? ?? ?? ?? 58 68 ?? ?? ?? ?? 66 a3 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GA_2147795116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GA!MTB"
        threat_id = "2147795116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 ba 6b 00 00 00 6a 00 c7 05 ?? ?? ?? ?? 6e 00 65 00 c7 05 ?? ?? ?? ?? 6c 00 33 00 66 89 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 15 58 00 2e 00 00 00 ?? 72 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GA_2147795116_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GA!MTB"
        threat_id = "2147795116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 40 ff 35 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 75 [0-6] c6 05 ?? ?? ?? ?? 6c [0-7] c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 69}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GA_2147795116_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GA!MTB"
        threat_id = "2147795116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 3b 2d 0b 00 01 45 ?? 8b 45 ?? 8a 04 08 88 04 31 41 3b 0d}  //weight: 10, accuracy: Low
        $x_10_2 = {81 00 47 86 c8 61 c3 c1 e0 04 89 01 c3 31 08 c3 33 44 24 04 c2 04 00 81 00 fe 36 ef c6 c3 01 08 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GA_2147795116_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GA!MTB"
        threat_id = "2147795116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4d fc 51 8c 00 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GA_2147795116_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GA!MTB"
        threat_id = "2147795116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {45 f8 40 00 00 00 c6 05 ?? ?? ?? ?? 7f c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 76 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 65}  //weight: 10, accuracy: Low
        $x_1_2 = "kernel32.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GA_2147795116_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GA!MTB"
        threat_id = "2147795116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {45 00 c6 05 ?? ?? ?? ?? 75 [0-6] c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 69 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {6a 40 ff 35 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 75 [0-6] c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 69 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GA_2147795116_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GA!MTB"
        threat_id = "2147795116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 40 ff 35 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 6f [0-6] c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 72 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 [0-7] c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 6b c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6c ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GB_2147795252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GB!MTB"
        threat_id = "2147795252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 3b 2d 0b 00 01 45 ?? 8b 45 ?? 8a 04 08 88 04 31 41 3b 0d}  //weight: 10, accuracy: Low
        $x_10_2 = {c1 e0 04 89 01 c3 31 08 c3 33 44 24 04 c2 04 00 81 00 fe 36 ef c6 c3 01 08 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GB_2147795252_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GB!MTB"
        threat_id = "2147795252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d}  //weight: 10, accuracy: High
        $x_10_2 = {c1 e0 04 89 01 c3 83 3d ?? ?? ?? ?? 7e 8b 44 24 04 31 06 c2 04 00 33 44 24 04 c2 04 00 81 00 ae 36 ef c6 c3 01 08 c3 29 08 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GB_2147795252_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GB!MTB"
        threat_id = "2147795252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 bb 52 c0 5d 8b [0-10] c1 ?? 04 03 [0-30] c1 [0-1] 05 03 0f 00 02 01 01 31 33 [0-50] 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {89 75 fc 8b 45 10 89 45 fc 8b 45 0c 31 45 fc 8b 45 fc 8b 4d 08 89 01 5e c9 c2 0c 00 81 00 a4 36 ef c6 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GB_2147795252_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GB!MTB"
        threat_id = "2147795252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {19 36 6b ff 5a 00 02 01 01 31 33 [0-45] c1 ?? 04 03 [0-40] c1 ?? 05 [0-15] c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {19 36 6b ff 5a 00 02 01 01 31 33 [0-45] c1 ?? 05 03 [0-40] c1 ?? 04 [0-15] c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GB_2147795252_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GB!MTB"
        threat_id = "2147795252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {19 36 6b ff 32 00 c1 ?? 04 03 [0-40] 02 01 01 31 33 [0-20] c1 ?? 05 03 [0-15] [0-20] c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {19 36 6b ff 32 00 c1 ?? 05 03 [0-40] 02 01 01 31 33 [0-20] c1 ?? 04 03 [0-15] [0-20] c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GB_2147795252_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GB!MTB"
        threat_id = "2147795252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 72 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c 66 c7 05 ?? ?? ?? ?? ?? ?? ff 15 78 00 cc cc 51 68 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 60 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 6f ff 15}  //weight: 10, accuracy: Low
        $x_1_2 = "kernel32.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GB_2147795252_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GB!MTB"
        threat_id = "2147795252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 bb 52 c0 5d 8b [0-10] c1 ?? 04 03 [0-30] c1 ?? 05 03 [0-15] 02 01 01 31 33 [0-50] 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {25 bb 52 c0 5d 83 [0-10] c1 ?? 04 03 [0-30] c1 ?? 05 03 [0-15] 02 01 01 31 33 [0-50] 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {25 bb 52 c0 5d 8b [0-10] c1 ?? 05 89 [0-30] c1 ?? 04 03 [0-15] 02 01 01 31 33 [0-50] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GB_2147795252_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GB!MTB"
        threat_id = "2147795252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 bb 52 c0 5d 8b [0-10] c1 ?? 04 03 [0-30] c1 ?? 05 03 [0-15] 02 01 01 31 33 ?? 02 01 01 31 33}  //weight: 1, accuracy: Low
        $x_1_2 = {25 bb 52 c0 5d 8b [0-20] c1 ?? 05 89 [0-30] c1 ?? 04 03 [0-15] 02 01 01 31 33 [0-2] 02 01 01 31 33}  //weight: 1, accuracy: Low
        $x_1_3 = {25 bb 52 c0 5d 8b [0-20] c1 ?? 04 03 [0-30] c1 ?? 05 89 [0-30] 02 01 01 31 33 [0-15] 02 01 01 31 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GB_2147795252_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GB!MTB"
        threat_id = "2147795252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 3b 2d 0b 00 01 05 ?? ?? ?? ?? 6a 65 58 6a 32 66 a3 ?? ?? ?? ?? 58 6a 2e 66 a3 ?? ?? ?? ?? 58 6a 6e 66 a3 ?? ?? ?? ?? 58 6a 65 66 a3 ?? ?? ?? ?? 58 6a 64 66 a3 ?? ?? ?? ?? 58 6a 33}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 3b 2d 0b 00 01 05 ?? ?? ?? ?? b8 65 00 00 00 66 a3 ?? ?? ?? ?? b8 33 00 00 00 66 a3 ?? ?? ?? ?? b9 6b 00 00 00 ba 72 00 00 00 b8 6c 00 00 00 68 ?? ?? ?? ?? c7 05 [0-8] c7 05 [0-8] c7 05 [0-8] c7 05 ?? ?? ?? ?? 6c 00 00 00 66 89 0d ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? 66 a3 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GC_2147797771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GC!MTB"
        threat_id = "2147797771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d}  //weight: 10, accuracy: High
        $x_10_2 = {89 30 5e c2 08 00 33 44 24 04 c2 04 00 81 00 ae 36 ef c6 c3 01 08 c3 29 08 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GC_2147797771_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GC!MTB"
        threat_id = "2147797771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 9b 21 1a c7 85 ?? ?? ?? ?? e7 d0 87 49 c7 85 ?? ?? ?? ?? 96 3a d0 46 c7 85 ?? ?? ?? ?? 29 5f 9d 30 c7 85 ?? ?? ?? ?? 6b 33 00 4b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GC_2147797771_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GC!MTB"
        threat_id = "2147797771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 ba 6c 00 00 00 6a 00 c7 05 ?? ?? ?? ?? 6c 00 33 00 c7 05 ?? ?? ?? ?? 6b 00 65 00 c7 05 ?? ?? ?? ?? 6e 00 65 00 66 89 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 15 58 00 2e 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GC_2147797771_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GC!MTB"
        threat_id = "2147797771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 73 58 6a 6d 66 a3 ?? ?? ?? ?? 58 6a 67 66 a3 ?? ?? ?? ?? 58 6a 69 66 a3 ?? ?? ?? ?? 58 6a 6c 66 a3 ?? ?? ?? ?? 58 6a 32 66 a3 ?? ?? ?? ?? 58 6a 6c 8b 3d ?? ?? ?? ?? 66 a3 ?? ?? ?? ?? 58 6a 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GC_2147797771_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GC!MTB"
        threat_id = "2147797771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 40 ff 35 [0-20] c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 69 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {44 00 6b c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 6c [0-7] c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 74 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GC_2147797771_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GC!MTB"
        threat_id = "2147797771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 2d 0b 00 8b 0d [0-4] 88 04 19 83 3d [0-4] 44}  //weight: 1, accuracy: Low
        $x_1_2 = "runexobozez" ascii //weight: 1
        $x_1_3 = "jemefumorepoveta" ascii //weight: 1
        $x_1_4 = "Xotafibiwacuyi nul" ascii //weight: 1
        $x_1_5 = ".pdb" ascii //weight: 1
        $x_1_6 = "Copyrighz (C) 2021, fudkorta" ascii //weight: 1
        $x_1_7 = "Pulezufiget gacuwumuhi yofelekudurika dulikahuy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GD_2147798369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GD!MTB"
        threat_id = "2147798369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 f1 1a 2b c7 44 24 ?? f9 0b 2b 23 89 4c 24 ?? c7 44 24 ?? d1 f0 0d 7b c7 44 24 ?? 68 17 ab 44}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GD_2147798369_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GD!MTB"
        threat_id = "2147798369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 04 8b [0-15] c1 ?? 05 8d [0-15] 02 01 01 31 33 [0-15] 02 01 01 31 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GD_2147798369_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GD!MTB"
        threat_id = "2147798369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 84 32 36 23 01 00 88 04 31 81 c4 ?? ?? 00 00 c3}  //weight: 10, accuracy: Low
        $x_10_2 = {c1 ea 05 03 d5 c7 05 ?? ?? ?? ?? b4 02 d7 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 74 24 ?? 8d 44 24 ?? e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GD_2147798369_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GD!MTB"
        threat_id = "2147798369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b4 21 e1 c5 32 00 c1 ?? 04 03 [0-15] c1 ?? 05 03 [0-30] 02 01 01 31 33 [0-20] c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {b4 21 e1 c5 32 00 c1 ?? 05 03 [0-15] c1 ?? 04 03 [0-30] 02 01 01 31 33 [0-20] c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GD_2147798369_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GD!MTB"
        threat_id = "2147798369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 40 ff 35 [0-20] c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 6f [0-7] c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 69 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GE_2147798437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GE!MTB"
        threat_id = "2147798437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 30 81 3d ?? ?? ?? ?? 03 02 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 0c 30 04 31 81 ff 91 05 00 00 46 3b f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GE_2147798437_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GE!MTB"
        threat_id = "2147798437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec b8 6e 00 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 72 c3 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GE_2147798437_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GE!MTB"
        threat_id = "2147798437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 00 2e 00 c7 05 ?? ?? ?? ?? 6e 00 65 00 c7 05 ?? ?? ?? ?? 64 00 6c 00 c7 05 ?? ?? ?? ?? 6c 00 00 00 66 89 0d ?? ?? ?? ?? 66 89 15 78 00 65 00 00 00 ?? 6b 00 00 00 [0-20] 33 00 00 00 [0-10] 72 00 00 00 ?? 6c 00 00 00 [0-2] c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {50 b9 6c 00 00 00 ba 2e 00 00 00 6a 00 c7 05 ?? ?? ?? ?? 6e 00 65 00 c7 05 ?? ?? ?? ?? 6c 00 00 00 c7 05 ?? ?? ?? ?? 6c 00 33 00 66 89 0d ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GE_2147798437_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GE!MTB"
        threat_id = "2147798437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 84 32 36 23 01 00 88 04 31 81 c4 ?? ?? 00 00 c3}  //weight: 10, accuracy: Low
        $x_10_2 = {c1 ea 05 03 d5 [0-5] c7 05 ?? ?? ?? ?? b4 02 d7 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 54 24}  //weight: 10, accuracy: Low
        $x_1_3 = {51 c7 04 24 02 00 00 00 8b 44 24 ?? ?? 01 04 24 83 2c 24 ?? 8b 04 24 31 01 59 c2}  //weight: 1, accuracy: Low
        $x_1_4 = {81 ec 00 01 00 00 c7 84 24 ?? ?? ?? ?? 57 78 d1 51 c7 84 24 ?? ?? ?? ?? 0b 4c 1b 7e c7 44 24 ?? dd 0b fa 64 c7 44 24 ?? cf 72 b2 3d c7 84 24 ?? ?? ?? ?? e9 0e 74 64 c7 44 24 ?? a9 53 5d 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Raccrypt_GF_2147798438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GF!MTB"
        threat_id = "2147798438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 04 31 81 3d ?? ?? ?? ?? 03 02 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {88 14 30 81 3d ?? ?? ?? ?? 03 02 00 00}  //weight: 1, accuracy: Low
        $x_4_3 = {8b 4c 24 10 30 04 31 81 bc 24 ?? ?? ?? ?? 91 05 00 00 46 3b b4 24}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Raccrypt_GF_2147798438_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GF!MTB"
        threat_id = "2147798438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {19 36 6b ff 32 00 c1 ?? 04 03 [0-40] c1 ?? 05 03 [0-15] [0-20] c7 05 [0-20] 02 01 01 31 33}  //weight: 1, accuracy: Low
        $x_1_2 = {19 36 6b ff 32 00 c1 ?? 05 03 [0-40] c1 ?? 04 03 [0-15] [0-20] c7 05 [0-20] 02 01 01 31 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GF_2147798438_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GF!MTB"
        threat_id = "2147798438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 14 4a 0a c7 84 24 ?? ?? ?? ?? 32 f5 41 2a c7 84 24 ?? ?? ?? ?? 52 89 eb 0e c7 84 24 ?? ?? ?? ?? fc 7d 9a 60 c7 84 24 ?? ?? ?? ?? e5 9a 40 22}  //weight: 1, accuracy: Low
        $x_1_2 = {ce 07 14 68 c7 44 24 ?? 95 70 b0 07 c7 44 24 ?? db 42 40 19 c7 44 24 ?? 2f 73 f1 3c c7 44 24 ?? 16 a9 ca 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GF_2147798438_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GF!MTB"
        threat_id = "2147798438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 3b 2d 0b 00 01 45 ?? 8b 45 ?? 8a 04 08 88 04 39 41 3b 0d}  //weight: 10, accuracy: Low
        $x_1_2 = {8b c6 d3 e8 03 45 ?? 33 45 ?? 2b f8 83 fa ?? 75 ?? ff 15 ?? ?? ?? ?? 25 bb 52 c0 5d}  //weight: 1, accuracy: Low
        $x_10_3 = {33 75 0c 8b 45 08 89 30 5e [0-1] c2 08 00 33 44 24 04 c2 04 00 81 00 ae 36 ef c6 c3 01 08 c3}  //weight: 10, accuracy: Low
        $x_1_4 = {c1 e0 04 89 01 c3 55 8b ec 83 ec 0c 83 3d ?? ?? ?? ?? 03 56 8b f0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Raccrypt_GH_2147798634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GH!MTB"
        threat_id = "2147798634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 b8 6c 00 00 00 6a 00 c7 05 ?? ?? ?? ?? 6c 00 33 00 c7 05 ?? ?? ?? ?? 6b 00 65 00 c7 05 ?? ?? ?? ?? 6e 00 65 00 66 a3 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GH_2147798634_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GH!MTB"
        threat_id = "2147798634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 04 [0-15] c1 ?? 05 [0-15] 02 01 01 31 33 [0-15] 02 01 01 31 33 ?? c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GH_2147798634_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GH!MTB"
        threat_id = "2147798634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 03 44 24 ?? 51 8d 4c 24 14 c7 05 ?? ?? ?? ?? b4 02 d7 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 44 24 ?? e8 ?? ?? ?? ?? 8b 54 24 ?? 52 8d 4c 24 ?? e8 ?? ?? ?? ?? 2b 74 24 ?? 8d 44 24 ?? 89 74 24 ?? e8 ?? ?? ?? ?? 4d 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GH_2147798634_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GH!MTB"
        threat_id = "2147798634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 7d 00 c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 72 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GI_2147798830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GI!MTB"
        threat_id = "2147798830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 35 a0 44 c7 44 24 ?? 93 35 23 2d c7 44 24 ?? 99 da f3 4c c7 44 24 ?? c3 f1 76 08 c7 44 24 ?? d9 ba db 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GI_2147798830_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GI!MTB"
        threat_id = "2147798830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 bb 52 c0 5d 8b [0-20] c1 ?? 05 89 [0-30] c1 ?? 04 03 [0-15] 33}  //weight: 1, accuracy: Low
        $x_1_2 = {33 44 24 04 c2 04 00 81 00 f9 34 ef c6 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GI_2147798830_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GI!MTB"
        threat_id = "2147798830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b4 02 d7 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 ?? 24 ?? e8 [0-13] e8 ?? ?? ?? ?? 2b 74 24 ?? 8d 44 24 ?? 89 74 24 ?? e8 [0-8] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GI_2147798830_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GI!MTB"
        threat_id = "2147798830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 b9 72 00 00 00 ba 6c 00 00 00 6a 00 c7 05 ?? ?? ?? ?? 64 00 6c 00 c7 05 ?? ?? ?? ?? 6c 00 00 00 66 89 0d ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? ff 15 6b 00 ba 65 00 00 00 [0-4] b8 6b 00 00 00 [0-20] ba 2e 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GI_2147798830_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GI!MTB"
        threat_id = "2147798830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 94 31 36 23 01 00 88 14 30 81 c4 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_2 = {51 c7 04 24 02 00 00 00 8b 44 24 08 01 04 24 83 2c 24 02 8b 04 24 31 01 59 c2}  //weight: 1, accuracy: High
        $x_1_3 = {b4 02 d7 cb c7 05 ?? ?? ?? ?? ff ff ff ff 10 00 c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GI_2147798830_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GI!MTB"
        threat_id = "2147798830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 2e 64 6c c7 05 ?? ?? ?? ?? 6b 65 72 6e 66 c7 05 ?? ?? ?? ?? 65 6c c6 05 ?? ?? ?? ?? 33 66 c7 05 ?? ?? ?? ?? 6c 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {b1 74 50 a3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 61 6c 66 c7 05 ?? ?? ?? ?? 72 6f c6 05 ?? ?? ?? ?? 50 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 0d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 75 c7 05 ?? ?? ?? ?? 56 69 72 74 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GI_2147798830_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GI!MTB"
        threat_id = "2147798830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 2e 64 6c c7 05 ?? ?? ?? ?? 6b 65 72 6e 66 c7 05 ?? ?? ?? ?? 65 6c c6 05 ?? ?? ?? ?? 33 66 c7 05 ?? ?? ?? ?? 6c 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {b1 74 50 a3 [0-4] 66 c7 05 [0-6] 66 c7 05 [0-6] c6 05 ?? ?? ?? ?? 50 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 0d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 75 c7 05 ?? ?? ?? ?? 56 69 72 74 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GJ_2147799604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GJ!MTB"
        threat_id = "2147799604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b4 02 d7 cb [0-6] c7 05 ?? ?? ?? ?? ff ff ff ff [0-10] 55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GJ_2147799604_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GJ!MTB"
        threat_id = "2147799604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {bb 52 c0 5d 8b 45 ?? 83 25 ?? ?? ?? ?? 00 03 c3 50 8b c3 c1 e0 04 03 45 ?? 33 44 24 04 c2 ?? ?? 81 00 40 36 ef c6 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GJ_2147799604_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GJ!MTB"
        threat_id = "2147799604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 04 03 [0-30] c1 ?? 05 03 [0-8] c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 05 03 [0-30] c1 ?? 04 03 [0-8] c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GJ_2147799604_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GJ!MTB"
        threat_id = "2147799604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b4 21 e1 c5 32 00 c1 ?? 04 03 [0-15] c1 ?? 05 03 [0-30] 02 01 01 31 33 14 00 c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {b4 21 e1 c5 32 00 c1 ?? 05 03 [0-15] c1 ?? 04 03 [0-30] 02 01 01 31 33 14 00 c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GJ_2147799604_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GJ!MTB"
        threat_id = "2147799604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 04 [0-15] c1 ?? 05 [0-15] 33 [0-8] c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 05 [0-15] c1 ?? 04 [0-15] 33 [0-8] c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GJ_2147799604_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GJ!MTB"
        threat_id = "2147799604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 23 01 00 90 02 06 88 0c 32 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_10_2 = {b4 02 d7 cb [0-6] c7 05 ?? ?? ?? ?? ff ff ff ff 89 [0-6] e8 ?? ?? ?? ?? 8b [0-3] 29 [0-3] 68 ?? ?? ?? ?? 8d [0-3] 52 e8 [0-7] 0f 85}  //weight: 10, accuracy: Low
        $x_10_3 = {55 8b ec 8b 45 08 8b 4d 0c 31 08 5d c2 ?? 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Raccrypt_GJ_2147799604_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GJ!MTB"
        threat_id = "2147799604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 94 31 36 23 01 00 88 ?? ?? 30 81 c4 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_2 = {36 23 01 00 88 0c 32 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_10_3 = {b4 02 d7 cb [0-6] c7 05 ?? ?? ?? ?? ff ff ff ff 89 [0-3] e8 ?? ?? ?? ?? 8b ca e8 ?? ?? ?? ?? 8b [0-3] 29 [0-3] 8d [0-3] e8 ?? ?? ?? ?? 4f 8b [0-3] 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Raccrypt_GJ_2147799604_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GJ!MTB"
        threat_id = "2147799604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 c3 c3 55 72 00 65 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec b8 72 00 65 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GL_2147805930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GL!MTB"
        threat_id = "2147805930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? c3 81 05 ?? ?? ?? ?? d6 38 00 00 c3 81 05 ?? ?? ?? ?? 00 00 00 00 c3 ff 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GL_2147805930_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GL!MTB"
        threat_id = "2147805930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 2e 64 6c c7 05 ?? ?? ?? ?? 6b 65 72 6e 66 c7 05 ?? ?? ?? ?? 65 6c c6 05 ?? ?? ?? ?? 33 66 c7 05 ?? ?? ?? ?? 6c 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GL_2147805930_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GL!MTB"
        threat_id = "2147805930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 bb 52 c0 5d 8b [0-20] c1 ?? 05 03 [0-30] c1 ?? 04 03 [0-15] 33}  //weight: 1, accuracy: Low
        $x_1_2 = {33 44 24 04 c2 04 00 81 00 f6 34 ef c6 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GL_2147805930_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GL!MTB"
        threat_id = "2147805930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b4 02 d7 cb [0-6] c7 05 ?? ?? ?? ?? ff ff ff ff [0-10] 55 8b ec 81 ec 00 01 00 00 c7 [0-6] 57 78 d1 51 c7 [0-6] 0b 4c 1b 7e c7 [0-6] dd 0b fa 64 c7 [0-6] cf 72 b2 3d c7 [0-6] e9 0e 74 64 c7 [0-6] a9 53 5d 16 c7 [0-6] 05 c8 4e 43 c7 [0-6] 82 2d 68 68}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GL_2147805930_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GL!MTB"
        threat_id = "2147805930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a d0 8a 2c c7 84 24 ?? ?? ?? ?? 15 6e 75 0e c7 84 24 ?? ?? ?? ?? 8e 52 57 39 c7 84 24 ?? ?? ?? ?? 5b 4a 15 44 c7 84 24 ?? ?? ?? ?? 0c ba 12 32 c7 84 24 ?? ?? ?? ?? 87 7d 73 71}  //weight: 1, accuracy: Low
        $x_1_2 = {65 aa 60 60 c7 84 24 ?? ?? ?? ?? 50 c8 81 35 c7 84 24 ?? ?? ?? ?? 1e e5 bc 4b c7 84 24 ?? ?? ?? ?? df 02 30 6d c7 84 24 ?? ?? ?? ?? 86 d5 5b 70 c7 84 24 ?? ?? ?? ?? 0b ef cb 64}  //weight: 1, accuracy: Low
        $x_1_3 = {86 22 d0 1b c7 84 24 ?? ?? ?? ?? bc ac 35 50 c7 84 24 ?? ?? ?? ?? b5 8b ad 60 c7 84 24 ?? ?? ?? ?? e2 84 9c 35 c7 84 24 ?? ?? ?? ?? 49 b7 1d 24 c7 84 24 ?? ?? ?? ?? 33 aa 61 23}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GL_2147805930_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GL!MTB"
        threat_id = "2147805930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 04 03 [0-30] c1 ?? 05 03 [0-15] 02 01 01 31 33}  //weight: 1, accuracy: Low
        $x_1_2 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 05 03 [0-30] c1 ?? 04 03 [0-15] 02 01 01 31 33}  //weight: 1, accuracy: Low
        $x_1_3 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 04 03 [0-30] c1 ?? 05 03 0f 00 02 01 01 31 33}  //weight: 1, accuracy: Low
        $x_1_4 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 32 00 c1 ?? 05 03 [0-30] c1 ?? 04 03 0f 00 02 01 01 31 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GM_2147805931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GM!MTB"
        threat_id = "2147805931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 3b 2d 0b 00 01 45 74 8b 45 74 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {33 44 24 04 c2 ?? 00 81 00 40 36 ef c6 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GM_2147805931_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GM!MTB"
        threat_id = "2147805931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 03 d0 c1 ?? 04 03 45 ?? c1 ?? 05 03 4d ?? 52 89 3d [0-4] 33 44 24 04 c2 ?? 00 81 00 40 36 ef c6 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GM_2147805931_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GM!MTB"
        threat_id = "2147805931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 66 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 2e 00 64 00 c7 05 ?? ?? ?? ?? 72 00 6e 00 c7 05 ?? ?? ?? ?? 33 00 32 00 c7 05 ?? ?? ?? ?? 6b 00 65 00 c7 05 ?? ?? ?? ?? 6c 00 6c 00 a3 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GM_2147805931_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GM!MTB"
        threat_id = "2147805931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 bb 52 c0 5d 8b [0-20] c1 ?? 04 03 [0-30] c1 ?? 05 03 [0-15] 33}  //weight: 1, accuracy: Low
        $x_1_2 = {33 44 24 04 c2 04 00 81 00 f5 34 ef c6 c3}  //weight: 1, accuracy: High
        $x_1_3 = {33 44 24 04 c2 04 00 81 00 f4 34 ef c6 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GM_2147805931_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GM!MTB"
        threat_id = "2147805931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b4 02 d7 cb [0-6] c7 05 ?? ?? ?? ?? ff ff ff ff 3c 00 c1 ?? 04 03 [0-4] c1 [0-1] 05 03 [0-6] 33 ?? 33}  //weight: 10, accuracy: Low
        $x_10_2 = {b4 02 d7 cb [0-6] c7 05 ?? ?? ?? ?? ff ff ff ff 3c 00 c1 ?? 05 03 [0-6] 68 b9 79 37 9e [0-6] 33 [0-6] 33}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GM_2147805931_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GM!MTB"
        threat_id = "2147805931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 55 7b 11 c7 [0-5] 8e e6 d8 1e c7 [0-5] 7b 0c db 13 c7 [0-5] a6 c3 f8 4a c7 [0-5] 51 b7 cd 49 c7 [0-5] 29 66 56 72 c7 [0-5] ed ?? ?? 49 c7 [0-5] 18 61 f3 05}  //weight: 1, accuracy: Low
        $x_1_2 = {a5 28 36 47 c7 [0-5] b7 e0 73 4c c7 [0-5] 02 97 13 70 c7 [0-5] 0d d2 eb 21 c7 [0-5] 05 3d e8 27 c7 [0-5] 86 38 39 19}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GM_2147805931_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GM!MTB"
        threat_id = "2147805931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 40 ff 35 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 75 ff 35 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 69 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {f6 56 ff 35 ?? ?? ?? ?? 66 c7 05 ?? ?? ?? ?? 61 6c 66 c7 05 ?? ?? ?? ?? 65 63 c6 05 ?? ?? ?? ?? 74 66 c7 05 ?? ?? ?? ?? 72 74 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 69 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GN_2147806294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GN!MTB"
        threat_id = "2147806294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 0c 01 45 fc 8b 45 fc 33 45 08 c9 c2 08 00 81 00 f5 34 ef c6 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GN_2147806294_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GN!MTB"
        threat_id = "2147806294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? c3 81 05 ?? ?? ?? ?? d6 38 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GN_2147806294_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GN!MTB"
        threat_id = "2147806294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 5d c3 ff 35 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? c3 81 05 ?? ?? ?? ?? d6 38 00 00 c3 ff 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GN_2147806294_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GN!MTB"
        threat_id = "2147806294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 0c 32 81 3d ?? ?? ?? ?? 03 02 00 00 23 00 a1 ?? ?? ?? ?? 8a 8c 30 ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 0c 30 04 31 81 ff 91 05 00 00 46 3b f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GN_2147806294_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GN!MTB"
        threat_id = "2147806294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 c3 c3 b8 50 00 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GN_2147806294_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GN!MTB"
        threat_id = "2147806294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b4 02 d7 cb [0-6] c7 05 ?? ?? ?? ?? ff ff ff ff [0-10] 55 8b ec 8b 45 08 8b 4d 0c 31 08 5d c2 08 00}  //weight: 10, accuracy: Low
        $x_10_2 = {b4 02 d7 cb [0-6] c7 05 ?? ?? ?? ?? ff ff ff ff [0-5] e8 ?? ?? ?? ?? 8b [0-3] 29 [0-3] 81 ?? 47 86 c8 61 ff [0-5] 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GN_2147806294_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GN!MTB"
        threat_id = "2147806294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? c3 81 05 ?? ?? ?? ?? d6 38 00 00 c3 ff 25}  //weight: 1, accuracy: Low
        $x_1_2 = {6b 65 53 c6 05 ?? ?? ?? ?? 72 c7 05 ?? ?? ?? ?? 6e 65 6c 33 c7 05 ?? ?? ?? ?? 64 6c 6c 00 66 c7 05 ?? ?? ?? ?? 32 2e ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {ec b5 5a 31 c7 45 ?? 60 ca 40 72 c7 45 ?? 6f 13 1b 3d c7 45 ?? 03 6c 37 04 c7 45 ?? bd 46 ea 13 c7 45 ?? b0 29 f6 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GN_2147806294_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GN!MTB"
        threat_id = "2147806294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 51 52 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 72 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {51 b0 65 68 ?? ?? ?? ?? a2 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 6e [0-5] c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 32 [0-5] c6 05 ?? ?? ?? ?? 6b ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GN_2147806294_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GN!MTB"
        threat_id = "2147806294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b c6 05 a9 ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 6c 88 1d ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6b c6 05 c9 ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 6c 88 1d ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 0c 01 45 fc 8b 45 fc 31 45 08 c9 c2 08 00 81 00 f5 34 ef c6 c3}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 0c 01 45 fc 8b 45 fc 31 45 08 8b 45 08 c9 c2 08 00 81 00 f5 34 ef c6 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GO_2147806402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GO!MTB"
        threat_id = "2147806402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {9f 99 a2 25 c7 85 ?? ?? ?? ?? e9 a9 1a 16 c7 85 ?? ?? ?? ?? eb 24 54 26 c7 85 ?? ?? ?? ?? 15 4f 12 30 c7 85 ?? ?? ?? ?? 35 2a da 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GO_2147806402_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GO!MTB"
        threat_id = "2147806402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 65 58 6a 32 66 a3 ?? ?? ?? ?? 58 6a 33 66 a3 ?? ?? ?? ?? 58 6a 65 66 a3 ?? ?? ?? ?? 58 6a 64 66 a3 ?? ?? ?? ?? 58 6a 6e 66 a3 ?? ?? ?? ?? 58 6a 6c 66 a3 ?? ?? ?? ?? 58 6a 6b 66 a3 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GO_2147806402_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GO!MTB"
        threat_id = "2147806402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b4 02 d7 cb [0-6] c7 05 ?? ?? ?? ?? ff ff ff ff 89 [0-3] e8 ?? ?? ?? ?? 8b ca e8 ?? ?? ?? ?? 8b [0-3] 29 [0-3] 8d [0-3] e8 [0-15] 0f 85 5a 00 8b [0-3] 8b ?? c1 [0-8] c7 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GO_2147806402_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GO!MTB"
        threat_id = "2147806402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 2d 0b 00 8b 0d ?? ?? ?? ?? 88 04 ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {25 bb 52 c0 5d 8b [0-2] 8b [0-4] c1 ?? 05 03 [0-4] c1 [0-1] 04 03 [0-6] 33 ?? 33}  //weight: 1, accuracy: Low
        $x_1_3 = {25 bb 52 c0 5d 8b [0-2] 8b [0-4] c1 ?? 04 03 [0-6] 33 [0-8] c1 [0-1] 05 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Raccrypt_GO_2147806402_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GO!MTB"
        threat_id = "2147806402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 9b c6 a0 04 8b [0-20] c1 ?? 04 03 [0-30] c1 ?? 05 03 [0-15] 33 [0-4] 33}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 9b c6 a0 04 8b [0-20] c1 ?? 05 03 [0-30] c1 ?? 04 03 [0-15] 33 [0-4] 33}  //weight: 1, accuracy: Low
        $x_1_3 = {bb 9b c6 a0 04 8b [0-20] c1 ?? 05 89 [0-30] c1 ?? 04 03 [0-15] 33 [0-4] 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GO_2147806402_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GO!MTB"
        threat_id = "2147806402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {19 36 6b ff 32 00 c1 ?? 04 03 [0-40] c1 ?? 05 [0-15] c7 05 [0-20] 02 01 01 31 33}  //weight: 1, accuracy: Low
        $x_1_2 = {19 36 6b ff 32 00 c1 ?? 05 03 [0-40] c1 ?? 04 [0-15] c7 05 [0-20] 02 01 01 31 33}  //weight: 1, accuracy: Low
        $x_1_3 = {19 36 6b ff 32 00 c1 ?? 05 [0-40] c1 ?? 04 03 [0-15] c7 05 [0-20] 02 01 01 31 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GO_2147806402_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GO!MTB"
        threat_id = "2147806402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c6 05 cf ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 6c [0-6] c6 05 ?? ?? ?? ?? 6b c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6c ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c6 05 c9 ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 6c [0-6] c6 05 ?? ?? ?? ?? 6b c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6c ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c6 05 a9 ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 6c [0-6] c6 05 ?? ?? ?? ?? 6b c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6c ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 0c 01 45 fc 8b 45 fc 31 45 08 c9 c2 08 00 81 00 e1 34 ef c6 c3}  //weight: 1, accuracy: High
        $x_1_5 = {8b 45 0c 01 45 fc 8b 45 fc 31 45 08 8b 45 08 c9 c2 08 00 81 00 e1 34 ef c6 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GP_2147807239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GP!MTB"
        threat_id = "2147807239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 3b 2d 0b 00 01 45 74 8b 45 74 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {33 44 24 04 c2 ?? 00 81 00 dc 35 ef c6 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GP_2147807239_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GP!MTB"
        threat_id = "2147807239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? 8b 44 24 ?? 8b 4c 24 ?? 33 44 24 ?? 03 4c 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 02 01 01 31 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GP_2147807239_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GP!MTB"
        threat_id = "2147807239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 2d 0b 00 8b 0d ?? ?? ?? ?? 88 04 31 75}  //weight: 1, accuracy: Low
        $x_1_2 = {25 bb 52 c0 5d 8b [0-2] 8b [0-4] c1 ?? 04 03 [0-4] c1 [0-1] 05 03 [0-6] 33 ?? 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GP_2147807239_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GP!MTB"
        threat_id = "2147807239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 3b 2d 0b 00 01 45 74 8b 45 74 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {25 bb 52 c0 5d 8b [0-2] 8b [0-4] c1 ?? 04 03 [0-4] c1 [0-1] 05 03 [0-6] 33 ?? 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GP_2147807239_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GP!MTB"
        threat_id = "2147807239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b1 6d b0 6c 88 0d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 73 a2 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 67 c6 05 ?? ?? ?? ?? 64 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 2e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GP_2147807239_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GP!MTB"
        threat_id = "2147807239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b0 65 b1 6c 68 [0-9] c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 [0-6] c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 6e [0-12] c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 32 [0-5] c6 05 ?? ?? ?? ?? 6b ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {b0 74 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 6f [0-20] c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 63 [0-10] c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 72 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GP_2147807239_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GP!MTB"
        threat_id = "2147807239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b0 65 b1 6c 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 00 [0-20] c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 32 [0-5] c6 05 ?? ?? ?? ?? 6b ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {53 b3 6c 68 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 [0-6] c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 65 88 1d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 32 [0-6] c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GP_2147807239_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GP!MTB"
        threat_id = "2147807239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {cc b0 65 68 [0-10] c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 6e [0-5] c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 32 [0-5] c6 05 ?? ?? ?? ?? 6b ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {b0 74 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 6f [0-5] c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 63 [0-10] c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 72 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GV_2147808963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GV!MTB"
        threat_id = "2147808963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 00 e1 34 ef c6 c3}  //weight: 1, accuracy: High
        $x_1_2 = {01 08 c3 29 08 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GV_2147808963_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GV!MTB"
        threat_id = "2147808963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 00 eb 34 ef c6 c3}  //weight: 1, accuracy: High
        $x_1_2 = {01 08 c3 29 08 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GV_2147808963_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GV!MTB"
        threat_id = "2147808963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 44 24 [0-10] 02 01 01 31 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GV_2147808963_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GV!MTB"
        threat_id = "2147808963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bd a3 53 78 c7 84 24 ?? ?? ?? ?? ?? ?? c4 0d c7 84 24 ?? ?? ?? ?? c5 00 1d 75 c7 84 24 ?? ?? ?? ?? 84 50 74 21 c7 84 24 ?? ?? ?? ?? 08 d3 e3 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GV_2147808963_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GV!MTB"
        threat_id = "2147808963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 bb 52 c0 5d 8b [0-10] c1 ?? 04 03 [0-30] c1 [0-1] 05 03 [0-15] 02 01 01 31 33 [0-10] 8b 45 ?? 29 45 [0-15] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GV_2147808963_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GV!MTB"
        threat_id = "2147808963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 6a 40 ff 35 96 00 6c c6 05 ?? ?? ?? ?? 6c [0-6] c6 05 ?? ?? ?? ?? 6b [0-7] c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 33 [0-7] ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GW_2147809032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GW!MTB"
        threat_id = "2147809032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4c 24 04 4b 00 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 72 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GW_2147809032_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GW!MTB"
        threat_id = "2147809032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 ec 00 01 00 00 c7 [0-6] 57 78 d1 51 c7 [0-6] 0b 4c 1b 7e c7 [0-6] dd 0b fa 64 c7 [0-6] cf 72 b2 3d c7 [0-6] e9 0e 74 64 c7 [0-6] a9 53 5d 16 c7 [0-6] 05 c8 4e 43 c7 [0-6] 82 2d 68 68}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GW_2147809032_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GW!MTB"
        threat_id = "2147809032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {19 36 6b ff 32 00 c1 ?? 04 03 [0-15] c1 ?? 05 03 [0-30] 02 01 01 31 33 [0-20] c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {19 36 6b ff 32 00 c1 ?? 05 03 [0-15] c1 ?? 04 03 [0-30] 02 01 01 31 33 [0-20] c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GW_2147809032_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GW!MTB"
        threat_id = "2147809032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 04 8b 4c 24 08 31 08 c2 08 00 8b 44 24 04 8b 4c 24 08 01 08 c2 08 00}  //weight: 10, accuracy: High
        $x_10_2 = {61 6c c6 05 ?? ?? ?? ?? 74 66 c7 05 ?? ?? ?? ?? 72 74 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 69 ff 15}  //weight: 10, accuracy: Low
        $x_10_3 = {61 6c 66 c7 05 [0-6] c6 05 ?? ?? ?? ?? 74 66 c7 05 ?? ?? ?? ?? 72 74 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 69 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GW_2147809032_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GW!MTB"
        threat_id = "2147809032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 65 00 00 00 ba 6e 00 00 00 b8 6b 00 00 00 68 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {52 50 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 60 c6 05 ?? ?? ?? ?? 7c c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 74 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {51 52 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 60 c6 05 ?? ?? ?? ?? 7c c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 74 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GW_2147809032_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GW!MTB"
        threat_id = "2147809032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 40 ff [0-20] c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 72 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 68 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 6b ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raccrypt_GDD_2147810218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GDD!MTB"
        threat_id = "2147810218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 08 83 c4 10 5d c3 81 00 03 35 ef c6 c3 01 08 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raccrypt_GK_2147818752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccrypt.GK!MTB"
        threat_id = "2147818752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e ae 0c 2f c7 45 ?? 61 9b 21 1a c7 45 ?? e7 d0 87 49 c7 45 ?? 96 3a d0 46 c7 45 ?? 29 5f 9d 30 c7 45 ?? 6b 33 00 4b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

