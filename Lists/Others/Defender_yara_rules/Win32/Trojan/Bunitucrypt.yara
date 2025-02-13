rule Trojan_Win32_Bunitucrypt_RMA_2147780485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMA!MTB"
        threat_id = "2147780485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d f2 05 00 00 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMA_2147780485_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMA!MTB"
        threat_id = "2147780485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 2d 16 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 2d 16 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMA_2147780485_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMA!MTB"
        threat_id = "2147780485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 33 c0 89 ?? ?? 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {01 02 8b 45 ?? 03 [0-5] 03 [0-5] 8b ?? ?? 31 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMA_2147780485_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMA!MTB"
        threat_id = "2147780485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 45 ?? 03 45 ?? 2d 29 09 00 00 03 45 ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 ?? 31 18 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMA_2147780485_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMA!MTB"
        threat_id = "2147780485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 18 83 45 ?? 04 83 ?? ?? ?? ?? ?? 04 8b ?? ?? 3b ?? ?? ?? ?? ?? 72 ?? a1 ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? 2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMA_2147780485_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMA!MTB"
        threat_id = "2147780485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 [0-5] 0e 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {31 18 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 00 e8 ?? ?? ?? ?? 2b d8 01 [0-30] 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMA_2147780485_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMA!MTB"
        threat_id = "2147780485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 02 6a 02 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 02 e8 ?? ?? ?? ?? 2b d8 01 1d ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMA_2147780485_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMA!MTB"
        threat_id = "2147780485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ?? 8b d8 8b 45 ?? 83 c0 04 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 89 [0-5] 8b [0-5] 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMA_2147780485_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMA!MTB"
        threat_id = "2147780485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 00 10 00 00 [0-10] 83 05 [0-5] 04 5a 00 [0-32] 31 [0-10] a1 [0-7] 04 01 05 [0-20] 04 01 05 [0-20] 3b [0-10] 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMA_2147780485_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMA!MTB"
        threat_id = "2147780485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a a5 08 00 [0-5] 0e 00 00 00}  //weight: 5, accuracy: Low
        $x_1_2 = {33 02 89 45 [0-10] 89 02 [0-10] 04 [0-10] 04}  //weight: 1, accuracy: Low
        $x_1_3 = {2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMA_2147780485_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMA!MTB"
        threat_id = "2147780485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 [0-5] 0e 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {01 02 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMA_2147780485_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMA!MTB"
        threat_id = "2147780485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 c7 [0-5] 0e 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {31 02 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 [0-70] 3b 05 ?? ?? ?? ?? 72 [0-16] 2d 00 10 00 00 ?? ?? 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMA_2147780485_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMA!MTB"
        threat_id = "2147780485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 8b 45 ?? 31 18 6a ?? e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a ?? e8 ?? ?? ?? ?? 2b d8 01 5d ?? 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMA_2147780485_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMA!MTB"
        threat_id = "2147780485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 8b 45 ?? 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e0 0f 82 ?? ?? ?? ?? c7 45 ?? 00 10 00 00 8b 45 ?? 03 45 ?? 2b 45 ?? 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMA_2147780485_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMA!MTB"
        threat_id = "2147780485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 ?? 6a ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {31 18 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 72 ?? a1 ?? ?? ?? ?? 03 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMA_2147780485_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMA!MTB"
        threat_id = "2147780485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 02 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 0f ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? 2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: Low
        $x_1_2 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 45 ?? 03 45 ?? 2d 67 2b 00 00 03 45 ?? 03 d8 e8 ?? ?? ?? ?? 2b d8 8b 45 ?? 31 18 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 [0-15] e0 e0 5d 0d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {31 02 6a 00 e8 ?? ?? ?? ?? 8b d8 8b 45 ?? 83 c0 04 03 d8 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 18 8b 45 ?? 03 ?? ?? 03 ?? ?? 8b ?? ?? 31 02 83 ?? ?? 04 83 ?? ?? 04 8b ?? ?? 3b ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 02 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 72 ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 02 6a 0c e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 0c e8 ?? ?? ?? ?? 2b d8 01 5d ?? 83 45 ?? 04}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d f2 05 00 00 03 ?? ?? 8b ?? ?? ?? ?? ?? 31 02 [0-5] e8 ?? ?? ?? ?? 8b d8 83 c3 04 [0-5] e8 ?? ?? ?? ?? 2b d8 01 ?? ?? 83 ?? ?? ?? ?? ?? 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {31 02 83 05 ?? ?? ?? ?? 04 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 00 e8 ?? ?? ?? ?? 2b d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 00 10 00 00 83 ?? 04 70 00 [0-32] a1 [0-9] 03 [0-20] 8b [0-20] 31 [0-80] 83 [0-9] 04 83 [0-9] 04 [0-15] 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 8b 45 ?? 89 18 8b 45 ?? 03 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45 ?? 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 01 02 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 33 c0 89 ?? ?? 8b ?? ?? 3b ?? ?? 73}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d8 8b 45 ?? 31 18 83 ?? ?? 04 83 ?? ?? 04 8b ?? ?? 3b ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 33 45 ?? 89 45 ?? 8b 45 ?? 8b 55 ?? 89 10 6a 01 e8 ?? ?? ?? ?? 8b d8 83 c3 04}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 10 00 00 [0-5] 83 45 [0-5] 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 0f 83}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d8 a1 94 ?? ?? ?? 31 18 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 83 ?? ?? ?? ?? 8b 45 ?? 8b 55 ?? 01 02 8b 45 ?? 05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 01 02}  //weight: 1, accuracy: Low
        $x_1_2 = {31 18 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a a5 08 00 33 c0 89 45 ?? 33 c0}  //weight: 5, accuracy: Low
        $x_1_2 = {01 02 8b 45 ?? 03 ?? ?? 03 ?? ?? 8b ?? ?? 31 02 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 ?? ?? 04 83 ?? ?? 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RW_2147780960_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RW!MTB"
        threat_id = "2147780960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 73}  //weight: 1, accuracy: Low
        $x_1_2 = {89 18 8b 45 ?? 03 45 ?? 03 45 ?? 8b 15 ?? ?? ?? ?? 31 02 a1 ?? ?? ?? ?? 83 c0 ?? a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RTA_2147782427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RTA!MTB"
        threat_id = "2147782427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 00 10 00 00 83 c0 04 5a 00 [0-32] 33 [0-22] 8b [0-22] 04 [0-10] 04 [0-10] 3b [0-10] 72 [0-10] 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RTA_2147782427_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RTA!MTB"
        threat_id = "2147782427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 10 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RTA_2147782427_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RTA!MTB"
        threat_id = "2147782427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 02 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RTA_2147782427_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RTA!MTB"
        threat_id = "2147782427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 02 83 45 ?? 04 8b ?? ?? 83 c0 04 89 ?? ?? 8b ?? ?? 3b ?? ?? 72 [0-5] c7 ?? ?? 00 10 00 00 8b ?? ?? 03 ?? ?? 2b ?? ?? 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RTA_2147782427_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RTA!MTB"
        threat_id = "2147782427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 33 18 89}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 10 00 00 [0-10] 83 05 [0-5] 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RTA_2147782427_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RTA!MTB"
        threat_id = "2147782427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 8b 45 ?? 3b 45 ?? 73 ?? 8b 45 ?? 8b 55 ?? 01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 6a ?? e8 ?? ?? ?? ?? 8b d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RTA_2147782427_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RTA!MTB"
        threat_id = "2147782427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 33 c0 89 45 ?? 8b 45 ?? 3b 45 ?? 73}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 6a ?? e8 ?? ?? ?? ?? 2b d8 8b 45 ?? 31 18 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RTA_2147782427_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RTA!MTB"
        threat_id = "2147782427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 33 c0 89 ?? ?? 8b ?? ?? 3b ?? ?? 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d8 8b 45 ?? 31 18 6a ?? e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a ?? e8 ?? ?? ?? ?? 2b d8 01 ?? ?? 83 ?? ?? 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RTA_2147782427_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RTA!MTB"
        threat_id = "2147782427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 0f 83}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 6a ?? e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RTB_2147782428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RTB!MTB"
        threat_id = "2147782428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 02 6a 00 e8 [0-4] 8b d8 83 c3 04 6a 00 e8 [0-4] 2b d8 01 [0-5] 83 [0-5] 04}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 10 00 00 [0-10] 83 [0-5] 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RTB_2147782428_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RTB!MTB"
        threat_id = "2147782428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 73 ?? e8 [0-14] 8b 45 ?? 8b 55 ?? 01 10 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RWA_2147782818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RWA!MTB"
        threat_id = "2147782818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 c7 [0-5] 0e 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {31 02 83 05 ?? ?? ?? ?? 04 83 ?? ?? ?? ?? ?? 04 [0-15] a1 ?? ?? ?? ?? 3b [0-25] 2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RWA_2147782818_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RWA!MTB"
        threat_id = "2147782818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 01 10 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 83 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RWA_2147782818_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RWA!MTB"
        threat_id = "2147782818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 8b 45 ?? 3b 45 ?? 0f 83}  //weight: 1, accuracy: Low
        $x_1_2 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 6a ?? e8 ?? ?? ?? ?? 8b d8 83 c3 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RWA_2147782818_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RWA!MTB"
        threat_id = "2147782818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b ?? ?? 3b ?? ?? 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 8b 45 ?? 03 ?? ?? 03 ?? ?? 03 d8 6a ?? e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 a1 ?? ?? ?? ?? 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMB_2147797042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMB!MTB"
        threat_id = "2147797042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 8b ?? ?? 3b ?? ?? 0f [0-9] 8b ?? ?? 8b ?? ?? 01 02 8b ?? ?? 03 ?? ?? 03 ?? ?? 8b ?? ?? 31 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMB_2147797042_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMB!MTB"
        threat_id = "2147797042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 99 52 50 8b 45 ?? 33 d2 3b 54 24 ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RMB_2147797042_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RMB!MTB"
        threat_id = "2147797042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 18 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f [0-8] a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 2d 00 10 00 00 83 c0 04}  //weight: 1, accuracy: Low
        $x_1_2 = {8a a5 08 00 [0-10] 0e 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RFA_2147797775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RFA!MTB"
        threat_id = "2147797775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a5 08 00 c7 [0-5] 0e 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {31 02 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68}  //weight: 1, accuracy: Low
        $x_1_3 = {2d 00 10 00 00 83 c0 04 [0-10] 0d 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Bunitucrypt_DE_2147807900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.DE!MTB"
        threat_id = "2147807900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2d 00 10 00 00 83 c0 04}  //weight: 10, accuracy: High
        $x_10_2 = {57 89 c7 88 cd 89 c8 c1 e0 10 66 89 c8 89 d1 c1 f9 02 78 09 f3 ab 89 d1 83 e1 03 f3 aa 5f c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitucrypt_RTC_2147810243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucrypt.RTC!MTB"
        threat_id = "2147810243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 02 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 10 00 00 [0-10] 83 [0-5] 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

