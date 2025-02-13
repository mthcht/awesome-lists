rule Backdoor_Win32_Tnega_2147788252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tnega.MT!MTB"
        threat_id = "2147788252"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 07 66 a9 84 38 c0 de aa c0 ea 28 66 8b 57 04 81 fc 15 46 19 29 f7 c6 df 39 23 1d 81 c7 06 00 00 00 36 66 89 10 2d 9b 1f cd 71 0f c8 d2 dc 81 ee 04 00 00 00 8b 06 33 c3 f5 0f c8 f5 c1 c8 02 e9 9b df 09 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tnega_MP_2147788256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tnega.MP!MTB"
        threat_id = "2147788256"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3a 59 ba d3 88 3f 49 0d ec 32 1e}  //weight: 1, accuracy: High
        $x_1_2 = {8b 3f d3 e8 66 0f a4 f8 fa 66 35 e7 2d 8b 44 25 00 81 c5 04 00 00 00 66 85 fd 33 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Tnega_MQ_2147788923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tnega.MQ!MTB"
        threat_id = "2147788923"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b5 0a c7 85 fc 34 4e ed 59 87 fe a0 ff cd 84 e2 80 77 79 a3 19 2f 78 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tnega_MA_2147788925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tnega.MA!MTB"
        threat_id = "2147788925"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 25 00 66 8b c4 d2 e8 81 c5 01 00 00 00 d2 d4 c1 f0 2e 32 d3 0f ab e0 d2 f8 80 ea cb d3 d8 9f 80 f2 5e 40 f6 da 0f 95 c4 80 ea 4f 66 2d ?? ?? c0 cc 72 35 ?? ?? ?? ?? 32 da 66 85 cf 88 0c 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

