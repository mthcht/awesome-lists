rule Trojan_Win32_Racoon_CG_2147788940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racoon.CG!MTB"
        threat_id = "2147788940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 1c 01 8b 4d ?? d3 e8 c7 05 ?? ?? ?? ?? 2e ce 50 91 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b 55 ?? 33 d3 33 55 ?? 8d 8d ?? ?? ?? ?? 89 55 ?? e8 ?? ?? ?? ?? 89 75 ?? 25 1b 07 d0 4d 81 6d ?? 88 eb 73 22 bb 87 d5 7c 3a 81 45 ?? 8c eb 73 22 8b 9d ?? ?? ?? ?? 8b 4d ?? 8b 95 ?? ?? ?? ?? 8b c3 d3 e0 8d 4d ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racoon_J_2147789208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racoon.J!MTB"
        threat_id = "2147789208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3 31 08 c3 33 44 24 04 c2 04 00 81 00 cc 36 ef c6 c3 [0-5] 29 08 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c2 d3 e0 [0-32] 8b c2 c1 e8 05 [0-32] 03 c2 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racoon_K_2147789433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racoon.K!MTB"
        threat_id = "2147789433"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 36 23 01 00 01 45 ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 8b 55 ?? 03 55 ?? 8a 02 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 8b 08 33 4d ?? 8b 55 ?? 89 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 e2 04 89 55 [0-64] d3 e8 89 45 ?? 8b 4d ?? 03 4d ?? 89 4d ?? 8b 55 ?? 33 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racoon_C_2147827681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racoon.C!MTB"
        threat_id = "2147827681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 8a 14 01 88 10 40 4f 75 f7 81 3d ?? ?? ?? ?? 9c 2b 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

