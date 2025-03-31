rule Trojan_Win32_Bublik_AP_2147839927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bublik.AP!MTB"
        threat_id = "2147839927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bublik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf 4e 3f 74 d2 57 2a 3d [0-4] 68 10 a7 38 08 00 2b 33 71 b5 87 33 68 7a 3a 47 b4 4e 87 4f a9 bb a1 e0 23 cf 02 3a e3}  //weight: 1, accuracy: Low
        $x_1_2 = {49 32 49 34 00 00 00 ed 94 f3 a7 d1 02 63 4a b3 90 21 98 bb 98 96 b5 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bublik_GZX_2147907106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bublik.GZX!MTB"
        threat_id = "2147907106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bublik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {54 44 2b e3 41 81 f4 ?? ?? ?? ?? 66 45 0f ab fc 31 1c 24 41 5c 40 f6 c6 b1 3c 88 48 63 db 48 03 eb ff e5}  //weight: 5, accuracy: Low
        $x_5_2 = {66 d3 d1 80 ea 8d 32 da f6 dd 66 ff c9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bublik_GZN_2147909743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bublik.GZN!MTB"
        threat_id = "2147909743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bublik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 f7 d1 0f b7 c5 66 ff c1 13 c1 66 33 d9 23 c2 25 ?? ?? ?? ?? 81 ef 02 00 00 00 66 89 0f f7 d0}  //weight: 10, accuracy: Low
        $x_1_2 = "feZvgPtdvv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bublik_AYA_2147937394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bublik.AYA!MTB"
        threat_id = "2147937394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bublik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 8d 1c 3e 29 f2 8b cb e8 e9 ff ff ff 89 f2 89 f9 e8 e0 ff ff ff 33 c0 09 f6 74 11 8a 14 03 8a 0c 38 88 14 38 88 0c 03 40 39 f0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

