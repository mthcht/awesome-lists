rule Trojan_Win32_VBInjector_2147697044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInjector"
        threat_id = "2147697044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInjector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fc ff 8b d0 8d 4d ?? e8 ?? ?? fc ff 68 ?? ?? ?? ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 89}  //weight: 10, accuracy: Low
        $x_1_2 = {85 c0 74 02 eb (32|38|3b) 83 c8 ff 85 c0 74 (29|2f|32) c7 ?? ?? [0-3] 01 00 00 00 c7 ?? ?? [0-3] 02 00 00 00 8d 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInjector_2147697044_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInjector"
        threat_id = "2147697044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInjector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 dd 05 3c ?? ?? 00 dc 1d ?? 11 40 00 df e0 9e 73 05 e9 ?? 01 00 00 e8 ?? ?? ?? ?? a1 38 ?? ?? 00 99 6a 07 59 f7 f9 a3 38 ?? ?? 00 6a 00 6a 00 6a 00 6a 00 ff 35 38 ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 04 83 65 ?? 00 83 7d ?? 0a 74 05 e8 ?? ?? fd ff c7 45 ec ?? ?? ?? 02 db 45 ec dd 5d ?? dd 45 ?? 83 3d 00 ?? ?? 00 00 75 08 dc 35 ?? ?? 40 00 eb 11 ff 35 ?? ?? 40 00 ff 35 ?? ?? 40 00 e8 ?? ?? fd ff df e0 a8 0d}  //weight: 1, accuracy: Low
        $x_1_3 = {75 08 dc 35 ?? 10 40 00 eb 11 ff 35 ?? 10 40 00 ff 35 ?? 10 40 00 e8 ?? ?? ?? ff df e0 a8 0d 0f 85 ?? 01 00 00 1d 00 c7 45 ?? ?? ?? ?? ?? db 45 ?? dd 9d ?? ?? ff ff dd 85 ?? ?? ff ff 83 3d 00 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {99 2b c2 d1 f8 89 45 ?? 83 3d 10 f0 42 00 00 75 1b 68 10 f0 42 00 68 ?? 14 40 00 e8 ?? ?? fd ff c7 85 ?? fd ff ff 10 f0 42 00 eb 0a c7 85 ?? fd ff ff 10 f0 42 00 0a 00 c7 45 ?? ?? ?? (81|84) 00 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_VBInjector_AAR_2147745391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInjector.AAR!eml"
        threat_id = "2147745391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInjector"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c4 10 68 ?? ?? ?? ?? 68 00 68 00 68 00 83 c4 10 2d 00 68 00 68 00 68 00 68 [0-31] 81}  //weight: 2, accuracy: Low
        $x_5_2 = "COntroraX.exe" wide //weight: 5
        $x_1_3 = {5f 31 f2 68 ?? ?? ?? ?? 68 00 68 00 68 00 83 c4 10 51 81}  //weight: 1, accuracy: Low
        $x_1_4 = {5a 4b 52 81 ca ?? ?? ?? ?? 5a eb 11 00 52 81 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VBInjector_AS_2147751138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInjector.AS!MTB"
        threat_id = "2147751138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 0d 22 85 9f d1 58 56 21 d6 5e 56 21 d6 5e 81 f9 24 51 00 00 75 ad}  //weight: 1, accuracy: High
        $x_1_2 = "humrsygengeneralauditrskrppernem" wide //weight: 1
        $x_1_3 = "Rekneadparterrersudmattetbiotek" wide //weight: 1
        $x_1_4 = "Dorskeiagttagelsesvelserrdvinens" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

