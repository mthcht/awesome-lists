rule Trojan_Win32_Krypter_AD_2147795758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Krypter.AD!MTB"
        threat_id = "2147795758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Krypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 11 8b 45 ?? 8b 4d ?? 89 48 ?? 83 3d ?? ?? ?? ?? ?? 75 45 00 8b 55 ?? 2b 55 ?? 89 55 ?? 81 3d [0-10] 75 ?? eb ?? 8b 45 ?? 2b 45 ?? 89 45 ?? e9 ?? ?? ?? ?? 8b 4d ?? 8b 55}  //weight: 1, accuracy: Low
        $x_1_2 = {89 02 8b 4d ?? 8b 55 ?? 89 51 ?? 5b 8b e5 5d c2 45 00 8b 45 ?? 2b 45 ?? 89 45 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? eb ?? 8b 4d ?? 2b 4d ?? 89 4d ?? e9 ?? ?? ?? ?? 8b 55 ?? 8b 45}  //weight: 1, accuracy: Low
        $x_1_3 = "LocalAlloc" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Krypter_AA_2147795879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Krypter.AA!MTB"
        threat_id = "2147795879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Krypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 14 06 e8 ?? ?? ?? ?? 30 02 46 59 3b 75 ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 8b 4d ?? 8b 41 ?? 69 c0 ?? ?? ?? ?? 05 ?? ?? ?? ?? 89 41 ?? c1 e8 ?? 25 ?? ?? ?? ?? 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Krypter_AG_2147796977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Krypter.AG!MTB"
        threat_id = "2147796977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Krypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 51 c7 45 ?? ?? ?? ?? ?? 8b 45 ?? 8b 4d ?? d3 e8 8b 4d ?? 89 01 8b 55 ?? 8b 02 03 45 ?? 8b 4d ?? 89 01 8b e5 5d c2}  //weight: 10, accuracy: Low
        $x_10_2 = "Visual C++" ascii //weight: 10
        $x_10_3 = {55 8b ec 51 c7 45 ?? ?? ?? ?? ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 8b 08 03 4d ?? 8b 55 ?? 89 0a 8b e5 5d c2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Krypter_AB_2147798246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Krypter.AB!MTB"
        threat_id = "2147798246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Krypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 d2 81 c2 ?? ?? ?? ?? 66 c1 c2 ?? 0f b7 d2 8b 0c 85 ?? ?? ?? ?? 03 ca 88 8c 05 ?? ?? ?? ?? 40 0f b6 c0 0f b6 b5 ?? ?? ?? ?? 3b c6 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Krypter_AB_2147798246_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Krypter.AB!MTB"
        threat_id = "2147798246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Krypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 89 30 5e 5b c9 c2 2f 00 2b 75 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85 ?? ?? ?? ?? 8b 45 ?? 89 78}  //weight: 1, accuracy: Low
        $x_1_2 = "LocalAlloc" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Krypter_AH_2147808166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Krypter.AH!MTB"
        threat_id = "2147808166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Krypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 32 02 aa 42 e2 ?? 61 5d c2 10 00 20 00 60 8b 7d ?? 8b 75 ?? 8b 4d ?? 8b 55 ?? 80 3a ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Krypter_AEE_2147903120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Krypter.AEE!MTB"
        threat_id = "2147903120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Krypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 83 ec 08 c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? ?? [0-48] 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? c7 45 ?? 40 00 00 00 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 7f c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? ?? [0-48] 0f be 05 ?? ?? ?? ?? 83 e8 1e a2 ?? ?? ?? ?? 0f be 0d ?? ?? ?? ?? 83 e9 14 88 0d ?? ?? ?? ?? 0f be 15 ?? ?? ?? ?? 83 ea 14 [0-54] c6 05 ?? ?? ?? ?? 69 68}  //weight: 10, accuracy: Low
        $x_2_2 = "LocalAlloc" ascii //weight: 2
        $x_10_3 = "VirtualProtect" ascii //weight: 10
        $x_2_4 = "GlobalAlloc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

