rule Trojan_Win32_SmokeLdr_GA_2147777692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLdr.GA!MTB"
        threat_id = "2147777692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 04 33 83 7d ?? ?? 46 3b 75 ?? ?? ?? 81 7d ?? 71 11 00 00 5f 5e}  //weight: 10, accuracy: Low
        $x_10_2 = {88 14 0f 3d 03 02 00 00 75 ?? 89 35 ?? ?? ?? ?? 41 3b c8 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLdr_GB_2147777693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLdr.GB!MTB"
        threat_id = "2147777693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 04 33 33 c0 81 ff 03 02 00 00 0f 44 d0 46 3b f7}  //weight: 10, accuracy: High
        $x_10_2 = {30 04 1f 47 3b fe [0-2] 5f 81 fe 71 11 00 00 5e 5d 5b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLdr_GC_2147777778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLdr.GC!MTB"
        threat_id = "2147777778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 04 37 83 ?? 19 46 3b ?? 7c ?? 5e 81 fb 71 11 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {88 14 0f 3d 03 02 00 00 75 ?? 89 35 ?? ?? ?? ?? 41 3b c8 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLdr_GD_2147777948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLdr.GD!MTB"
        threat_id = "2147777948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 01 42 3b 54 24 1e 00 8b 44 24 ?? 8d 0c 02 a1 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 25 ?? ?? ?? ?? c3}  //weight: 10, accuracy: Low
        $x_10_2 = {88 14 0f 3d 03 02 00 00 75 ?? 89 35 ?? ?? ?? ?? 41 3b c8 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLdr_GE_2147778105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLdr.GE!MTB"
        threat_id = "2147778105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 0c 06 e8 ?? ?? ?? ?? 30 01 46 3b f7 7c 19 00 8b 44 24}  //weight: 10, accuracy: Low
        $x_10_2 = {3d 03 02 00 00 75 ?? 89 35 ?? ?? ?? ?? 41 3b c8 32 00 8b 15 ?? ?? ?? ?? 8a 94 0a ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 88 14}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLdr_GF_2147778192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLdr.GF!MTB"
        threat_id = "2147778192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 08 8d 0c 06 e8 ?? ?? ?? ?? 30 01 46 3b f7}  //weight: 10, accuracy: Low
        $x_10_2 = {3d 03 02 00 00 75 [0-9] 41 3b c8 32 00 8b 15 ?? ?? ?? ?? 8a 94 0a ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 88 14}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLdr_GH_2147778350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLdr.GH!MTB"
        threat_id = "2147778350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 0c 3e 46 3b f3 7c 28 00 a1 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8a 0d}  //weight: 10, accuracy: Low
        $x_1_2 = {3d 03 02 00 00 75 [0-9] 41 3b c8 32 00 8b 15 ?? ?? ?? ?? 8a 94 0a ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 88 14}  //weight: 1, accuracy: Low
        $x_1_3 = {88 0c 02 8b 0d ?? ?? ?? ?? 81 f9 03 02 00 00 75 ?? 89 ?? ?? ?? ?? ?? 40 3b ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SmokeLdr_GI_2147778458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLdr.GI!MTB"
        threat_id = "2147778458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 0c 3e 46 3b f3 7c 28 00 a1 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8a 0d}  //weight: 10, accuracy: Low
        $x_1_2 = {8a 04 0f 88 04 0e 81 fa 03 02 00 00 75 ?? 89 ?? ?? ?? ?? ?? 41 3b ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLdr_GJ_2147778868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLdr.GJ!MTB"
        threat_id = "2147778868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 0c 1e 83 ff ?? 46 3b f7 81 3d ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8a 0d}  //weight: 10, accuracy: Low
        $x_1_2 = {88 0c 32 3d 03 02 00 00 46 3b f0 8b 15 ?? ?? ?? ?? 8a 8c 32 ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

