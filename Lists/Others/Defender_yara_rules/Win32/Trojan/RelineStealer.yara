rule Trojan_Win32_RelineStealer_RPB_2147798253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RelineStealer.RPB!MTB"
        threat_id = "2147798253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RelineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 95 2c f6 ff ff 21 ca 89 8d 04 f6 ff ff 8b 8d 2c f6 ff ff 89 95 00 f6 ff ff 8b 95 04 f6 ff ff 31 d1 8b 95 00 f6 ff ff 09 ca 88 d1 8b 95 a4 f8 ff ff 88 0c 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RelineStealer_BXF_2147817795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RelineStealer.BXF!MTB"
        threat_id = "2147817795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RelineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 fc 8b 4d f8 2b f0 8b d6 d3 ea 89 75 9c 89 55 fc 8b 45 88 01 45 fc 8b 45 9c c1 e6 04}  //weight: 10, accuracy: High
        $x_10_2 = {dc c0 69 54 c7 45 ?? 98 c3 e4 01 c7 85 ?? ?? ?? ?? be 14 4a 0a c7 85 ?? ?? ?? ?? 32 f5 41 2a c7 85 ?? ?? ?? ?? 52 89 eb 0e c7 85 ?? ?? ?? ?? fc 7d 9a 60 c7 85 ?? ?? ?? ?? e5 9a 40 22 c7 85 ?? ?? ?? ?? 95 54 fe 1a c7 45 ?? 87 64 58 7c c7 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RelineStealer_FM_2147818353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RelineStealer.FM!MTB"
        threat_id = "2147818353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RelineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 c1 96 00 00 00 89 8d ?? ?? ?? ?? 8b 55 08 81 c2 c2 00 00 00 89 95 ?? ?? ?? ?? 8b 45 08 83 c0 01 89 85 ?? ?? ?? ?? 8b 4d 08 83 c1 27 89 8d 84 fe ff ff 8b 55 08 81 c2 c6 00 00 00 89 95 ?? ?? ?? ?? 8b 45 08 83 c0 49}  //weight: 10, accuracy: Low
        $x_10_2 = {89 45 b0 8b 4d dc 0f af 8d ?? ?? ?? ?? 89 4d ec 8b 95 ?? ?? ?? ?? 0f af 95 ?? ?? ?? ?? 89 55 a0 8b 85 f0 fe ff ff 3b 45 88 7f 0c}  //weight: 10, accuracy: Low
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RelineStealer_FT_2147818498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RelineStealer.FT!MTB"
        threat_id = "2147818498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RelineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 85 8c fe ff ff 03 85 ?? ?? ?? ?? 89 45 a4 8b 4d b4 0f af 8d ?? ?? ?? ?? 89 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 0f af 95 ?? ?? ?? ?? 89 55 f8 8b 45 c4 0f af 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 3b 8d 24 ff ff ff 7c 0f}  //weight: 10, accuracy: Low
        $x_10_2 = {89 8d fc fd ff ff 8b 55 08 83 c2 70 89 95 ?? ?? ?? ?? 8b 45 08 05 a6 00 00 00 89 85 ?? ?? ?? ?? 8b 4d 08 83 c1 3e 89 8d ?? ?? ?? ?? 8b 55 08 83 c2 1d 89 95}  //weight: 10, accuracy: Low
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RelineStealer_FU_2147818659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RelineStealer.FU!MTB"
        threat_id = "2147818659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RelineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 95 64 fd ff ff 03 55 a4 89 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 0f af 4d a8 89 4d b0 8b 95 ?? ?? ?? ?? 0f af 95 ?? ?? ?? ?? 89 55 94 8b 85 ?? ?? ?? ?? 3b 85 d0 fe ff ff}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 08 83 c0 61 89 85 ?? ?? ?? ?? 8b 4d 08 83 c1 09 89 8d ?? ?? ?? ?? 8b 55 08 83 c2 3f 89 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 3b 85 10 ff ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RelineStealer_FV_2147818698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RelineStealer.FV!MTB"
        threat_id = "2147818698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RelineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {a0 7e 4f 00 88 0d ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 0f be 11 33 d0 a1 ?? ?? ?? ?? 03 45 ?? 88 10}  //weight: 10, accuracy: Low
        $x_10_2 = {a0 7e 4f 00 03 05 ?? ?? ?? ?? 33 d2 b9 ?? ?? ?? ?? f7 f1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8a 88 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a1 94 7e 4f 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RelineStealer_VK_2147818979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RelineStealer.VK!MTB"
        threat_id = "2147818979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RelineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f0 3b 06 6c c7 84 24 ?? ?? ?? ?? 91 d5 b8 3c c7 84 24 ?? ?? ?? ?? ed cf 0e 06 c7 84 24 ?? ?? ?? ?? da 73 71 22 c7 84 24 ?? ?? ?? ?? 84 1f e8 75 c7 84 24 ?? ?? ?? ?? 17 64 50 28}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "Copyright (C) 2022, pozkarte" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RelineStealer_VA_2147819067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RelineStealer.VA!MTB"
        threat_id = "2147819067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RelineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 47 04 8d bf ?? ?? ?? ?? 88 02 f7 d9 d2 c9 81 ee ?? ?? ?? ?? 8b 0e 33 cb}  //weight: 10, accuracy: Low
        $x_10_2 = {d2 e4 8b 07 33 c3 f7 d0 48 f5}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RelineStealer_XB_2147820288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RelineStealer.XB!MTB"
        threat_id = "2147820288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RelineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7c af fc 03 f8 5d 89 bd ?? ?? ?? ?? 33 db b8 ?? ?? ?? ?? 83 c0 ?? 64 8b 3c 03 8b 7f 0c 8b 77 14 8b 36 8b 36 8b 46 10 8b f8 03 78 ?? 8b 57 78 03 d0 8b 7a 20 03 f8 55 8b eb 8b 34 af 03 f0 45 81 3e ?? ?? ?? ?? ?? ?? 81 7e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RelineStealer_UB_2147824704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RelineStealer.UB!MTB"
        threat_id = "2147824704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RelineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 30 04 31 83 ff ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

