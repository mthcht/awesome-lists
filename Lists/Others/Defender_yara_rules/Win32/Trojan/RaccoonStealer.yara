rule Trojan_Win32_RaccoonStealer_DA_2147775327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RaccoonStealer.DA!MTB"
        threat_id = "2147775327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RaccoonStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d5 c1 ea 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 44 24 ?? 33 c7 33 c6 2b d8 81 3d ?? ?? ?? ?? 17 04 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RaccoonStealer_D_2147786323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RaccoonStealer.D!MTB"
        threat_id = "2147786323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RaccoonStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Umendkaidwkoa" ascii //weight: 1
        $x_1_2 = "euisfdjsxadfds7" ascii //weight: 1
        $x_1_3 = "ecrumsaws" ascii //weight: 1
        $x_1_4 = "vsefocsledsy" ascii //weight: 1
        $x_1_5 = "Jemfscmses" ascii //weight: 1
        $x_1_6 = "Numeraniumrekx" ascii //weight: 1
        $x_1_7 = "wd3dwerewolioldsd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RaccoonStealer_I_2147787431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RaccoonStealer.I!MTB"
        threat_id = "2147787431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RaccoonStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 36 23 01 00 01 45 [0-8] 03 ?? ?? 8b ?? ?? 03 ?? ?? 8a ?? 88}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 83 [0-21] c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 7e c6 05 ?? ?? ?? ?? 7e c6 05 ?? ?? ?? ?? 6c [0-16] c7 45 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 7c c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 75 ?? ?? ?? ?? ?? ?? ?? 83 e8 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RaccoonStealer_RPB_2147814812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RaccoonStealer.RPB!MTB"
        threat_id = "2147814812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RaccoonStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 24 00 00 00 00 a1 ?? ?? ?? ?? 01 04 24 b8 d6 38 00 00 01 04 24 8b 0c 24 8b 84 24 90 00 00 00 8a 14 01 8b 0d ?? ?? ?? ?? 88 14 01 81 c4 8c 00 00 00 c2 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RaccoonStealer_RPX_2147848253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RaccoonStealer.RPX!MTB"
        threat_id = "2147848253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RaccoonStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 d0 61 c6 45 d1 6b c6 45 d2 68 c6 45 d3 6a c6 45 d4 66 c6 45 d5 77 c6 45 d6 78 c6 45 d7 6d c6 45 d8 73 c6 45 d9 49}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RaccoonStealer_CCBK_2147891549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RaccoonStealer.CCBK!MTB"
        threat_id = "2147891549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RaccoonStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 02 8d 52 ?? 03 c7 89 04 8b 41 3b ce 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

