rule Trojan_Win32_PovertyStealer_RPX_2147893181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PovertyStealer.RPX!MTB"
        threat_id = "2147893181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PovertyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 57 00 00 00 66 89 8d 74 ff ff ff ba 61 00 00 00 66 89 95 76 ff ff ff b8 6c 00 00 00 66 89 85 78 ff ff ff b9 6c 00 00 00 66 89 8d 7a ff ff ff ba 65 00 00 00 66 89 95 7c ff ff ff b8 74 00 00 00 66 89 85 7e ff ff ff b9 73 00 00 00 66 89 4d 80 ba 5c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PovertyStealer_A_2147898655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PovertyStealer.A!MTB"
        threat_id = "2147898655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PovertyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 8b c1 c1 e8 ?? 33 c1 69 c8 ?? ?? ?? ?? 33 f9 3b f3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PovertyStealer_RDA_2147901657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PovertyStealer.RDA!MTB"
        threat_id = "2147901657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PovertyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Poverty is the parent of crime." ascii //weight: 1
        $x_1_2 = "- OperationSystem: %d:%d:%d" ascii //weight: 1
        $x_1_3 = "- HWID: %s" ascii //weight: 1
        $x_1_4 = "- ScreenSize: {lWidth=%d, lHeight=%d}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PovertyStealer_GZD_2147903163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PovertyStealer.GZD!MTB"
        threat_id = "2147903163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PovertyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 fc 8b 4d fc 8a 94 4d ?? ?? ?? ?? 88 54 05 bc 8b 45 fc 0f be 4c 05 bc 83 f9 2c ?? ?? 8b 55 fc c6 44 15 bc 2e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PovertyStealer_APV_2147927105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PovertyStealer.APV!MTB"
        threat_id = "2147927105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PovertyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ca c1 f9 06 83 e2 3f 6b d2 38 8b 0c 8d 08 4e 42 00 88 44 11 29 8b 0b 8b c1 c1 f8 06 83 e1 3f 6b d1 38 8b 0c 85 08 4e 42 00 8b 45 14 c1 e8 10 32 44 11 2d 24 01 30 44 11 2d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

