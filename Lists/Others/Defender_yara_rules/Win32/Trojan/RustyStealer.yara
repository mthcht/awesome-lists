rule Trojan_Win32_RustyStealer_ME_2147907648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RustyStealer.ME!MTB"
        threat_id = "2147907648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 fc 19 00 00 00 8b c3 0f b6 0e f7 75 fc 41 0f af cb 8a 44 15 d8 30 81 77 af 00 10 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RustyStealer_GKP_2147943659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RustyStealer.GKP!MTB"
        threat_id = "2147943659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff d3 8b 37 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 89 c7 68 ?? ?? ?? ?? 56 ff d0 89 44 24 ?? 68 ?? ?? ?? ?? 56 ff d7 89 44 24 ?? 68 ?? ?? ?? ?? 56 ff d7 89 44 24 ?? 68 ?? ?? ?? ?? 89 74 24 ?? 56 89 7c 24 ?? ff d7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RustyStealer_ARY_2147962538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RustyStealer.ARY!MTB"
        threat_id = "2147962538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 18 03 74 24 5c 03 6c 24 14 03 5c 24 54 03 54 24 30 03 7c 24 68 01 84 24 c8 00 00 00 8b 44 24 24 89 b4 24 d8 00 00 00 31 74 24 04 31 6c 24 38 c1 44 24 38 10 89 ac 24 c4 00 00 00 8b 6c 24 10 31 5c 24 58 89 94 24 b0 00 00 00 c1 44 24 58 10 31 7c 24 48 89 9c 24 9c 00 00 00 8b 5c 24 64 89 bc 24 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

