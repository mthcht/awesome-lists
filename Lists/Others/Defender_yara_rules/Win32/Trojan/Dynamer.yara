rule Trojan_Win32_Dynamer_GTH_2147835990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dynamer.GTH!MTB"
        threat_id = "2147835990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dynamer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 c2 03 d8 81 e3 ?? ?? ?? ?? 0f b6 84 1d ?? ?? ?? ?? 88 84 35 ?? ?? ?? ?? 88 94 1d ?? ?? ?? ?? 0f b6 8c 35 ?? ?? ?? ?? 0f b6 c2 03 c8 81 e1 ?? ?? ?? ?? 0f b6 84 0d ?? ?? ?? ?? 8b 4d f8 30 04 0f 47 3b 7d fc 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dynamer_RPX_2147848251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dynamer.RPX!MTB"
        threat_id = "2147848251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dynamer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 05 53 00 44 00 6c c6 05 4d 00 44 00 6c c6 05 4b 00 44 00 6e c6 05 51 00 44 00 64 c6 05 52 00 44 00 6c c6 05 49 00 44 00 65 c6 05 50 00 44 00 2e c6 05 4f 00 44 00 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

