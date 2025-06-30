rule Trojan_Win64_LummacStealer_IY_2147945070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummacStealer.IY!MTB"
        threat_id = "2147945070"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummacStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 c2 44 0f b6 44 15 ?? 44 01 c0 25 ?? ?? ?? ?? 48 63 d0 8a 4c 15 ?? 88 4d ?? 48 8b 95 ?? ?? ?? ?? 4c 8b 4d ?? 42 0f b6 04 0a 44 0f b6 45 ?? 44 31 c0 88 c1 48 8b 95 ?? ?? ?? ?? 4c 8b 4d ?? 42 88 0c 0a 48 8b 45 ?? 48 83 c0 ?? 48 89 45 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummacStealer_WAI_2147945073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummacStealer.WAI!MTB"
        threat_id = "2147945073"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummacStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 01 48 63 4d ?? 48 8b 55 ?? 30 04 0a 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 05 ?? ?? ?? ?? 8d 48 ?? 0f af c8 f6 c1 ?? b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

