rule Trojan_Win64_EmotetPacker_AY_2147842315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EmotetPacker.AY!MTB"
        threat_id = "2147842315"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EmotetPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 c8 99 44 8b 4d ?? 41 f7 f9 4c 63 d2 42 0f b6 14 11 41 31 d0 45 88 c3 48 8b 8d ?? ?? ?? ?? 4c 63 55 ?? 46 88 1c 11 8b 45 ?? 83 c0 01 89 45 ?? 8b 45 ?? 3b 45 ?? 73 ?? b8 ?? ?? ?? ?? 48 8b ?? ?? 48 63 ?? ?? 44 0f b6 04 11 48 8b 8d ?? ?? ?? ?? 44 8b 4d ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

