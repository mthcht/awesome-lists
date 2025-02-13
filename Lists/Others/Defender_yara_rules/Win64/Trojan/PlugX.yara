rule Trojan_Win64_PlugX_LK_2147913411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PlugX.LK!MTB"
        threat_id = "2147913411"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PlugX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e9 00 00 00 00 8b 84 24 ?? 00 00 00 2d ?? ?? ?? ?? ?? ?? ?? ?? ff ff e9 00 00 00 00 8b 84 24 ?? 00 00 00 2d ?? ?? ?? ?? ?? ?? ?? ?? ff ff e9 00 00 00 00 8b 84 24 ?? 00 00 00 2d ?? ?? ?? ?? ?? ?? ?? ?? ff ff e9 00 00 00 00 8b 84 24 ?? 00 00 00 2d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

