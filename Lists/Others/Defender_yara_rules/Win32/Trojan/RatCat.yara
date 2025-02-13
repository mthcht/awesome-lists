rule Trojan_Win32_RatCat_C_2147755496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RatCat.C!MTB"
        threat_id = "2147755496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RatCat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 66 83 3d ?? ?? ?? ?? 00 74 0f 83 3d ?? ?? ?? ?? 00 74 06 89 0d ?? ?? ?? ?? 8a 14 85 ?? ?? ?? ?? 8b 74 24 08 02 d1 88 14 30 40 3d ?? ?? ?? ?? 7c cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

