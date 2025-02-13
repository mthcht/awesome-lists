rule Trojan_Win32_DiamondFox_G_2147781237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DiamondFox.G!MTB"
        threat_id = "2147781237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DiamondFox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 8b c1 f7 f7 8a 99 ?? ?? ?? ?? 41 0f be 82 ?? ?? ?? ?? 03 f0 0f b6 d3 03 f2 81 e6 ff 00 00 00 8a 86 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 88 9e ?? ?? ?? ?? 81 f9 00 01 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

