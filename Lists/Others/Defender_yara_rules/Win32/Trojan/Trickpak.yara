rule Trojan_Win32_Trickpak_DK_2147786219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickpak.DK!MTB"
        threat_id = "2147786219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e2 06 03 d6 88 44 24 0f 0f b6 05 ?? ?? ?? ?? 89 54 24 14 b2 03 f6 ea 8a 54 24 0f c1 e3 04 02 d0 c0 e2 06 89 5c 24 10 88 54 24}  //weight: 10, accuracy: Low
        $x_10_2 = {2b d1 69 d2 f0 00 00 00 83 c4 24 03 d3 ff d2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

