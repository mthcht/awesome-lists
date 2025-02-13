rule Trojan_Win64_Anchor_ZX_2147773505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Anchor.ZX"
        threat_id = "2147773505"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Anchor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 5c 24 08 57 48 83 ec 20 49 63 d9 4c 8b 0d ?? ?? ?? ?? 4d 85 c9 74 18 8d 43 ff 3d 38 02 00 00 77 0e 49 8b 04 d9 40 b7 01 48 85 c0 75 1a eb 03 40 32 ff e8 ?? ?? ?? ?? 40 84 ff 74 0b 48 8b 0d ?? ?? ?? ?? 48 89 04 d9 48 8b 5c 24 30 48 83 c4 20 5f c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

