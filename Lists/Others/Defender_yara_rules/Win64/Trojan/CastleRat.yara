rule Trojan_Win64_CastleRat_ACT_2147958999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CastleRat.ACT!MTB"
        threat_id = "2147958999"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CastleRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c0 b9 10 04 00 00 f3 aa 4c 8d 44 24 50 48 8d 54 24 50 b9 04 00 00 00 ff 15 ?? ?? ?? ?? 41 b8 04 01 00 00 48 8d 94 24 e0 00 00 00 48 8b 4c 24 50 ff 15 ?? ?? ?? ?? 4c 8d 84 24 e0 00 00 00 48 8d 15 c7 85 02 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

