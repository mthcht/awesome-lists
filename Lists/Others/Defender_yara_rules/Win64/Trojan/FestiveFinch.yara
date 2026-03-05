rule Trojan_Win64_FestiveFinch_D_2147964132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FestiveFinch.D"
        threat_id = "2147964132"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FestiveFinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 3d fc 12 00 00 [0-30] 8b 0c 24 33 d2 8b 04 24 41 b8 08 00 00 00 41 f7 f0 8b c2 8b c0 0f b6 44 04 08 48 8b 54 24 10 0f b6 4c 0a 08 33 c8 8b c1 8b 0c 24 48 8d ?? ?? ?? ?? ?? 88 44 0a 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

