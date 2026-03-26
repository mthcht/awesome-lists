rule Trojan_Win64_MoonRiseRat_AMOON_2147965721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MoonRiseRat.AMOON!MTB"
        threat_id = "2147965721"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MoonRiseRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 6d 00 48 8b 54 24 50 48 89 94 24 e0 01 00 00 48 8b 74 24 30 48 89 b4 24 e8 01 00 00 4c 8d 05 e7 84 07 00 4c 89 84 24 f0 01 00 00 48 c7 84 24 f8 01 00 00 ?? ?? ?? ?? 4c 8d 0d 84 84 07 00 4c 89 8c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

