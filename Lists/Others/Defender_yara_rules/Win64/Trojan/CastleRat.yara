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

rule Trojan_Win64_CastleRat_AB_2147974301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CastleRat.AB!MTB"
        threat_id = "2147974301"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CastleRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {48 8d 44 24 34 48 89 44 24 28 c7 44 24 20 00 00 00 00 4c 8b 0d 51 8e 17 00 4c 8d 05 62 fb 00 00 33 d2 33 c9 e8 b1 7c 13 00 48 89 44 24 40 48 8b 4c 24 40 ff 15 41 62 15 00 41 b8 00 00 00 10 33 d2 33 c9 ff 15 91 65 15 00 48 89 05 c2 9d 18 00 4c 8b 0d 7b 90 17 00 41 b8 04 01 00 00 48 8b 15 2e 90 17 00 48 8d 4c 24 50}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

