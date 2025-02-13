rule Trojan_Win64_GravityRat_AGRV_2147932457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GravityRat.AGRV!MTB"
        threat_id = "2147932457"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GravityRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 54 24 3c 8b 04 3b 89 44 24 38 48 89 1c 24 48 89 74 24 08 48 89 4c 24 10 e8 ?? ?? ?? ?? 0f 10 44 24 18 0f 11 44 24 70 0f 10 44 24 28 0f 11 84 24 80 00 00 00 8b 44 24 3c 0f c8 89 44 24 68 8b 44 24 38 0f c8}  //weight: 2, accuracy: Low
        $x_1_2 = {48 89 f9 48 29 df 48 f7 df 48 c1 ff 3f 48 21 df 48 89 c6 48 29 d8 48 8b 5c 24 50 8b 14 13 48 83 f8 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

