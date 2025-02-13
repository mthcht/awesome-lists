rule Trojan_Win64_Shelood_MBXY_2147925373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelood.MBXY!MTB"
        threat_id = "2147925373"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelood"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 34 11 33 48 ff c1 48 8b 05 ?? ?? 00 00 48 8b 15 ?? ?? 00 00 48 2b c2 48 3b c8 72}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 28 c6 44 24 60 7e c6 44 24 61 69 c6 44 24 62 a3 c6 44 24 63 33 c6 44 24 64 30 c6 44 24 65 33 c6 44 24 66 33 c6 44 24 67 33 c6 44 24 68 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

