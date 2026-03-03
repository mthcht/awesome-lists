rule Trojan_Win64_BruteRat_ABR_2147964054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRat.ABR!MTB"
        threat_id = "2147964054"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 e2 48 01 d9 e8 ?? ?? ?? ?? 41 89 c0 48 8d 46 01 45 85 c0 75 1c 8b 57 24 48 01 f6 8b 47 1c 48 01 de 0f b7 14 16 48 8d 14 93 8b 04 02 48 01 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

