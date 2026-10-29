rule Trojan_Win64_SheetRat_AQ_2147981215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SheetRat.AQ!MTB"
        threat_id = "2147981215"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SheetRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 89 d0 89 d1 41 c1 e8 ?? f7 d1 46 8b 84 84 ?? ?? ?? ?? 83 e1 03 c1 e1 03 41 d3 e8 44 30 04 13 48 83 c2 01 48 83 fa}  //weight: 5, accuracy: Low
        $x_5_2 = {41 89 c0 41 c1 e8 ?? 44 31 c0 41 89 c0 01 d0 41 c1 e8 ?? 44 30 04 11 48 83 c2 01 48 39 d6 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

