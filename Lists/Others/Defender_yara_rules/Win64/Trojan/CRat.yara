rule Trojan_Win64_CRat_MA_2147847893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CRat.MA!MTB"
        threat_id = "2147847893"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4b 8d 04 02 48 99 83 e2 07 48 03 c2 48 8b c8 83 e0 07 48 2b c2 48 c1 f9 03 48 63 c9 0f b6 14 29 8b c8 b8 01 00 00 00 d3 e0 84 d0 74 ?? 41 b9 ff 00 00 00 45 2a 08 45 88 08 49 ff c0 4c 3b c3 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

