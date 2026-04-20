rule Trojan_Win64_TigerRat_ATR_2147961677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TigerRat.ATR!MTB"
        threat_id = "2147961677"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TigerRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 d0 4d 8d 52 01 41 32 d3 41 32 c9 41 22 d1 32 c8 41 32 cb 41 88 4a ff 0f b6 c8 41 22 cb 44 0f b6 da 42 8d 14 cd 00 00 00 00 41 33 d1 44 32 d9 41 8b c9 81 e2 f8 07 00 00 c1 e9 08 c1 e2 14 44 8b ca 8d 14 00 33 d0 44 0b c9 8b c8 c1 e2 04 c1 e1 07 33 d0 83 e2 80 33 d1 8b c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

