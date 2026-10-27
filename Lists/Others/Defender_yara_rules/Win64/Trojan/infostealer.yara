rule Trojan_Win64_infostealer_LR_2147980987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/infostealer.LR!MTB"
        threat_id = "2147980987"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "infostealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {4c 8b 5c 24 70 48 8b 5c 24 78 49 ba d0 6a 09 7f b5 af f6 1f 49 83 c2 36 49 f7 d2 48 b9 28 bc 44 20 17 eb 9e 1a 48 83 c1 4d 4c 01 d1 48 be 07 b5 d1 9a 3a 8d 81 a7 48 0f af f1 48 39 f2}  //weight: 20, accuracy: High
        $x_10_2 = {44 31 cd 40 20 ee 42 88 b4 04 c8 00 00 00 66 41 b9 bf 00 41 29 e9 41 29 e9 41 f7 d9 41 f7 d1 48 89 d6 41 0f b7 c9 48 39 d1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

