rule Trojan_Win64_Mozaakai_CE_2147783107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mozaakai.CE!MTB"
        threat_id = "2147783107"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mozaakai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 41 8d 43 [0-1] f7 f1 48 83 c3 [0-1] 4c 63 da 33 d2 47 0f b6 04 13 42 8d 04 06 f7 f1 48 63 f2 33 d2 42 0f b6 04 16 43 88 04 13 46 88 04 16 43 0f b6 04 13 41 03 c0 f7 35 [0-4] 48 63 c2 42 0f b6 0c 10 30 4b ff 48 83 ef [0-1] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mozaakai_MKV_2147907165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mozaakai.MKV!MTB"
        threat_id = "2147907165"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mozaakai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 8b c1 b9 01 00 00 00 48 6b c9 00 48 8b 54 24 40 0f b6 0c 0a 8b 54 24 20 2b d1 8b ca 48 63 c9 48 8b 54 24 ?? 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

