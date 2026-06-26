rule Trojan_Win64_KongTuke_PAA_2147972438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KongTuke.PAA!MTB"
        threat_id = "2147972438"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KongTuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b c8 4c 8d 44 24 60 4c 03 c1 0f 1f 00 41 0f b6 08 8d 14 18 30 0c 3a 4d 8d 40 01 ff c0 41 3b c1 72 eb 41 03 d9 41 3b dc}  //weight: 3, accuracy: High
        $x_2_2 = {c7 44 24 20 65 78 70 61 c7 44 24 24 6e 64 20 33 c7 44 24 28 32 2d 62 79 c7 44 24 2c 74 65 20 6b 0f 11 44 24 30}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

