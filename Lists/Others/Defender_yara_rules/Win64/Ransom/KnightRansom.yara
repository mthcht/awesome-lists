rule Ransom_Win64_KnightRansom_PBA_2147853165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/KnightRansom.PBA!MTB"
        threat_id = "2147853165"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "KnightRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 d2 89 d5 c1 ed 0f c1 ea 06 01 ea 89 d5 c1 e5 07 29 ea 01 d1 81 c1 ?? ?? ?? ?? 80 c1 7f 0f b6 c9 8d 14 49 c1 ea 08 89 cb 28 d3 d0 eb 00 d3 c0 eb 06 0f b6 eb 89 ea c1 e2 07 29 ea 28 d1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_KnightRansom_YAA_2147889163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/KnightRansom.YAA!MTB"
        threat_id = "2147889163"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "KnightRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 08 48 8d 40 04 48 83 ea 01 75}  //weight: 1, accuracy: High
        $x_1_2 = {64 00 6f 00 c7 44 24 ?? 69 00 2e 00 c7 44 24 ?? 6f 00 72 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 63 c8 ff c3 48 b8 c5 4e ec c4 4e ec c4 4e 48 f7 e1 48 c1 ea 03 48 6b c2 1a 48 2b c8 0f be 44 0c ?? 66 41 89 06 4d 8d 76 ?? 3b 9c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_KnightRansom_YAB_2147889372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/KnightRansom.YAB!MTB"
        threat_id = "2147889372"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "KnightRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 01 d0 48 89 85 ?? ?? ?? ?? 48 8b 85 ?? ?? ?? ?? 8b 00 33 85 ?? ?? ?? ?? 48 8b 95 ?? ?? ?? ?? 89 02 83 85}  //weight: 1, accuracy: Low
        $x_1_2 = {c5 4e ec c4 4e ec c4 4e 48 89 c8 48 f7 e2 48 89 d0 48 c1 e8 03 48 6b c0 1a 48 29 c1 48 89 c8 0f b6 44 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

