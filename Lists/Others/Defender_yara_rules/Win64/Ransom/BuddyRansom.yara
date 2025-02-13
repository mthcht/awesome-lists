rule Ransom_Win64_BuddyRansom_YAA_2147890387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BuddyRansom.YAA!MTB"
        threat_id = "2147890387"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BuddyRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 c2 73 17 41 0f b7 cb 41 ff c3 0f b6 2c 0b 89 d1 83 c2 08 d3 e5 41 01 e8 eb ?? 44 89 c1 29 c2 21 f9 66 43 89 4c 51 ?? 44 89 e1 49 ff c2 41 d3 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {44 31 dd 44 21 d5 41 c1 ca 02 31 dd 01 f5 44 89 e6 c1 c6 05 01 f5 8b 71}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

