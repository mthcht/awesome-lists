rule Ransom_Win64_Cyclops_PBA_2147849989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Cyclops.PBA!MTB"
        threat_id = "2147849989"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Cyclops"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 ea 10 01 ea 83 c2 ?? 0f b7 d2 89 d3 c1 eb 0f c1 ea 06 01 da 89 d3 c1 e3 07 29 da 01 ea 83 c2 ?? 80 c2 7f 0f b6 d2 8d 2c 52 c1 ed 08 89 d3 40 28 eb d0 eb 40 00 eb c0 eb 06 0f b6 db 89 dd c1 e5 07 29 dd 40 28 ea}  //weight: 2, accuracy: Low
        $x_1_2 = {0f b7 c9 89 cb c1 eb 0f c1 e9 06 01 d9 89 cb c1 e3 07 29 d9 01 d1 81 c1 ?? ?? ?? ?? 80 c1 7f 0f b6 c9 8d 14 49 c1 ea 08 89 cb 28 d3 d0 eb 00 d3 c0 eb 06 0f b6 db 89 da c1 e2 07 29 da 28 d1 88 8c 04}  //weight: 1, accuracy: Low
        $x_1_3 = "cyclops" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_Cyclops_LKV_2147853250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Cyclops.LKV!MTB"
        threat_id = "2147853250"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Cyclops"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 0f b6 04 12 44 09 c8 44 0f a4 c8 08 42 89 84 01 ?? ?? ?? ?? 49 83 fa 1e 77}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e5 07 29 dd 40 28 e9 88 4c 04 ?? 48 83 c0 01 48 83 f8 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Cyclops_LKW_2147853251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Cyclops.LKW!MTB"
        threat_id = "2147853251"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Cyclops"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c0 eb 06 0f b6 eb 89 ea c1 e2 07 29 ea 28 d1 88 4c 04 20 48 83 c0 01 48 83 f8 0e 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

