rule Ransom_Win64_QuantumLocker_AA_2147819041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/QuantumLocker.AA!MTB"
        threat_id = "2147819041"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "QuantumLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 44 24 ?? 66 ff c0 66 89 44 24 ?? 0f b7 44 24 ?? 0f b7 4c 24 ?? 3b c1 7d ?? 8b 4c 24 ?? e8 ?? ?? ?? ?? 89 44 24 ?? 0f b7 44 24 ?? 48 8b 4c 24 ?? 0f b6 04 01 0f b6 4c 24 ?? 33 c1 0f b7 4c 24 ?? 48 8b 54 24 ?? 88 04 0a eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_QuantumLocker_AA_2147819434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/QuantumLocker.AA"
        threat_id = "2147819434"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "QuantumLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {0f b7 44 24 20 66 ff c0 66 89 44 24 20 0f b7 44 24 20 0f b7 4c 24 24 3b c1 7d 31 8b 4c 24 28 e8 ?? ?? ?? ?? 89 44 24 28 0f b7 44 24 20 48 8b 4c 24 40 0f b6 04 01 0f b6 4c 24 28 33 c1 0f b7 4c 24 20 48 8b 54 24 48 88 04 0a eb b4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_QuantumLocker_DA_2147825048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/QuantumLocker.DA!MTB"
        threat_id = "2147825048"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "QuantumLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 1f 80 00 00 00 00 0f b6 c3 41 2a c4 32 03 40 32 c7 88 03 49 03 df 48 3b dd 72 ?? 48 ff c6 49 ff c5 49 ff ce 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

