rule Ransom_Win64_BastaLoader_AA_2147842876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BastaLoader.AA!MTB"
        threat_id = "2147842876"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BastaLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 ?? 48 8b 44 24 ?? 48 8b 4c 24 ?? 48 8b 09 48 8b 40 ?? 48 2b c1 48 89 84 24 ?? ?? ?? ?? 48 63 44 24 ?? 48 3b 84 24 ?? ?? ?? ?? 0f 83}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8d 44 24 ?? 48 89 84 24 ?? ?? ?? ?? 48 63 44 24 ?? 48 8b 8c 24 ?? ?? ?? ?? 48 8b 09 48 03 c8 48 8b c1 48 89 84 24 ?? ?? ?? ?? 48 63 44 24 ?? 48 8b d0 48 8d 8c 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? 48 8b 94 24 ?? ?? ?? ?? 48 8b 8c 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_3 = "VisibleEntry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_BastaLoader_NE_2147894438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BastaLoader.NE!MTB"
        threat_id = "2147894438"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BastaLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 3a 3a 9c 59 ?? ?? ?? ?? 44 ec 33 4f ?? 43 43 eb ?? 34 ?? ac 1b 44 6c ?? c7 47}  //weight: 1, accuracy: Low
        $x_1_2 = {31 3a 3a 9c 59 ?? ?? ?? ?? ec d3 c7 42 63 43}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_BastaLoader_KF_2147899735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BastaLoader.KF!MTB"
        threat_id = "2147899735"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BastaLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 89 c8 11 89 ?? ?? ?? ?? 2c ?? 3c ?? 85 65 ?? be ?? ?? ?? ?? c8 ?? ?? ?? 89 76 ?? 65 79}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c8 3b 70 ?? 30 89 ?? ?? ?? ?? 29 aa ?? ?? ?? ?? 89 c8 00 89 ?? ?? ?? ?? 89 c0 05 ?? ?? ?? ?? 0d ?? ?? ?? ?? 0d ?? ?? ?? ?? 0d ?? ?? ?? ?? 69 be ?? ?? ?? ?? ?? ?? ?? ?? 7b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

