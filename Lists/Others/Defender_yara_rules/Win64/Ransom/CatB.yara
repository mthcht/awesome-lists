rule Ransom_Win64_CatB_A_2147838371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/CatB.A!MTB"
        threat_id = "2147838371"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "CatB"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files are encrypted" ascii //weight: 1
        $x_1_2 = "Bitcoin" ascii //weight: 1
        $x_1_3 = "data loss" ascii //weight: 1
        $x_1_4 = "Free decryption" ascii //weight: 1
        $x_1_5 = "catB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_CatB_AD_2147838913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/CatB.AD!MTB"
        threat_id = "2147838913"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "CatB"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 0f b6 09 48 8b d9 44 0f b6 51 ?? 44 0f b6 41 ?? 4b 8d 14 ?? 0f b6 4c 57 ?? 4b 8d 04 ?? 32 0c ?? 4b 8d 04 ?? 41 32 c8 41 32 ca 88 0b}  //weight: 1, accuracy: Low
        $x_1_2 = {41 32 d0 41 32 d1 88 53 04 0f b6 54 4f ?? 4b 8d 0c ?? 32 14 ?? 4b 8d 04 ?? 44 0f b6 43 ?? 41 32 d3 41 32 d1}  //weight: 1, accuracy: Low
        $x_1_3 = {44 8b c0 8b c8 41 8b d0 48 c1 e9 ?? 83 e1 ?? 48 c1 e8 ?? 48 c1 e1 ?? 83 e0 ?? 48 03 c8 48 c1 ea ?? 83 e2 ?? 48 c1 e2 ?? 42 0f b6 04 19}  //weight: 1, accuracy: Low
        $x_1_4 = {41 8b c8 48 c1 e9 ?? 83 e1 ?? c1 e0 ?? 48 03 d1 42 0f b6 0c 1a 41 8b d0 c1 e1 ?? 03 c1 48 c1 ea ?? 41 8b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

