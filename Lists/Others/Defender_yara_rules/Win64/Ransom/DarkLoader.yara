rule Ransom_Win64_DarkLoader_AA_2147844344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/DarkLoader.AA!MTB"
        threat_id = "2147844344"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "DarkLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 63 d0 0f b6 04 0a 41 88 04 ?? 44 88 ?? 0a 41 0f b6 ?? ?? ?? 03 [0-3] 0f b6 c2 0f b6 14 08 32 14 2f 88 17 48 ff c7 48 83 eb 01 41 ff c1 41 81 e1 ?? ?? ?? ?? 4d 63 ?? 45 0f b6 ?? ?? 45 03 ?? 41 81 e0 ?? ?? ?? ?? 49 63 d0 0f b6 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

