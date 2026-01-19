rule Trojan_Win64_KazuarLoader_CG_2147961317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KazuarLoader.CG!MTB"
        threat_id = "2147961317"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KazuarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 8a 0e 48 8b 1d ?? ?? ?? ?? 83 c9 ?? 88 0b 41 8a 5d 00 0f b6 0c 06 31 d1 80 fb ?? 74}  //weight: 5, accuracy: Low
        $x_5_2 = {8a 04 17 4c 8b 3d ?? ?? ?? ?? 31 c8 88 04 13 41 8a 07 48 ff c2 4c 8b 3d ?? ?? ?? ?? 41 0f af c6 41 88 07 e9}  //weight: 5, accuracy: Low
        $x_5_3 = {45 8a 1f 89 d2 8a 54 14 ?? 45 8d 43 ?? 4c 8b 1d ?? ?? ?? ?? 45 88 03 30 14 03 48 ff c0 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

