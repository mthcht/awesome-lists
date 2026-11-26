rule Trojan_Win64_AzaleaRAT_PA_2147982818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AzaleaRAT.PA!MTB"
        threat_id = "2147982818"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AzaleaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 89 c0 41 c1 e0 0e 41 31 c0 45 89 c2 41 c1 ea 15 45 31 c2 44 89 d0 c1 e0 11 44 31 d0 44 69 c0 fd 43 03 00 41 81 c0 13 1e f7 3c 46 0f b6 14 ?? 41 c1 e8 18 45 31 d0 46 88 04 ?? 44 31 d0 c1 c0 07 49 ff c1 4c 39 ca 75 ?? 5b 5f 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

