rule Trojan_Win64_AdaptixC2_AHC_2147961567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AdaptixC2.AHC!MTB"
        threat_id = "2147961567"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AdaptixC2"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {48 d3 ef 8d 48 ?? 41 29 f8 44 31 c1 0f b6 c9 66 89 4c 45 00 48 83 c0 ?? 48 83 f8 ?? 75}  //weight: 30, accuracy: Low
        $x_20_2 = {89 d1 8d 50 [0-4] 31 ca 0f b6 d2 66 41 89 14 ?? 48 83 c0 ?? 48 83 f8}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AdaptixC2_SXA_2147961638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AdaptixC2.SXA!MTB"
        threat_id = "2147961638"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AdaptixC2"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {ff c0 89 44 24 ?? 83 7c 24 ?? 10 7d 26 e8 ?? ?? ?? ?? 33 d2 b9 00 01 00 00 f7 f1 8b c2 48 63 4c 24}  //weight: 20, accuracy: Low
        $x_10_2 = {8b c1 88 44 24 ?? 0f b6 44 24 ?? d0 e0 88 44 24 ?? 48 8b 84 24 ?? ?? ?? ?? 48 8b 00 0f b6 4c 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

