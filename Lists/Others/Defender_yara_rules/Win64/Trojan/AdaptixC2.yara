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

