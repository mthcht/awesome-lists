rule Trojan_Win64_RedCapGo_AB_2147921616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RedCapGo.AB!MTB"
        threat_id = "2147921616"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RedCapGo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 66 26 cb 39 a6 20 d4 8b 8a 10 4a 2d e1 dd 0f 6e a9 55 c5 98 1f 67 b8 83 57 f0 85 6d 98 b9 36 9e c7 5f 5f 1a 53 13 aa 18 57 a7 df 7e 6d d4 45 12 d8 af 8e d2 3f 0c a2 da db a2 2b 56 89 eb 00 69 14 06 a6 91 84 d3 bb ee e2 1f 67 d2 81 52 2b 3e fd c7 d2 92 d3 a5 0a 67 16 0a 0e a3 04 c9 28 15 9e 4d 37 69 b0 d3 43 67 99 98 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

