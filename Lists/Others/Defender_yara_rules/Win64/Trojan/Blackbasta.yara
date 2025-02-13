rule Trojan_Win64_Blackbasta_BH_2147846407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Blackbasta.BH!MTB"
        threat_id = "2147846407"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Blackbasta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 44 24 24 48 69 c0 08 01 00 00 48 8d 0d ab 93 1b 00 48 03 c8 48 8b c1 48 63 4c 24 28 48 6b c9 21 48 03 c1 48 63 4c 24 2c 48 6b c9 0b 48 03 c1 48 63 4c 24 30 0f b6 04 08 44 8b c0 8b 54 24 38 48 8b 4c 24 50 e8 43 62 19 00 85 c0 74 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

