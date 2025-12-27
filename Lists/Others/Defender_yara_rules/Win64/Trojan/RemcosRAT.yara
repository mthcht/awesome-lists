rule Trojan_Win64_RemcosRAT_KAT_2147946557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RemcosRAT.KAT!MTB"
        threat_id = "2147946557"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 30 00 00 00 48 8b 50 60 48 85 c9 75 09 48 8b 42 10 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

