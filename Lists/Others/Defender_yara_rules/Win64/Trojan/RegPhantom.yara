rule Trojan_Win64_RegPhantom_ARH_2147972262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RegPhantom.ARH!MTB"
        threat_id = "2147972262"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RegPhantom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 45 00 4c 8b 40 30 48 8b 45 08 48 8b 00 48 8b 4d 10 48 8b 09 0f b6 14 08 4c 31 c2 88 14 08 8b 0d ?? 3f 00 00 8b 05 ?? 3f 00 00 89 ca 83 ea 01 0f af ca 83 e1 01 83 f9 00 0f 94 c2 83 f8 0a 0f 9c c0 08 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

