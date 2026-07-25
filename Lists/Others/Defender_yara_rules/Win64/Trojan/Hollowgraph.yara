rule Trojan_Win64_Hollowgraph_GVA_2147974523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Hollowgraph.GVA!MTB"
        threat_id = "2147974523"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Hollowgraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 7b 08 03 75 14 8b 4b 0c 81 f1 67 00 65 00 0f b7 43 10 83 f0 74 0b c8 74 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

