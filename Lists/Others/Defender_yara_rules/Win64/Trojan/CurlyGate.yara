rule Trojan_Win64_CurlyGate_ARAZ_2147974093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CurlyGate.ARAZ!MTB"
        threat_id = "2147974093"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CurlyGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8b 44 24 34 8b 4c 24 3c d1 e9 39 c8 72 0a c7 44 24 54 11 00 00 00 eb 57 48 8b 44 24 48 8b 4c 24 34 8a 04 08 88 44 24 3b 48 8b 44 24 48 8b 4c 24 3c 83 e9 01 2b 4c 24 34 89 c9 8a 04 08 48 8b 4c 24 48 8b 54 24 34 88 04 11 8a 44 24 3b 48 8b 4c 24 48 8b 54 24 3c 83 ea 01 2b 54 24 34 89 d2 88 04 11 8b 44 24 34 83 c0 01 89 44 24 34 eb 91}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

