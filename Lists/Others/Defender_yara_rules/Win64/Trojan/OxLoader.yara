rule Trojan_Win64_OxLoader_GVA_2147972748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OxLoader.GVA!MTB"
        threat_id = "2147972748"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OxLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3b cb ed 0f 62 6e d8 a7 56 e0 9f 59 d3 ca 4e 6c c5 10 df 61 5e 2d 83 75 5c 19 04 cf d6 82 04 84}  //weight: 1, accuracy: High
        $x_1_2 = {d0 52 46 4c c2 33 7b 64 20 61 5a 6a df aa 3b bc bc bc 3c 62 d1 5c 3c 76 b9 77 2c e7 b6 ec 57 19}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_OxLoader_AOXL_2147973383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OxLoader.AOXL!MTB"
        threat_id = "2147973383"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OxLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4d 0f a3 c0 c9 2a 23 05 0e e6 d8 3b a2 05 53 64 cb 97 51 93 00 44 30 14 0a 44 02 14 0a e2 f6 58 ab}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

