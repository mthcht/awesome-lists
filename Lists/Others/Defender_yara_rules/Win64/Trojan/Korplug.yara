rule Trojan_Win64_Korplug_AT_2147920333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Korplug.AT!MTB"
        threat_id = "2147920333"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Korplug"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 57 31 ff 56 89 d6 53 83 ec 2c 8b 5d 08 8b 42 04 89 4d e4 2b 45 08 01 d3 89 45 e0 89 43 04 8b 45 08 89 7b 0c 89 7b 10 8b 7a 04 89 03 89 c8 01 d7 89 4b 08 05 80 10 00 00 89 fa 89 c1 89 45 dc c1 fa 0c}  //weight: 1, accuracy: High
        $x_1_2 = {55 89 e5 83 ec 18 89 44 24 04 31 c0 c7 44 24 0c 04 00 00 00 c7 44 24 08 00 30 00 00 89 04 24 ff 15 ?? ?? ?? ?? 83 ec 10 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {89 de b8 01 00 00 00 89 d9 c1 fe 05 d3 e0 83 e6 0f 23 44 b2 08 0f 95 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Korplug_GVN_2147964475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Korplug.GVN!MTB"
        threat_id = "2147964475"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Korplug"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f af c2 83 e0 01 83 f8 00 0f 94 c0 83 f9 0a 0f 9c c1 88 c2 20 ca 30 c8 08 c2 b8 89 cf 75 d8 b9 90 f7 6a cd f6 c2 01 0f 45 c1 89 45 ac e9 e1 03 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

