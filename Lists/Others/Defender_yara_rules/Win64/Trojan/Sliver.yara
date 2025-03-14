rule Trojan_Win64_Sliver_D_2147805308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sliver.D"
        threat_id = "2147805308"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sliver"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "124"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {48 83 ec 38 48 89 6c 24 30 48 8d 6c 24 30 48 8d 05 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 44 24 18 c6 00 ?? 48 8d 05 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 44 24 28 48 c7 00 00 00 00 00 48 8d 05 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 44 24 20 48 8d 05 ?? ?? ?? ?? 0f 1f 00 e8 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 48 89 08 83 ?? ?? ?? ?? 00 00 75 20 48 8b 4c 24 28 48 89 48 08 48 8b 5c 24 18 48 89 58 10 48 8b 5c 24 20 48 89 58 18 48 89 03 eb 35}  //weight: 100, accuracy: Low
        $x_10_2 = {48 0f ba e0 3f 73 1a 48 89 c1 48 d1 e0 48 c1 e8 1f 48 ba 80 7f b1 d7 0d 00 00 00}  //weight: 10, accuracy: High
        $x_10_3 = {44 0f b6 04 0f 49 89 c9 48 31 c1 41 01 c8 46 88 04 0f 49 8d 49 01}  //weight: 10, accuracy: High
        $x_1_4 = {66 81 39 77 67}  //weight: 1, accuracy: High
        $x_1_5 = {80 79 02 73}  //weight: 1, accuracy: High
        $x_1_6 = {81 39 68 74 74 70}  //weight: 1, accuracy: High
        $x_1_7 = {80 79 04 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sliver_ASV_2147894261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sliver.ASV!MTB"
        threat_id = "2147894261"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c1 b9 04 00 00 00 48 6b c9 00 48 8b 54 24 40 89 44 0a 1c 48 8b 44 24 40 48 63 40 4c 48 8b 4c 24 40 48 8b 49 78 0f b6 54 24 64 88 14 01 48 8b 44 24 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sliver_ASV_2147894261_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sliver.ASV!MTB"
        threat_id = "2147894261"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 45 17 e8 ?? ?? ?? ?? 48 8b c8 48 8d 15 65 3f 00 00 e8 ?? ?? ?? ?? 48 8d 4d d7 48 89 45 1f e8 ?? ?? ?? ?? 48 8b c8 48 8d 15 59 3f 00 00 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {c7 45 db 76 00 61 00 c7 45 df 70 00 69 00 c7 45 e3 33 00 32 00 c7 45 e7 2e 00 64 00 c7 45 eb 6c 00 6c 00 e8 ?? ?? ?? ?? 48 8b c8 48 8d 15 8b 3f 00 00 e8 ?? ?? ?? ?? 48 8d 4d d7 48 8b d8}  //weight: 1, accuracy: Low
        $x_3_3 = {57 48 83 ec 20 48 8d 15 6d 3e 00 00 48 8d 0d 6e 3e 00 00 e8 ?? ?? ?? ?? 33 d2 48 8b c8 48 8b f8 44 8d 42 02 e8 ?? ?? ?? ?? 48 8b cf e8 3e 0f 00 00 48 63 d8 45 33 c0 33 d2 48 8b cf 48 8b eb e8 ?? ?? ?? ?? 48 8b cb e8 ?? ?? ?? ?? 4c 8b cf 41 b8 01 00 00 00 48 8b d3 48 8b c8}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sliver_A_2147935988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sliver.A!MTB"
        threat_id = "2147935988"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 8b 20 01 00 00 2b 4b 74 81 c1 1d 14 00 00 89 4b 64 8b 83 f8 00 00 00 39 83 04 01 00 00 73 0d 8b 43 2c 35 1b 14 00 00 2b c8 89 4b 64 48 8b 05 0a 28 6b 00 44 8d ?? ?? 83 f7 38 48 89 05 ec 27 6b 00 45 8b cf 48 89 5c 24 20 8b cf 41 8d ?? ?? 41 81 f1 de 03 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

