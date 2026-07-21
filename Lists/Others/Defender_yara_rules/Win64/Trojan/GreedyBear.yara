rule Trojan_Win64_GreedyBear_NG_2147962192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GreedyBear.NG!MTB"
        threat_id = "2147962192"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GreedyBear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 f2 e8 f4 5c 21 00 48 85 c0 0f 84 19 2f 00 00 48 89 c6 eb 05 be 01 00 00 00 48 89 f1 48 8b 95 98 0e 00 00 4c 8b b5 90 0e 00 00 4d 89 f0 e8 4d 8e 3e 00 4c 89 b5 d0 0d 00 00 48 89 b5 d8 0d 00 00 4c 89 b5 e0 0d 00 00 c6 85 e8 0d 00 00 00 41 b8 0b 00 00 00 4c 89 e1 48 8d 15 4a 16 40 00 e8 77 a5 21 00 48 8b 85 d0 0d 00 00 48 89 85 c0 0c 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {48 8d 48 ff 48 89 8d 78 0e 00 00 48 8b 48 ff 48 89 8d 98 0e 00 00 48 8b 40 07 48 89 85 90 0e 00 00 48 8b 00 48 85 c0 74 09 48 8b 8d 98 0e 00 00 ff d0 48 8b b5 98 0e 00 00 48 8b 85 90 0e 00 00 48 83 78 08 00 74 1f 48 83 78 10 11}  //weight: 1, accuracy: High
        $x_1_3 = "dazer.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GreedyBear_NG_2147962192_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GreedyBear.NG!MTB"
        threat_id = "2147962192"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GreedyBear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 8d 10 01 00 00 0f b6 85 28 01 00 00 0f b6 8d 2f 01 00 00 c1 e1 10 0f b7 95 2d 01 00 00 09 ca 48 c1 e2 20 8b 8d 29 01 00 00 48 09 d1 48 8b 9d 30 01 00 00 48 c1 e1 08 48 09 c1 48 89 8d a0 01 00 00 48 8d 8d 80 01 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {48 8d 41 ff 48 89 85 c8 00 00 00 48 8b 41 ff 48 89 85 b0 01 00 00 48 8b 41 07 48 89 85 68 01 00 00 48 8b 00 48 85 c0 74 09 48 8b 8d b0 01 00 00 ff d0}  //weight: 1, accuracy: High
        $x_1_3 = "Voxtek Trust Us With Your Safety" wide //weight: 1
        $x_1_4 = "absolute_solver" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GreedyBear_NB_2147962644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GreedyBear.NB!MTB"
        threat_id = "2147962644"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GreedyBear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8b 11 49 31 c2 44 0f b6 59 08 49 83 f3 ?? ?? 00 00 48 ff c1 48 ff ca 4d 09 d3 75}  //weight: 2, accuracy: Low
        $x_2_2 = {4c 8b 11 49 31 c2 44 0f b6 59 ?? 49 83 f3 ?? 48 ff c1 48 ff ca 4d 09 d3 75}  //weight: 2, accuracy: Low
        $x_2_3 = {44 8b 1a 41 31 c3 8b 72 ?? 31 ce 48 ff c2 49 ff ca 44 09 de 75}  //weight: 2, accuracy: Low
        $x_1_4 = "VirtualBox MAC OUISystemManufacturer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_GreedyBear_NB_2147962644_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GreedyBear.NB!MTB"
        threat_id = "2147962644"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GreedyBear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 c1 48 ff c9 48 89 8d 18 02 00 00 48 8b 48 ff 48 89 8d 38 02 00 00 48 8b 40 07 48 89 85 28 02 00 00 48 8b 00 48 85 c0}  //weight: 2, accuracy: High
        $x_1_2 = {41 b8 01 00 00 00 48 8b 8d 38 02 00 00 e8 45 08 03 00 c6 85 d8 00 00 00 01 48 8b 55 e8 48 8b 7d f0 48 8d 8d d8 00 00 00 48 89 95 38 02 00 00 49 89 f8}  //weight: 1, accuracy: High
        $x_1_3 = "WriteFileEx" ascii //weight: 1
        $x_1_4 = "Voxtek Trust Us With Your Safety" wide //weight: 1
        $x_1_5 = "Absolute Solver" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GreedyBear_NC_2147974262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GreedyBear.NC!MTB"
        threat_id = "2147974262"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GreedyBear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 0f af c0 49 31 c8 48 c1 c1 2f 4c 31 c1 48 89 c8 48 83 c8 01 48 c1 e9 ?? 41 89 c8 41 b9 ?? ?? ?? ?? 4d 0f af c8 49 c1 e9 ?? 47 8d 04 89 47 8d 04 40 44 29 c1 ff c1 49 89 d8 49 31 c0 49 d3 c0}  //weight: 2, accuracy: Low
        $x_1_2 = {41 89 de 41 c1 ee 07 41 31 de 43 8d 1c f6 39 f3}  //weight: 1, accuracy: High
        $x_1_3 = "Encrypted data" ascii //weight: 1
        $x_1_4 = "payload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

