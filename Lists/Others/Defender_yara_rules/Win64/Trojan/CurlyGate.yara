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

rule Trojan_Win64_CurlyGate_DA_2147976561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CurlyGate.DA!MTB"
        threat_id = "2147976561"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CurlyGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5e 48 61 ff 5e 47 61 ff 5e 47 62 ff 5e 46 62 ff 61 49 64 ff 61 49 62 ff 61 49 62 ff 60 48 61 ff 61 4a 64 ff 5e 49 62 ff 60 4c 65 ff 6c 58 70 ff 86 72 8a ff 66 52 6a ff 62 4d 65 ff 61 4a 63 ff 64 4c 65 ff 62 4a 64 ff 62 4a 65 ff 6a 51 6b ff 62 49 63 ff 62 49 63 ff}  //weight: 1, accuracy: High
        $x_1_2 = {ff 69 46 67 ff 6a 48 67 ff 6a 48 66 ff 6c 4a 68 ff 6c 4a 67 ff 6b 49 66 ff 6b 49 67 ff 6c 4a 67 ff 6e 4d 68 ff 6f 4e 69 ff 6d 4d 66 ff 6b 4d 66 ff 6a 4f 69 ff 78 5c 76 ff 6e 4f 6b ff 6e 4f 6c ff 71 4f 6d ff 75 51 70 ff 75 50 6e ff 75 50 6f ff 74 4d 6d ff}  //weight: 1, accuracy: High
        $x_1_3 = {5a ff 61 45 5a ff 62 45 5c ff 61 44 5b ff 61 43 5c ff 64 46 5f ff 65 47 60 ff 63 45 5e ff 64 45 5e ff 67 47 60 ff 6a 4a 63 ff 70 50 69 ff 69 49 62 ff 69 49 62 ff 6a 4a 63 ff 6d 4b 64 ff 69 46 60 ff 6a 47 61 ff 69 46 60 ff 69 46 60 ff 6c 49 63 ff 70}  //weight: 1, accuracy: High
        $x_1_4 = {ff 6a 52 72 ff 66 51 6f ff 63 4f 6c ff 66 50 6d ff 69 51 6e ff 6f 58 75 ff 65 4d 6b ff 65 4d 6b ff 64 4d 69 ff 64 4d 69 ff 63 4d 67 ff 63 4d 66 ff 5f 49 65 ff 5e 4b 66 ff 81 6e 89 ff 5e 4b 64 ff 5f 49 62 ff 60 48 61 ff 5c 45 5f ff}  //weight: 1, accuracy: High
        $x_1_5 = {5f 48 64 ff 60 49 65 ff 60 49 64 ff 61 4b 64 ff 61 4b 64 ff 60 49 65 ff 5f 48 64 ff 60 49 65 ff 62 4a 68 ff 6f 59 75 ff 60 4a 66 ff 60 4a 66 ff 64 4d 69 ff 61 4a 66 ff 62 49 65 ff 64 4b 67 ff 61 4a 66 ff 62 4b 67 ff}  //weight: 1, accuracy: High
        $x_1_6 = {4e 69 ff 6e 4c 67 ff 6f 4f 6a ff 6f 4e 69 ff 72 4f 6a ff 74 50 6b ff 7a 57 72 ff 74 50 6d ff 72 4f 6d ff 72 4f 6d ff 73 4f 6d ff 77 50 71 ff 79 50 75 ff 78 4f 76 ff 7c 51 75 ff 7c 52 75 ff 7d 52 78 ff 80 54 7d ff 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

