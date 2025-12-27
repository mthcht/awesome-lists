rule Trojan_Win64_Stelega_GVA_2147951372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stelega.GVA!MTB"
        threat_id = "2147951372"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 8b c1 4a 8d 54 02 10 0f b6 12 33 c2 89 45 d4 8b 45 bc ff c0 89 45 bc 8b 45 bc 3b 45 d8 0f 9c c0 0f b6 c0 89 45 b8 83 7d b8 00 75 b4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stelega_GVB_2147951392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stelega.GVB!MTB"
        threat_id = "2147951392"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b d1 48 8d 44 10 10 0f b6 00 33 45 bc 0f b6 c0 89 45 ac 48 8b 45 d8 8b 4d c8 3b 48 08 72 05}  //weight: 2, accuracy: High
        $x_1_2 = {8b d0 48 8d 4c 11 10 0f b6 01 48 8b 4d b8 30 01 90 8b 45 e0 ff c0 89 45 e0 33 c9 83 7d e0 10 0f 9c c1 89 4d cc 83 7d cc 00 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stelega_GVC_2147951393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stelega.GVC!MTB"
        threat_id = "2147951393"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d1 48 8d 44 10 10 48 89 45 e0 8b 45 f0 48 8b 4d e0 30 01 90 8b 45 f4 ff c0 89 45 f4 8b 45 f4 48 8b 4d 10 3b 41 08 0f 9c c0 0f b6 c0 89 45 ec 83 7d ec 00 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

