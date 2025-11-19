rule Trojan_Win64_OysterLoader_GVA_2147956935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OysterLoader.GVA!MTB"
        threat_id = "2147956935"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OysterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 0f 6e 44 04 ?? 66 0f 60 c0 66 0f 71 e0 08 66 0f d6 44 45 ?? 48 83 c0 04 48 3b c1 72 e2}  //weight: 2, accuracy: Low
        $x_1_2 = {0f be 4c 04 ?? 66 89 4c 45 ?? 48 ff c0 49 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_OysterLoader_GVD_2147957794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OysterLoader.GVD!MTB"
        threat_id = "2147957794"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OysterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 b8 eb 1b 48 8b 4d 20 8b 55}  //weight: 2, accuracy: High
        $x_1_2 = {48 b8 48 83 c4 20 5d c3 90 90}  //weight: 1, accuracy: High
        $x_2_3 = {48 b8 ab 3d 79 d4 62 62 65 4f}  //weight: 2, accuracy: High
        $x_1_4 = {48 b9 07 ad e1 25 e8 4c 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

