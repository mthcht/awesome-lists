rule Trojan_MSIL_zgRAT_ABSA_2147846497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.ABSA!MTB"
        threat_id = "2147846497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 08 07 6f ?? 00 00 0a 16 73 ?? 00 00 0a 0d 06 8e 69 8d ?? 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 26 11 04 28 ?? 00 00 06 26 73 ?? 00 00 06 17 6f ?? 00 00 06 7e ?? 00 00 04 6f ?? 00 00 06 de 14 09 2c 06 09 6f ?? 00 00 0a dc}  //weight: 5, accuracy: Low
        $x_1_2 = "_007Stub.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_MBFN_2147898427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.MBFN!MTB"
        threat_id = "2147898427"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 07 07 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f 11 0f 11 0c 59 13 10 08 11 06 11 10 11 05 5d d2 9c 07 17 58 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_AE_2147905971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.AE!MTB"
        threat_id = "2147905971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 04 20 00 01 00 00 0e 04 50 74 ?? 00 00 01 0e 04 50 28 ?? 00 00 0a 28 ?? ?? 00 06 05 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_zgRAT_AE_2147905971_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/zgRAT.AE!MTB"
        threat_id = "2147905971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "zgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 00 61 00 45 00 6f 00 01 15 49 00 21 00 6f 00 5b 00 58 00 3b 00 67 00 45 00 5c 00 39 00 00 15 49 00 21 00 6d 00 53 00 72 00 61 00 61 00 26 00 32 00 5a 00 00 15 49 00 21 00 6f 00 73 00 60 00 4b 00 36 00 5f 00 63 00 69 00 00 15 49 00 21 00 6f 00 6d}  //weight: 1, accuracy: High
        $x_1_2 = {49 00 21 00 6d 00 66 00 23 00 6f 00 51 00 62 00 62 00 30 00 00 15 49 00 21 00 70 00 3c 00 6a 00 46 00 2a 00 57 00 28 00 59 00 00 15 49 00 21 00 70 00 2d 00 65 00 4d 00 67 00 39 00 56 00 71 00 01 15 49 00 21 00 6d 00 4d 00 70 00 38 00 39 00 6f 00 4e}  //weight: 1, accuracy: High
        $x_2_3 = "bb16ec941e714ae3d2b837c89603471b" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

