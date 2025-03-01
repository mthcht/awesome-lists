rule Trojan_MSIL_njRat_MBAD_2147838484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRat.MBAD!MTB"
        threat_id = "2147838484"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 04 09 04 6f ?? 00 00 0a 5d 17 d6 28 ?? 00 00 0a da 13 04 07 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 09 17 d6 0d 09 08 31 cb}  //weight: 10, accuracy: Low
        $x_2_2 = "VeginereDecrypt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRat_MBBJ_2147840354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRat.MBBJ!MTB"
        threat_id = "2147840354"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 00 32 00 33 00 00 a9 d9 51 00 37 00 42 00 67 00 5a 00 41 00 46 00 4b 00 78 00 67 00 77 00 6b 00 32 00 4c 00 49 00 52 00 79 00 44 00 43 00 4d 00 48 00 75 00 67 00 44 00 41}  //weight: 1, accuracy: High
        $x_1_2 = {43 00 50 00 58 00 4f 00 78 00 37 00 36 00 39 00 30 00 42 00 73 00 39 00 57 00 59 00 62 00 61 00 77 00 75 00 70 00 76 00 47 00 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRat_MBCQ_2147843959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRat.MBCQ!MTB"
        threat_id = "2147843959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DwQAQwFTAJAPBAAEgAAAAAAAAAAAAAAAAAAAAAAz" wide //weight: 1
        $x_1_2 = "g0DAEMBDQAcDgMAQwEPAFcOAwA" wide //weight: 1
        $x_1_3 = "EntryPoint" wide //weight: 1
        $x_1_4 = "Invoke" wide //weight: 1
        $x_1_5 = "FromBase64String" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRat_MBFR_2147850543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRat.MBFR!MTB"
        threat_id = "2147850543"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0c 2b 01 00 0f 00 08 20 00 04 00 00 58 28 ?? 00 00 2b 07 02 08 20 00 04 00 00 20 08 03 00 00 20 40 03 00 00 28 de 01 00 06 0d 08 09 58 0c 09 20 00 04 00 00 fe 04 2c cb}  //weight: 1, accuracy: Low
        $x_1_2 = "3-5001c90b71e7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRat_MBGD_2147850556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRat.MBGD!MTB"
        threat_id = "2147850556"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 3c 02 07 28 ?? 00 00 0a 28 ?? 00 00 0a 03 07 03 6f ?? 00 00 0a 5d 17 d6 28 ?? 00 00 0a 28 ?? 00 00 0a da 13 04 09 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0d 07 17 d6 0b 00 07 08 fe 02 16 fe 01 13 05 11 05 2d b7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRat_MBXH_2147916089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRat.MBXH!MTB"
        threat_id = "2147916089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 08 6f 94 00 00 0a 0d 09 06 08 59 61 d2 13 04 09 1e 63 08 61 d2 13 05 07 08 11 05 1e 62 11 04}  //weight: 5, accuracy: High
        $x_3_2 = "3a9bfdf8eba4455a4.resour" ascii //weight: 3
        $x_2_3 = {6c 76 65 00 53 65 72 76 65 72 20 6e 65 77}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRat_AE_2147918393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRat.AE!MTB"
        threat_id = "2147918393"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {11 00 11 03 11 00 11 01 11 03 59 17 59 91 9c 20}  //weight: 3, accuracy: High
        $x_2_2 = {59 17 59 11}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

