rule Trojan_MSIL_XenoRAT_MBYF_2147909691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRAT.MBYF!MTB"
        threat_id = "2147909691"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 03 6f ?? 00 00 0a 08 06 6f ?? 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {65 6d 6f 76 65 00 6d 61 6e 61 67 69 6e 67 5f 61 70 70 2e 65 78 65 00 63 62 53 69 7a 65 00 46 69 6e 61 6c}  //weight: 1, accuracy: High
        $x_1_3 = {54 00 61 00 73 00 6b 00 20 00 54 00 6f 00 20 00 52 00 75 00 6e 00 00 07 22 00 2c 00 22 00 00 1b 2f 00 64 00 65 00 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XenoRAT_RDA_2147912880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRAT.RDA!MTB"
        threat_id = "2147912880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Important video file do not delete" ascii //weight: 1
        $x_1_2 = "cc7fad03-816e-432c-9b92-001f2d378390" ascii //weight: 1
        $x_1_3 = "server1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XenoRAT_SPBF_2147913670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRAT.SPBF!MTB"
        threat_id = "2147913670"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {28 04 00 00 0a 0c 00 08 03 6f 05 00 00 0a 00 08 06 6f 06 00 00 0a 00 08 08 6f 07 00 00 0a 08 6f 08 00 00 0a 6f 10 00 00 0a 0d 73 0a 00 00 0a 13 04 00 11 04 09 17 73 0b 00 00 0a 13 05 00 11 05 02 16 02 8e 69 6f 0c 00 00 0a 00 11 05 6f 0d 00 00 0a 00 11 04 6f 0e 00 00 0a 0b 00 de 0d}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XenoRAT_RDB_2147915350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRAT.RDB!MTB"
        threat_id = "2147915350"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cc7fad03-816e-432c-9b92-001f2d378392" ascii //weight: 2
        $x_1_2 = "Display Driver Version 3" ascii //weight: 1
        $x_1_3 = "Important display driver" ascii //weight: 1
        $x_1_4 = "server1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XenoRAT_RDC_2147917710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRAT.RDC!MTB"
        threat_id = "2147917710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Display Driver Display Improve Inc" ascii //weight: 1
        $x_1_2 = "HDisplay Driver Recovery" ascii //weight: 1
        $x_1_3 = "Important display driver update (Don not delete)" ascii //weight: 1
        $x_2_4 = "server1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XenoRAT_B_2147919761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRAT.B!MTB"
        threat_id = "2147919761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 04 11 04 28 ?? 00 00 0a 13 05 7e ?? 00 00 0a 11 05 8e 69 20 00 ?? 00 00 1f ?? 28 ?? 00 00 06 13 06 11 05 16 11 06 11 05 8e 69 28}  //weight: 4, accuracy: Low
        $x_2_2 = {0a 16 11 06 7e ?? 00 00 0a 16 7e ?? 00 00 0a 28 ?? 00 00 06 13 07 28 ?? 00 00 0a 13 08 11 08 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XenoRAT_PPPH_2147922443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRAT.PPPH!MTB"
        threat_id = "2147922443"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 06 07 6f ?? 00 00 0a 0c 2b 29 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 2b 11 03 6f ?? 00 00 0a 19 58 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XenoRAT_ZHJ_2147936674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRAT.ZHJ!MTB"
        threat_id = "2147936674"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 08 06 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 0b de 18}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XenoRAT_AR_2147952487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRAT.AR!MTB"
        threat_id = "2147952487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {fe 0c 05 00 fe 09 00 00 28 a8 00 00 06 fe 09 00 00 8e 69 6f 1c 00 00 0a fe 0c 05 00 6f 1d 00 00 0a fe 0c 04 00 6f 1e 00 00 0a fe 0e 00 00 de 20}  //weight: 20, accuracy: High
        $x_10_2 = {fe 09 01 00 8e 69 fe 09 02 00 59 8d 3a 00 00 01 fe 0e 00 00 fe 09 01 00 fe 09 02 00 fe 0c 00 00 28 c5 00 00 06 fe 0c 00 00 8e 69 28 35 00 00 0a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

