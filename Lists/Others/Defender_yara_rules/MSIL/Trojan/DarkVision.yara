rule Trojan_MSIL_DarkVision_AMCL_2147926943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkVision.AMCL!MTB"
        threat_id = "2147926943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkVision"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {1e 62 60 0f ?? 28 ?? 00 00 0a 60 0a 02 06 1f 10 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 02 06 1e 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 02 06 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = {9c 25 18 0f ?? 28 ?? 00 00 0a 9c 0b 02 07 04 28 ?? 00 00 2b 6f ?? 00 00 0a 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkVision_AHGA_2147928387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkVision.AHGA!MTB"
        threat_id = "2147928387"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkVision"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8e 69 5d 1d 58 1f 10 58 1f 18 59 1f 19 58 1f 18 59 91 61 03 08 20 0a 02 00 00 58 20 09 02 00 00 59 1e 59 1e 58 03 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkVision_APJA_2147931580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkVision.APJA!MTB"
        threat_id = "2147931580"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkVision"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 03 06 1a 58 4a 20 0b 02 00 00 58 20 0a 02 00 00 59 1f 09 59 1f 09 58 03 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkVision_AMCZ_2147932346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkVision.AMCZ!MTB"
        threat_id = "2147932346"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkVision"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0d 09 07 6f ?? 00 00 0a 09 08 6f ?? 00 00 0a 09 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 13 04 de}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

