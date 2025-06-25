rule Trojan_MSIL_nJRat_AG_2147838187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/nJRat.AG!MTB"
        threat_id = "2147838187"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "nJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 07 11 04 08 17 28 ?? ?? ?? 0a 11 05 08 17 28 ?? ?? ?? 0a 11 06 08 17 28}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_nJRat_ANJ_2147841499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/nJRat.ANJ!MTB"
        threat_id = "2147841499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "nJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 d2 61 d2 81 0d 00 00 01 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 08 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_nJRat_ANJ_2147841499_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/nJRat.ANJ!MTB"
        threat_id = "2147841499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "nJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 64 11 64 16 11 62 a2 00 11 64 17 07 11 61 17 28 ?? 00 00 0a a2 00 11 64 18 11 0c 11 61 17 28 ?? 00 00 0a a2 00 11 64 19 11 17 11 61 17 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_nJRat_ANJ_2147841499_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/nJRat.ANJ!MTB"
        threat_id = "2147841499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "nJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 2b 41 7e 07 00 00 04 11 04 6f ?? ?? ?? 0a 74 03 00 00 01 6f ?? ?? ?? 0a 2c 25 11 04 08 fe 01 16 fe 01 2c 17 7e 07 00 00 04 08 7e 07 00 00 04 11 04 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_nJRat_ANJ_2147841499_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/nJRat.ANJ!MTB"
        threat_id = "2147841499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "nJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1f 09 8d 1e 00 00 01 13 0d 11 0d 16 11 04 a2 00 11 0d 17 11 05 08 17 28 ?? ?? ?? 0a a2 00 11 0d 18 11 06 08 17 28 ?? ?? ?? 0a a2 00 11 0d 19 11 07 08 17 28}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_nJRat_ANJ_2147841499_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/nJRat.ANJ!MTB"
        threat_id = "2147841499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "nJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 18 00 00 0a 0a 06 28 19 00 00 0a 03 6f 1a 00 00 0a 6f 1b 00 00 0a 0b 73 1c 00 00 0a 0c 08 07 6f 1d 00 00 0a 00 08 18 6f 1e 00 00 0a 00 08 6f 1f 00 00 0a 02 16 02 8e 69 6f 20 00 00 0a 0d 09 13 04 2b 00 11 04}  //weight: 2, accuracy: High
        $x_1_2 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_nJRat_ANJ_2147841499_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/nJRat.ANJ!MTB"
        threat_id = "2147841499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "nJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 0b 16 0c 2b 52 07 08 6f ?? 00 00 0a 0d 16 13 04 2b 33 7e 5a 00 00 04 11 04 6f ?? 00 00 0a 09 33 1e 06 7e 59 00 00 04 11 04 6f ?? 00 00 0a 13 05 12 05 28 ?? 01 00 0a 28}  //weight: 3, accuracy: Low
        $x_2_2 = {2b 12 02 28 ?? 00 00 06 2c 06 16 28 ?? 00 00 0a 06 17 58 0a 06 73 15 00 00 0a 19 1f 0a 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_nJRat_ANJ_2147841499_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/nJRat.ANJ!MTB"
        threat_id = "2147841499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "nJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {14 0a 17 0b 2b 3b 00 02 07 28 ?? 00 00 0a 28 ?? 00 00 0a 03 07 03 6f ?? 00 00 0a 5d 17 58 28 ?? 00 00 0a 28 ?? 00 00 0a 59 0c 06 08 28 ?? 00 00 0a 8c ?? 00 00 01 28 ?? 00 00 0a 0a 00 07 17}  //weight: 3, accuracy: Low
        $x_2_2 = {58 17 59 17 58 17 59 17 58 8d ?? 00 00 01 0c 08 8e 69 17 59 0d 16 13 04 2b 1b 08 11 04 07 11 04 1e 5a 1e 6f ?? 00 00 0a 18 28 ?? 00 00 0a 9c 11 04 17 58 13 04 11 04 09 fe 02 16 fe 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_nJRat_AJ_2147841500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/nJRat.AJ!MTB"
        threat_id = "2147841500"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "nJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 00 02 16 28 45 00 00 0a 00 02 16 28 46 00 00 0a 00 28 0e 00 00 06 0a 06 28 47 00 00 0a 0b 02 07 72 1f 00 00 70}  //weight: 2, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_nJRat_ADF_2147853338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/nJRat.ADF!MTB"
        threat_id = "2147853338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "nJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 04 00 07 08 16 20 00 10 00 00 6f ef 00 00 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 0d 11 04 08 16 11 05 6f 54 00 00 0a 00 00 00 00 11 05 16 fe 02 13 07 11 07 2d cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

