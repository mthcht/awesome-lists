rule Trojan_MSIL_DarkKomet_MBDB_2147844936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkKomet.MBDB!MTB"
        threat_id = "2147844936"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 03 50 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 0c 00 00 0a 0c 08 07 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 08 6f ?? 00 00 0a 02 50 16 02 50 8e 69 6f ?? 00 00 0a 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "Win32Helper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkKomet_MBFD_2147849896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkKomet.MBFD!MTB"
        threat_id = "2147849896"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0f 08 11 13 9a 28 ?? 00 00 0a 11 12 11 13 6f ?? 00 00 0a 6a 61 b7 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 13 0f 11 13 17 d6 13 13 11 13 11 22 31 cc}  //weight: 1, accuracy: Low
        $x_1_2 = "uWrCdQiIgR" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkKomet_AAOJ_2147890075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkKomet.AAOJ!MTB"
        threat_id = "2147890075"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 00 60 05 00 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 06 0a 2b 07 28 ?? 00 00 06 2b e1 06 16 06 8e 69 28 ?? 00 00 06 2b 07 28 ?? 00 00 0a 2b cb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkKomet_AAOX_2147890435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkKomet.AAOX!MTB"
        threat_id = "2147890435"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b 40 2b 41 2b 42 08 91 06 08 06 8e b7 5d 91 61 9c 08 17 d6 16 2d d7 0c 1b 2c 09}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkKomet_AATY_2147893862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkKomet.AATY!MTB"
        threat_id = "2147893862"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 8e b7 6f ?? 00 00 0a 6f ?? 00 00 0a 73 ?? 00 00 0a 13 04 11 04 11 05 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0d 02 28 ?? 00 00 0a 0b 09 07 16 07 8e b7 6f ?? 00 00 0a 09 6f ?? 00 00 0a 28 ?? 00 00 0a 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 10 00 de 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkKomet_AAUH_2147894375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkKomet.AAUH!MTB"
        threat_id = "2147894375"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 07 11 0f 02 11 0f 91 11 04 61 11 08 11 0a 91 61 b4 9c 11 0a 03 6f ?? 00 00 0a 17 da 33 05 16 13 0a 2b 06 11 0a 17 d6 13 0a 11 0f 17 d6 13 0f 11 0f 11 10 31 ca}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkKomet_AALJ_2147896761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkKomet.AALJ!MTB"
        threat_id = "2147896761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 0d 16 13 04 2b 2a 09 11 04 9a 13 05 07 72 ?? ?? 00 70 11 05 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 26 00 11 04 17 d6 13 04 11 04 09 8e 69 fe 04 13 06 11 06 2d c9}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkKomet_CHAA_2147901542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkKomet.CHAA!MTB"
        threat_id = "2147901542"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 11 06 11 04 6f ?? 00 00 0a 13 05 06 08 19 d8 18 d6 12 05 28 ?? 00 00 0a 9c 06 08 19 d8 17 d6 12 05 28 ?? 00 00 0a 9c 06 08 19 d8 12 05 28 ?? 00 00 0a 9c 08 17 d6 0c 11 06 17 d6 13 06 11 06 11 07 31 bc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkKomet_DEAA_2147902139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkKomet.DEAA!MTB"
        threat_id = "2147902139"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 11 08 03 11 08 91 06 11 08 07 5d 91 61 9c 00 11 08 17 d6 13 08 11 08 11 0b 31 e4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkKomet_UFAA_2147919256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkKomet.UFAA!MTB"
        threat_id = "2147919256"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 11 06 91 13 05 02 11 06 17 58 91 13 04 11 04 18 5a 06 59 11 05 59 0c 06 11 05 59 11 04 58 0d 02 11 06 09 20 00 01 00 00 5d 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 02 11 06 17 58 08 20 00 01 00 00 5d 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 11 06 18 58 13 06}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkKomet_SIL_2147935954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkKomet.SIL!MTB"
        threat_id = "2147935954"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 6f 66 00 00 0a 03 16 03 8e b7 6f 67 00 00 0a 0a de 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

