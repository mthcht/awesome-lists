rule Trojan_MSIL_MonikerLoader_ST_2147964186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MonikerLoader.ST!MTB"
        threat_id = "2147964186"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MonikerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 06 08 91 1f 4d 58 0d 09 1f 78 61 0d 07 08 09 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 13 04 11 04 2d dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MonikerLoader_SU_2147964187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MonikerLoader.SU!MTB"
        threat_id = "2147964187"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MonikerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 09 91 1f 4d 58 13 04 11 04 1f 78 61 13 04 07 09 11 04 d2 9c 09 17 58 0d 09 06 8e 69 32 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MonikerLoader_SV_2147964188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MonikerLoader.SV!MTB"
        threat_id = "2147964188"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MonikerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 07 91 1f 4d 58 0c 08 1f 78 61 0c 06 07 08 d2 9c 07 17 58 0b 07 02 8e 69 32 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

