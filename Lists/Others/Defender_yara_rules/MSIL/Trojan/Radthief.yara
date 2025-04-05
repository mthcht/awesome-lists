rule Trojan_MSIL_Radthief_SIF_2147937239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Radthief.SIF!MTB"
        threat_id = "2147937239"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1f 10 8d 1a 00 00 01 0b 1f 10 8d 1a 00 00 01 0c 7e 34 00 00 0a 0d 14 fe 06 1f 00 00 06 73 27 00 00 06 13 04 20 00 10 00 00 8d 1a 00 00 01 13 05 73 37 00 00 0a 13 06 7e 1d 00 00 04 16 08 16 1f 10 28 38 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Radthief_MKV_2147937870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Radthief.MKV!MTB"
        threat_id = "2147937870"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 08 8d 1a 00 00 01 13 0b 06 1e 11 0b 16 11 08 28 ?? 00 00 0a 00 11 07 11 0b 16 11 0b 8e 69 6f 40 00 00 0a 13 0c 11 0c 11 0c 8e 69 11 05 20 00 10 00 00 28 20 00 00 06 20 00 10 00 00 fe 01 16 fe 01 13 18 11 18 3a 98 01 00 00 00 11 09 8d 1a 00 00 01 13 0d 12 0e 11 0a 28 4c 00 00 0a 00 11 0a 28 4d 00 00 0a 13 0f 06 1e 11 08 58 11 09 58 11 0f 11 0a 28 47 00 00 0a 00 06 1e 11 08 58 11 0d 16 11 09 28 38 00 00 0a 00 20 00 20 00 00 8d 1a 00 00 01 13 10 11 0d 11 09 11 10 20 00 20 00 00 ?? 20 00 00 06 13 11 11 11 16 fe 02 16 fe 01 13 18 11 18 3a 21 01 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

