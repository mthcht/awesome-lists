rule Trojan_MSIL_Marsilla_SK_2147919612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilla.SK!MTB"
        threat_id = "2147919612"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5f 95 d2 13 0f 11 1a 11 0f 61 13 10 11 0a 11 06 d4 11 10 d2 9c 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilla_SK_2147919612_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilla.SK!MTB"
        threat_id = "2147919612"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 11 05 18 5b 07 11 05 18 6f 36 00 00 0a 1f 10 28 37 00 00 0a 9c 11 05 18 d6 13 05 11 05 11 04 31 de}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilla_SL_2147927106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilla.SL!MTB"
        threat_id = "2147927106"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 07 09 11 06 09 91 06 11 0b 95 61 d2 9c 09 17 58 0d 09 11 06 8e 69 32 84}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

