rule Trojan_MSIL_Davinci_RPZ_2147900450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Davinci.RPZ!MTB"
        threat_id = "2147900450"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Davinci"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 91 13 0c 08 11 06 1f 16 5d 91 13 0d 11 0c 11 0d 61 13 0e 07 11 09 11 0e 11 0b 59 11 07 5d d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Davinci_MBZS_2147905689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Davinci.MBZS!MTB"
        threat_id = "2147905689"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Davinci"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 8e 69 5d 91 13 [0-12] 61 11 [0-4] 59 20 00 01 00 00 58 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

