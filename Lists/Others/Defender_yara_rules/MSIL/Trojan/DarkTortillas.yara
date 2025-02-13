rule Trojan_MSIL_DarkTortillas_AALS_2147888292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortillas.AALS!MTB"
        threat_id = "2147888292"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortillas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 07 75 ?? 00 00 1b 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 b4 6f ?? 00 00 0a 18 13 0c 2b 92 08 17 d6 0c 1a 13 0c 2b 89}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortillas_AALV_2147888326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortillas.AALV!MTB"
        threat_id = "2147888326"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortillas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 07 75 ?? 00 00 1b 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 b4 6f ?? 00 00 0a 1d 13 0c 2b 92 08 17 d6 0c ?? 13 0c 2b 89}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortillas_AALW_2147888476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortillas.AALW!MTB"
        threat_id = "2147888476"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortillas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 1e 13 0c 2b 9d 07 74 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c ?? 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

