rule Trojan_MSIL_Revcoderat_PZR_2147968453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Revcoderat.PZR!MTB"
        threat_id = "2147968453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Revcoderat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 00 06 11 10 17 58 6f ?? 00 00 0a 8c 26 00 00 01 28 ?? 00 00 0a 13 12 11 12 1f 10 28 ?? 00 00 0a 13 13 11 0f 12 11 28 ?? 00 00 0a 11 13 61 d2 6f ?? 00 00 0a 11 10 18 58 13 10 12 11 28 ?? 00 00 0a [0-5] 11 0f 6f ?? 00 00 0a 13 14 28 ?? 00 00 0a 11 14 6f ?? 00 00 0a 13 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Revcoderat_PQR_2147968454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Revcoderat.PQR!MTB"
        threat_id = "2147968454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Revcoderat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 17 58 20 00 01 00 00 5d 13 05 11 06 08 11 05 91 58 20 00 01 00 00 5d 13 06 08 11 05 91 13 04 08 11 05 08 11 06 91 9c 08 11 06 11 04 9c 08 11 05 91 08 11 06 91 58 20 00 01 00 00 5d 13 08 06 11 07 8f ?? 00 00 01 25 47 08 11 08 91 61 d2 52 11 07 17 58 13 07 11 07 06 8e 69}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

