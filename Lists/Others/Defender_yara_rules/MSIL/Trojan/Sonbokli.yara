rule Trojan_MSIL_Sonbokli_ASN_2147907198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sonbokli.ASN!MTB"
        threat_id = "2147907198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sonbokli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 10 08 7b 02 00 00 04 8e 69 16 fe 02 16 fe 01 2b 01 17 00 13 05 11 05 2d 0c 00 07 16 6f 13 00 00 0a 00 00 2b 0a 00 07 17 6f 13 00 00 0a 00 00 07}  //weight: 1, accuracy: High
        $x_1_2 = {0a 00 00 06 02 6f ?? 00 00 0a 6f ?? 00 00 0a 0c de 21 0b 00 72 ?? 00 00 70 28 ?? 00 00 0a 00 14 0c de 10 06 14 fe 01 0d 09 2d 07 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

