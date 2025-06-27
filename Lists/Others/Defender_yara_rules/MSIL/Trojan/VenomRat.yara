rule Trojan_MSIL_VenomRat_AVN_2147929611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VenomRat.AVN!MTB"
        threat_id = "2147929611"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VenomRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 07 2b 29 11 06 11 07 e0 58 11 04 11 07 91 52 11 06 11 07 e0 58 47 11 04 11 07 91 fe 01 16 fe 01 13 08 11 08 2d dd 11 07 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VenomRat_AXXA_2147944906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VenomRat.AXXA!MTB"
        threat_id = "2147944906"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VenomRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0c 2b 29 02 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 0d 07 09 b4 6f ?? 00 00 0a 00 08 17 d6 0c 00 08 8c ?? 00 00 01 02 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 16 28 ?? 00 00 0a 13 04 11 04 2d b0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

