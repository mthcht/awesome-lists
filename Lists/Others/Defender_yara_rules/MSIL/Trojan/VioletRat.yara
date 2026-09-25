rule Trojan_MSIL_VioletRat_CB_2147978872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VioletRat.CB!MTB"
        threat_id = "2147978872"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VioletRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 13 05 02 06 28 ?? ?? 00 06 8d ?? 00 00 01 13 06 16 13 07 07 0e 04 0e 04 8e 69 12 04 11 06 11 06 8e 69 14 16 12 07 16 28 ?? ?? 00 06 13 08 11 08 39 ?? 00 00 00 00 28 ?? 00 00 0a 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 11 08 8c ?? 00 00 01 28 ?? ?? 00 0a 73 ?? ?? 00 0a 7a 11 07 8d ?? 00 00 01 0d 07 0e 04 0e 04 8e 69 12 04 11 06 11 06 8e 69 09 09 8e 69 12 07 16}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

