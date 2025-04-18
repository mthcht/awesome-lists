rule Trojan_MSIL_ModiRat_AMO_2147939415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ModiRat.AMO!MTB"
        threat_id = "2147939415"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ModiRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 16 0c 08 28 ?? 00 00 06 20 01 80 ff ff fe 01 0d 09 2c 54 08 13 04 02 11 04 28 ?? 00 00 06 13 05 11 05 6f ?? 00 00 0a 16 fe 02 13 06 11 06 2c 2d 02}  //weight: 2, accuracy: Low
        $x_3_2 = "myhousecam.ddns.net" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

