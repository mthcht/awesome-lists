rule Trojan_MSIL_MassloggerRAT_SYDF_2147929789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassloggerRAT.SYDF!MTB"
        threat_id = "2147929789"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassloggerRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0b 00 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 13 04 de 16 07 2c 07 07}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

