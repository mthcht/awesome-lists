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

rule Trojan_MSIL_MassloggerRAT_SEDA_2147934876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassloggerRAT.SEDA!MTB"
        threat_id = "2147934876"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassloggerRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 16 0f 00 28 ?? ?? ?? 0a 9c 25 17 0f 00 28 ?? ?? ?? 0a 9c 25 18 0f 00 28 ?? ?? ?? 0a 9c 6f ?? ?? 00 0a 1b 13}  //weight: 1, accuracy: Low
        $x_3_2 = {58 12 02 28 ?? 00 00 0a 58 20 88 13 00 00 5d 20 e8 03 00 00 58 13 04}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

