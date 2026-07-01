rule Trojan_MSIL_CastleStealer_CZ_2147972207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CastleStealer.CZ!MTB"
        threat_id = "2147972207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CastleStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 17 62 6f ?? ?? ?? ?? 94 7e ?? ?? ?? ?? 02 03 17 62 17 58 6f ?? ?? ?? ?? 94 1a 62 60 2a}  //weight: 5, accuracy: Low
        $x_5_2 = {61 13 0b 11 0b 1f 0f 5f 17}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CastleStealer_ACXB_2147972703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CastleStealer.ACXB!MTB"
        threat_id = "2147972703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CastleStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 02 7b ?? 00 00 04 6f ?? 00 00 0a 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0b 07 03 16 03 8e 69 6f ?? 00 00 0a 0c 06 6f ?? 00 00 0a 8e 69 08 8e 69 58 8d ?? 00 00 01 0d 06 6f ?? 00 00 0a 16 09 16 06 6f ?? 00 00 0a 8e 69 28 ?? 00 00 0a 08 16 09 06 6f ?? 00 00 0a 8e 69 08 8e 69 28 ?? 00 00 0a 09 13 04 de 14}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

