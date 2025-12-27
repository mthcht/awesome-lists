rule Trojan_MSIL_SpectreLoader_AJDB_2147949941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpectreLoader.AJDB!MTB"
        threat_id = "2147949941"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpectreLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 0f 2b 7a 1f 28 8d ?? 00 00 01 13 10 11 05 11 06 1f 18 11 0c 58 58 1f 28 11 0f 5a 58 11 10 16 1f 28 28 ?? 00 00 0a 11 10 1f 14 28 ?? 00 00 0a 13 11 11 10 1f 10 28 ?? 00 00 0a 13 12 11 10 1f 0c 28 ?? 00 00 0a 13 13 11 12 8d ?? 00 00 01 13 14 11 05 11 11 11 14 16 11 14 8e 69 28 ?? 00 00 0a 11 0e 11 07 11 13 6a 58 11 14 11 14 8e 69 16 6a 28 ?? 00 00 06 26 11 0f 17 58 68 13 0f 11 0f 11 08 32 80}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpectreLoader_ALSE_2147952320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpectreLoader.ALSE!MTB"
        threat_id = "2147952320"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpectreLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 14 11 05 11 11 11 14 16 11 14 8e 69 28 ?? 00 00 0a 11 0e 11 07 11 13 6a 58 11 14 11 14 8e 69 16 6a 28 ?? 00 00 06 26 11 0f 17 58 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

