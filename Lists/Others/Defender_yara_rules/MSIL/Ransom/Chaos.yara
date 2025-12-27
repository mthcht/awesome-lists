rule Ransom_MSIL_Chaos_AFF_2147832253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Chaos.AFF!MTB"
        threat_id = "2147832253"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chaos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 09 0e 04 6f ?? ?? ?? 0a 26 09 0e 05 6f ?? ?? ?? 0a 26 09 0e 06 8c 28 00 00 01 6f ?? ?? ?? 0a 26 02 50 28 ?? ?? ?? 0a 13 04 11 04 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Chaos_NITA_2147939927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Chaos.NITA!MTB"
        threat_id = "2147939927"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chaos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 28 1d 00 00 0a 6f ?? 00 00 0a 0a 28 ?? 00 00 0a 1f 0a 28 ?? 00 00 06 72 c1 08 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 07 73 21 00 00 0a 0c 00 08 72 6b 0a 00 70 6f ?? 00 00 0a 00 08 72 c5 0a 00 70 06 72 fd 0a 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 de 0b 08 2c 07 08 6f ?? 00 00 0a 00 dc 72 1b 0b 00 70 07 28 ?? 00 00 0a 26 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {06 07 9a 0c 00 02 72 33 0b 00 70 08 28 ?? 00 00 0a 17 28 ?? 00 00 0a 0d 00 09 13 04 16 13 05 2b 22 11 04 11 05 9a 13 06 00 00 11 06 03 28 ?? 00 00 06 00 00 de 06 13 07 00 00 de 00 00 11 05 17 58 13 05 11 05 11 04 8e 69 32 d6 00 07 17 58 0b 07 06 8e 69 32 aa}  //weight: 2, accuracy: Low
        $x_1_3 = {a2 13 06 28 ?? 00 00 0a 13 07 00 11 06 13 0d 16 13 0e 2b 1a 11 0d 11 0e 9a 13 0f 00 11 0f 06 11 05 28 ?? 00 00 06 00 00 11 0e 17 58 13 0e 11 0e 11 0d 8e 69 32 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Chaos_ACH_2147946600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Chaos.ACH!MTB"
        threat_id = "2147946600"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chaos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0c 2b 2e 08 6f ?? 00 00 0a 0d 00 09 28 ?? 00 00 0a 13 04 06 11 04 28 ?? 00 00 2b 13 05 11 05 2c 0f 00 02 7b ?? 00 00 04 09 6f}  //weight: 3, accuracy: Low
        $x_2_2 = {2b 01 16 2b 01 17 0b 04 2c 14 04 2c 0e 0e 05 72 ?? 04 00 70 28 ?? 00 00 0a 2b 01 16 2b 01 17 0c 05 2c 14 05 2c 0e 0e 05 72 ?? 04 00 70 28 ?? 00 00 0a 2b 01}  //weight: 2, accuracy: Low
        $x_1_3 = "10.30.10.243" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

