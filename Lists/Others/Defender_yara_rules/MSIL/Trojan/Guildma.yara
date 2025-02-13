rule Trojan_MSIL_Guildma_2147838530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Guildma.psyK!MTB"
        threat_id = "2147838530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Guildma"
        severity = "Critical"
        info = "psyK: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {04 20 ff 00 00 00 5f 2b 1d 03 6f ?? ?? ?? 0a 0c 2b 17 08 06 08 06 93 02 7b 03 00 00 04 07 91 04 60 61 d1 9d 2b 03 0b 2b e0 06 17 59 25 0a 16 2f 02 2b 05 2b dd 0a 2b c8}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Guildma_2147844897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Guildma.psyX!MTB"
        threat_id = "2147844897"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Guildma"
        severity = "Critical"
        info = "psyX: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {38 f4 1c 00 00 1f 10 6a 28 95 00 00 06 0a 1f 41 6a 28 95 00 00 06 0b 28 94 00 00 06 06 16 fe 01 5f 07 17 5f 17 fe 01 5f 28 94 00 00 06 16 fe 01 06 16 fe 01 16 fe 01 5f 07 17 5f 17 fe 01 5f 60 0c 08 2c 14 7e 89 00 00 04 72 20 25 00 70 28 72 00 00 0a 80 89 00 00 04 00 28 94 00 00 06 16 fe 01 06 16 fe 01 5f 07 17 5f 17 fe 01 5f 28 94 00 00 06 06 16 fe 01 16 fe 01 5f 07 17 5f 17 fe 01 5f 60 0c 08 2c 14 7e 89 00 00 04 72 f4 25 00 70 28 72 00 00 0a 80 89 00 00 04}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Guildma_2147845837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Guildma.psyT!MTB"
        threat_id = "2147845837"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Guildma"
        severity = "Critical"
        info = "psyT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {28 32 00 00 0a 03 6f 33 00 00 0a 0d 02 02 8e b7 17 da 91 1f 70 61 0a 02 8e b7 17 d6 8d 25 00 00 01 0c 16 02 8e b7 17 da 13 06 13 05 2b 2d 08 11 05 02 11 05 91 06 61 09 11 04 91 61 b4 9c 11 04 03 6f 34 00 00 0a 17 da 33 05 16 13 04 2b 06 11 04 17 d6 13 04 11 05 17 d6 13 05 11 05 11 06 31 cd 08 74 26 00 00 01 02 8e b7 18 da 17 d6 8d 25 00 00 01 28 35 00 00 0a 74 09 00 00 1b 0c 08 2a}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

