rule Trojan_MSIL_Blustealer_MA_2147834236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blustealer.MA!MTB"
        threat_id = "2147834236"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blustealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {07 18 58 0b 07 02 6f 22 00 00 0a 32 ab 06 6f 23 00 00 0a 2a 73 24 00 00 0a 38 7e ff ff ff 0a 38 8b ff ff ff 0b 38 8c ff ff ff 06 38 90 ff ff ff 0d 38 94 ff ff ff 0c}  //weight: 10, accuracy: High
        $x_10_2 = {07 0d 16 13 05 09 12 05 28 1c 00 00 0a 08 06 18 6f 1d 00 00 0a 11 04 28 1e 00 00 0a 13 06 07 06 11 06 6f 1f 00 00 0a de 0b}  //weight: 10, accuracy: High
        $x_5_3 = {47 15 02 08 09 00 00 00 00 10 00 00 00 00 00 00 01 00 00 00 23 00 00 00 04 00 00 00 09 00 00 00 04 00 00 00 27 00 00 00 0e 00 00 00 03 00 00 00 03 00 00 00 01 00 00 00 02 00 00 00 00 00 01 00 01 00 00 00 00 00 06}  //weight: 5, accuracy: High
        $x_5_4 = {57 15 02 08 09 08 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 29 00 00 00 04 00 00 00 01 00 00 00 0b 00 00 00 01 00 00 00 29 00 00 00 0e 00 00 00 03 00 00 00 02 00 00 00 01 00 00 00 03 00 00 00 01}  //weight: 5, accuracy: High
        $x_1_5 = "://cdn.discordapp.com/attachments/103" wide //weight: 1
        $x_1_6 = "GetDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Blustealer_MB_2147834237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blustealer.MB!MTB"
        threat_id = "2147834237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blustealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {08 13 04 16 13 05 11 04 12 05 28 0d 00 00 0a 07 09 18 6f 0e 00 00 0a 06 28 0f 00 00 0a 13 06 08 09 11 06 6f 10 00 00 0a de 0c}  //weight: 10, accuracy: High
        $x_10_2 = {07 02 07 18 6f 14 00 00 0a 1f 10 28 15 00 00 0a 6f 16 00 00 0a de 20 08 2b e0 28 17 00 00 0a 2b dd 06 2b dc}  //weight: 10, accuracy: High
        $x_5_3 = {57 15 02 08 09 08 00 00 00 5a a4 00 00 14 00 00 01 00 00 00 2b 00 00 00 07 00 00 00 06 00 00 00 13 00 00 00 04 00 00 00 2f 00 00 00 0e 00 00 00 04 00 00 00 02 00 00 00 01 00 00 00 05 00 00 00 01 00 00 00 00 00 97 02}  //weight: 5, accuracy: High
        $x_5_4 = {57 15 02 08 09 08 00 00 00 10 00 00 00 00 00 00 01 00 00 00 23 00 00 00 07 00 00 00 02 00 00 00 0b 00 00 00 02 00 00 00 26 00 00 00 0e 00 00 00 03 00 00 00 02 00 00 00 01 00 00 00 03 00 00 00 01 00 00 00 00 00 01 00 01}  //weight: 5, accuracy: High
        $x_1_5 = "://cdn.discordapp.com/attachments/103" wide //weight: 1
        $x_1_6 = "GetDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Blustealer_ABL_2147850638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blustealer.ABL!MTB"
        threat_id = "2147850638"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blustealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 2b 31 02 08 91 0d 08 1f 0e 5d 13 04 03 11 04 9a 13 05 02 08 11 05 09 28 ?? ?? ?? 06 9c 08 04 fe 01 13 06 11 06 2c 07 28 ?? ?? ?? 0a 0a 00 00 08 17 d6 0c 08 07 31 cb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

