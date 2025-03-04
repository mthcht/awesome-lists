rule Trojan_MSIL_LgoogLoader_A_2147837527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LgoogLoader.A!MTB"
        threat_id = "2147837527"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LgoogLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 02 09 91 07 09 04 5d 93 28 ?? 00 00 06 d2 6f}  //weight: 2, accuracy: Low
        $x_2_2 = {02 03 60 02 66 03 66 60 5f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LgoogLoader_PA_2147837600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LgoogLoader.PA!MTB"
        threat_id = "2147837600"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LgoogLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 09 06 09 93 07 09 07 8e 69 5d 93 28 [0-4] d1 9d 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LgoogLoader_MBS_2147838381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LgoogLoader.MBS!MTB"
        threat_id = "2147838381"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LgoogLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0a 00 06 7e ?? 00 00 04 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0b 02 28 ?? 00 00 0a 0c 07 08 16 08 8e 69 6f ?? 00 00 0a 0d 09 13 04 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LgoogLoader_MBT_2147838382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LgoogLoader.MBT!MTB"
        threat_id = "2147838382"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LgoogLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0a 00 06 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 0b 02 28 ?? ?? ?? 0a 0c 07 08 16 08 8e 69 6f ?? ?? ?? 0a 0d 09 13 04 de 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LgoogLoader_CBT_2147845604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LgoogLoader.CBT!MTB"
        threat_id = "2147845604"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LgoogLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 07 6f 20 00 00 0a 07 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 0c 03 73 ?? ?? ?? ?? 0d 09 08 16 73 ?? ?? ?? ?? 13 04 00 03 8e 69 8d ?? ?? ?? ?? 13 05 11 04 11 05 16 11 05 8e 69 6f ?? ?? ?? ?? 13 06 11 05 11 06 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 07 de 2e 11 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LgoogLoader_ABUD_2147846307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LgoogLoader.ABUD!MTB"
        threat_id = "2147846307"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LgoogLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 06 03 6f ?? 00 00 0a 0b 00 07 6f ?? 00 00 0a 0c 00 02 08 28 ?? 00 00 06 0d de 16 08 2c 07 08 6f ?? 00 00 0a 00 dc}  //weight: 3, accuracy: Low
        $x_2_2 = {07 02 16 02 8e 69 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0c de 16 07 2c 07 07 6f ?? 00 00 0a 00 dc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

