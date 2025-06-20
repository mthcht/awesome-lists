rule Trojan_MSIL_InjectorNetT_AGHA_2147929009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjectorNetT.AGHA!MTB"
        threat_id = "2147929009"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectorNetT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 03 08 20 0a 02 00 00 58 20 09 02 00 00 59 1e 59 1e 58 03 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_InjectorNetT_AMHA_2147929152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjectorNetT.AMHA!MTB"
        threat_id = "2147929152"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectorNetT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {73 a0 00 00 0a 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0b dd}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_InjectorNetT_APHA_2147929225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjectorNetT.APHA!MTB"
        threat_id = "2147929225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectorNetT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 06 04 6f ?? 00 00 0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c de 1e}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_InjectorNetT_AJLA_2147933548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjectorNetT.AJLA!MTB"
        threat_id = "2147933548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectorNetT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 2d 20 72 16 06 00 70 38 94 00 00 00 15 3a 98 00 00 00 26 72 48 06 00 70 38 93 00 00 00 38 98 00 00 00 38 99 00 00 00 75 20 00 00 1b 38 99 00 00 00 16 2d cb 38 97 00 00 00 38 9c 00 00 00 73 ?? 00 00 0a 13 04 11 04 09 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 2b 15 08 16 08 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 06 de 29 11 05 2b e7}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_InjectorNetT_ADSA_2147940055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjectorNetT.ADSA!MTB"
        threat_id = "2147940055"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectorNetT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 94 07 00 70 38 77 00 00 00 38 7c 00 00 00 72 c6 07 00 70 38 78 00 00 00 38 7d 00 00 00 16 2d ee 38 7b 00 00 00 38 80 00 00 00 08 06 6f ?? ?? 00 0a 08 07 6f ?? ?? 00 0a 08 6f ?? ?? 00 0a 0d 2b 10 2b 11 16 2b 11 8e 69 6f ?? ?? 00 0a 13 04 de 26 09 2b ed 02 2b ec 02 2b ec}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_InjectorNetT_AAXA_2147944198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjectorNetT.AAXA!MTB"
        threat_id = "2147944198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectorNetT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {03 1f 3c 28 ?? 00 00 0a 13 08 03 11 08 1f 34 58 28 ?? 00 00 0a 13 09 20 b3 00 00 00 8d ?? 00 00 01 13 0a 16 13 0b 2b 0f 11 0a 11 0b 11 0b 06 61 9e 11 0b 17 58 13 0b 11 0b 11 0a 8e 69 32 e9}  //weight: 4, accuracy: Low
        $x_3_2 = {03 11 12 1f 0c 58 28 ?? 00 00 0a 13 16 03 11 12 1f 10 58 28 ?? 00 00 0a 13 17 03 11 12 1f 14 58 28 ?? 00 00 0a 13 18 11 17 2c 3e 11 17 8d ?? 00 00 01 13 19 03 11 18 11 19 16 11 19 8e 69}  //weight: 3, accuracy: Low
        $x_1_3 = "a2VybmVsMzI=" wide //weight: 1
        $x_1_4 = "VmlydHVhbEFsbG9jRXg=" wide //weight: 1
        $x_1_5 = "Q3JlYXRlUHJvY2Vzc0E=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

