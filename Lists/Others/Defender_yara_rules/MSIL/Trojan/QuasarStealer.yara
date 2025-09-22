rule Trojan_MSIL_QuasarStealer_EA_2147937249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarStealer.EA!MTB"
        threat_id = "2147937249"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 07 02 07 91 03 07 03 6f 20 00 00 0a 5d 6f 21 00 00 0a 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarStealer_PA_2147952664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarStealer.PA!MTB"
        threat_id = "2147952664"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {a2 14 14 14 28 ?? 00 00 0a 14 72 fe d4 00 70 16 8d 03 00 00 01 14 14 14 28 ?? 00 00 0a 74 80 00 00 01 6f ?? 00 00 0a 13 07 2b 37 11 07 6f ?? 00 00 0a 28 37 00 00 0a 13 08 00 11 08 74 81 00 00 01 14 16 8d 03 00 00 01 6f ?? 00 00 0a 26 de 10 25 28 ?? 00 00 0a 13 09 00 28 ?? 00 00 0a de 00}  //weight: 6, accuracy: Low
        $x_4_2 = {00 04 18 5d 2c 03 03 2b 07 03 20 c1 00 00 00 61 b4 0a 2b 00 06 2a}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarStealer_MNED_2147952665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarStealer.MNED!MTB"
        threat_id = "2147952665"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {00 00 0a 0c 08 14 72 2d 4c 00 70 16 8d 01 00 00 01 14 14 14 28 ?? 00 00 0a 6f ?? 00 00 0a 02 6f ?? 01 00 0a 13 08 11 08 2c 1d 08 14 72 4d 03 00 70 16 8d 01 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 0d 2b 0f 00 00 11 07 6f ?? 01 00 0a 13 09 11 09 2d a1}  //weight: 3, accuracy: Low
        $x_5_2 = "resources/almoheki.png" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

