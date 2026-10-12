rule Trojan_MSIL_SalatStealer_AWNB_2147960259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SalatStealer.AWNB!MTB"
        threat_id = "2147960259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 2c 04 02 8e 2d 06 7e ?? 00 00 0a 2a 03 2d 0c 28 ?? 00 00 0a 02 6f ?? 00 00 0a 2a 02 8e 69 8d ?? 00 00 01 0a 16 0b 2b 0d 06 07 02 07 91 03 61 d2 9c 07 17 58 0b 07 02 8e 69 32 ed 28 ?? 00 00 0a 06 6f ?? 00 00 0a 2a}  //weight: 5, accuracy: Low
        $x_2_2 = {06 18 5d 2d 07 28 ?? 00 00 06 2b 05 28 ?? 00 00 06 1f 64 07 1f 32 5a 58 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 07 17 58 0b 07 19 32 d5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SalatStealer_SWQR_2147961051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SalatStealer.SWQR!MTB"
        threat_id = "2147961051"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 07 02 07 91 03 61 d2 9c 07 1f 0a 5d 2d 05 28 ?? ?? ?? 06 07 17 58 0b 07 02 8e 69 32 e2}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SalatStealer_APRB_2147964218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SalatStealer.APRB!MTB"
        threat_id = "2147964218"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 17 58 20 00 01 00 00 5d 0d 08 07 09 94 58 20 00 01 00 00 5d 0c 07 09 94 13 08 07 09 07 08 94 9e 07 08 11 08 9e 06 11 07 02 11 07 91 07 07 09 94 07 08 94 58 20 00 01 00 00 5d 94 61 d2 9c 11 07 17 58 13 07 11 07 02 8e 69 32 b4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SalatStealer_AS_2147980133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SalatStealer.AS!MTB"
        threat_id = "2147980133"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a2 25 17 72 ?? 00 00 70 a2 25 18 72 ?? 01 00 70 a2 25 19 72 ?? 01 00 70 a2 0b 16 0c 2b 20 07 08 9a 0d 06 72 ?? 01 00 70 09 28 ?? 00 00 0a 28 ?? 00 00 0a 2c 05 17 13 04 de 1e 08 17 58 0c 08 07 8e 69}  //weight: 1, accuracy: Low
        $x_2_2 = {a2 25 17 06 a2 25 18 72 ?? 01 00 70 a2 25 19 06 a2 25 1a 72 ?? 01 00 70 a2 25 1b 07 a2 25 1c 72 ?? 01 00 70 a2 28 ?? 00 00 0a 0c 07 08 28 ?? 00 00 0a 73 ?? 00 00 0a 25 07 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 17 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

