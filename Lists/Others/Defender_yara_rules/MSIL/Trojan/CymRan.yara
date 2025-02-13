rule Trojan_MSIL_CymRan_ACY_2147896957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CymRan.ACY!MTB"
        threat_id = "2147896957"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CymRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 2b 1f 00 08 09 9a 28 ?? 00 00 0a 28 ?? 00 00 06 13 04 11 04 2c 06 00 06 17 58 0a 00 00 09 17 58 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {08 11 06 9a 28 ?? 00 00 0a 6f ?? 00 00 06 00 08 11 06 9a 28 ?? 00 00 06 13 08 11 08 2c 06 00 07 17 58 0b 00 00 00 11 06 17 58 13 06 11 06 08 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CymRan_ACA_2147896975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CymRan.ACA!MTB"
        threat_id = "2147896975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CymRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 16 16 6f ?? 00 00 0a 0a 06 2c 05 00 16 0b de 0b 00 17 0b de 06 26 00 17 0b de 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 16 fe 01 0c 08 2c 61 00 02 28 ?? 00 00 0a 0d 09 2c 51 00 00 02 73 ?? 00 00 0a 03 04 05 28 ?? 00 00 0a 25 0a 13 04 00 06 16 6a 16 6a 6f ?? 00 00 0a 00 00 06 16 6a 16 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

