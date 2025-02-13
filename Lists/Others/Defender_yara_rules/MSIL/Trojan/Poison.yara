rule Trojan_MSIL_Poison_PSOT_2147848861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Poison.PSOT!MTB"
        threat_id = "2147848861"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Poison"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 0b 00 00 06 0a 28 0b 00 00 0a 06 6f 0c 00 00 0a 28 0a 00 00 06 75 01 00 00 1b 0b 07 16 07 8e 69 28 0d 00 00 0a 07 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Poison_PSSB_2147850763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Poison.PSSB!MTB"
        threat_id = "2147850763"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Poison"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 6b 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 18 2d 09 26 12 00 1a 2d 06 26 de 0d 0a 2b f5 28 ?? 00 00 06 2b f4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

