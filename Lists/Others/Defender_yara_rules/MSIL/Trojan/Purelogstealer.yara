rule Trojan_MSIL_Purelogstealer_SRT_2147936584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Purelogstealer.SRT!MTB"
        threat_id = "2147936584"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Purelogstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 10 00 00 0a 07 6f 11 00 00 0a 6f 12 00 00 0a 06 fe 06 ?? ?? ?? 06 73 13 00 00 0a 28 01 00 00 2b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Purelogstealer_SOLD_2147938427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Purelogstealer.SOLD!MTB"
        threat_id = "2147938427"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Purelogstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 61 00 00 70 28 0c 00 00 0a 0a 72 bb 00 00 70 28 0c 00 00 0a 0b 28 0d 00 00 0a 0c 08 06 6f 0e 00 00 0a 08 07 6f 0f 00 00 0a 73 10 00 00 0a 0d 09 08 6f 11 00 00 0a 17 73 12 00 00 0a 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Purelogstealer_SEAW_2147940709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Purelogstealer.SEAW!MTB"
        threat_id = "2147940709"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Purelogstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 28 0a 00 00 06 0a 73 0b 00 00 0a 25 06 28 09 00 00 06 6f 0c 00 00 0a 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Purelogstealer_PGPL_2147954907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Purelogstealer.PGPL!MTB"
        threat_id = "2147954907"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Purelogstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 73 00 74 00 61 00 63 00 79 00 73 00 75 00 62 00 6c 00 65 00 74 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 77 00 70 00 2d 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2f 00 70 00 6c 00 75 00 67 00 69 00 6e 00 73 00 2f 00 [0-26] 2e 00 70 00 64 00 66 00}  //weight: 5, accuracy: Low
        $x_5_2 = {68 74 00 74 00 70 73 3a 2f 2f 73 74 61 63 79 73 75 62 6c 65 74 74 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f [0-26] 2e 70 64 66}  //weight: 5, accuracy: Low
        $x_5_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 73 00 74 00 61 00 63 00 79 00 73 00 75 00 62 00 6c 00 65 00 74 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 77 00 70 00 2d 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2f 00 70 00 6c 00 75 00 67 00 69 00 6e 00 73 00 2f 00 [0-26] 2e 00 64 00 61 00 74 00}  //weight: 5, accuracy: Low
        $x_5_4 = {68 74 00 74 00 70 73 3a 2f 2f 73 74 61 63 79 73 75 62 6c 65 74 74 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f [0-26] 2e 64 61 74}  //weight: 5, accuracy: Low
        $x_5_5 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 73 00 74 00 61 00 63 00 79 00 73 00 75 00 62 00 6c 00 65 00 74 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 77 00 70 00 2d 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2f 00 70 00 6c 00 75 00 67 00 69 00 6e 00 73 00 2f 00 [0-26] 2e 00 76 00 64 00 66 00}  //weight: 5, accuracy: Low
        $x_5_6 = {68 74 00 74 00 70 73 3a 2f 2f 73 74 61 63 79 73 75 62 6c 65 74 74 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f [0-26] 2e 76 64 66}  //weight: 5, accuracy: Low
        $x_5_7 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 73 00 74 00 61 00 63 00 79 00 73 00 75 00 62 00 6c 00 65 00 74 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 77 00 70 00 2d 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2f 00 70 00 6c 00 75 00 67 00 69 00 6e 00 73 00 2f 00 [0-26] 2e 00 6d 00 70 00 33 00}  //weight: 5, accuracy: Low
        $x_5_8 = {68 74 00 74 00 70 73 3a 2f 2f 73 74 61 63 79 73 75 62 6c 65 74 74 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f [0-26] 2e 6d 70 33}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

