rule Trojan_MSIL_CeeInject_AC_2147716340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CeeInject.AC!bit"
        threat_id = "2147716340"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 65 74 5f 42 00 73 65 74 5f 42 00 67 65 74 5f 4b 00 73 65 74 5f 4b}  //weight: 1, accuracy: High
        $x_1_2 = {49 6e 76 6f 6b 65 [0-16] 41 70 70 44 6f 6d 61 69 6e 00 67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e 00 4c 6f 61 64 00 67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74}  //weight: 1, accuracy: Low
        $x_1_3 = {06 d3 08 58 06 d3 08 58 47 07 d3 08 02 28 04 00 00 06 8e 69 5d 58 47 61 d2 52 08 17 58 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CeeInject_AD_2147719015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CeeInject.AD!bit"
        threat_id = "2147719015"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 da 11 04 da 03 11 04 91 ?? 61 ?? 11 04 ?? 8e b7 5d 91 61 9c 11 04 17 d6}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 74 00 43 61 6c 6c 00 43 61 6c 6c 76 69 72 74 [0-16] 2e 50 6e 67}  //weight: 1, accuracy: Low
        $x_1_3 = {65 00 72 00 72 00 6f 00 72 00 [0-96] 2e 00 50 00 6e 00 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CeeInject_AE_2147719134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CeeInject.AE!bit"
        threat_id = "2147719134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 da 11 04 da 03 11 04 91 ?? 61 ?? 11 04 ?? 8e b7 5d 91 61 9c 11 04 17 d6}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 64 61 72 67 5f 30 00 4c 64 61 72 67 5f 31 00 4c 64 61 72 67 5f 32 00 4c 64 61 72 67 5f 33 00 4c 64 63 5f 49 34 5f 31 00}  //weight: 1, accuracy: High
        $x_1_3 = {52 65 74 00 43 61 6c 6c 00 43 61 6c 6c 76 69 72 74 [0-16] 2e 50 6e 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

