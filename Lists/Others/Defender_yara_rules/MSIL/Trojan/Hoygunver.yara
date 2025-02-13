rule Trojan_MSIL_Hoygunver_A_2147655107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hoygunver.A"
        threat_id = "2147655107"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hoygunver"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 69 6c 65 00 66 69 6c 65 32 00 4d 61 69 6e 00 72 75 6e 00 67 6f 00 68 65 79 00}  //weight: 10, accuracy: High
        $x_1_2 = {5c 00 52 00 75 00 6e 00 00 07 4d 00 53 00 45 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 52 00 75 00 6e 00 00 29 4d 00 69 00 63 00}  //weight: 1, accuracy: High
        $x_1_4 = {28 09 00 00 0a 2d 27 7e 01 00 00 04 28 0a 00 00 0a 2d 1b 7e 02 00 00 04 28 0a 00 00 0a 2c 0f 7e 02 00 00 04 7e 01 00 00 04 28 0b 00 00 0a 7e 0c 00 00 0a 72 01 00 00 70 17 6f 0d 00 00 0a 72 5d 00 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Hoygunver_B_2147685327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hoygunver.B"
        threat_id = "2147685327"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hoygunver"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 69 6e 00 72 75 6e 00 67 6f 00 63 72 65 61 74 65 00 68 65 79}  //weight: 1, accuracy: High
        $x_1_2 = "rsion\\Run" wide //weight: 1
        $x_1_3 = {7e 0c 00 00 0a 72 ?? 00 00 70 17 6f 0d 00 00 0a 02 7e 01 00 00 04 6f 0e 00 00 0a 2a}  //weight: 1, accuracy: Low
        $x_1_4 = {28 0f 00 00 0a 72 ?? 00 00 70 28 10 00 00 0a 80 01 00 00 04 72 ?? 00 00 70 80 02 00 00 04 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

