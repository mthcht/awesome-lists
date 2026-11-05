rule Trojan_MSIL_Odbijen_A_2147981464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Odbijen.A"
        threat_id = "2147981464"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Odbijen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3c 4d 6f 64 75 6c 65 3e 00 43 61 73 74 6c 65 4c 69 62 2e 64 6c 6c}  //weight: 10, accuracy: High
        $x_1_2 = {55 48 8d 64 24 f8 48 89 1c 24 56 48 8d 64 24 f8 48 89 3c 24}  //weight: 1, accuracy: High
        $x_1_3 = {53 43 5f 67 65 74 50 61 67 65 [0-32] 43 6f 6e 76 65 72 74 54 68 72 65 61 64 54 6f 46 69 62 65 72}  //weight: 1, accuracy: Low
        $x_1_4 = {53 43 5f 65 78 65 63 00 4c 61 75 6e 63 68 53 43}  //weight: 1, accuracy: High
        $x_1_5 = {50 41 47 45 5f 45 58 45 43 55 54 45 5f 52 45 41 44 57 52 49 54 45 [0-128] 50 41 47 45 5f 52 45 41 44 4f 4e 4c 59}  //weight: 1, accuracy: Low
        $x_1_6 = {88 02 48 31 fa 48 [0-3] 48 39 f3 75 [0-48] ff e2 e8}  //weight: 1, accuracy: Low
        $x_1_7 = {88 e3 32 1c 0e 88 5c 15 00 48 [0-48] ff e0 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

