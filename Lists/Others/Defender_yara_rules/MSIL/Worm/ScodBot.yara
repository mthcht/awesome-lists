rule Worm_MSIL_ScodBot_A_2147633920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/ScodBot.A"
        threat_id = "2147633920"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ScodBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4b 69 6c 6c 57 69 6e 64 6f 77 73 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 41 6e 64 46 69 72 65 57 61 6c 6c 00}  //weight: 2, accuracy: High
        $x_2_2 = {55 53 42 53 70 72 65 61 64 00}  //weight: 2, accuracy: High
        $x_1_3 = {42 6f 74 49 44 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 6f 52 6f 6f 74 6b 69 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {67 65 6e 65 72 61 74 65 69 70 73 61 6e 64 73 68 69 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

