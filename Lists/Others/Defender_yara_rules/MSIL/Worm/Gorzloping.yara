rule Worm_MSIL_Gorzloping_A_2147706974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Gorzloping.A"
        threat_id = "2147706974"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gorzloping"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {4c 6f 67 47 6f 5f 43 6c 69 65 6e 74 5f 56 [0-2] 2e 65 78 65}  //weight: 4, accuracy: Low
        $x_2_2 = "LogGo (MachineFingerPrint" wide //weight: 2
        $x_2_3 = "id=BJCSMainDB.mssql.somee.com" wide //weight: 2
        $x_2_4 = {43 00 6f 00 70 00 79 00 54 00 6f 00 41 00 6c 00 6c 00 44 00 72 00 69 00 76 00 65 00 73 00 00 00 41 00 64 00 64 00 54 00 6f 00 53 00 74 00 61 00 72 00 74 00 55 00 70 00 00 00}  //weight: 2, accuracy: High
        $x_1_5 = {67 65 74 5f 55 73 65 72 4e 61 6d 65 00 67 65 74 5f 4d 61 63 68 69 6e 65 4e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {67 65 74 5f 44 72 69 76 65 54 79 70 65 00 44 69 72 65 63 74 6f 72 79 49 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_7 = {47 65 74 44 72 69 76 65 73 00 67 65 74 5f 49 73 52 65 61 64 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

