rule Trojan_MSIL_Rohorkox_A_2147706908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rohorkox.A"
        threat_id = "2147706908"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rohorkox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FakeMessageBox" ascii //weight: 3
        $x_1_2 = {44 69 73 61 62 6c 65 43 4d 44 00 44 69 73 61 62 6c 65 54 61 73 6b 4d 61 6e}  //weight: 1, accuracy: High
        $x_1_3 = {44 69 73 61 62 6c 65 52 65 67 65 64 69 74 00 44 69 73 61 62 6c 65 4d 53 43 6f 6e 66 69 67}  //weight: 1, accuracy: High
        $x_1_4 = {50 72 6f 74 65 63 74 50 72 6f 63 65 73 73 00 47 65 74 49 6e 73 74 61 6c 6c 65 64 50 72 6f 67 72 61 6d 73}  //weight: 1, accuracy: High
        $x_1_5 = {47 65 74 4f 53 00 47 65 74 46 69 72 65 77 61 6c 6c 00 47 65 74 41 6e 74 69 76 69 72 75 73}  //weight: 1, accuracy: High
        $x_1_6 = {75 6e 68 6f 6f 6b 00 48 6f 6f 6b 50 00 4e 69 74 72 6f 00 57 65 73 74 50 61 67 65}  //weight: 1, accuracy: High
        $x_1_7 = "juliaseksulana.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

