rule TrojanDropper_MSIL_Suloc_A_2147718606_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Suloc.A!bit"
        threat_id = "2147718606"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Suloc"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {50 72 6f 74 65 63 74 65 64 00 53 65 63 75 72 65 64 46 69 6c 65}  //weight: 10, accuracy: High
        $x_10_2 = {4d 61 69 6e 00 41 62 75 73 65 52 65 70 6f 72 74 00 44 77 61 64 61}  //weight: 10, accuracy: High
        $x_10_3 = {43 6f 6e 76 65 72 74 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 53 79 73 74 65 6d 2e 44 69 61 67 6e 6f 73 74 69 63 73 00 50 72 6f 63 65 73 73 00 53 74 61 72 74}  //weight: 10, accuracy: High
        $x_1_4 = "File_Protected.exe" wide //weight: 1
        $x_1_5 = {53 00 45 00 43 00 55 00 52 00 45 00 44 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

