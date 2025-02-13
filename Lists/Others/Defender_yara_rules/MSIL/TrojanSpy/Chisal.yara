rule TrojanSpy_MSIL_Chisal_A_2147696821_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Chisal.A"
        threat_id = "2147696821"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chisal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yZTIhKlB4+01PySmWVihhA==" wide //weight: 1
        $x_1_2 = "pk/EY0norOoEqcn15FD9UA==" wide //weight: 1
        $x_1_3 = "dQ+FupqKNg+aR7UTS/T2g==" wide //weight: 1
        $x_1_4 = "UqeCCEcQvtHub3+DOB9WWg==" wide //weight: 1
        $x_1_5 = {44 64 41 52 00 44 64 41 52 32 00 44 64 55 53}  //weight: 1, accuracy: High
        $x_1_6 = {41 74 00 63 68 72 6f 6d 65 00 63 61 62 75 00 49 4e 4f 00 4b 59}  //weight: 1, accuracy: High
        $x_1_7 = "china love" ascii //weight: 1
        $x_1_8 = "fuck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

