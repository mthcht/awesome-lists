rule TrojanSpy_MSIL_Daculoa_A_2147683508_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Daculoa.A"
        threat_id = "2147683508"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Daculoa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dracula Logger -" wide //weight: 1
        $x_1_2 = "Sick_Recovery@gmail.com" wide //weight: 1
        $x_1_3 = "\\_OP1.tx" wide //weight: 1
        $x_1_4 = {00 42 44 00 46 42 00 4e 44 44 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 42 6f 00 50 41 53 53 5f 52 45 43 4f 56 45 52 59 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

