rule Trojan_MSIL_PurpleMustard_A_2147963338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PurpleMustard.A!dha"
        threat_id = "2147963338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PurpleMustard"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CK9ILKSF" ascii //weight: 2
        $x_1_2 = {53 65 74 52 65 61 64 43 62 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 74 45 78 69 74 43 62 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 65 74 4f 75 74 70 75 74 43 62 00}  //weight: 1, accuracy: High
        $x_2_5 = "CKLKKJS" ascii //weight: 2
        $x_1_6 = {5f 65 78 69 74 43 62 00}  //weight: 1, accuracy: High
        $x_1_7 = {5f 72 65 63 76 43 62 00}  //weight: 1, accuracy: High
        $x_2_8 = "select=id,name,size,lastModifiedDateTime&orderby=lastModifiedDateTime" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

