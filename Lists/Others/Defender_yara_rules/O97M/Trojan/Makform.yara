rule Trojan_O97M_Makform_A_2147739983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Makform.A"
        threat_id = "2147739983"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Makform"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 65 70 6c 61 63 65 41 6c 6c ?? 2e 53 65 6e 64}  //weight: 1, accuracy: Low
        $x_2_2 = {52 65 70 6c 61 63 65 41 6c 6c ?? 2e 73 61 76 65 74 6f 66 69 6c 65 20 22 66 74 7a 70 2e 65 22 20 26 20 22 78 65 22 2c 20 32}  //weight: 2, accuracy: Low
        $x_2_3 = "ReplaceAll2.savetofile \"xlx.e\" & \"xe\", 2" ascii //weight: 2
        $x_1_4 = "ExecuteExcel4Macro \"MESSAGE(True, \"\"davichi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_O97M_Makform_B_2147740241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Makform.B"
        threat_id = "2147740241"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Makform"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "savetofile \"rfm.e\" & \"xe\", 2" ascii //weight: 2
        $x_1_2 = "UserForm1.Label5_Click" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

