rule TrojanDropper_O97M_Artitex_A_2147706750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Artitex.A"
        threat_id = "2147706750"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Artitex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ActiveDocument.SaveAs FileName:=Name, FileFormat:=wdFormatRTF" ascii //weight: 1
        $x_1_2 = "docWord = appWord.Documents.Open(TCA)" ascii //weight: 1
        $x_1_3 = "SaveAsRTF(Name As String)" ascii //weight: 1
        $x_2_4 = "TMP = Environ$(\"TEMP\")" ascii //weight: 2
        $x_2_5 = "TEX = TMP + \"q2.ex\" + \"e\"" ascii //weight: 2
        $x_2_6 = {54 45 58 20 3d 20 54 4d 50 20 2b 20 22 70 6d [0-2] 2e 22 20 26 20 22 65 78 22}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_O97M_Artitex_B_2147707189_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Artitex.B"
        threat_id = "2147707189"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Artitex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \"e\" + \"xe\"" ascii //weight: 1
        $x_1_2 = "+ \"rt\" + \"f\"" ascii //weight: 1
        $x_1_3 = "& \"EMP\"" ascii //weight: 1
        $x_1_4 = ".SaveAs FileName:=Name, FileFormat:=wdFormatRTF" ascii //weight: 1
        $x_1_5 = "= TMP + \"311\" +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDropper_O97M_Artitex_C_2147709203_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Artitex.C"
        threat_id = "2147709203"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Artitex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\" & \".rtf\"" ascii //weight: 1
        $x_1_2 = {2e 53 61 76 65 41 73 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-96] 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 77 64 46 6f 72 6d 61 74 52 54 46}  //weight: 1, accuracy: Low
        $x_1_3 = "(23 + 64) & \"o\" & \"rd\" & \".A\" & \"pplication\"" ascii //weight: 1
        $x_1_4 = "(23 + 64) & \"ord.Application\")" ascii //weight: 1
        $x_1_5 = {3d 20 22 74 22 20 26 20 [0-96] 20 2b 20 22 70 22}  //weight: 1, accuracy: Low
        $x_1_6 = {22 66 74 76 [0-2] 22 20 26}  //weight: 1, accuracy: Low
        $x_1_7 = {26 20 22 78 22 20 2b 20 [0-96] 28 39 31 20 2b 20 31 30 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

