rule TrojanDropper_O97M_Farheyt_A_2147706709_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Farheyt.A"
        threat_id = "2147706709"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Farheyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 65 79 20 28 32 29 0d 0a 53 68 65 6c 6c 20 28 54 45 58 29 0d 0a 48 65 79 20 28 31 29}  //weight: 1, accuracy: High
        $x_1_2 = "Sub Hey(Kalamana As Long)" ascii //weight: 1
        $x_1_3 = "Public Function SaveAsRTF(Name As String)" ascii //weight: 1
        $x_1_4 = "Do While Timer < Jhbhds" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_O97M_Farheyt_A_2147706709_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Farheyt.A"
        threat_id = "2147706709"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Farheyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ActiveDocument.SaveAs FileName:=Name, FileFormat:=wdFormatRTF" ascii //weight: 1
        $x_1_2 = "SaveAsRTF(Name As String)" ascii //weight: 1
        $x_10_3 = ".Documents.Open(TCA)" ascii //weight: 10
        $x_10_4 = "TMP = Environ$(\"TEMP\")" ascii //weight: 10
        $x_10_5 = "TMP = Environ$(\"TE\" + \"MP\")" ascii //weight: 10
        $x_10_6 = "TEX = TMP + \"" ascii //weight: 10
        $x_10_7 = "TMP = Environ$(\"\" & \"TEMP\")" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_O97M_Farheyt_B_2147707373_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Farheyt.B"
        threat_id = "2147707373"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Farheyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(102 + haa) + \"xe\"" ascii //weight: 1
        $x_1_2 = "Chr(haa + 100 + 2) + \"x\" + Chr(Asc(\"e\"))" ascii //weight: 1
        $x_1_3 = "Sgn(CInt(Hour(Now)) - 25)" ascii //weight: 1
        $x_1_4 = "ActiveDocument.SaveAs FileName:=Name, FileFormat:=wdFormatRTF" ascii //weight: 1
        $x_1_5 = "+ \"pm2\" & \"\" +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_O97M_Farheyt_C_2147707393_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Farheyt.C"
        threat_id = "2147707393"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Farheyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"Word.Application\")" ascii //weight: 1
        $x_5_2 = "\"pm1" ascii //weight: 5
        $x_10_3 = {2e 56 69 73 69 62 6c 65 20 3d 20 46 61 6c 73 65 [0-26] 2e 44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 20 28 54 43 41 29}  //weight: 10, accuracy: Low
        $x_5_4 = "Environ$(" ascii //weight: 5
        $x_10_5 = "\"rt\" & Chr(102)" ascii //weight: 10
        $x_2_6 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-10] 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 77 64 46 6f 72 6d 61 74 52 54 46}  //weight: 2, accuracy: Low
        $x_5_7 = "\"pm3\" & \"\" + FEFE" ascii //weight: 5
        $x_10_8 = "\"rt\" & Chr(100 + 2)" ascii //weight: 10
        $x_5_9 = "\"tt1\" & \"\" + FEFE" ascii //weight: 5
        $x_3_10 = "Workbook_Open()" ascii //weight: 3
        $x_3_11 = "Auto_Open()" ascii //weight: 3
        $x_3_12 = {2e 51 75 69 74 0d 0a 53 65 74 20}  //weight: 3, accuracy: High
        $x_6_13 = "Chr(114) & Chr(116) & Chr(102)" ascii //weight: 6
        $x_2_14 = "= CreateObject(\"W\" & \"ord.Application\")" ascii //weight: 2
        $x_2_15 = " + \"e\" & Chr(90 + " ascii //weight: 2
        $x_2_16 = " = \"\" & \"\" + \"T\" + \"\" & \"EM\" + \"\" & \"\"" ascii //weight: 2
        $x_10_17 = {56 69 73 69 62 6c 65 20 3d 20 46 61 6c 73 65 [0-26] 2e 44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 20 28 54 54 54 44 41 44 53 53 29}  //weight: 10, accuracy: Low
        $x_2_18 = "= CreateObject(Chr(87) + \"or\" + \"d.Application\")" ascii //weight: 2
        $x_5_19 = "& Chr(haa + 117) & \"f\"" ascii //weight: 5
        $x_7_20 = "\"r\" & Chr(haa + 117) + \"\" & \"f\"" ascii //weight: 7
        $x_7_21 = {56 61 6c 28 [0-10] 29 20 2d 20 38}  //weight: 7, accuracy: Low
        $x_5_22 = "\"EM\" + \"P\"" ascii //weight: 5
        $x_7_23 = "\"or\" + \"d.A\" & \"pplication\")" ascii //weight: 7
        $x_5_24 = "\"rt\" & \"f\"" ascii //weight: 5
        $x_7_25 = "= \"E\" & \"M\"" ascii //weight: 7
        $x_5_26 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-48] 29 0d 0a [0-21] 2e 56 69 73 69 62 6c 65 20 3d 20 46 61 6c 73 65}  //weight: 5, accuracy: Low
        $x_7_27 = "\".A\" & \"pplication\")" ascii //weight: 7
        $x_7_28 = {4d 6f 64 75 6c 65 31 2e [0-10] 20 28 31 29 0d 0a [0-10] 2e 51 75 69 74}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((4 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((5 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_5_*) and 4 of ($x_2_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((5 of ($x_5_*) and 3 of ($x_3_*))) or
            ((6 of ($x_5_*) and 1 of ($x_2_*))) or
            ((6 of ($x_5_*) and 1 of ($x_3_*))) or
            ((7 of ($x_5_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 3 of ($x_5_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 4 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 4 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_6_*) and 5 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 5 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 5 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_6_*) and 6 of ($x_5_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_7_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_7_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_7_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_7_*) and 3 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_7_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_7_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_7_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_7_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_7_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_7_*) and 4 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_7_*) and 4 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_7_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_7_*) and 4 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_7_*) and 5 of ($x_5_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*) and 2 of ($x_5_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*) and 2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*) and 2 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*) and 3 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*) and 3 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*) and 4 of ($x_5_*))) or
            ((2 of ($x_7_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_7_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_7_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_7_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_7_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_7_*) and 2 of ($x_5_*) and 4 of ($x_2_*))) or
            ((2 of ($x_7_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_7_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_7_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_7_*) and 2 of ($x_5_*) and 3 of ($x_3_*))) or
            ((2 of ($x_7_*) and 3 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_7_*) and 3 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_7_*) and 3 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_7_*) and 4 of ($x_5_*))) or
            ((2 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_7_*) and 1 of ($x_6_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_7_*) and 1 of ($x_6_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_7_*) and 1 of ($x_6_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((2 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((2 of ($x_7_*) and 1 of ($x_6_*) and 2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_7_*) and 1 of ($x_6_*) and 2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_7_*) and 1 of ($x_6_*) and 3 of ($x_5_*))) or
            ((3 of ($x_7_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_7_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((3 of ($x_7_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_7_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_7_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_7_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((3 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_7_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((3 of ($x_7_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_7_*) and 2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((3 of ($x_7_*) and 2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((3 of ($x_7_*) and 3 of ($x_5_*))) or
            ((3 of ($x_7_*) and 1 of ($x_6_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_7_*) and 1 of ($x_6_*) and 3 of ($x_2_*))) or
            ((3 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_7_*) and 1 of ($x_6_*) and 2 of ($x_3_*))) or
            ((3 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*))) or
            ((4 of ($x_7_*) and 2 of ($x_2_*))) or
            ((4 of ($x_7_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((4 of ($x_7_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_7_*) and 2 of ($x_3_*))) or
            ((4 of ($x_7_*) and 1 of ($x_5_*))) or
            ((4 of ($x_7_*) and 1 of ($x_6_*))) or
            ((5 of ($x_7_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 2 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 3 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 3 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 4 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 3 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 2 of ($x_5_*))) or
            ((1 of ($x_10_*) and 2 of ($x_7_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_7_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_7_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_7_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_7_*) and 3 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_7_*) and 1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_7_*) and 2 of ($x_5_*))) or
            ((1 of ($x_10_*) and 2 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*))) or
            ((1 of ($x_10_*) and 3 of ($x_7_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_7_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_7_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 3 of ($x_7_*) and 1 of ($x_5_*))) or
            ((1 of ($x_10_*) and 3 of ($x_7_*) and 1 of ($x_6_*))) or
            ((1 of ($x_10_*) and 4 of ($x_7_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*))) or
            ((2 of ($x_10_*) and 1 of ($x_6_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_6_*) and 2 of ($x_3_*))) or
            ((2 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_10_*) and 1 of ($x_6_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_7_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_3_*))) or
            ((2 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_6_*))) or
            ((2 of ($x_10_*) and 2 of ($x_7_*))) or
            ((3 of ($x_10_*) and 1 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            ((3 of ($x_10_*) and 1 of ($x_6_*))) or
            ((3 of ($x_10_*) and 1 of ($x_7_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_O97M_Farheyt_E_2147707895_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Farheyt.E"
        threat_id = "2147707895"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Farheyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 31 32 29 20 3d 20 03 00 [0-5] 28 30 29 20 3d 20 03 00 [0-5] 28 31 29 20 3d 20 03 00 [0-5] 28 32 29 20 3d 20 03 00 [0-5] 28 33 29 20 3d 20 03 00 [0-5] 28 34 29 20 3d 20 [0-16] 41 73 20 4f 62 6a 65 63 74 [0-16] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 10 00 28 10 00 2c 20 10 00 29 29 [0-16] 2e 52 75 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Farheyt_E_2147707895_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Farheyt.E"
        threat_id = "2147707895"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Farheyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-8] 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 77 64 46 6f 72 6d 61 74 52 54 46}  //weight: 1, accuracy: Low
        $x_1_2 = " + TETE" ascii //weight: 1
        $x_1_3 = " + JNBBH" ascii //weight: 1
        $x_1_4 = "= CreateObject(\"Wo" ascii //weight: 1
        $x_1_5 = ".Application\")" ascii //weight: 1
        $x_1_6 = {45 6e 76 69 72 6f 6e 24 28 [0-10] 29 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Farheyt_F_2147708509_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Farheyt.F"
        threat_id = "2147708509"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Farheyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 20 22 65 22 20 26 20 43 68 72 28 [0-2] 20 2b 20 [0-3] 20 2b 20 [0-2] 20 2b 20 [0-2] 29 20 26 20 22 65}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 22 2e 22 0d 0a [0-8] 20 3d 20 [0-8] 20 2b 20 43 68 72 28 [0-6] 20 2b 20 [0-6] 20 2b 20 [0-6] 29 20 26 20 22 78 22 0d 0a 4d 4f 4e 45 20 3d 20 [0-8] 20 2b 20 43 68 72 28 [0-6] 20 2b 20 [0-6] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-8] 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 77 64 46 6f 72 6d 61 74 52 54 46}  //weight: 1, accuracy: Low
        $x_1_4 = "+ \"r\" & \"tf" ascii //weight: 1
        $x_1_5 = "= CreateObject(" ascii //weight: 1
        $x_1_6 = ".Application\")" ascii //weight: 1
        $x_1_7 = ".A\" & \"pplication" ascii //weight: 1
        $x_1_8 = {45 6e 76 69 72 6f 6e 28 [0-10] 29 20 2b}  //weight: 1, accuracy: Low
        $x_1_9 = {2b 20 43 68 72 28 [0-2] 20 2b 20 [0-2] 20 2b 20 [0-6] 29 20 26 20 22 78 22}  //weight: 1, accuracy: Low
        $x_1_10 = {2e 44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 20 28 [0-15] 29 0d 0a [0-15] 20 28 32 29}  //weight: 1, accuracy: Low
        $x_1_11 = {28 32 29 0d 0a [0-15] 2e 51 75 69 74 0d 0a 53 65 74 20 [0-15] 20 3d 20 4e 6f 74 68 69 6e 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDropper_O97M_Farheyt_G_2147708664_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Farheyt.G"
        threat_id = "2147708664"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Farheyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 20 22 54 22 20 2b 20 [0-192] 20 2b 20 22 50 22}  //weight: 2, accuracy: Low
        $x_2_2 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-192] 29 20 2b 20}  //weight: 2, accuracy: Low
        $x_2_3 = {2b 20 43 68 72 28 39 32 20 2b 20 31 30 20 2b 20 [0-192] 29 20 26 20 22 78 22}  //weight: 2, accuracy: Low
        $x_1_4 = "(19 + 68) & \"or\" + \"d.Application\"" ascii //weight: 1
        $x_1_5 = "+ Chr(9 + 92)" ascii //weight: 1
        $x_1_6 = "+ \"r\" & \"tf\"" ascii //weight: 1
        $x_2_7 = "+ \"rra1\" &" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_O97M_Farheyt_H_2147709183_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Farheyt.H"
        threat_id = "2147709183"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Farheyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 20 22 45 6e 76 69 72 6f 6e 6d 65 22 20 2b 20 [0-16] 28 22 4e 54 73 74 52 69 6e 47 53 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = ", VbMethod, \"%temp%\")" ascii //weight: 1
        $x_1_3 = {26 20 22 5c [0-16] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_4 = "= VBA.CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_5 = "\"Run\", VbMethod," ascii //weight: 1
        $x_1_6 = {4f 70 65 6e 20 [0-16] 20 46 6f 72 20 42 69 6e 61 72 79 20 41 63 63 65 73 73 20 57 72 69 74 65 20 41 73 20 23}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDropper_O97M_Farheyt_J_2147710784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Farheyt.J"
        threat_id = "2147710784"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Farheyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= -17 + 16" ascii //weight: 1
        $x_1_2 = {20 26 20 22 72 74 22 20 26 20 [0-16] 28 39 39 20 2b 20 33 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= CreateObject(\"Wor\" & \"d.\" & \"Applicatio\" &" ascii //weight: 1
        $x_1_4 = "= \"T\" & \"EM\"" ascii //weight: 1
        $x_1_5 = "& \"\" & \"q2\" &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Farheyt_D_2147711316_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Farheyt.D"
        threat_id = "2147711316"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Farheyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 [0-2] 44 69 6d 20 [0-16] 20 41 73 20 56 61 72 69 61 6e 74 [0-96] 46 6f 72 20 [0-16] 20 3d 20 [0-2] 20 54 6f 20 [0-64] 4c 63 61 73 65 28 22 [0-8] 22 29 20 2b 20 4c 63 61 73 65 28 22 [0-8] 22 29}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Farheyt_M_2147714820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Farheyt.M"
        threat_id = "2147714820"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Farheyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= StrReverse(\"cS\") + Ucase(\"rIPt\") + Ucase(\"INg.\")" ascii //weight: 1
        $x_1_2 = "= \"Fi\" & Ucase(\"lEsysT\") & StrReverse(\"tcejbOme\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Farheyt_N_2147718644_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Farheyt.N"
        threat_id = "2147718644"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Farheyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 20 22 74 6d 70 22 [0-15] 0f 00 20 3d 20 [0-15] 26 [0-5] 72 74 66 22 [0-47] 2b 20 01}  //weight: 2, accuracy: Low
        $x_1_2 = "+ \"fhew\" +" ascii //weight: 1
        $x_1_3 = "& \"hrbs\" +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

