rule TrojanDropper_W97M_Bartallex_B_2147695373_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:W97M/Bartallex.B"
        threat_id = "2147695373"
        type = "TrojanDropper"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Chr(104) + Chr(116) + Chr(116) + Chr(112) + Chr(58) + Chr(47) + Chr(47) + Chr(115) + Chr(97) + Chr(118) + Chr(101) + Chr(112) + Chr(105) + Chr(99) + Chr(46) + Chr(115) + Chr(117) + Chr(47)" ascii //weight: 1
        $x_1_2 = "Chr(73) + Chr(78) + Chr(67) + Chr(76) + Chr(85) + Chr(68) + Chr(69) + Chr(80) + Chr(73) + Chr(67) + Chr(84) + Chr(85) + Chr(82) + Chr(69) + Chr(32) + Chr(32) + Chr(34)" ascii //weight: 1
        $x_1_3 = "= \"&H\" +" ascii //weight: 1
        $x_1_4 = "For Binary Access Read Write As" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_W97M_Bartallex_C_2147696478_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:W97M/Bartallex.C"
        threat_id = "2147696478"
        type = "TrojanDropper"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Path = wsh.ExpandEnvironmentStrings(\"%APPDATA%\")" ascii //weight: 2
        $x_2_2 = "fso.OpenTextFile(Path & \"\\\" & \"windows.exe\", 2, True)" ascii //weight: 2
        $x_1_3 = ".Run Path & \"\\windows.exe\"" ascii //weight: 1
        $x_1_4 = "= base64.Base64Decode(UserForm2.TextBox1)" ascii //weight: 1
        $x_1_5 = ".DataType = \"bin.base64\"" ascii //weight: 1
        $x_1_6 = ".WriteLine (exe)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_W97M_Bartallex_D_2147708615_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:W97M/Bartallex.D"
        threat_id = "2147708615"
        type = "TrojanDropper"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 46 69 6e 64 [0-16] 2e 54 65 78 74 20 3d 20 22 [0-16] 22 [0-16] 2e 46 6f 72 77 61 72 64 20 3d 20 54 72 75 65}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 20 22 65 22 20 2b 20 22 78 22 20 2b 20 22 65 22 [0-32] 20 3d 20 46 72 65 65 46 69 6c 65 28 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= Environ(\"TEMP\")" ascii //weight: 1
        $x_1_4 = ") = CByte(\"&H\" & Mid(" ascii //weight: 1
        $x_1_5 = "= CreateObject(\"S\" + \"hel\" + \"l.Ap\" + \"pl\" + \"i\" + \"cation\")" ascii //weight: 1
        $x_1_6 = "= \"tnNjMRzMbperfect\"" ascii //weight: 1
        $x_1_7 = {50 75 74 20 23 [0-32] 2c 20 31 2c 20 [0-32] 43 6c 6f 73 65 20 23 [0-128] 41 73 20 53 74 72 69 6e 67 29 [0-16] 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-16] 49 66 20 [0-32] 20 3d 20 22 32 22 20 54 68 65 6e [0-16] 4d 73 67 42 6f 78 20 28}  //weight: 1, accuracy: Low
        $x_1_8 = {44 6f 20 57 68 69 6c 65 20 [0-8] 20 3e 20 [0-32] 4d 79 52 61 6e 67 65 2e 43 6f 6c 6c 61 70 73 65 [0-32] 4d 79 52 61 6e 67 65 2e 49 6e 73 65 72 74 41 66 74 65 72 20 28 [0-32] 29 [0-16] 45 78 69 74 20 44 6f [0-16] 4c 6f 6f 70 [0-48] 2e 4f 70 65 6e 20 28 [0-32] 20 26 20 22 5c 22 20 26 20 [0-32] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDropper_W97M_Bartallex_E_2147716564_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:W97M/Bartallex.E"
        threat_id = "2147716564"
        type = "TrojanDropper"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Left(\"wintc\", 3) & \"mgmts\" & Right(\"tetragon:\\\\\", 3)" ascii //weight: 1
        $x_1_2 = "& \"oot\" + UCase(\"\\cimV\") + \"2\"" ascii //weight: 1
        $x_1_3 = "= LCase(\"wiN\") & \"32_Pro\" & LCase(\"CeSs\")" ascii //weight: 1
        $x_1_4 = "For Binary Access Read Write As" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

