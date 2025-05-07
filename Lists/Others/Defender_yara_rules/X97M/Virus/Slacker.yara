rule Virus_X97M_Slacker_G_2147731093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:X97M/Slacker.G"
        threat_id = "2147731093"
        type = "Virus"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Slacker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 54 4d 50 5c 22 20 2b 20 [0-32] 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 43 6f 70 79 41 73 20 46 69 6c 65 6e 61 6d 65 3a 3d}  //weight: 1, accuracy: Low
        $x_1_2 = ".Lines(1, 1) <> \"'OOO\" Then" ascii //weight: 1
        $x_1_3 = "SaveAs Filename:=Application.StartupPath + \"\\Book1.\", FileFormat:=xlNormal" ascii //weight: 1
        $x_1_4 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 4f 6e 4b 65 79 20 22 7b 46 35 7d 22 2c 20 22 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 76 74 48 69 64 65 52 6f 77 22 [0-21] 41 70 70 6c 69 63 61 74 69 6f 6e 2e 4f 6e 4b 65 79 20 22 7b 46 36 7d 22 2c 20 22 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 76 74 53 68 6f 77 52 6f 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_X97M_Slacker_A_2147939222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:X97M/Slacker.gen!A"
        threat_id = "2147939222"
        type = "Virus"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Slacker"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If w2.Lines(1, 1) <> \"'OOO\" Then" ascii //weight: 1
        $x_1_2 = "If UCase(Dir(Application.StartupPath + \"\\book1.\")) <> \"BOOK1\" Then" ascii //weight: 1
        $x_1_3 = "xlCM.InsertLines 1, w1.Lines(1, w1.CountOfLines)" ascii //weight: 1
        $x_1_4 = "xlWB.SaveAs Filename:=Application.StartupPath + \"\\Book1.\", FileFormat:=xlNormal, AddToMru:=False" ascii //weight: 1
        $x_1_5 = "mFileName = \"C:\\TMP\\\" + oldname" ascii //weight: 1
        $x_1_6 = "Application.Selection.EntireRow.Hidden = True" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

