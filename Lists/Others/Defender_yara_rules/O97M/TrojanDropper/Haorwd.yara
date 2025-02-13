rule TrojanDropper_O97M_Haorwd_DHA_2147731001_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Haorwd!DHA"
        threat_id = "2147731001"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Haorwd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Environ(\"APPDATA\") & \"\\wird.exe\"" ascii //weight: 1
        $x_1_2 = "Environ(\"APPDATA\") & \"\\lkn\"" ascii //weight: 1
        $x_1_3 = "FileCopy oWsh.SpecialFolders(\"Desktop\") & \"\\\" & strFileName, s & \"\\\" & strFileName" ascii //weight: 1
        $x_1_4 = "werd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Haorwd_A_2147731736_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Haorwd.A!DHA"
        threat_id = "2147731736"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Haorwd"
        severity = "Critical"
        info = "DHA: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChDir Environ(\"T\" & \"e\" & \"m\" & \"p\")" ascii //weight: 1
        $x_1_2 = "= StrConv(DecodeBase64" ascii //weight: 1
        $x_1_3 = "Open Environ(\"T\" & \"e\" & \"m\" & \"p\") & \"\\1.hta\"" ascii //weight: 1
        $x_1_4 = ".pif\"" ascii //weight: 1
        $x_1_5 = "Shell Environ(StrConv(DecodeBase64(laax), vbUnicode)) & StrConv(DecodeBase64(\"XDYuZXhl\"), vbUnicode), vbHide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Haorwd_B_2147731922_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Haorwd.B!DHA"
        threat_id = "2147731922"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Haorwd"
        severity = "Critical"
        info = "DHA: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 [0-6] 65 [0-6] 6d [0-6] 70 22 29 20 26 20 22 5c 22}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 65 6c 6c 20 22 [0-4] 2e 62 61 74 22 2c 20 76 62 48 69 64 65}  //weight: 1, accuracy: Low
        $x_1_3 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 28 53 74 72 43 6f 6e 76 28 44 65 63 6f 64 65 42 61 73 65 36 34 28 [0-16] 29 2c 20 76 62 55 6e 69 63 6f 64 65 29 29 20 26 20 53 74 72 43 6f 6e 76 28 44 65 63 6f 64 65 42 61 73 65 36 34 28 22 [0-16] 22 29 2c 20 76 62 55 6e 69 63 6f 64 65 29 2c 20 76 62 48 69 64 65}  //weight: 1, accuracy: Low
        $x_2_4 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-16] 20 26 20 22 36 66 73 64 46 66 61 2e 63 6f 6d 22 2c 20 54 72 75 65 29}  //weight: 2, accuracy: Low
        $x_2_5 = {4f 70 65 6e 20 [0-16] 20 26 20 22 36 66 73 64 46 66 61 2e 63 6f 6d 22 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

