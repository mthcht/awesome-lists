rule TrojanDropper_O97M_Carpcdl_AJ_2147742642_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Carpcdl.AJ"
        threat_id = "2147742642"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Carpcdl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c [0-5] 2e 78 6c 73 78 22}  //weight: 1, accuracy: Low
        $x_1_2 = "= TempName + \".zip\"" ascii //weight: 1
        $x_1_3 = "= Environ(\"TEMP\") '& \"\\UnzTmp\"" ascii //weight: 1
        $x_1_4 = "= Environ(\"APPDATA\")" ascii //weight: 1
        $x_1_5 = {4b 69 6c 6c 20 [0-16] 20 26 20 22 5c 6f 6c 65 4f 62 6a 65 63 74 2a 2e 62 69 6e 22}  //weight: 1, accuracy: Low
        $x_1_6 = {6f 41 70 70 2e 4e 61 6d 65 73 70 61 63 65 28 [0-16] 29 2e 43 6f 70 79 48 65 72 65 20 6f 41 70 70 2e 4e 61 6d 65 73 70 61 63 65 28 [0-16] 29 2e 69 74 65 6d 73 2e 49 74 65 6d 28 22 78 6c 5c 65 6d 62 65 64 64 69 6e 67 73 5c 6f 6c 65 4f 62 6a 65 63 74 31 2e 62 69 6e 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

