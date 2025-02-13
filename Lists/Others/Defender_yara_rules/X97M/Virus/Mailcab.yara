rule Virus_X97M_Mailcab_A_2147688702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:X97M/Mailcab.gen!A"
        threat_id = "2147688702"
        type = "Virus"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Mailcab"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".InsertLines 6, \"Call Do_What\"" ascii //weight: 1
        $x_1_2 = {49 66 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 3c 3e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 54 68 65 6e 0d 0a 20 20 52 65 73 74 6f 72 65 41 66 74 65 72 4f 70 65 6e 0d 0a 20 20 43 61 6c 6c 20 4f 70 65 6e 44 6f 6f 72 0d 0a 20 20 43 61 6c 6c 20 4d 69 63 72 6f 73 6f 66 74 68 6f 62 62 79}  //weight: 1, accuracy: High
        $x_1_3 = {41 63 74 69 76 65 43 65 6c 6c 2e 46 6f 72 6d 75 6c 61 52 31 43 31 20 3d 20 22 3d 41 4c 45 52 54 28 22 22 ef bf bd ef bf bd ef bf bd c3 ba ea a3 ac ef bf bd d8 b1 ef bf bd 20 22 20 26 20 43 68 72 28 31 30 29 20 26 20 4e 6f 77 20 26 20 43 68 72 28 31 30 29 20 26 20 22 50 6c 65 61 73 65 20 45 6e 61 62 6c 65 20 4d 61 63 72 6f 21 22 22 2c 33 29 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_X97M_Mailcab_C_2147688703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:X97M/Mailcab.C"
        threat_id = "2147688703"
        type = "Virus"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Mailcab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Environ(\"Temp\") & \"\\\" & ModuleName & \".bas\"" ascii //weight: 1
        $x_1_2 = "Shell Environ$(\"comspec\") & \" /c attrib -S -h \"\"\" & Application.StartupPath & \"\\K4.XLS\"" ascii //weight: 1
        $x_1_3 = "= \"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\\" & VS & \"\\Excel\\Security\\AccessVBOM" ascii //weight: 1
        $x_1_4 = "WshShell.Run Environ$(\"comspec\") & \" /c RD /S /Q E:\\KK\", vbHide, False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

