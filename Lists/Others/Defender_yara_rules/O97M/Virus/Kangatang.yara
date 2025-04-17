rule Virus_O97M_Kangatang_A_2147933087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:O97M/Kangatang.gen!A"
        threat_id = "2147933087"
        type = "Virus"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Kangatang"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " Application.ScreenUpdating = False" ascii //weight: 1
        $x_1_2 = "ThisWorkbook.SaveCopyAs Filename:=Application.StartupPath & \"\\mypersonnel.xls\"" ascii //weight: 1
        $x_1_3 = "If ActiveWorkbook.Sheets(1).Name <> \"Kangatang\" Then" ascii //weight: 1
        $x_1_4 = "ThisWorkbook.Sheets(\"Kangatang\").Copy before:=ActiveWorkbook.Sheets(1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_O97M_Kangatang_A_2147933087_1
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:O97M/Kangatang.gen!A"
        threat_id = "2147933087"
        type = "Virus"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Kangatang"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 70 70 6c 69 63 61 74 69 6f 6e 2e 6f 6e 73 68 65 65 74 61 63 74 69 76 61 74 65 3d 22 6d 79 70 65 72 73 6f 6e 6e 65 6c [0-4] 2e 78 6c 73 21 61 6c 6c 6f 63 61 74 65 64 22}  //weight: 1, accuracy: Low
        $x_1_2 = "ifactiveworkbook.sheets(1).name<>\"kangatang\"thenapplication.screenupdating" ascii //weight: 1
        $x_1_3 = "thisworkbook.sheets(\"kangatang\").copybefore:=activeworkbook.sheets(1)activeworkbook.sheets(currentsh).selectapplication.screenupdating=trueendifendsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

