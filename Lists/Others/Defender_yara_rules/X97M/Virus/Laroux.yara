rule Virus_X97M_Laroux_A_2147646399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:X97M/Laroux.gen!A"
        threat_id = "2147646399"
        type = "Virus"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Laroux"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Workbooks(\"StartUp.xls\").Sheets(\"StartUp\").Copy before:=Worksheets(1)" ascii //weight: 2
        $x_1_2 = "Sub ycop()" ascii //weight: 1
        $x_1_3 = "Application.OnSheetActivate = \"StartUp.xls!ycop\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_X97M_Laroux_B_2147691652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:X97M/Laroux.gen!B"
        threat_id = "2147691652"
        type = "Virus"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Laroux"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Workbooks(\"MEMO1.XLS\").Sheets(\"Knight\").Copy before:=Workbooks(n4$).Sheets(1)" ascii //weight: 1
        $x_1_2 = "Sub check_files()" ascii //weight: 1
        $x_1_3 = "Application.OnSheetActivate = \"MEMO1.xls!check_files\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_X97M_Laroux_C_2147691677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:X97M/Laroux.gen!C"
        threat_id = "2147691677"
        type = "Virus"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Laroux"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 78 6c 73 21 [0-2] 63 6f 70}  //weight: 10, accuracy: Low
        $x_10_2 = ".xls!escape" ascii //weight: 10
        $x_1_3 = "ActiveWindow.Visible = False" ascii //weight: 1
        $x_1_4 = "Application.DisplayAlerts = False" ascii //weight: 1
        $x_1_5 = "Application.ScreenUpdating = False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_X97M_Laroux_D_2147693042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:X97M/Laroux.gen!D"
        threat_id = "2147693042"
        type = "Virus"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Laroux"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If ActiveWorkbook.Modules.Count > 0 Then w = 1 Else w = 0" ascii //weight: 1
        $x_1_2 = "\").Copy before:=Workbooks(n4$).Sheets(1)" ascii //weight: 1
        $x_1_3 = "Workbooks(newname$).SaveAs FileName:=Application.StartupPath & \"/\" & \"" ascii //weight: 1
        $x_1_4 = "whichfile = p + w * 10" ascii //weight: 1
        $x_1_5 = "\").Visible = False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_X97M_Laroux_E_2147708933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:X97M/Laroux.gen!E"
        threat_id = "2147708933"
        type = "Virus"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Laroux"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".XLS\" Then p = 1 Else p = 0" ascii //weight: 1
        $x_1_2 = "If ActiveWorkbook.Modules.Count > 0 Then w = 1 Else w = 0" ascii //weight: 1
        $x_1_3 = "whichfile = p + w * 10" ascii //weight: 1
        $x_1_4 = ".Copy before:=Workbooks(n4$).Sheets(1)" ascii //weight: 1
        $x_1_5 = "Workbooks(newname$).SaveAs FileName:=Application.StartupPath &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Virus_X97M_Laroux_A_2147728588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:X97M/Laroux.A"
        threat_id = "2147728588"
        type = "Virus"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Laroux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ThisWorkbook.SaveAs Filename:=Application.Path & \"\\XLSTART\\mypersonel.xls\"" ascii //weight: 1
        $x_1_2 = "ThisWorkbook.SaveCopyAs Filename:=Application.StartupPath & \"\\mypersonnel.xls\"" ascii //weight: 1
        $x_1_3 = "Kill ThisWorkbook.Path & \"\\\" & Replace(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

