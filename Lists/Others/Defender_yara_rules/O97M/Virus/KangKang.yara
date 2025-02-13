rule Virus_O97M_KangKang_A_2147799664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:O97M/KangKang.gen!A"
        threat_id = "2147799664"
        type = "Virus"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "KangKang"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attributevb_name=\"kangatang\"subauto_open()" ascii //weight: 1
        $x_1_2 = "filename:=application.startuppath&\"\\mypersonnel.xls\"windows(1).visible=trueendifapplication.onsheetactivate=\"\"application.screenupdating" ascii //weight: 1
        $x_1_3 = "=trueapplication.onsheetactivate=\"mypersonnel.xls!allocated\"endsubsuballocated()onerrorresumenextifactiveworkbook.sheets(1).name<>\"kangatang\"thenapplication.screenupdating" ascii //weight: 1
        $x_1_4 = "falsecurrentsh=activesheet.namethisworkbook.sheets(\"kangatang\").copybefore:=activeworkbook.sheets(1)activeworkbook.sheets(currentsh).selectapplication.screenupdating=trueendifendsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_O97M_KangKang_A_2147799664_1
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:O97M/KangKang.gen!A"
        threat_id = "2147799664"
        type = "Virus"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "KangKang"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "subauto_open()'ifthisworkbook.path<>application.path&\"\\xlstart\"thenthisworkbook.saveasfilename:=application.path&\"\\xlstart\\mypersonel1.xls\"application.displayalerts=false" ascii //weight: 1
        $x_1_2 = ".savecopyasfilename:=application.startuppath&\"\\mypersonnel1.xls\"windows(1).visible=trueendifapplication.onsheetactivate=\"\"application.screenupdating" ascii //weight: 1
        $x_1_3 = "trueapplication.onsheetactivate=\"mypersonnel1.xls!allocated\"endsubsuballocated()onerrorresumenextifactiveworkbook.sheets(1).name<>\"kangatang\"thenapplication.screenupdating" ascii //weight: 1
        $x_1_4 = "falsecurrentsh=activesheet.namethisworkbook.sheets(\"kangatang\").copybefore:=activeworkbook.sheets(1)activeworkbook.sheets(currentsh).selectapplication.screenupdating=trueendifendsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

