rule Trojan_O97M_Clayslide_2147727372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Clayslide"
        threat_id = "2147727372"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Clayslide"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Libraries\\fireeye.vbs" ascii //weight: 1
        $x_1_2 = "\\Libraries\\up" ascii //weight: 1
        $x_1_3 = "\\Libraries\\dn" ascii //weight: 1
        $x_1_4 = "\\Libraries\\tp" ascii //weight: 1
        $x_1_5 = "Set FireeyeVbs = ActiveWorkbook.Worksheets(\"Incompatible\").Cells(1, 25)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_O97M_Clayslide_A_2147727387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Clayslide.A"
        threat_id = "2147727387"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Clayslide"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Private Sub Workbook_Open" ascii //weight: 1
        $x_1_2 = "Call fireeye_Init" ascii //weight: 1
        $x_1_3 = "Set wss = CreateObject(\"WS" ascii //weight: 1
        $x_1_4 = "wss.Run cm" ascii //weight: 1
        $x_1_5 = "ActiveWorkbook.Worksheets(1).Visible = False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

