rule Trojan_O97M_ExecXlF_YA_2147740096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/ExecXlF.YA!MTB"
        threat_id = "2147740096"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ExecXlF"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 20 52 65 70 6c 61 63 65 28 55 73 65 72 46 6f 72 6d [0-2] 2e 54 65 78 74 42 6f 78 [0-2] 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_2 = "ExecuteExcel4Macro (\"exec(\"\"CMD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

