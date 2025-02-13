rule TrojanDropper_O97M_Drixed_B_2147708538_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Drixed.B"
        threat_id = "2147708538"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = ", \"%temp%\")" ascii //weight: 1
        $x_1_3 = "& \"\\chaotic.exe" ascii //weight: 1
        $x_1_4 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_5 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 52 69 67 68 74 28 22 [0-16] 22 2c 20 [0-2] 29 20 2b 20 4c 65 66 74 28 22 [0-16] 22 2c 20 [0-2] 29 29}  //weight: 1, accuracy: Low
        $x_1_6 = "CByte(\"&\" + Chr(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

