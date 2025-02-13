rule TrojanDropper_O97M_Bedenel_A_2147708825_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Bedenel.A"
        threat_id = "2147708825"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bedenel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+ \"\\\" + CStr((2147483648# * Rnd) + 1) + \".1\"" ascii //weight: 1
        $x_1_2 = "'w.Exec (\"rundll32.exe \" + Chr(34) + tmpfile + Chr(34) + \",DllGetClassObject host 000000000000\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

