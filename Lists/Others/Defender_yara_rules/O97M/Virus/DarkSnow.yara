rule Virus_O97M_DarkSnow_A_2147691653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:O97M/DarkSnow.gen!A"
        threat_id = "2147691653"
        type = "Virus"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "DarkSnow"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Private Sub runblackice()" ascii //weight: 1
        $x_1_2 = "Private Declare Function WriteFile Lib \"kernel32\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

