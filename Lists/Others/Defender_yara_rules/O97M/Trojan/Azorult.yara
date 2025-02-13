rule Trojan_O97M_Azorult_A_2147753772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Azorult.A!MSR"
        threat_id = "2147753772"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Azorult"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell \"ipconfig\"" ascii //weight: 1
        $x_1_2 = "\"S\" & \"o\" & \"f\" & \"t\" & \"w\" & \"a\" & \"r" ascii //weight: 1
        $x_1_3 = "RegWrite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

