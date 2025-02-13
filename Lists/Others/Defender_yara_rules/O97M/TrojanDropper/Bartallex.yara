rule TrojanDropper_O97M_Bartallex_2147710022_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Bartallex"
        threat_id = "2147710022"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"Wor\" & \"d.\" & \"Applicatio\"" ascii //weight: 1
        $x_1_2 = "= \".rtf\"" ascii //weight: 1
        $x_1_3 = "= \"T\" & \"EM\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Bartallex_2147710022_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Bartallex"
        threat_id = "2147710022"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"\" & \"W\" & \"\" & \"or\" & \"d.\" & \"Applicatio" ascii //weight: 1
        $x_1_2 = "& \".rtf\"" ascii //weight: 1
        $x_1_3 = "& \"T\" & \"EM\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Bartallex_2147710022_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Bartallex"
        threat_id = "2147710022"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcase(\"wiN3\") & StrReverse(\"dorP_2\") & StrReverse(\" tcu\")" ascii //weight: 1
        $x_1_2 = "ivory & \".\\root\\cimv2\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

