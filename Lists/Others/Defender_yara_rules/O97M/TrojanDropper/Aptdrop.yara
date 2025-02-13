rule TrojanDropper_O97M_Aptdrop_H_2147731862_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Aptdrop.H"
        threat_id = "2147731862"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Aptdrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " = FreeFile" ascii //weight: 1
        $x_1_2 = " = Environ(\"TMP\") & \"\\vba_macro.exe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Aptdrop_I_2147734473_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Aptdrop.I"
        threat_id = "2147734473"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Aptdrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& Chr$(Val(\"&H\" & Mid$(" ascii //weight: 1
        $x_1_2 = " = \"ABCDEFGHI\" & \"JKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

