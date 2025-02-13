rule TrojanDropper_O97M_SilverMob_A_2147724638_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/SilverMob.A!dha"
        threat_id = "2147724638"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "SilverMob"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "(1) = \"AABD77E7E4E7E7E7E3E7E7" ascii //weight: 10
        $x_1_2 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_3 = "liveOn" ascii //weight: 1
        $x_1_4 = "svchost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_O97M_SilverMob_A_2147724638_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/SilverMob.A!dha"
        threat_id = "2147724638"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "SilverMob"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(46 + (Asc(" ascii //weight: 1
        $x_1_2 = ") - 46 - 20 + (122 - 46)) Mod (122 - 46))" ascii //weight: 1
        $x_1_3 = "+ Chr(Asc(Mid$(" ascii //weight: 1
        $x_1_4 = "obj.Run filename, 1, False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_SilverMob_D_2147740106_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/SilverMob.D!dha"
        threat_id = "2147740106"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "SilverMob"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Documents.Open (Environ(\"temp\")" ascii //weight: 1
        $x_1_2 = "objEmbeddedDoc.SaveAs Environ(\"temp\") & \"\\\" & strEmbeddedDocName" ascii //weight: 1
        $x_1_3 = "BinName = Environ(\"temp\") & \"\\dwm.exe\"" ascii //weight: 1
        $x_1_4 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_5 = "obj.Run BinName &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

