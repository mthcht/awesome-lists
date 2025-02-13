rule TrojanDropper_O97M_Netwire_PDA_2147830109_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Netwire.PDA!MTB"
        threat_id = "2147830109"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call sss(Options.DefaultFilePath(wdTempFilePath))" ascii //weight: 1
        $x_1_2 = "koka = \"\\hepluss3.d\" & \"oc\"" ascii //weight: 1
        $x_1_3 = "Call Search(sfxcv.GetFolder(ffff))" ascii //weight: 1
        $x_1_4 = ".Open FileName:=strReturn, PasswordDocument:=\"44\"" ascii //weight: 1
        $x_1_5 = "strReturn = pal.Path" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

