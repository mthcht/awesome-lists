rule TrojanDownloader_O97M_Meadnk_RB_2147760167_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Meadnk.RB!MSR"
        threat_id = "2147760167"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Meadnk"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = "\"Ws\"" ascii //weight: 1
        $x_1_3 = "\"C:\\Users\\public\" & \"\\ReadMe.txt.lnk\"" ascii //weight: 1
        $x_1_4 = "& \"cr\"" ascii //weight: 1
        $x_1_5 = "& \"ip\"" ascii //weight: 1
        $x_1_6 = "& \"t.Sh\"" ascii //weight: 1
        $x_1_7 = "& \"ell\"" ascii //weight: 1
        $x_1_8 = "= s.CreateShortcut(" ascii //weight: 1
        $x_1_9 = ".TargetPath = \"mshta.exe\"" ascii //weight: 1
        $x_1_10 = ".Save" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

