rule TrojanDownloader_O97M_Thunbin_B_2147742466_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Thunbin.B"
        threat_id = "2147742466"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Thunbin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = "= \"S\" & \"h\" & \"e\" & \"l\" & \"l\"" ascii //weight: 1
        $x_1_3 = "= \"W\" & \"S\" & \"c\" & \"r\" & \"i\" & \"p\" & \"t\"" ascii //weight: 1
        $x_1_4 = "= \"p\" & \"o\" & \"w\" & \"e\" & \"r\" & \"s\" & \"h\" & \"e\" & \"l\" & \"l\" & \".\" & \"e\" & \"x\" & \"e\"" ascii //weight: 1
        $x_1_5 = ".Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

