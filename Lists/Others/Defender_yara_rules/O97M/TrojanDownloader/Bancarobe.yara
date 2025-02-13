rule TrojanDownloader_O97M_Bancarobe_A_2147718883_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bancarobe.A"
        threat_id = "2147718883"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bancarobe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(Environ(\"ap\" &" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA 0&, Replace(\"h" ascii //weight: 1
        $x_1_3 = "& \".\" & StrReverse(\"exe\")" ascii //weight: 1
        $x_1_4 = "ShellExecuteW 0&, StrPtr(\"Open\"), StrPtr(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

