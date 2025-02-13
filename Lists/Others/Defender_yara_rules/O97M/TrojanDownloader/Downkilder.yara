rule TrojanDownloader_O97M_Downkilder_A_2147719346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Downkilder.A"
        threat_id = "2147719346"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Downkilder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"START\").Visible = xlVeryHidden" ascii //weight: 1
        $x_1_2 = "fname = Environ(\"TMP\") & \"\\explorer.exe\"" ascii //weight: 1
        $x_1_3 = "rss = Shell(fname, 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

