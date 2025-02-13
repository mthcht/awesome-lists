rule TrojanDownloader_O97M_Sheurnif_A_2147731152_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Sheurnif.A"
        threat_id = "2147731152"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Sheurnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sleep = \"bitsadmin /transfer" ascii //weight: 1
        $x_1_2 = "/download /priority high http://" ascii //weight: 1
        $x_1_3 = "forfiles /S /M *.doc /C \"\"cmd /c del @file\"\"\"" ascii //weight: 1
        $x_1_4 = "= Int((9999999 * Rnd) + 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

