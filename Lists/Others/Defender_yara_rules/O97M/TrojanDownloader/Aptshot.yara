rule TrojanDownloader_O97M_Aptshot_A_2147731186_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Aptshot.A"
        threat_id = "2147731186"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Aptshot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rising_sun = \"kernel32\"" ascii //weight: 1
        $x_1_2 = "qwdzxcv = dnnaigej(gweasdf, \"LoadLibraryA\")" ascii //weight: 1
        $x_1_3 = "wetqdawe = dnnaigej(gweasdf, \"GetProcAddress\")" ascii //weight: 1
        $x_1_4 = "LMCooperator = SharpShooter(vAddress, 0, 0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

