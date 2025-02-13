rule TrojanDownloader_O97M_Mulseyco_A_2147694220_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Mulseyco.A"
        threat_id = "2147694220"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Mulseyco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellExecuteA\" (ByVal" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA\" (ByVal" ascii //weight: 1
        $x_1_3 = "yllM = \"360security.exe" ascii //weight: 1
        $x_1_4 = "Environ$(\"tmp\") & \"\\\" & yllM" ascii //weight: 1
        $x_1_5 = "ChangeText 0, \"open" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

