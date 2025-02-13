rule TrojanDownloader_O97M_Watniks_A_2147708286_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Watniks.A"
        threat_id = "2147708286"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Watniks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WshShell.Run file, 0, 1" ascii //weight: 1
        $x_1_2 = ".SaveToFile localFile, 2" ascii //weight: 1
        $x_1_3 = "s = df(url, FileP(\"\"))" ascii //weight: 1
        $x_1_4 = "FileP = getTempPath() + \"windows.exe" ascii //weight: 1
        $x_1_5 = "Set f = filesys.GetSpecialFolder(2)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

