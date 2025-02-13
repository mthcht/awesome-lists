rule TrojanDownloader_O97M_Jaranat_A_2147716555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Jaranat.A"
        threat_id = "2147716555"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Jaranat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Document_Open()" ascii //weight: 1
        $x_1_2 = "\"URLDownloadToFileA\"" ascii //weight: 1
        $x_1_3 = "\"ShellExecuteA\"" ascii //weight: 1
        $x_1_4 = "\"urlmon\"" ascii //weight: 1
        $x_1_5 = "Lib \"shell32.dll\"" ascii //weight: 1
        $x_1_6 = {2e 65 78 65 2e 45 58 45 22 [0-32] 45 6e 76 69 72 6f 6e 24 28 22 74 6d 70 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

