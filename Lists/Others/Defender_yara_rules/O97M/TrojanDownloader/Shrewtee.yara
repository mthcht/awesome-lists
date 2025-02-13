rule TrojanDownloader_O97M_Shrewtee_A_2147690644_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Shrewtee.A"
        threat_id = "2147690644"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Shrewtee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = "WHERE = Environ(\"Temp\") & \"\\\" & \"test.exe" ascii //weight: 1
        $x_1_3 = "DownloadStatus = URLDownloadToFile(0, URL, WHERE, 0, 0)" ascii //weight: 1
        $x_1_4 = "CreateObject(\"WScript.Shell\").Run WHERE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

