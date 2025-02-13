rule TrojanDownloader_W97M_Poshkod_2147695123_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Poshkod"
        threat_id = "2147695123"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Poshkod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub Document_Open()" ascii //weight: 1
        $x_1_2 = "= \"C:\\Windows\\Temp\\chrupdate.ps1" ascii //weight: 1
        $x_1_3 = "www.ilaunchmanager.com/x/wp-content/plugins/fb-infiltrator-personal/dl2.php" ascii //weight: 1
        $x_1_4 = "= Shell(\"powershell.exe -nologo -file C:\\Windows\\Temp\\chrupdate.ps1\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

