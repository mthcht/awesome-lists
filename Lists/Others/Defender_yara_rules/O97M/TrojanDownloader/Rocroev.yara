rule TrojanDownloader_O97M_Rocroev_A_2147686201_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Rocroev.A"
        threat_id = "2147686201"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Rocroev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://5.199.165.239/march23.php" ascii //weight: 1
        $x_1_2 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 [0-15] 20 26 20 22 [0-15] 5c [0-15] 2e 63 6f 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

