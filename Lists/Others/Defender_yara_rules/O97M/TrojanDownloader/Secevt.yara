rule TrojanDownloader_O97M_Secevt_2147730116_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Secevt"
        threat_id = "2147730116"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Secevt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 52 65 67 57 72 69 74 65 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c ?? ?? 2e 30 5c 45 78 63 65 6c 5c 53 65 63 75 72 69 74 79 5c 56 42 41 57 61 72 6e 69 6e 67 73 22 2c 20 31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 52 65 67 57 72 69 74 65 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c ?? ?? 2e 30 5c 57 6f 72 64 5c 53 65 63 75 72 69 74 79 5c 50 72 6f 74 65 63 74 65 64 56 69 65 77 5c 44 69 73 61 62 6c 65 41 74 74 61 63 68 65 6d 65 6e 74 73 49 6e 50 56 22 2c 20 31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 52 65 67 57 72 69 74 65 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c ?? ?? 2e 30 5c 57 6f 72 64 5c 53 65 63 75 72 69 74 79 5c 50 72 6f 74 65 63 74 65 64 56 69 65 77 5c 44 69 73 61 62 6c 65 55 6e 73 61 66 65 4c 6f 63 61 74 69 6f 6e 73 49 6e 50 56 22 2c 20 31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

