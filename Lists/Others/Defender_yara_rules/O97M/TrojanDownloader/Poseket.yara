rule TrojanDownloader_O97M_Poseket_A_2147708910_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Poseket.A"
        threat_id = "2147708910"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Poseket"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6f 77 65 72 53 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 62 79 70 61 73 73 20 2d 6e 6f 70 72 6f 66 69 6c 65 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 3a 2f 2f [0-48] 2f [0-16] 2e 65 78 65 27 2c 27 25 41 50 50 44 41 54 41 25 5c [0-16] 2e 65 78 65 27 29 3b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 25 41 50 50 44 41 54 41 25 5c [0-16] 2e 65 78 65 27}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 24 28 22 43 4f 4d 53 50 45 43 22 29 20 26 20 22 20 2f 63 20 22 20 26 20 [0-16] 2c 20 76 62 48 69 64 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

