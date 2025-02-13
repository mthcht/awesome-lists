rule TrojanDownloader_O97M_Dimsob_A_2147709461_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dimsob.A"
        threat_id = "2147709461"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dimsob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 20 [0-24] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-24] 2e 54 65 78 74 42 6f 78 [0-2] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 57 72 69 74 65 20 [0-24] 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79}  //weight: 1, accuracy: Low
        $x_1_3 = {20 3d 20 22 4d 53 22 20 2b 20 [0-24] 2e 54 65 78 74 42 6f 78}  //weight: 1, accuracy: Low
        $x_1_4 = {20 3d 20 45 6e 76 69 72 6f 6e 28 [0-24] 2e [0-24] 29 20 26 20 22 2f [0-16] 22 20 2b [0-24] 2e 54 65 78 74 42 6f 78}  //weight: 1, accuracy: Low
        $x_1_5 = {20 3d 20 53 68 65 6c 6c 28 [0-24] 2e 54 65 78 74 42 6f 78 [0-2] 29}  //weight: 1, accuracy: Low
        $x_1_6 = {44 69 6d 20 [0-24] 20 41 73 20 49 6e 74 65 67 65 72 0d 0a 46 6f 72 20 [0-24] 20 3d 20 04 00 20 54 6f 20 04 00 20 2b 20 04 00 0d 0a 44 6f 45 76 65 6e 74 73 0d 0a 4e 65 78 74 20 [0-24] 0d 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

