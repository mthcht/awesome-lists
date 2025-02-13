rule TrojanDownloader_O97M_Sharby_A_2147733746_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Sharby.A"
        threat_id = "2147733746"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Sharby"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-6] 53 68 65 6c 6c 20 28 22 6d 73 68 74 61 20 68 74 74 70 73 3a 2f 2f [0-80] 2e 68 74 61 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Sharby_B_2147733766_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Sharby.B"
        threat_id = "2147733766"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Sharby"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f [0-80] 22 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = {53 65 74 20 77 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-8] 29}  //weight: 1, accuracy: Low
        $x_1_4 = {66 69 6c 65 5f 64 6f 63 20 3d 20 77 53 68 65 6c 6c 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 74 65 6d 70 25 22 29 20 26 20 22 [0-16] 2e 64 6f 63 22}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 77 53 68 65 6c 6c 2e 52 75 6e 28 [0-8] 20 2b 20 66 69 6c 65 5f 64 6f 63 20 2b 20 22 22 22 22 2c 20 30 2c 20 54 72 75 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

