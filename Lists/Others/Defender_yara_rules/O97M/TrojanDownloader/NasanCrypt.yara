rule TrojanDownloader_O97M_NasanCrypt_PA_2147779980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/NasanCrypt.PA!MTB"
        threat_id = "2147779980"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "NasanCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 50 6f 77 65 72 53 68 65 6c 6c [0-80] 68 69 64 64 65 6e 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 73 3a 2f 2f 61 6e 79 66 69 6c 65 2e 32 35 35 62 69 74 73 2e 63 6f 6d 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {25 41 50 50 44 41 54 41 25 5c [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 25 41 50 50 44 41 54 41 25 5c [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

