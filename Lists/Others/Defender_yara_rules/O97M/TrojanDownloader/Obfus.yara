rule TrojanDownloader_O97M_Obfus_B_2147750794_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Obfus.B!MTB"
        threat_id = "2147750794"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 22 77 73 63 72 69 70 74 20 2f 2f 6e 6f 6c 6f 67 6f 20 63 3a 5c 43 6f 6c 6f 72 66 6f 6e 74 73 33 32 5c 76 69 73 69 74 63 61 72 64 2e 76 62 73 20 [0-64] 20 63 3a 5c 43 6f 6c 6f 72 66 6f 6e 74 73 33 32 5c 73 65 63 70 69 31 35 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "start c:\\Colorfonts32\\secpi15.exe" ascii //weight: 1
        $x_1_3 = "LoadScriptVBS GetObject(HashTable()), \"c:\\Colorfonts32\\B4D9D02119.cmd\", 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Obfus_D_2147751639_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Obfus.D!MTB"
        threat_id = "2147751639"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "b_rt = Chr(dsacdsas - 14)" ascii //weight: 1
        $x_1_2 = {62 5f 72 74 28 31 30 31 29 20 26 20 62 5f 72 74 28 39 37 29 20 26 20 62 5f 72 74 28 38 31 29 20 26 20 62 5f 72 74 28 31 32 38 29 20 26 20 62 5f 72 74 28 31 31 39 29 20 26 20 62 5f 72 74 28 31 32 36 29 20 26 20 62 5f 72 74 28 39 38 29 20 26 20 62 5f 72 74 28 36 30 29 20 26 20 62 5f 72 74 28 31 32 39 29 20 26 20 62 5f 72 74 28 38 36 29 20 26 20 62 5f 72 74 28 38 33 29 20 26 20 62 5f 72 74 28 31 32 32 29 20 26 20 62 5f 72 74 28 39 30 29 0d 0a 53 65 74 [0-150] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-155] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 62 5f 72 74 28 31 31 38 29 20 26 20 62 5f 72 74 28 31 33 30 29 20 26 20 62 5f 72 74 28 31 33 30 29 20 26 20 62 5f 72 74 28 31 32 36 29 [0-12] 20 26 20 62 5f 72 74 28 37 32 29 20 26 20 62 5f 72 74 28 36 31 29 20 26 20 62 5f 72 74 28 36 31 29 20 [0-220] 20 26 20 62 5f 72 74 28 36 30 29 20 26 20 62 5f 72 74 28 31 31 33 29 20 26 20 62 5f 72 74 28 31 32 35 29 20 26 20 62 5f 72 74 28 31 32 33 29 20 26 20 62 5f 72 74 28 36 31 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

