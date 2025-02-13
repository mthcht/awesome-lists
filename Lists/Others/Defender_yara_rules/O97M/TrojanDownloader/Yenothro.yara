rule TrojanDownloader_O97M_Yenothro_A_2147708511_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Yenothro.A"
        threat_id = "2147708511"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Yenothro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Environ(\"tmp\") & \"\\\" & Mid(" ascii //weight: 1
        $x_1_2 = {3d 20 22 68 74 74 70 [0-1] 3a 2f 2f [0-64] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_3 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_4 = {49 6e 53 74 72 52 65 76 28 50 00 2c 20 22 2f 22 29 20 2b 20 31 2c 20 4c 65 6e 28}  //weight: 1, accuracy: Low
        $x_1_5 = "Lib \"shell32.dll\" Alias \"ShellExecuteA\" (ByVal" ascii //weight: 1
        $x_1_6 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 58 4d 4c 48 54 54 50 22 29 0d 0a 53 65 74 20 50 00 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d 22 29 0d 0a 50 00 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 50 00 2c 20 46 61 6c 73 65 0d 0a 50 00 2e 73 65 6e 64 0d 0a 50 00 2e 54 79 70 65 20 3d 20 31 0d 0a 50 00 2e 4f 70 65 6e 0d 0a 50 00 2e 57 72 69 74 65 20 50 00 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 0d 0a 50 00 2e 53 61 76 65 54 6f 46 69 6c 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

