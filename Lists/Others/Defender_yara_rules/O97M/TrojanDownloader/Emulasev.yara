rule TrojanDownloader_O97M_Emulasev_A_2147692487_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emulasev.A"
        threat_id = "2147692487"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emulasev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 31 4d 77 4c 61 55 37 30 37 20 56 51 75 77 64 6a 43 4b 7a 66 62 62 61 66 50 28 22 68 ?? 74 ?? 74 ?? 70}  //weight: 1, accuracy: Low
        $x_1_2 = {45 6e 76 69 72 6f 6e 28 56 51 75 77 64 6a 43 4b 7a 66 62 62 61 66 50 28 22 54 ?? 4d ?? 50}  //weight: 1, accuracy: Low
        $x_1_3 = "VQuwdjCKzfbbafP(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

