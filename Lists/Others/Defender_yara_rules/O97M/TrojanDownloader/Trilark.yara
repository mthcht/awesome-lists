rule TrojanDownloader_O97M_Trilark_A_2147749446_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Trilark.A!dha"
        threat_id = "2147749446"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Trilark"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 68 65 6c 6c [0-3] 28 74 65 78 74 62 6f 78 [0-3] 2e 74 65 78 74 20 2b 20 74 65 78 74 62 6f 78 [0-3] 2e 74 65 78 74 20 2b 20 74 65 78 74 62 6f 78 [0-3] 2e 74 65 78 74}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 74 65 78 74 20 2b 20 22 2e 22 20 2b 20 74 65 78 74 62 6f 78 [0-3] 2e 74 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

