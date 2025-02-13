rule TrojanDownloader_O97M_Pocrimee_A_2147713061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Pocrimee.A"
        threat_id = "2147713061"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Pocrimee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 6f 77 65 72 73 68 65 6c 6c [0-128] 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 [0-128] 2c 27 25 54 45 4d 50 25 5c 70 75 74 74 79 72 2e 65 78 65 27}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

