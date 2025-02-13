rule TrojanDownloader_O97M_Ebijo_PB_2147731029_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ebijo.PB"
        threat_id = "2147731029"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ebijo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 6e 74 65 72 61 63 74 69 6f 6e 20 5f 0d 0a 2e 53 68 65 6c 6c 28 [0-32] 29 2c 20 [0-10] 29}  //weight: 1, accuracy: Low
        $x_1_2 = "Function Ebijo()" ascii //weight: 1
        $x_1_3 = {53 65 74 20 [0-10] 20 3d 20 [0-10] 2e 53 68 61 70 65 73 28 [0-64] 29 2e 54 65 78 74 46 72 61 6d 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

