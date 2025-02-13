rule TrojanDownloader_W97M_Adobdocro_A_2147685882_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adobdocro.A"
        threat_id = "2147685882"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adobdocro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 64 6f 64 62 2e 53 74 72 65 61 6d 22 29 [0-133] 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f [0-53] 2e 65 78 65 22 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 54 79 70 65 20 3d 20 31 [0-16] 2e 4f 70 65 6e [0-16] 2e 77 72 69 74 65 [0-53] 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 [0-53] 2e 73 61 76 65 74 6f 66 69 6c 65 [0-53] 2e 63 6f 6d 22 2c [0-5] 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

