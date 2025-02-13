rule TrojanDownloader_VBA_Obfuse_AK_2147745814_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:VBA/Obfuse.AK!eml"
        threat_id = "2147745814"
        type = "TrojanDownloader"
        platform = "VBA: Visual Basic for Applications scripts"
        family = "Obfuse"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub Document_Open()" ascii //weight: 1
        $x_1_2 = {2e 00 52 00 75 00 6e 00 20 00 [0-31] 28 00 41 00 63 00 74 00 69 00 76 00 65 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 2e 00 56 00 61 00 72 00 69 00 61 00 62 00 6c 00 65 00 73 00 28 00 22 00 [0-31] 22 00 29 00 2e 00 56 00 61 00 6c 00 75 00 65 00 29 00 2c 00 20 00 30 00 2c 00 20 00 54 00 72 00 75 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 52 75 6e 20 [0-31] 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 56 61 72 69 61 62 6c 65 73 28 22 [0-31] 22 29 2e 56 61 6c 75 65 29 2c 20 30 2c 20 54 72 75 65}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-15] 28 22 [0-31] 22 29 29}  //weight: 1, accuracy: Low
        $x_1_5 = {26 00 20 00 43 00 68 00 72 00 28 00 56 00 61 00 6c 00 28 00 43 00 68 00 72 00 28 00 49 00 6e 00 74 00 28 00 [0-3] 20 00 2b 00 20 00 [0-3] 20 00 2b 00 20 00 [0-3] 20 00 2b 00 20 00 49 00 6e 00 74 00 28 00 [0-3] 20 00 2f 00 20 00 [0-3] 29 00 20 00 2d 00 20 00 [0-3] 20 00 2d 00 20 00 [0-3] 20 00 2d 00 20 00 [0-3] 20 00 2d 00 20 00 [0-3] 20 00 2b 00 20 00 [0-3] 20 00 2d 00 20 00 [0-3] 20 00 2d 00 20 00 [0-3] 20 00 2b 00 20 00 [0-3] 29 00 29 00 20 00 26 00 20 00 43 00 68 00 72 00 28 00 49 00 6e 00 74 00 28 00 [0-3] 20 00 2b 00 20 00 [0-3] 20 00 2b 00 20 00 49 00 6e 00 74 00 28 00 [0-3] 20 00 2f 00 20 00 [0-3] 29 00 20 00 2d 00 20 00 [0-3] 20 00 2d 00 20 00 [0-3] 20 00 2d 00}  //weight: 1, accuracy: Low
        $x_1_6 = {26 20 43 68 72 28 56 61 6c 28 43 68 72 28 49 6e 74 28 [0-3] 20 2b 20 [0-3] 20 2b 20 [0-3] 20 2b 20 49 6e 74 28 [0-3] 20 2f 20 [0-3] 29 20 2d 20 [0-3] 20 2d 20 [0-3] 20 2d 20 [0-3] 20 2d 20 [0-3] 20 2b 20 [0-3] 20 2d 20 [0-3] 20 2d 20 [0-3] 20 2b 20 [0-3] 29 29 20 26 20 43 68 72 28 49 6e 74 28 [0-3] 20 2b 20 [0-3] 20 2b 20 49 6e 74 28 [0-3] 20 2f 20 [0-3] 29 20 2d 20 [0-3] 20 2d 20 [0-3] 20 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

