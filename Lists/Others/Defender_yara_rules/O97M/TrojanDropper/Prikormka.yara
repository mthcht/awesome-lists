rule TrojanDropper_O97M_Prikormka_A_2147720131_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Prikormka.A"
        threat_id = "2147720131"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Prikormka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 03 00 52 75 6e 46 69 6c 65 03 00 44 65 63 6f 64 65}  //weight: 1, accuracy: Low
        $x_1_2 = {46 6f 72 20 69 20 3d 20 31 20 54 6f 20 4c 65 6e 28 62 6f 64 79 29 20 53 74 65 70 20 32 03 00 62 20 3d 20 56 61 6c 28 22 26 48 22 20 2b 20 4d 69 64 28 62 6f 64 79 2c 20 69 2c 20 32 29 29 03 00 61 20 3d 20 03 00 03 00 62 20 3d 20 62 20 58 6f 72 20 61 03 00 50 75 74 20 23 31 2c 20 6e 2c 20 62}  //weight: 1, accuracy: Low
        $x_1_3 = {52 65 70 6c 61 63 65 28 73 2c 20 22 2e 74 6d 70 22 2c 20 22 2e 65 78 65 22 2c 20 2c 20 2c 20 76 62 54 65 78 74 43 6f 6d 70 61 72 65 29 03 00 73 20 3d 20 46 53 4f 2e 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 32 29 2e 50 61 74 68 20 2b 20 22 5c 22 20 2b 20 73 03 00 4f 70 65 6e 20 73 20 46 6f 72 20 42 69 6e 61 72 79 20 41 63 63 65 73 73 20 57 72 69 74 65 20 41 73 20 23 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

