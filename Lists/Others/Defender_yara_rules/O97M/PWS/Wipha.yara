rule PWS_O97M_Wipha_A_2147689255_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:O97M/Wipha.A"
        threat_id = "2147689255"
        type = "PWS"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Wipha"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 75 6e 63 74 69 6f 6e 20 75 70 6c 6f 61 64 50 4f 53 54 28 42 79 56 61 6c 20 75 73 65 72 [0-8] 5f 6e 6f 5f 73 70 61 63 65 73 20 41 73 20 53 74 72 69 6e 67 2c 20 42 79 56 61 6c 20 70 61 73 73 [0-8] 5f 6e 6f 5f 73 70 61 63 65 73 20 41 73 20 53 74 72 69 6e 67 2c 20 42 79 56 61 6c 20 6d 65 73 73 [0-8] 5f 6e 6f 5f 73 70 61 63 65 73 20 41 73 20 53 74 72 69 6e 67 29}  //weight: 1, accuracy: Low
        $x_1_2 = {55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f [0-96] 2f 72 65 70 6f 72 74 65 72 2e 70 68 70 3f 6d 73 67 3d 22 20 26 20 6d 65 73 73 [0-8] 5f 6e 6f 5f 73 70 61 63 65 73 20 26 20 22 26 75 6e 61 6d 65 3d 22 20 26 20 75 73 65 72 [0-8] 5f 6e 6f 5f 73 70 61 63 65 73 20 26 20 22 26 70 77 6f 72 64 3d 22 20 26 20 70 61 73 73 [0-8] 5f 6e 6f 5f 73 70 61 63 65 73}  //weight: 1, accuracy: Low
        $x_1_3 = {43 61 6c 6c 20 75 70 6c 6f 61 64 50 4f 53 54 28 [0-12] 2c 20 [0-12] 2c 20 22 [0-40] 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

