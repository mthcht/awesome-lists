rule Virus_W97M_Bansa_A_2147653447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:W97M/Bansa.A"
        threat_id = "2147653447"
        type = "Virus"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bansa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 75 6c 61 42 61 6e 67 73 61 74 20 3d 20 [0-112] 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 2e 49 74 65 6d 28 22 42 61 6e 67 73 61 74 22 29 2e 43 6f 64 65 4d 6f 64 75 6c 65 2e 43 6f 75 6e 74 4f 66 4c 69 6e 65 73 29}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 61 63 61 6d 5f 6a 61 72 75 6d 40 79 61 68 6f 6f 2e 63 6f 6d 22 [0-8] 2e 45 78 65 63 75 74 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

