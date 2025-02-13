rule Trojan_W97M_Nahooli_A_2147688869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:W97M/Nahooli.A"
        threat_id = "2147688869"
        type = "Trojan"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Nahooli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 55 73 65 72 46 6f 72 6d 31 2e 53 63 72 69 70 74 43 6f 6e 74 72 6f 6c 31 [0-14] 2e 4c 61 6e 67 75 61 67 65 20 3d 20 22 56 42 53 22 20 2b 20 22 63 72 69 70 74 22 [0-17] 3d 20 22 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 22 [0-14] 3d 20 22 50 61 72 61 67 72 61 70 68 73 22}  //weight: 1, accuracy: Low
        $x_1_2 = "= \"exe\"" ascii //weight: 1
        $x_1_3 = {3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 [0-7] 43 68 44 72 69 76 65 20 28 [0-7] 29 [0-7] 43 68 44 69 72 20 28 [0-7] 29 [0-20] 3d 20 46 72 65 65 46 69 6c 65 28 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

