rule TrojanDownloader_W97M_Ursnif_A_2147712165_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Ursnif.A"
        threat_id = "2147712165"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "godmmw/ph\")" ascii //weight: 5
        $x_1_2 = {3d 20 33 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_3 = {28 29 20 41 73 20 56 61 72 69 61 6e 74 [0-107] 3d 20 41 72 72 61 79 28 [0-448] 28 22 [0-512] 22 29 [0-24] 2c 20 01 28 22 [0-512] 22 29 2c 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Ursnif_A_2147712165_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Ursnif.A"
        threat_id = "2147712165"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 [0-18] 50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 [0-96] 28 42 79 56 61 6c 20 [0-96] 20 41 73 20 53 74 72 69 6e 67 2c 20 42 79 56 61 6c 20 [0-96] 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 53 74 72 69 6e 67 [0-64] 46 6f 72 20 [0-96] 20 3d 20 [0-96] 20 54 6f 20 [0-96] 2e [0-96] 28 22 25 00 22 2c 20 02 29 [0-4] 01 20 3d 20 07 2e [0-96] 28 22 25 00 22 2c 20 01 2c}  //weight: 2, accuracy: Low
        $x_1_2 = {49 66 20 4e 6f 74 20 [0-96] 2e 18 00 28 18 00 2c 20 22 (30|2d|39|41|2d|5a|61|2d|7a) (30|2d|39|41|2d|5a|61|2d|7a) 20 00 22 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Ursnif_A_2147712165_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Ursnif.A"
        threat_id = "2147712165"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 6e 64 20 53 75 62 0d 0a 50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 [0-144] 28 29 20 41 73 20 53 74 72 69 6e 67 0d 0a 00 20 3d 20 [0-144] 2e [0-144] 28 22 [0-512] 22 2c 20 22 [0-64] 22 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 0d 0a 50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 [0-144] 28 29 20 41 73 20 53 74 72 69 6e 67 0d 0a 06 20 3d 20 02 2e 03 28 22 [0-512] 22 2c 20 22 [0-64] 22 29 0d 0a [0-128] 3d 20 02 2e 03 28 22 [0-255] 3d 20 02 2e 03 28 22}  //weight: 5, accuracy: Low
        $x_1_2 = {28 29 20 41 73 20 56 61 72 69 61 6e 74 [0-24] 3d 20 41 72 72 61 79 28 [0-144] 2e [0-144] 28 22 [0-512] 22 2c 20 22 [0-64] 22 29 [0-24] 2c 20 01 2e 02 28 22 [0-512] 22 2c 20 22 [0-64] 22 29 [0-96] 2c 20 01 2e 02 28 22 [0-512] 22 2c 20 22 [0-64] 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 33 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

