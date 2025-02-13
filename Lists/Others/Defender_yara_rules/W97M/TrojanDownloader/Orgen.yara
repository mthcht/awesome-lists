rule TrojanDownloader_W97M_Orgen_A_2147688414_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Orgen.A"
        threat_id = "2147688414"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Orgen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 76 34 35 28 29 0d 0a 44 69 6d 20 64 76 49 5a 35 31 20 41 73 20 53 74 72 69 6e 67}  //weight: 1, accuracy: High
        $x_1_2 = "suka = \"http://" ascii //weight: 1
        $x_1_3 = {2e 77 72 69 74 65 20 72 30 38 4c 6c 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 0d 0a 2e 53 61 76 65 54 6f 46 69 6c 65 20 64 76 49 5a 35 31 20 26 20 22 5c [0-10] 2e 73 63 72 22 2c 20 32}  //weight: 1, accuracy: Low
        $x_1_4 = "r08Ll.Open \"GET\", suka, False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

