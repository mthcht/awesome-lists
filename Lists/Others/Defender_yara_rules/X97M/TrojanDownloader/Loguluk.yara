rule TrojanDownloader_X97M_Loguluk_A_2147714853_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:X97M/Loguluk.A"
        threat_id = "2147714853"
        type = "TrojanDownloader"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Loguluk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 6c 6f 67 69 6e 2e 75 6c 2d 74 73 2e 75 6b 2f 70 72 69 76 61 63 79 2f 30 30 2d 50 52 56 2d 32 30 31 36 [0-2] 50 72 69 76 61 63 79 25 32 30 61 6e 64 25 32 30 4c 65 67 61 6c 25 32 30 41 67 72 65 65 6d 65 6e 74 2e 64 6f 63 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

