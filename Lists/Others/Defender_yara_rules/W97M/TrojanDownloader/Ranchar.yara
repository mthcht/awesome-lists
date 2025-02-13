rule TrojanDownloader_W97M_Ranchar_A_2147707158_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Ranchar.A"
        threat_id = "2147707158"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Ranchar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 6f 72 20 32 35 36 0d 0a 4e 65 78 74 20 [0-72] 0d 0a 46 6f 72 20 00 20 3d 20 31 20 54 6f [0-24] 28 00 20 2b 20 ?? (30|2d|39) (30|2d|39) 29 20 3d 20 [0-32] 2d 20 00 29 [0-32] 28 00 20 2d 20 31 29 20 3d 20 [0-63] 28 00 20 2d 20 31 29 20 58 6f 72 20 28 32 35 35 20 2d}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 52 6e 64 28 (30|2d|39) (30|2d|39) 29 0d 0a 45 6e 64 20 49 66 [0-24] 2e (4f|6f) (50|70) (45|65) (4e|6e) 20 [0-24] 28 43 68 72 28 ?? (30|2d|39) (30|2d|39) 29 20 2b 20 43 68 72 28 ?? (30|2d|39) (30|2d|39) 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

