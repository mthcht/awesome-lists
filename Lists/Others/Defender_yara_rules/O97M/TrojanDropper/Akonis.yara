rule TrojanDropper_O97M_Akonis_A_2147718511_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Akonis.A"
        threat_id = "2147718511"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Akonis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 20 2f 00 20 3d 20 2f 00 28 2f 00 28 22 [0-15] 6e [0-5] 66 [0-5] 75 [0-5] 74 [0-5] 7a [0-47] 22 29 29 [0-80] 3d 20 00 2e 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 32 29 20 26 20 02 28 22 [0-5] 74 [0-5] 6b [0-5] 2f [0-255] 00 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

