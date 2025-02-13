rule TrojanDropper_O97M_Dallawot_A_2147695453_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Dallawot.A"
        threat_id = "2147695453"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dallawot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 6e 76 6e 31 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 22 20 26 20 64 73 67 66 37 37 7a 70 7a 33 33 33 67 33 33 33 38 33 37 36 67 66 68 64 66 67 79 66 74 65 29 0d 0a 64 73 67 66 37 37 7a 70 7a 33 33 33 67 33 33 33 38 33 37 36 67 66 68 64 66 67 79 66 74 65 20 3d 20 22 6f 73 74 2e 65 22 20 26 20 22 78 65 22 0d 0a 74 6e 33 33 6e 31 20 3d 20 74 6e 76 6e 31 20 26 20 22 73 76 63 6e 22 20 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

