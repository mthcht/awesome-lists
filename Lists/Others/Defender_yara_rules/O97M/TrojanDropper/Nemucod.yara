rule TrojanDropper_O97M_Nemucod_A_2147718776_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Nemucod.A"
        threat_id = "2147718776"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Nemucod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 22 65 73 6a 2e 22 29 29 0d 0a 76 62 5f}  //weight: 1, accuracy: High
        $x_1_2 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 76 62 5f [0-16] 28 22 6c 6c 65 68 53 2e 74 70 69 72 63 53 57 22 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = "(\"nuR\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

