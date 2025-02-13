rule Virus_W97M_DocCopy_L_2147647695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:W97M/DocCopy.L"
        threat_id = "2147647695"
        type = "Virus"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "DocCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Attribute VB_Name = \"Dark\"" ascii //weight: 1
        $x_1_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 4f 72 67 61 6e 69 7a 65 72 43 6f 70 79 20 53 6f 75 72 63 65 3a 3d [0-16] 44 65 73 74 69 6e 61 74 69 6f 6e 3a 3d [0-16] 2c 20 6e 61 6d 65 3a 3d 22 44 61 72 6b 22 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

