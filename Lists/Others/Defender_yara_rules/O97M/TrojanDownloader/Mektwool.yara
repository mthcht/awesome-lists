rule TrojanDownloader_O97M_Mektwool_A_2147706107_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Mektwool.A"
        threat_id = "2147706107"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Mektwool"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 69 62 20 22 73 68 65 6c 6c 33 32 22 20 41 6c 69 61 73 20 5f 0d 0a 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 28 42 79 56 61 6c}  //weight: 1, accuracy: High
        $x_1_2 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 5f 0d 0a 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 42 79 56 61 6c}  //weight: 1, accuracy: High
        $x_1_3 = {44 69 6d 20 55 72 6c 54 6f 44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 20 41 73 20 53 74 72 69 6e 67 0d 0a 55 72 6c 54 6f 44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 20 3d}  //weight: 1, accuracy: High
        $x_1_4 = "byOut(i) = ((byIn(i) + Not bEncOrDec) Xor byKey(l)) - bEncOrDec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

