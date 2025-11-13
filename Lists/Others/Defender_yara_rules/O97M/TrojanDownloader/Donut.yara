rule TrojanDownloader_O97M_Donut_ABA_2147957417_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donut.ABA!MTB"
        threat_id = "2147957417"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 75 62 61 75 74 6f 5f 6f 70 65 6e 28 29 63 61 6c 6c [0-32] 65 6e 64 73 75 62 73 75 62 00 28 29 64 69 6d ?? 61 73 73 74 72 69 6e 67 02 3d 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 2d 6e 6f 70 2d 77 68 69 64 64 65 6e 2d 65 6e 63 6a 61 62 78 61 67 6b 61 62 67 61 7a 61 64 69 61 69 61 61 39 61 63 61 61 71 61 61 69 61 61 30 61 63 67 62 31 61 68 6d 61 61 71 62 75 61 67 63 61 69 61 62 74 61 68 6b 61 63 77 62 30 61 67 75 61 62 71 61 37 61 61 30 61 63 67 62 31 61 68 6d 61 61 71 62 75 [0-1530] 22 5f 26 22 [0-1530] 22 5f 26 22}  //weight: 1, accuracy: Low
        $x_1_2 = {22 5f 26 22 [0-1785] 22 73 68 65 6c 6c 28 ?? 29 65 6e 64 73 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

