rule Trojan_O97M_Encdoc_PRBA_2147888724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Encdoc.PRBA!MTB"
        threat_id = "2147888724"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Encdoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 22 66 79 66 2f 6f 73 73 22 29 [0-100] 3d 65 6e 76 69 72 6f 6e 24 28 22 74 65 6d 70 22 29 26 22 5c 22 26 [0-255] 3d [0-32] 28 22 66 79 66 2f [0-80] 2f [0-48] 2f 78 78 78 30 30 3b 74 71 75 75 69 22 29 [0-15] 2c [0-80] 2c 00 2c 30 2c [0-48] 2c 22 6f 70 65 6e 22 2c 00 2c 22 22 2c 76 62 6e 75 6c 6c 73 74 72 69 6e 67 2c 76 62 6e 6f 72 6d 61 6c 66 6f 63 75 73 65 6e 64 73 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {73 75 62 77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 [0-64] 28 65 6e 63 29 64 69 6d 76 2c 72 2c 74 65 6d 70 65 6e 63 3d 73 74 72 72 65 76 65 72 73 65 28 65 6e 63 29 66 6f 72 72 3d 31 74 6f 6c 65 6e 28 65 6e 63 29 76 3d 6d 69 64 28 65 6e 63 2c 72 2c 31 29 74 65 6d 70 3d 74 65 6d 70 26 63 68 72 28 61 73 63 28 76 29 2d 31 29 [0-48] 3d 74 65 6d 70 65 6e 64 66 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

