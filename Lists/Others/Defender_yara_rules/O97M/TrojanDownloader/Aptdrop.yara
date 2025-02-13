rule TrojanDownloader_O97M_Aptdrop_J_2147734827_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Aptdrop.J"
        threat_id = "2147734827"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Aptdrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Do While True" ascii //weight: 1
        $x_1_2 = "On Error GoTo " ascii //weight: 1
        $x_1_3 = {53 65 74 20 ?? ?? ?? ?? 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 ?? ?? ?? ?? 2c 20 ?? ?? ?? ?? 28 22}  //weight: 1, accuracy: Low
        $x_1_4 = {53 65 74 20 ?? ?? 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 ?? ?? 2c 20 ?? ?? ?? ?? 28 22}  //weight: 1, accuracy: Low
        $x_1_5 = {20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 ?? ?? 28 31 29 2c 20 ?? ?? ?? ?? 28 22}  //weight: 1, accuracy: Low
        $x_1_6 = {53 65 74 20 ?? ?? ?? ?? 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 ?? ?? ?? ?? 29}  //weight: 1, accuracy: Low
        $x_1_7 = {20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 0d 0a}  //weight: 1, accuracy: High
        $x_1_8 = {22 29 2c 20 56 62 4d 65 74 68 6f 64 2c 20 26 48 38 30 30 30 30 30 30 31 2c 20 ?? ?? ?? ?? 2c 20 ?? ?? ?? ?? 2c 20 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

