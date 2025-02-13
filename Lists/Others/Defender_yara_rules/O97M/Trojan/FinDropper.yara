rule Trojan_O97M_FinDropper_H_2147752410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/FinDropper.H!dha"
        threat_id = "2147752410"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "FinDropper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MsgBox (\"Document decrypt error.\")" ascii //weight: 1
        $x_1_2 = {55 73 65 72 46 6f 72 6d 31 2e [0-10] 2e 43 61 70 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {43 68 44 69 72 20 [0-10] 4f 70 65 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 49 6e 53 74 72 28 [0-16] 2c 22 3b 3b 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 6f 72 20 69 20 3d 20 [0-10] 20 54 6f 20 [0-10] 3a 20 [0-10] 20 3d 20 [0-10] 20 26 20 [0-10] 3a 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_6 = {4f 70 65 6e 20 [0-16] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 39 3a 20 50 72 69 6e 74 20 23 31 39 2c 20 [0-16] 3a 20 43 6c 6f 73 65 20 23 31 39}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

