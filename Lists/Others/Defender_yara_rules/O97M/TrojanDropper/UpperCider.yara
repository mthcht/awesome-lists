rule TrojanDropper_O97M_UpperCider_A_2147729886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/UpperCider.A!dha"
        threat_id = "2147729886"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "UpperCider"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6f 6d 6d 61 6e 64 4d 6f 76 65 54 6f 20 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 63 6f 70 79 20 25 74 65 6d 70 25 5c 5c [0-16] 2a 20 22 20 26 20 41 6c 6c 55 73 65 72 73 50 72 6f 66 69 6c 65 20 26 20 22 2a 22}  //weight: 1, accuracy: Low
        $x_1_2 = {64 73 74 43 6f 70 79 54 6f [0-4] 20 3d 20 41 6c 6c 55 73 65 72 73 50 72 6f 66 69 6c 65 20 26 20 22 [0-20] 22}  //weight: 1, accuracy: Low
        $x_1_3 = {4f 62 6a 52 75 6e 20 43 6f 6d 6d 61 6e 64 4d 6f 76 65 54 6f 2c 20 64 73 74 43 6f 70 79 54 6f [0-4] 2c 20 64 73 74 43 6f 70 79 54 6f [0-4] 2c 20 64 73 74 43 6f 70 79 54 6f [0-4] 2c 20 41 6c 6c 55 73 65 72 73 50 72 6f 66 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 4f 62 6a 52 75 6e 28 43 6f 6d 6d 61 6e 64 4d 6f 76 65 54 6f 20 41 73 20 53 74 72 69 6e 67 2c 20 43 6f 70 79 54 6f [0-4] 20 41 73 20 53 74 72 69 6e 67 2c 20 43 6f 70 79 54 6f [0-4] 20 41 73 20 53 74 72 69 6e 67 2c 20 43 6f 70 79 54 6f [0-4] 20 41 73 20 53 74 72 69 6e 67 2c 20 41 6c 6c 55 73 65 72 73 50 72 6f 66 69 6c 65 20 41 73 20 53 74 72 69 6e 67 29}  //weight: 1, accuracy: Low
        $x_1_5 = "cermoveComand = \"cmd.exe /c copy %windir%\\\\system32\\\\certutil.exe " ascii //weight: 1
        $x_1_6 = {63 65 72 74 75 74 69 6c 43 6f 6d 61 6e 64 20 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 [0-32] 20 2d 64 65 63 6f 64 65 20 22}  //weight: 1, accuracy: Low
        $x_1_7 = "objws.Run CommandMoveTo, 0, True" ascii //weight: 1
        $x_1_8 = "objws.Run cermoveComand, 0, True" ascii //weight: 1
        $x_1_9 = {6f 62 6a 77 73 2e 52 75 6e 20 63 65 72 74 75 74 69 6c 43 6f 6d 61 6e 64 20 26 20 41 6c 6c 55 73 65 72 73 50 72 6f 66 69 6c 65 20 26 20 [0-20] 20 26 20 43 6f 70 79 54 6f [0-4] 2c 20 30 2c 20 54 72 75 65}  //weight: 1, accuracy: Low
        $x_1_10 = {6f 62 6a 77 73 2e 52 75 6e 20 22 65 73 65 6e 74 75 74 6c 2e 65 78 65 20 2f 79 20 22 20 26 20 43 6f 70 79 54 6f [0-4] 20 26 20 22 20 2f 64 20 22 20 26 20 41 6c 6c 55 73 65 72 73 50 72 6f 66 69 6c 65 20 26 20 [0-20] 20 26 20 22 20 2f 6f 22 2c 20 30 2c 20 54 72 75 65}  //weight: 1, accuracy: Low
        $x_1_11 = {6f 62 6a 77 73 2e 52 75 6e 20 41 6c 6c 55 73 65 72 73 50 72 6f 66 69 6c 65 20 26 20 [0-48] 2c 20 30 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_12 = {6f 62 6a 77 73 2e 52 75 6e 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 22 20 26 20 41 6c 6c 55 73 65 72 73 50 72 6f 66 69 6c 65 20 26 20 [0-16] 2c 20 30 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

