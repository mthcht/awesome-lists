rule Virus_O97M_Shellrun_A_2147680012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:O97M/Shellrun.gen!A"
        threat_id = "2147680012"
        type = "Virus"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Shellrun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Function WriteProcessMemory Lib" ascii //weight: 1
        $x_1_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 28 30 26 2c [0-8] 4c 65 6e 28 [0-2] 53 68 65 6c 6c 43 6f 64 65 29 2c [0-8] 4d 45 4d 5f 43 4f 4d 4d 49 54 2c [0-8] 50 41 47 45 5f 45 58 45 43 55 54 45 5f 52 45 41 44 57 52 49 54 45 29}  //weight: 1, accuracy: Low
        $x_1_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 28 2d 31 26 2c [0-8] 6c 70 4d 65 6d 6f 72 79 2c [0-8] [0-2] 53 68 65 6c 6c 43 6f 64 65 2c [0-8] 4c 65 6e 28 [0-2] 53 68 65 6c 6c 43 6f 64 65 29 2c [0-8] 30 26 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 68 65 6c 6c 43 6f 64 65 [0-8] 3d [0-8] [0-2] 53 68 65 6c 6c 43 6f 64 65 [0-8] 2b [0-8] 43 68 72 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

