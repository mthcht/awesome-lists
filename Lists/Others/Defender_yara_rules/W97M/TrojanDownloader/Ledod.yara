rule TrojanDownloader_W97M_Ledod_E_2147687913_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Ledod.E"
        threat_id = "2147687913"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Ledod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 72 45 61 64 79 53 54 61 54 65 20 3c 3e 20 34 0d 0a 44 6f 45 76 65 6e 74 73 0d 0a 4c 6f 6f 70 0d 0a ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 3d 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 72 65 73 50 6f 6e 73 65 42 6f 44 79}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 65 6c 6c 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 31 29 [0-80] 22 68 74 74 70 3a 2f 2f [0-48] 2e 65 78 65 22 2c 20 45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 73 63 72 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Ledod_I_2147688627_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Ledod.I"
        threat_id = "2147688627"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Ledod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Hola Puto" ascii //weight: 1
        $x_1_2 = {4d 6f 72 64 65 64 6f 72 20 30 2c 20 22 [0-96] 2e (65|73) 22 2c 20 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 20 26 20 22 5c [0-8] 2e 65 78 65 22 2c 20 30 2c 20 30}  //weight: 1, accuracy: Low
        $x_1_3 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 20 26 20 22 5c [0-8] 2e 65 78 65 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Ledod_J_2147688628_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Ledod.J"
        threat_id = "2147688628"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Ledod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 28 30 2c 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 30 2c 20 30 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 68 65 6c 6c 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_3 = {22 68 74 74 70 3a 2f 2f 77 77 77 2e 77 65 72 68 61 63 6b 65 72 73 2e 6e 65 74 2f [0-8] 2e 65 78 65 22 2c 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_4 = {22 68 74 74 70 3a 2f 2f [0-128] 22 2c 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 22 20 26 20 22 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_W97M_Ledod_K_2147688629_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Ledod.K"
        threat_id = "2147688629"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Ledod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".ExpandEnvironmentStrings(\"%APPDATA%\")" ascii //weight: 1
        $x_1_2 = {53 65 74 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f [0-96] 2e 65 78 65 22 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 26 20 22 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 63 6f 6d 22 2c 20 32}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 52 75 6e 20 43 68 72 28 33 34 29 20 26 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 26 20 43 68 72 28 33 34 29 2c 20 31 2c 20 54 72 75 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Ledod_L_2147688630_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Ledod.L"
        threat_id = "2147688630"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Ledod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 75 6b 61 20 3d 20 22 68 74 74 70 3a 2f 2f [0-96] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_2 = ".Open \"GET\", suka, False" ascii //weight: 1
        $x_1_3 = "Set X2 = CreateObject(\"Adodb.Stream\")" ascii //weight: 1
        $x_1_4 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 [0-16] 20 26 20 22 5c [0-16] 2e 63 6f 6d 22 2c 20 32}  //weight: 1, accuracy: Low
        $x_1_5 = ".Run (Suka" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Ledod_P_2147697672_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Ledod.P"
        threat_id = "2147697672"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Ledod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 56 61 6c 28 22 26 48 22 20 26 20 28 4d 69 64 24 28 [0-15] 2c 20 28 32 20 2a 20 73 6e 69 70 70 65 74 44 59 79 44 71 29 20 2d 20 31 2c 20 32 29 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 41 73 63 28 4d 69 64 24 28 [0-15] 2c 20 28 28 [0-15] 20 4d 6f 64 20 4c 65 6e 28 [0-15] 29 29 20 2b 20 31 29 2c 20 31 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= Environ(\"TEMP\")" ascii //weight: 1
        $x_1_4 = "= \"Sh\" & \"e\" & Chr(108)" ascii //weight: 1
        $x_1_5 = "& Chr(108) & \".Application" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

