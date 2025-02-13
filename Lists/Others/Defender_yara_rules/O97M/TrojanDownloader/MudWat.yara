rule TrojanDownloader_O97M_MudWat_A_2147734614_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/MudWat.A"
        threat_id = "2147734614"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "MudWat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 58 4d 4c 48 54 54 50 22 29 10 00 [0-16] 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 43 6f 6d 6d 65 6e 74 73 22 29 [0-32] 2e 4f 70 65 6e 20 22 47 45 54 22 2c [0-96] 26 20 01 2c 20 46 61 6c 73 65}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_MudWat_B_2147734615_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/MudWat.B"
        threat_id = "2147734615"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "MudWat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 75 6e 63 74 69 6f 6e 20 [0-96] 20 3d 20 43 68 72 28 [0-6] 20 2d 20 [0-3] 29 [0-6] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e 20 [0-96] 20 3d 20 4c 65 66 74 28 [0-6] 2c 20 [0-3] 29 [0-6] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {46 75 6e 63 74 69 6f 6e 20 [0-96] 20 3d 20 52 69 67 68 74 28 [0-6] 2c 20 4c 65 6e 28 [0-6] 29 20 2d 20 [0-3] 29 [0-6] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 [0-16] 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-48] 20 22 22 29 2c 20 [0-16] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_MudWat_C_2147743873_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/MudWat.C!MTB"
        threat_id = "2147743873"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "MudWat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 62 4d 65 74 68 6f 64 2c 20 [0-21] 2c 20 45 6e 76 69 72 6f 6e 28 [0-21] 29 20 26}  //weight: 1, accuracy: Low
        $x_1_2 = "Text & ThisWorkbook.Name" ascii //weight: 1
        $x_1_3 = "= \"\"" ascii //weight: 1
        $x_1_4 = "= Asc(Mid(q, (o Mod Len(" ascii //weight: 1
        $x_1_5 = "\"The version of Excel for Windows you are using is not compatible with this document\", _" ascii //weight: 1
        $x_1_6 = "Close #1" ascii //weight: 1
        $x_1_7 = {4f 70 65 6e 20 45 6e 76 69 72 6f 6e 28 [0-21] 29 20 26 20 [0-21] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_MudWat_D_2147743909_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/MudWat.D!MTB"
        threat_id = "2147743909"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "MudWat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ThisWorkbook.Sheets(\"Sheet1\")" ascii //weight: 1
        $x_1_2 = {2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-32] 2c 20 45 6e 76 69 72 6f 6e 28 [0-32] 29 20 26}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 41 73 63 28 4d 69 64 28 ?? 2c 20 28 ?? 20 4d 6f 64 20 4c 65 6e 28}  //weight: 1, accuracy: Low
        $x_1_4 = ".Text, \".\")" ascii //weight: 1
        $x_1_5 = "= \"\"" ascii //weight: 1
        $x_1_6 = {4f 70 65 6e 20 45 6e 76 69 72 6f 6e 28 [0-32] 29 20 26 20 [0-32] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_7 = "Close #1" ascii //weight: 1
        $x_1_8 = "Print #1," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_MudWat_E_2147750759_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/MudWat.E!MTB"
        threat_id = "2147750759"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "MudWat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 [0-16] 2c 20 [0-21] 28 [0-3] 29 2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-21] 28 [0-3] 29 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 41 73 63 28 4d 69 64 28 [0-21] 2c 20 28 [0-21] 20 4d 6f 64 20 4c 65 6e 28 [0-21] 29 20 2b 20 [0-2] 29 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 53 68 65 65 74 32 2e 52 61 6e 67 65 28 [0-5] 20 2b 20 43 53 74 72 28 [0-21] 29 29 2e 56 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 53 70 6c 69 74 28 [0-16] 2c 20 22 2e 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 53 70 6c 69 74 28 [0-16] 2c 20 22 3a 3a 22 29}  //weight: 1, accuracy: Low
        $x_1_6 = "= ThisWorkbook.Name" ascii //weight: 1
        $x_1_7 = "Print #1," ascii //weight: 1
        $x_1_8 = "= \"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

