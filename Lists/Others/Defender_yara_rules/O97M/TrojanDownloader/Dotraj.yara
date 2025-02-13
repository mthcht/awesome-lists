rule TrojanDownloader_O97M_Dotraj_A_2147731243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.A"
        threat_id = "2147731243"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 43 68 72 28 03 00 29 20 2b 20 43 68 72 28 03 00 29 20 2b 20 43 68 72 28 03 00 29 20 2b 20 43 68 72 28 03 00 29 20 2b 20 43 68 72 28}  //weight: 1, accuracy: Low
        $x_1_2 = "Call Shell(" ascii //weight: 1
        $x_5_3 = "Lib \"kernel32\" Alias \"GetThreadInformation" ascii //weight: 5
        $x_5_4 = "Lib \"kernel32\" Alias \"CheckElevation" ascii //weight: 5
        $x_5_5 = "Lib \"urlmon\" Alias \"URLDownloadToFileA" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dotraj_C_2147731750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.C"
        threat_id = "2147731750"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {46 6f 72 20 [0-6] 20 3d 20 30 20 54 6f 20 [0-32] 46 6f 72 20 [0-6] 20 3d 20 30 20 54 6f 20 [0-6] 49 66 20 48 69 7a 61 66 6c 63 4a 28 7a 50 29 20 3d 20 [0-6] 28 [0-6] 29 20 54 68 65 6e 20 [0-32] 4e 65 78 74 [0-5] 49 66 20 [0-6] 20 3d 20 30 20 54 68 65 6e [0-16] 20 3d 20 [0-16] 28 [0-6] 29 20 2d 20 [0-32] 20 3d 20 [0-6] 20 2b 20 43 68 72 24 28 [0-8] 29 [0-4] 45 6e 64 20 49 66 [0-4] 4e 65 78 74}  //weight: 5, accuracy: Low
        $x_1_2 = {49 66 20 4c 65 6e 28 [0-6] 29 20 3d 20 [0-6] 20 54 68 65 6e 20 53 68 65 6c 6c 20 [0-6] 2c 20 [0-6] 20 2d 20}  //weight: 1, accuracy: Low
        $x_1_3 = "User1.Lab.Top" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dotraj_D_2147731751_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.D"
        threat_id = "2147731751"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 [0-16] 22 2c 20 [0-5] 2c 20 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dotraj_F_2147731841_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.F"
        threat_id = "2147731841"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 43 53 74 72 28 04 00 20 2b 20 41 74 6e 28 04 00 29 20 2d 20 30 00 29}  //weight: 1, accuracy: Low
        $x_1_2 = {41 72 72 61 79 28 [0-880] 20 53 68 65 6c 6c 28 [0-960] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dotraj_G_2147731894_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.G"
        threat_id = "2147731894"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 22 20 2b 20 15 00 20 2b 20 15 00 20 2b 20 15 00 20 2b 20 15 00 20 2b 20 [0-1760] 29 2e 52 75 6e [0-1] 28 [0-1] 22 22 20 2b 20 15 00 20 2b 20 15 00 20 2b 20 15 00 20 2b 20 15 00 2e 54 65 78 74 42 6f 78 31 29}  //weight: 1, accuracy: Low
        $x_1_2 = "wscript.shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dotraj_G_2147731894_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.G"
        threat_id = "2147731894"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "[runtime.interopservices.marshal].getmembers()[4].name).invoke( [runtime.interopservices.marshal]::securestringtoglqj" ascii //weight: 2
        $x_1_2 = {20 3d 20 43 6f 73 28 08 00 20 2d 20 4f 63 74 28 08 00 20 2b 20 09 00 20 2a 20 09 00 20 2d 20 43 42 6f 6f 6c 28 09 00 29 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Dotraj_G_2147731894_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.G"
        threat_id = "2147731894"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "CreateObject(\"shell.application\")" ascii //weight: 10
        $x_1_2 = "Selection.TypeText (" ascii //weight: 1
        $x_1_3 = "ActiveDocument.Password = " ascii //weight: 1
        $x_10_4 = {49 66 20 4e 6f 74 20 22 20 00 22 20 4c 69 6b 65 20 [0-16] 20 54 68 65 6e}  //weight: 10, accuracy: Low
        $x_10_5 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 63 6d 64 2e 65 78 65 22 2c 20 [0-32] 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 30}  //weight: 10, accuracy: Low
        $x_10_6 = {46 6f 72 20 [0-32] 20 3d 20 31 20 54 6f 20 4c 65 6e 28 [0-144] 20 26 20 [0-16] 28 4d 69 64 28 [0-48] 2c 20 31 29 29}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Dotraj_H_2147733319_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.H"
        threat_id = "2147733319"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d 20 53 68 65 6c 6c 28 10 00 2c 20 07 00 04 00 20 2d 20 07 00 04 00 29}  //weight: 10, accuracy: Low
        $x_1_2 = "UnncIvYPIsh" ascii //weight: 1
        $x_1_3 = "ilwTFTCASN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Dotraj_I_2147733725_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.I"
        threat_id = "2147733725"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-16] 69 66 20 61 70 70 6c 69 63 61 74 69 6f 6e 2e 72 65 63 65 6e 74 66 69 6c 65 73 2e 63 6f 75 6e 74 20 3e 20 [0-6] 20 74 68 65 6e [0-16] 73 68 65 6c 6c 20 28 [0-16] 68 74 74 70 73}  //weight: 10, accuracy: Low
        $x_5_2 = "cdudley" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Dotraj_J_2147734525_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.J"
        threat_id = "2147734525"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 20 53 70 6c 69 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 56 61 72 69 61 62 6c 65 73 28 22 ?? ?? ?? ?? ?? [0-5] 22 29 2e 56 61 6c 75 65 2c 20 43 68 72 28 28 28 28 [0-32] 29 29 29}  //weight: 2, accuracy: Low
        $x_1_2 = {43 61 6c 6c 42 79 4e 61 6d 65 20 15 00 2c 20 15 00 28 02 00 29 2c 20 56 62 4d 65 74 68 6f 64 2c 20 22 47 45 54 22 2c 20 15 00 28 02 00 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_2_3 = {43 61 6c 6c 42 79 4e 61 6d 65 20 15 00 2c 20 15 00 28 02 00 29 2c 20 56 62 4d 65 74 68 6f 64 2c 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 10 00 2e 74 78 74 22 2c 20 32}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Dotraj_K_2147734539_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.K"
        threat_id = "2147734539"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"WScript.Shell\").Run" ascii //weight: 1
        $x_1_2 = {46 75 6e 63 74 69 6f 6e 20 [0-48] 20 3d 20 10 00 20 2d 20 04 00 05 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {53 75 62 20 [0-48] 46 6f 72 20 45 61 63 68 20 [0-2] 20 49 6e 20 [0-16] 49 66 20 4c 65 6e 28 [0-2] 29 20 54 68 65 6e [0-32] 20 3d 20 [0-16] 20 2b 20 43 68 72 28 [0-16] 28 [0-2] 29 29 10 00 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dotraj_L_2147734540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.L"
        threat_id = "2147734540"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 [0-16] 0d 0a 45 6e 64 20 53 75 62 [0-144] 20 46 6f 72 20 45 61 63 68 20 [0-3] 20 49 6e 20 [0-48] 49 66 20 4c 65 6e 28 [0-48] 20 3d 20 00 20 2b 20 43 68 72 28 [0-3] 20 2d 20 03 00 29 10 00 45 6e 64 20 49 66}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dotraj_M_2147735027_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.M"
        threat_id = "2147735027"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 65 74 4f 62 6a 65 63 74 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-64] 29 2e 43 72 65 61 74 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (28|29|61|2d|7a|30|2d|39|20|2b|0d|0a|5f|2e) (28|29|61|2d|7a|30|2d|39|20|2b|0d|0a|5f|2e) [0-3570] 2c 20 [0-256] 2c 20 [0-256] 2c 20 [0-384] 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dotraj_N_2147735638_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.N"
        threat_id = "2147735638"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2c 20 31 29 20 3d 20 43 68 72 28 41 73 63 28 4d 69 64 28 20 00 20 00 2c 20 20 00 20 00 2c 20 31 29 29 20 2d 20}  //weight: 5, accuracy: Low
        $x_1_2 = {4f 70 65 6e 20 20 00 20 00 28 22 ?? ?? ?? 22 2c 20 22 ?? ?? 22 29 2c 20 20 00 20 00 28 22 [0-64] 22 2c 20 22 ?? ?? 22 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 77 72 69 74 65 20 20 00 20 00 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dotraj_O_2147735717_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.O"
        threat_id = "2147735717"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 20 [0-48] 28 22 59 32 31 6b 4c 6d 56 34 5a 51 3d 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dotraj_P_2147735756_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.P"
        threat_id = "2147735756"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"MSXML2.ServerXMLHTTP" ascii //weight: 1
        $x_1_2 = "CreateObject(\"WScript.Shell" ascii //weight: 1
        $x_1_3 = {57 72 69 74 65 20 [0-16] 2e 52 65 73 70 6f 6e 73 65 42 6f 64 79}  //weight: 1, accuracy: Low
        $x_10_4 = {50 75 62 6c 69 63 20 53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 [0-255] [0-255] [0-255] 2e 65 78 65 63 20 28 22 [0-16] 2e 65 78 65 22 29}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Dotraj_P_2147735756_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.P"
        threat_id = "2147735756"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Attribute VB_Name = \"NewMacros\"" ascii //weight: 1
        $x_1_2 = "CreateObject(\"WScript.Shell\").Exec " ascii //weight: 1
        $x_1_3 = "CreateObject(\"WScript.Shell\").Run " ascii //weight: 1
        $x_1_4 = {63 20 3d 20 43 68 72 28 62 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_5 = " + Replace(c(x), " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dotraj_Q_2147735757_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.Q"
        threat_id = "2147735757"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 [0-9] 0d 0a 45 6e 64 20 53 75 62 0d 0a 46 75 6e 63 74 69 6f 6e 20 63 28 61 29}  //weight: 1, accuracy: Low
        $x_1_2 = "'MsgBox b" ascii //weight: 1
        $x_1_3 = {63 20 3d 20 43 68 72 28 62 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_4 = {20 20 46 6f 72 20 45 61 63 68 20 78 20 49 6e 20 61 0d 0a 20 20 20 20 49 66 20 4c 65 6e 28 78 29 20 54 68 65 6e}  //weight: 1, accuracy: High
        $x_1_5 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 4e 65 77 4d 61 63 72 6f 73 22 0d 0a 20 0d 0a 53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dotraj_R_2147735758_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.R"
        threat_id = "2147735758"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 73 65 20 [0-24] 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 73 78 6d 6c 32 2e 53 65 72 76 65 72 58 4d 4c 48 54 54 50 22 29 [0-16] 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {43 61 73 65 20 [0-24] 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f [0-24] 2e 6a 70 67 22 2c 20 46 61 6c 73 65 [0-16] 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {43 61 73 65 [0-24] 2e 53 61 76 65 54 6f 46 69 6c 65 20 28 45 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 20 2b 20 22 5c [0-24] 2e 65 78 65 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dotraj_R_2147735758_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.R"
        threat_id = "2147735758"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 4e 65 77 4d 61 63 72 6f 73 22 0d 0a 20 0d 0a 53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29}  //weight: 1, accuracy: High
        $x_1_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 [0-9] 0d 0a 45 6e 64 20 53 75 62 0d 0a 46 75 6e 63 74 69 6f 6e 20}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 45 78 65 63 20 [0-9] 0d 0a 45 6e 64 20 53 75 62 0d 0a 46 75 6e 63 74 69 6f 6e 20}  //weight: 1, accuracy: Low
        $x_1_4 = {28 61 2c 20 [0-9] 29 0d 0a 20 20 46 6f 72 20 45 61 63 68 20 78 20 49 6e 20 61 0d 0a 20 20 20 20 49 66 20 4c 65 6e 28 78 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {20 3d 20 41 72 72 61 79 28 [0-4] 2c 20 [0-4] 2c 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Dotraj_C_2147775140_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dotraj.C!MTB"
        threat_id = "2147775140"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dotraj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallByName SubProperty, \"s\" + ProjectTransformation + \"ile\"," ascii //weight: 1
        $x_1_2 = "CallByName rptProblem, sTVOL.ToggleButton1.Caption, VbMethod" ascii //weight: 1
        $x_1_3 = "Raise vbObjectError + 555, \"5\", \"55\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

