rule TrojanDownloader_O97M_Obfusmacro_2147691789_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Obfusmacro"
        threat_id = "2147691789"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfusmacro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 76 69 72 6f 6e 28 58 4f 52 49 28 48 65 78 74 6f 73 74 72 69 6e 67 28 22 [0-32] 22 29 2c 20 48 65 78 74 6f 73 74 72 69 6e 67 28 22 [0-32] 22 29 29 29 20 26 20 58 4f 52 49 28 48 65 78 74 6f 73 74 72 69 6e 67 28 22 [0-32] 22 29 2c 20 48 65 78 74 6f 73 74 72 69 6e 67 28 22 [0-32] 22 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {49 66 20 4c 65 6e 28 22 [0-32] 22 29 20 3d 20 4c 65 6e 28 22 [0-32] 22 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {49 66 20 4c 65 6e 28 58 4f 52 49 28 48 65 78 74 6f 73 74 72 69 6e 67 28 22 [0-32] 22 29 2c 20 48 65 78 74 6f 73 74 72 69 6e 67 28 22 [0-32] 22 29 29 29 20 3d 20 4c 65 6e 28 58 4f 52 49 28 48 65 78 74 6f 73 74 72 69 6e 67 28 22 [0-32] 22 29 2c 20 48 65 78 74 6f 73 74 72 69 6e 67 28 22 [0-32] 22 29 29 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_4 = "CreateObject(XORI(Hextostring" ascii //weight: 1
        $x_1_5 = "Function XORI" ascii //weight: 1
        $x_1_6 = "CreateObject(XORI(Hextostring(" ascii //weight: 1
        $x_1_7 = ".responseBody" ascii //weight: 1
        $x_1_8 = "XORI = XORI & Chr(Asc(Mid(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_O97M_Obfusmacro_AR_2147743449_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Obfusmacro.AR!MTB"
        threat_id = "2147743449"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfusmacro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-47] 28 22 77 51 41 23 69 6e 6d 51 41 23 67 6d 51 41 23 74 73 51 41 23 3a 51 41 23 57 51 41 23 69 6e 51 41 23 33 51 41 23 32 51 41 23 5f 51 41 23 50 72 51 41 23 6f 51 41 23 51 41 23 63 65 51 41 23 73 51 41 23 73 22 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = "Replace(\"!!Q!!!!!!A!!!!!!!!!!#\", \"!\", \"\"), \"\")" ascii //weight: 1
        $x_1_3 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e [0-20] 29 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Obfusmacro_AV_2147743611_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Obfusmacro.AV!MTB"
        threat_id = "2147743611"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfusmacro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-150] 2b 20 22 77 37 38 69 37 38 6e 37 38 6d 67 37 38 6d 74 73 37 38 3a 57 69 37 38 6e 33 32 37 38 5f 50 72 37 38 6f 63 65 37 38 73 73 22 29 29}  //weight: 10, accuracy: Low
        $x_10_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-150] 2b 20 22 77 36 30 69 36 30 6e 36 30 6d 67 36 30 6d 74 73 36 30 3a 57 69 36 30 6e 33 32 36 30 5f 50 72 36 30 6f 63 65 36 30 73 73 22 29 29}  //weight: 10, accuracy: Low
        $x_10_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-150] 2b 20 22 77 38 34 69 38 34 6e 38 34 6d 67 38 34 6d 74 73 38 34 3a 57 69 38 34 6e 33 32 38 34 5f 50 72 38 34 6f 63 65 38 34 73 73 22 29 29}  //weight: 10, accuracy: Low
        $x_10_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-150] 22 71 77 6c 68 6c 73 61 64 77 71 77 6c 68 6c 73 61 64 69 6e 6d 71 77 6c 68 6c 73 61 64 67 6d 71 77 6c 68 6c 73 61 64 74 73 3a 57 71 77 6c 68 6c 73 61 64 69 6e 33 71 77 6c 68 6c 73 61 64 32 5f 50 71 77 6c 68 6c 73 61 64 72 71 77 6c 68 6c 73 61 64 6f 63 65 71 77 6c 68 6c 73 61 64 73 73 71 77 6c 68 6c 73 61 64 22 29 29}  //weight: 10, accuracy: Low
        $x_10_5 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-150] 22 69 77 71 68 77 6c 73 61 77 69 77 71 68 77 6c 73 61 69 6e 6d 69 77 71 68 77 6c 73 61 67 6d 69 77 71 68 77 6c 73 61 74 73 3a 57 69 77 71 68 77 6c 73 61 69 6e 33 69 77 71 68 77 6c 73 61 32 5f 50 69 77 71 68 77 6c 73 61 72 69 77 71 68 77 6c 73 61 6f 63 65 69 77 71 68 77 6c 73 61 73 73 69 77 71 68 77 6c 73 61 22 29 29}  //weight: 10, accuracy: Low
        $x_1_6 = {2e 43 72 65 61 74 65 28 [0-56] 2c}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 20 48 65 78 28 [0-56] 2f [0-56] 29}  //weight: 1, accuracy: Low
        $x_1_8 = ".ShowWindow =" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Obfusmacro_ARA_2147743612_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Obfusmacro.ARA!MTB"
        threat_id = "2147743612"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfusmacro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 20 22 77 69 6e 6d 67 6d 74 73 3a 57 69 22 20 2b [0-20] 2b 20 22 6e 33 32 5f 50 72 6f 63 65 73 73 73 74 61 72 74 75 70 22 20 2b}  //weight: 10, accuracy: Low
        $x_10_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-20] 2e 43 72 65 61 74 65 [0-150] 2b 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e}  //weight: 10, accuracy: Low
        $x_10_3 = {2b 20 22 77 69 6e 6d 67 6d 74 73 3a 57 69 22 20 2b [0-20] 2b 20 22 6e 33 32 5f 50 72 6f 63 65 73 73 22 20 2b}  //weight: 10, accuracy: Low
        $x_1_4 = "ShowWindow =" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Obfusmacro_AJ_2147743613_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Obfusmacro.AJ!MTB"
        threat_id = "2147743613"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfusmacro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-150] 2b 20 22 [0-47] 77 [0-8] 69 [0-8] 6e [0-8] 6d 67 [0-8] 6d [0-8] 74 73 [0-8] 3a [0-15] 57 69 [0-8] 6e [0-15] 5f [0-8] 50 72 [0-8] 6f 63 [0-8] 65 [0-8] 73 73}  //weight: 10, accuracy: Low
        $x_10_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-150] 2b 20 [0-150] 28}  //weight: 10, accuracy: Low
        $x_1_3 = {2e 43 72 65 61 74 65 28 [0-56] 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 52 65 70 6c 61 63 65 28 [0-53] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Obfusmacro_AA_2147743640_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Obfusmacro.AA!MTB"
        threat_id = "2147743640"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfusmacro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-150] 2b 20 22 [0-47] 77 [0-8] 69 [0-8] 6e [0-8] 6d 67 [0-8] 6d [0-8] 74 73 [0-8] 3a [0-15] 57 [0-8] 69 [0-8] 6e [0-15] 5f [0-8] 50 [0-8] 72 [0-8] 6f [0-8] 63 [0-8] 65 [0-8] 73 73}  //weight: 10, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-56] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-53] 2c}  //weight: 1, accuracy: Low
        $x_1_4 = "Sub autoopen()" ascii //weight: 1
        $x_1_5 = ", MSForms, TextBox\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Obfusmacro_GG_2147743678_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Obfusmacro.GG!MTB"
        threat_id = "2147743678"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfusmacro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 75 74 6f 4f 70 65 6e 28 29 [0-120] 2c 20 [0-10] 2e [0-10] 28 [0-10] 28 22 68 ?? 74 ?? 74 ?? 70 ?? 3a ?? 2f ?? 2f [0-15] 2e [0-10] 2f [0-10] 2f [0-12] 2e ?? 70 ?? 68 ?? 70 ?? 3f ?? 6c ?? 3d [0-15] 2e [0-10] 22 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 65 78 65 63 [0-15] 26 20 22 20 22 20 26 [0-15] 28 22 63 [0-2] 3a [0-2] 5c [0-30] 5c [0-15] 2e ?? 6a ?? 70 ?? 67 ?? 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "New WshShell" ascii //weight: 1
        $x_1_4 = "= FreeFile" ascii //weight: 1
        $x_1_5 = "Print #" ascii //weight: 1
        $x_1_6 = {26 20 4d 69 64 28 [0-10] 2c 20 [0-10] 2c 20 31 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Obfusmacro_GG_2147743678_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Obfusmacro.GG!MTB"
        threat_id = "2147743678"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfusmacro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 00 20 00 22 00 43 00 6d 00 22 00 20 00 26 00 20 00 22 00 64 00 20 00 2f 00 22 00 20 00 26 00 20 00 22 00 43 00 20 00 6d 00 73 00 5e 00 69 00 65 00 5e 00 58 00 65 00 5e 00 43 00 22 00 20 00 26 00 20 00 43 00 68 00 72 00 28 00 [0-10] 29 00 20 26 00 20 43 00 68 00 72 00 28 00 [0-10] 29 00 20 26 00 20 43 00 68 00 72 00 28 00 [0-10] 29 00 20 26 00 20 43 00 68 00 72 00 28 00 [0-10] 29 00 20 26 00 20 43 00 68 00 72 00 28 00 [0-10] 29 00 20 26 00 20 43 00 68 00 72 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 22 43 6d 22 20 26 20 22 64 20 2f 22 20 26 20 22 43 20 6d 73 5e 69 65 5e 58 65 5e 43 22 20 26 20 43 68 72 28 [0-10] 29 20 26 20 43 68 72 28 [0-10] 29 20 26 20 43 68 72 28 [0-10] 29 20 26 20 43 68 72 28 [0-10] 29 20 26 20 43 68 72 28 [0-10] 29 20 26 20 43 68 72}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 00 20 00 22 00 43 00 6d 00 64 00 20 00 2f 00 43 00 20 00 6d 00 73 00 49 00 65 00 5e 00 58 00 5e 00 65 00 43 00 20 00 22 00 20 00 26 00 20 00 43 00 68 00 72 00 28 00 [0-10] 29 00 20 26 00 20 43 00 68 00 72 00 28 00 [0-10] 29 00 20 26 00 20 43 00 68 00 72 00 28 00 [0-10] 29 00 20 26 00 20 43 00 68 00 72 00 28 00 [0-10] 29 00 20 26 00 20 43 00 68 00 72 00 28 00 [0-10] 29 00 20 26 00 20 43 00 68 00 72 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 22 43 6d 64 20 2f 43 20 6d 73 49 65 5e 58 5e 65 43 20 22 20 26 20 43 68 72 28 [0-10] 29 20 26 20 43 68 72 28 [0-10] 29 20 26 20 43 68 72 28 [0-10] 29 20 26 20 43 68 72 28 [0-10] 29 20 26 20 43 68 72 28 [0-10] 29 20 26 20 43 68 72}  //weight: 1, accuracy: Low
        $x_1_5 = "WSCRipt.sHELl" ascii //weight: 1
        $x_1_6 = "On Error Resume Next" ascii //weight: 1
        $x_1_7 = "= CreateObject(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Obfusmacro_GA_2147743870_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Obfusmacro.GA!MTB"
        threat_id = "2147743870"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfusmacro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_2 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-100] 28 22 63 [0-2] 3a [0-2] 5c [0-30] 5c [0-15] 2e ?? 6a ?? 70 [0-1] 65 [0-1] 67 ?? 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-175] 2c 20 [0-10] 2e [0-10] 28 [0-10] 28 22 68 ?? 74 ?? 74 ?? 70 ?? 3a ?? 2f ?? 2f [0-15] 2e [0-10] 2f [0-30] 2f [0-12] 2e ?? 70 ?? 68 ?? 70 ?? 3f ?? 6c ?? 3d [0-20] 2e [0-10] 22 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 65 78 65 63 20 [0-10] 20 26 20 22 20 22 20 26}  //weight: 1, accuracy: Low
        $x_1_5 = "Print #" ascii //weight: 1
        $x_1_6 = "Close #" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Obfusmacro_GA_2147743870_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Obfusmacro.GA!MTB"
        threat_id = "2147743870"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfusmacro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 00 69 00 6e 00 48 00 74 00 74 00 70 00 52 00 65 00 71 00 2e 00 4f 00 70 00 65 00 6e 00 20 00 22 00 47 00 45 00 54 00 22 00 2c 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-25] 2f 00 [0-10] 2e 00 6a 00 70 00 67 00 22 00 2c 00 20 00 46 00 61 00 6c 00 73 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {57 69 6e 48 74 74 70 52 65 71 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f [0-25] 2f [0-10] 2e 6a 70 67 22 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = {57 00 69 00 6e 00 48 00 74 00 74 00 70 00 52 00 65 00 71 00 2e 00 4f 00 70 00 65 00 6e 00 20 00 22 00 47 00 45 00 54 00 22 00 2c 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-3] 2e 00 [0-3] 2e 00 [0-3] 2e 00 [0-3] 2f 00 [0-10] 2e 00 65 00 78 00 65 00 22 00 2c 00 20 00 46 00 61 00 6c 00 73 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {57 69 6e 48 74 74 70 52 65 71 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f [0-10] 2e 65 78 65 22 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_5 = ".Write WinHttpReq.ResponseBody" ascii //weight: 1
        $x_1_6 = {2e 00 53 00 61 00 76 00 65 00 54 00 6f 00 46 00 69 00 6c 00 65 00 20 00 28 00 45 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 28 00 22 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 22 00 29 00 20 00 2b 00 20 00 22 00 5c 00 [0-50] 2e 00 65 00 78 00 65 00 22 00 29 00 2c 00}  //weight: 1, accuracy: Low
        $x_1_7 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 28 45 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 20 2b 20 22 5c [0-50] 2e 65 78 65 22 29 2c}  //weight: 1, accuracy: Low
        $x_1_8 = ".SaveToFile (Environ(\"TMP\") + \"" ascii //weight: 1
        $x_1_9 = ".Open Environ" ascii //weight: 1
        $x_1_10 = "Select Case" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Obfusmacro_GB_2147743871_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Obfusmacro.GB!MTB"
        threat_id = "2147743871"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfusmacro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_2 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-100] 28 22 63 [0-2] 3a [0-2] 5c [0-30] 5c [0-15] 2e ?? 6a ?? 70 [0-1] 67 ?? 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-175] 2c 20 [0-10] 2e [0-10] 28 [0-10] 28 22 68 ?? 74 ?? 74 ?? 70 ?? 3a ?? 2f ?? 2f [0-15] 2e [0-10] 2f [0-30] 2f [0-12] 2e ?? 70 ?? 68 ?? 70 ?? 3f ?? 6c ?? 3d [0-20] 2e [0-10] 22 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 65 78 65 63 20 [0-10] 20 26 20 22 20 22 20 26}  //weight: 1, accuracy: Low
        $x_1_5 = "Print #" ascii //weight: 1
        $x_1_6 = "Close #" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Obfusmacro_GB_2147743871_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Obfusmacro.GB!MTB"
        threat_id = "2147743871"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfusmacro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 00 20 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 [0-20] 2c 00 20 00 [0-20] 2c 00 20 00 22 00 22 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 52 65 70 6c 61 63 65 28 [0-20] 2c 20 [0-20] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 00 20 00 43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 [0-20] 28 00 [0-20] 28 00 43 00 53 00 74 00 72 00 28 00 [0-30] 29 00 20 00 2b 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-20] 28 [0-20] 28 43 53 74 72 28 [0-30] 29 20 2b 20 22}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 [0-20] 2c 00 20 00 [0-20] 2c 00 20 00 [0-20] 2c 00 20 00 [0-20] 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 43 72 65 61 74 65 28 [0-20] 2c 20 [0-20] 2c 20 [0-20] 2c 20 [0-20] 29}  //weight: 1, accuracy: Low
        $n_1_7 = "DebugPrintFile" ascii //weight: -1
        $n_1_8 = "Debug.Print" ascii //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Obfusmacro_GD_2147743872_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Obfusmacro.GD!MTB"
        threat_id = "2147743872"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfusmacro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 [0-30] 28 00 22 00 70 00 22 00 20 00 2b 00 20 00 [0-30] 2e 00 [0-30] 20 00 2b 00 20 00 [0-30] 2e 00 [0-30] 29 00 2c 00 20 00 [0-30] 2c 00 20 00 [0-30] 2c 00 20 00 [0-30] 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-30] 28 22 70 22 20 2b 20 [0-30] 2e [0-30] 20 2b 20 [0-30] 2e [0-30] 29 2c 20 [0-30] 2c 20 [0-30] 2c 20 [0-30] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 00 20 00 47 00 65 00 74 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 [0-30] 28 00 [0-30] 28 00 22 00 1e 00 77 00 1e 00 69 00 1e 00 6e 00 1e 00 6d 00 1e 00 67 00 1e 00 6d 00 1e 00 74 00 1e 00 73 00 1e 00 3a 00 1e 00 57 00 1e 00 69 00 1e 00 6e 00 1e 00 5f 00 1e 00 50 00 1e 00 72 00 1e 00 6f 00 1e 00 63 00 1e 00 65 00 1e 00 73 00 1e 00 73 00 1e 00 22 00 29 00 29 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-30] 28 [0-30] 28 22 1e 00 77 1e 00 69 1e 00 6e 1e 00 6d 1e 00 67 1e 00 6d 1e 00 74 1e 00 73 1e 00 3a 1e 00 57 1e 00 69 1e 00 6e 1e 00 5f 1e 00 50 1e 00 72 1e 00 6f 1e 00 63 1e 00 65 1e 00 73 1e 00 73 1e 00 22 29 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

