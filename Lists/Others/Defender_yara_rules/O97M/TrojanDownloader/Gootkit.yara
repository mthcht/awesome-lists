rule TrojanDownloader_O97M_Gootkit_A_2147743093_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gootkit.A!MSR"
        threat_id = "2147743093"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gootkit"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "CreateObject(\"WScript.Shell\").Run" ascii //weight: 5
        $x_1_2 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 [0-10] 20 3d 20 30 [0-16] 20 03 00 [0-16] 20 03 00 [0-16] 20 03 00 [0-16] 20 03 00 [0-16] 20 03 00 [0-16] 20 03 00 [0-16] 20 03 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e [0-32] 45 6e 64 20 53 75 62 ?? ?? 50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e [0-160] 45 6e 64 20 46 75 6e 63 74 69 6f 6e ?? ?? 50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e [0-112] 45 6e 64 20 49 66 ?? ?? 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gootkit_C_2147743204_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gootkit.C!MSR"
        threat_id = "2147743204"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gootkit"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "Attribute VB_Base = \"1Normal.ThisDocument\"" ascii //weight: 5
        $x_5_2 = "Sub AutoOpen()" ascii //weight: 5
        $x_5_3 = "Private Sub Document_Open()" ascii //weight: 5
        $x_20_4 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-16] 20 03 00 [0-16] 20 03 00 [0-16] 20 03 00 [0-16] 20 03 00 [0-16] 20 03 00 [0-16] 20 03 00 [0-16] 20 03 00}  //weight: 20, accuracy: Low
        $x_15_5 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 [0-26] 53 65 74 20 [0-16] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 [0-48] 49 66 20 [0-26] 54 68 65 6e [0-26] 45 6c 73 65 [0-16] 2e 52 75 6e 20 [0-26] 45 6e 64 20 49 66 [0-5] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 15, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 2 of ($x_5_*))) or
            ((1 of ($x_20_*) and 1 of ($x_5_*))) or
            ((1 of ($x_20_*) and 1 of ($x_15_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Gootkit_D_2147750711_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gootkit.D!MSR"
        threat_id = "2147750711"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gootkit"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "Attribute VB_Base = \"1Normal.ThisDocument\"" ascii //weight: 5
        $x_20_2 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-16] 20 03 00 [0-16] 20 03 00 [0-16] 20 03 00 [0-16] 20 03 00 [0-16] 20 03 00 [0-16] 20 03 00 [0-16] 20 03 00}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

