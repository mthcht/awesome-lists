rule TrojanDownloader_O97M_FTCdedoc_A_2147743726_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/FTCdedoc.A!MTB"
        threat_id = "2147743726"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "FTCdedoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 22 57 53 63 72 69 70 74 2e 22 20 26 20 [0-8] 29 29 2e 52 75 6e 20 [0-8] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = "= \"\"" ascii //weight: 1
        $x_1_3 = {28 22 22 2c 20 43 68 72 28 [0-8] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = "= \"1Normal.ThisDocument\"" ascii //weight: 1
        $x_1_5 = "Private Sub Document_Open()" ascii //weight: 1
        $x_1_6 = "\"Shell\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_FTCdedoc_B_2147743823_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/FTCdedoc.B!MTB"
        threat_id = "2147743823"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "FTCdedoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-21] 29 2e 52 75 6e 20 [0-8] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = "cript.Shell\"" ascii //weight: 1
        $x_1_3 = {28 22 22 2c 20 43 68 72 28 [0-8] 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = "= \"1Normal.ThisDocument\"" ascii //weight: 1
        $x_1_5 = "Private Sub Document_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_FTCdedoc_C_2147743918_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/FTCdedoc.C!MTB"
        threat_id = "2147743918"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "FTCdedoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 22 20 26 20 [0-21] 29 2e 52 75 6e 20 [0-21] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {26 20 22 2e 22 20 26 20 28 52 65 70 6c 61 63 65 28 [0-21] 2c 20 22 [0-8] 22 2c 20 22 22 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= \"\"" ascii //weight: 1
        $x_1_4 = {28 22 22 2c 20 43 68 72 28 [0-21] 29 29}  //weight: 1, accuracy: Low
        $x_1_5 = "= \"1Normal.ThisDocument\"" ascii //weight: 1
        $x_1_6 = "Private Sub Document_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_FTCdedoc_D_2147744038_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/FTCdedoc.D!MTB"
        threat_id = "2147744038"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "FTCdedoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 22 20 26 20 [0-16] 29 2e 52 75 6e 20 [0-16] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = "= \".\" &" ascii //weight: 1
        $x_1_3 = {26 20 28 52 65 70 6c 61 63 65 28 [0-16] 2c 20 22 [0-16] 22 2c 20 22 22 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {28 52 65 70 6c 61 63 65 28 [0-16] 2c 20 22 [0-16] 22 2c 20 22 22 29 2c 20 [0-16] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {28 22 22 2c 20 43 68 72 28 [0-16] 29 29}  //weight: 1, accuracy: Low
        $x_1_6 = "= \"\"" ascii //weight: 1
        $x_1_7 = "= \"1Normal.ThisDocument\"" ascii //weight: 1
        $x_1_8 = "Private Sub Document_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_FTCdedoc_E_2147744105_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/FTCdedoc.E!MTB"
        threat_id = "2147744105"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "FTCdedoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 22 20 26 20 [0-16] 29 2e 52 75 6e 20 [0-16] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 22 2e [0-32] 22}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 28 52 65 70 6c 61 63 65 28 [0-16] 2c 20 22 [0-16] 22 2c 20 22 22 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {28 52 65 70 6c 61 63 65 28 [0-16] 2c 20 22 [0-16] 22 2c 20 22 22 29 2c 20 [0-8] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {28 22 22 2c 20 43 68 72 28 [0-7] 29 29}  //weight: 1, accuracy: Low
        $x_1_6 = "= \"\"" ascii //weight: 1
        $x_1_7 = "= \"1Normal.ThisDocument\"" ascii //weight: 1
        $x_1_8 = "Private Sub Document_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_FTCdedoc_F_2147744307_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/FTCdedoc.F!MTB"
        threat_id = "2147744307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "FTCdedoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 52 75 6e 20 [0-5] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 20 43 68 72 28 [0-5] 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= \"\"" ascii //weight: 1
        $x_1_4 = "= \"1Normal.ThisDocument\"" ascii //weight: 1
        $x_1_5 = "Private Sub Document_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_FTCdedoc_G_2147744520_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/FTCdedoc.G!MTB"
        threat_id = "2147744520"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "FTCdedoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 52 75 6e 20 [0-5] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 20 43 68 72 28 [0-5] 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= \"1Normal.ThisDocument\"" ascii //weight: 1
        $x_1_4 = "Private Sub Document_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

