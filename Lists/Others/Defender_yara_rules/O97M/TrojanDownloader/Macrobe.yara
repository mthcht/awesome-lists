rule TrojanDownloader_O97M_Macrobe_2147710500_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Macrobe"
        threat_id = "2147710500"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Macrobe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 42 79 4e 61 6d 65 20 4c 65 67 65 6e 64 61 72 79 2c 20 46 55 2e 54 65 78 74 42 6f 78 31 2e 54 65 78 74 2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-96] 5f 52 48 2c 20 22 4d 6f 7a 69 6c 6c 61 2f 35 2e 31 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 72 76 3a 35 30 2e 30 29 20 47 65 63 6b 6f 2f 32 30 32 30 30 31 30 32 20 46 69 72 65 66 6f 78 2f 35 30 2e 30 22}  //weight: 1, accuracy: Low
        $x_1_2 = "MovedPermanently = Split(\"" ascii //weight: 1
        $x_1_3 = {53 65 74 20 43 75 72 72 65 6e 74 52 65 76 69 73 69 6f 6e 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-96] 5f 48 65 61 64 48 75 6e 74 65 72 28 31 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Macrobe_CS_2147745729_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Macrobe.CS!eml"
        threat_id = "2147745729"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Macrobe"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 45 6e 76 69 72 6f 6e 28 43 68 72 24 28 [0-6] 2d [0-5] 29 20 26 20 43 68 72 24 28 [0-6] 2d [0-6] 29 20 26 20 43 68 72 24 28 [0-6] 2d [0-6] 29 20 26 20 43 68 72 24 28 [0-6] 2d [0-6] 29 29 20 26 20 22 5c [0-80] 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 31 29 2e 4f 4c 45 46 6f 72 6d 61 74 2e 4f 70 65 6e [0-8] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20}  //weight: 1, accuracy: Low
        $x_1_3 = "Sub Document_open()" ascii //weight: 1
        $x_1_4 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-8] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20 [0-100] 44 69 6d 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Macrobe_BD_2147750795_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Macrobe.BD!MTB"
        threat_id = "2147750795"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Macrobe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 76 63 76 69 61 67 65 6e 73 2e 73 73 6c 62 6c 69 6e 64 61 64 6f 2e 63 6f 6d 2f [0-4] 2e (68|68 74) 22 3a 00 76 61 72 30 20 3d 20 22 4d 53 48 54 41 20 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "Sub Auto_Open()" ascii //weight: 1
        $x_1_3 = "Shell (Var)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Macrobe_BD1_2147751641_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Macrobe.BD1!MTB"
        threat_id = "2147751641"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Macrobe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 61 72 30 20 3d 20 22 4d 53 48 54 41 20 68 74 74 70 73 3a 2f 2f [0-13] 2e 73 73 6c 62 6c 69 6e 64 61 64 6f 2e 63 6f 6d 2f [0-12] 2e (68|68 74) 22}  //weight: 1, accuracy: Low
        $x_1_2 = "Sub Auto_Open()" ascii //weight: 1
        $x_1_3 = "Shell (Var)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Macrobe_PS_2147751643_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Macrobe.PS!MTB"
        threat_id = "2147751643"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Macrobe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 52 65 70 6c 61 63 65 28 [0-72] 2c 20 22 6f 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {26 20 45 6d 70 74 79 20 26 20 22 53 ?? 68 00 65 6c 00 6c 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 22 2f 2a 22 20 26 20 43 68 72 28 [0-2] 29 20 26 20 43 68 72 28 [0-10] 29 20 26 20 [0-10] 28 22 [0-10] 77 73 [0-10] 63 [0-10] 72 69 [0-10] 70 74 [0-10] 2f 65 [0-10] 3a [0-10] 4a [0-10] 53 43 72 [0-10] 69 70 [0-10] 74 [0-10] 20 [0-10] 22 22 [0-10] 25 [0-10] 7e [0-10] 66 [0-10] 30 [0-10] 22 22 [0-10] 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Macrobe_GM_2147757622_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Macrobe.GM!MTB"
        threat_id = "2147757622"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Macrobe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XOREncryption" ascii //weight: 1
        $x_1_2 = "CreateObject(zVhHpUZKyJwmuwdlEkqc(Fortunatus))" ascii //weight: 1
        $x_1_3 = "Callisto(XOREncryption" ascii //weight: 1
        $x_1_4 = "XOREncryption = XOREncryption & Chr(Asc(Mid(sKey, IIf(i Mod Len(sKey)" ascii //weight: 1
        $x_1_5 = "Chedomir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

