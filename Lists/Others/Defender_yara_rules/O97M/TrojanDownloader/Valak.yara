rule TrojanDownloader_O97M_Valak_RA_2147756765_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Valak.RA!MTB"
        threat_id = "2147756765"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Valak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VB_Name = \"rT\"" ascii //weight: 1
        $x_1_2 = "\"regsvr\" & 32 & \" \"" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = {44 69 6d 20 ?? ?? 20 41 73 20 4e 65 77 20 57 73 68 53 68 65 6c 6c 0d 0a 00 2e 65 78 65 63 20 6b 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Valak_RA_2147756765_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Valak.RA!MTB"
        threat_id = "2147756765"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Valak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Sub AutoOpen()" ascii //weight: 2
        $x_1_2 = "= Environ(\"tmp\") & \"\\index.jpg" ascii //weight: 1
        $x_1_3 = "Environ(\"tmp\") & \"\\1.jpg" ascii //weight: 1
        $x_1_4 = "(\"r14ea6g25sd5vc8rf630a2de\")" ascii //weight: 1
        $x_2_5 = {43 61 6c 6c 20 [0-10] 2e 65 78 65 63 28 [0-10] 20 26 20 22 20 22 20 26 20 [0-10] 29}  //weight: 2, accuracy: Low
        $x_2_6 = {43 61 6c 6c 20 [0-10] 2e 4f 70 65 6e 28 22 47 45 54 22 2c 20 [0-10] 2c 20 46 61 6c 73 65 29}  //weight: 2, accuracy: Low
        $x_1_7 = "rd0e1egf9s9bv31rc738b202" ascii //weight: 1
        $x_1_8 = {45 6e 76 69 72 6f 6e 28 22 74 6d 70 22 29 20 26 20 22 5c [0-10] 2e 6a 70 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Valak_YB_2147760470_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Valak.YB!MTB"
        threat_id = "2147760470"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Valak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "L_o5 = \"https://%69%69%69%69%69%69%69%69%69%69%69%69%69%69%69%69%69%69%69%69@j.mp" ascii //weight: 1
        $x_1_2 = "vb_name=\"zubbi_" ascii //weight: 1
        $x_1_3 = "L_o1 = \"m\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Valak_PA_2147760655_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Valak.PA!MTB"
        threat_id = "2147760655"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Valak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Environ(\"tmp\") & \"\\111.jpg\"" ascii //weight: 1
        $x_1_2 = {2e 65 78 65 63 28 [0-10] 28 22 72 [0-5] 65 [0-5] 67 [0-5] 73 [0-5] 76 [0-5] 22 29 20 26 20 22 72 33 32 20 22 20 26}  //weight: 1, accuracy: Low
        $x_1_3 = {44 69 6d 20 [0-10] 20 41 73 20 4e 65 77 20 57 73 68 53 68 65 6c 6c}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 53 74 72 43 6f 6e 76 28 [0-10] 2c 20 36 34 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Valak_YC_2147760793_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Valak.YC!MTB"
        threat_id = "2147760793"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Valak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "p://%20%20@j.mp/asdaasdaasdoasdodkaos" ascii //weight: 1
        $x_1_2 = "CreateObject(pudloal).Exec fuda" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Valak_PB_2147761097_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Valak.PB!MTB"
        threat_id = "2147761097"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Valak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Environ(\"temp\") & \"\\main.theme\"" ascii //weight: 1
        $x_1_2 = "= ActiveWindow.Split" ascii //weight: 1
        $x_1_3 = "d9cc42e0.Send" ascii //weight: 1
        $x_1_4 = "Call ed3931ab.exec(f26e39fe)" ascii //weight: 1
        $x_1_5 = "CreateObject(\"wscript.shell\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Valak_SM_2147761366_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Valak.SM!MTB"
        threat_id = "2147761366"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Valak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = " = Environ(\"temp\") & \"\\main.theme\"" ascii //weight: 2
        $x_1_2 = {20 3d 20 53 74 72 43 6f 6e 76 28 ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 36 34 29}  //weight: 1, accuracy: Low
        $x_1_3 = {53 65 74 20 [0-48] 20 3d 20 4e 65 77 20 4d 53 58 4d 4c 32 2e 58 4d 4c 48 54 54 50 36 30}  //weight: 1, accuracy: Low
        $x_1_4 = {43 61 6c 6c 20 [0-48] 2e 4f 70 65 6e 28 22 47 45 54 22 2c 20 [0-48] 2c 20 46 61 6c 73 65 29}  //weight: 1, accuracy: Low
        $x_1_5 = {53 65 74 20 [0-48] 20 3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29}  //weight: 1, accuracy: Low
        $x_1_6 = {53 65 74 20 [0-48] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Valak_YE_2147761820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Valak.YE!MTB"
        threat_id = "2147761820"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Valak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(hireme).Exec suckmydickfornoreason" ascii //weight: 1
        $x_1_2 = "p://%40%40%40%40@j.mp/" ascii //weight: 1
        $x_1_3 = "Function hireme()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Valak_YG_2147763610_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Valak.YG!MTB"
        threat_id = "2147763610"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Valak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mas = \"/%911%911%911%911%911@j.mp\\kasdasjasjdaoskdolasmdokkoasddsdskdd" ascii //weight: 1
        $x_1_2 = "asmdiasd = \"s:/" ascii //weight: 1
        $x_1_3 = "asn = moasd + asdmmm + asdmmm + mwimx + asmdiasd + mas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Valak_YH_2147763879_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Valak.YH!MTB"
        threat_id = "2147763879"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Valak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%909123id%909123id%909123id%909123id%909123id@j.mp" ascii //weight: 1
        $x_1_2 = {25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 [0-48] 2e 6d 70}  //weight: 1, accuracy: Low
        $x_1_3 = "zuoosaod = pyar + kook + kook + tyrisabi + okal2s + jasikk" ascii //weight: 1
        $x_1_4 = "zuoosaod = pyar1 + kook1 + kook1 + tyrisabi1 + okal2s1 + jasikk1" ascii //weight: 1
        $x_1_5 = {6f 6b 61 6c 32 [0-3] 20 3d 20 22 73 3a 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

