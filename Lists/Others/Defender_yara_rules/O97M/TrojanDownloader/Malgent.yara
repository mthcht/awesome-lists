rule TrojanDownloader_O97M_Malgent_A_2147728846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Malgent.A"
        threat_id = "2147728846"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Malgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 44 65 73 6b 74 6f 70 22 20 26 20 22 5c 71 75 6f 74 61 74 69 6f 6e 2e 65 78 65 22 0d 0a 53 68 65 6c 6c 20 28}  //weight: 1, accuracy: High
        $x_1_2 = "http://45.78.21.150/boost/boosting.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Malgent_B_2147733456_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Malgent.B"
        threat_id = "2147733456"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Malgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ": Call URLDownloadToFileA(5 - 5, N8nBn, h05vNu4LmCyY, 1 - 1, 2 - 2)" ascii //weight: 1
        $x_1_2 = "zmxn = CallByName(jtra, hrqf(" ascii //weight: 1
        $x_1_3 = "hzka = CallByName(lytl, flgc(" ascii //weight: 1
        $x_1_4 = "ep = \"SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAJAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Malgent_C_2147734197_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Malgent.C"
        threat_id = "2147734197"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Malgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Environ$(Replace(\"App##Da##ta\", \"##\", \"\"))" ascii //weight: 1
        $x_1_2 = "= Replace(\"ht##tp##:##/##/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Malgent_E_2147734886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Malgent.E"
        threat_id = "2147734886"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Malgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "#If VBA7 And Win64 And 1 Then" ascii //weight: 1
        $x_1_2 = "Private Declare PtrSafe Function URLDownloadToFileA Lib \"URLMON\" (ByVal " ascii //weight: 1
        $x_1_3 = " = Left(StrConv(" ascii //weight: 1
        $x_1_4 = "Call URLDownloadToFileA(" ascii //weight: 1
        $x_1_5 = {20 3d 20 30 20 54 6f 20 55 42 6f 75 6e 64 28 [0-32] 29 20 2d 20 31 0d 0a 20 20 20 20 20 20 20 20 49 66 20 28 [0-32] 20 4d 6f 64 20 35 20 3d 20 28}  //weight: 1, accuracy: Low
        $x_1_6 = {20 3d 20 45 6e 76 69 72 6f 6e 28 [0-32] 28 [0-1] 05 00 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Malgent_KSH_2147769245_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Malgent.KSH!MSR"
        threat_id = "2147769245"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Malgent"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "arguments=\"https://d3727mhevtk2n4.cloudfront.net/srv-stg-agent" ascii //weight: 1
        $x_1_2 = "mcafeeavupdatetask" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Malgent_AJK_2147782376_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Malgent.AJK!MSR"
        threat_id = "2147782376"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Malgent"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Call trenes(\"http://kuzov-remont.com/wp-admin/js/win.exe\"," ascii //weight: 5
        $x_5_2 = "Environ(\"AppData\") & \"\\Ds.exe\")" ascii //weight: 5
        $x_5_3 = {45 6e 76 69 72 6f 6e 28 22 55 73 65 72 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 4d 65 6e fa 20 49 6e 69 63 69 6f 5c 50 72 6f 67 72 61 6d 61 73 5c 49 6e 69 63 69 6f 5c 44 73 2e 65 78 65 22 29}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

