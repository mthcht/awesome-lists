rule TrojanDownloader_O97M_Adnel_2147690585_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 38 33 29 [0-12] 28 31 30 34 29 [0-12] 28 31 30 31 29 [0-12] 28 31 30 38 29 [0-12] 28 31 30 38 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cWolIdDu" ascii //weight: 1
        $x_1_2 = {c6 c4 d3 8c 78 af}  //weight: 1, accuracy: High
        $x_1_3 = "Shell " ascii //weight: 1
        $x_1_4 = ", vbHide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Scri  %TE MP% \\\\\".split(\" \");" ascii //weight: 1
        $x_1_2 = " .e xe G ET\").split(\" \")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 34 20 2b 20 [0-16] 20 2b 20 36 0d 0a 45 78 69 74 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 20 39 37 20 2b 20 [0-21] 20 32 36 29 20 2b 20 39 37 29 0d 0a 45 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 4f 00 2f 2f 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "JpIvdmPtFwrKOi = ueZrXnHD(\"pip.pntqqz/dprlxt/dpofwnyt-ah/xzn.21tdcln.hhh//:aees\", 15)" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 52 54 59 67 75 68 69 68 64 66 66 59 54 55 64 73 66 28 29 ?? ?? 52 44 46 43 47 56 48 6a 64 61 64 20 3d 20 57 45 44 52 54 59 67 75 66 2e 67 66 64 63 77 65 66 77 65 72 66 66 66 ?? ?? 53 68 65 6c 6c 20 52 44 46 43 47 56 48 6a 64 61 64 2c 20 76 62 48 69 64 65 ?? ?? 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 70 6c 69 74 28 22 04 00 04 00 04 00 04 00 04 00 [0-240] 22 2c 20 5f 04 00 22 01 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 4f 70 65 6e 0d 0a 47 65 74 46 49 46 4f 43 6f 73 74 20 22 22 2c 20 22 22 2c 20 22 22 2c 20 4e 6f 77 28 29 2c 20 22 22 2c 20 [0-16] 2c 20 22 22 2c 20 22 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Sub Tyryka(Uhrb As Long)" ascii //weight: 5
        $x_5_2 = "Dim Hbhe As Long, Ehdh As Long" ascii //weight: 5
        $x_5_3 = "dhdw = 64 * 3 * 4 * 1 * 1 * 3 * 1" ascii //weight: 5
        $x_5_4 = "ffw = Shell(rre, 0)" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "dTYFidsff = Environ(\"TEMP\") & hsdiufghbjkbHJFUHkjbsdhbfdskf.TextBox2" ascii //weight: 5
        $x_5_2 = "pjIOHdsfc = hsdiufghbjkbHJFUHkjbsdhbfdskf.TextBox1" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 20 [0-21] 2c 20 30 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {46 6f 72 20 ?? ?? ?? ?? ?? [0-16] 20 3d 20 [0-21] 28 [0-21] 29 20 54 6f 20 02 28 [0-21] 29 0d 0a [0-21] 28 [0-9] 29 20 3d 20 [0-21] 28 00 [0-16] 2c 20 31 29 0d 0a 06 28 [0-9] 29 20 3d 20 [0-21] 28 00 [0-16] 2c 20 32 29}  //weight: 1, accuracy: Low
        $x_1_3 = "Sub Document_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ") = \"LAEqzGGz158JDGyBhDGHNTjX0twK\" Then Exit For" ascii //weight: 1
        $x_1_2 = ") = \"MDvCZXL4oqqymkHf9fhb2qBePykB\" Then Exit For" ascii //weight: 1
        $x_1_3 = ") = \"BSUhZ7yhZGPjEXeLkCq65aRMJEc\" Then Exit For" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_11
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Attribute VB_Name = \"Module1\"" ascii //weight: 1
        $x_1_2 = "Private Const yY1UL = " ascii //weight: 1
        $x_1_3 = "Private Const DDuKQ = " ascii //weight: 1
        $x_1_4 = "Sub tyrtyaag()" ascii //weight: 1
        $x_1_5 = "oPOJidsf = lqjWjFO(DDuKQ, yY1UL)" ascii //weight: 1
        $x_1_6 = "Shell oPOJidsf, vbHide" ascii //weight: 1
        $x_1_7 = "End Sub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_12
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(0) = 41" ascii //weight: 1
        $x_1_2 = "(1) = 63" ascii //weight: 1
        $x_1_3 = "(2) = 73" ascii //weight: 1
        $x_1_4 = "(3) = 178" ascii //weight: 1
        $x_1_5 = "(4) = 60" ascii //weight: 1
        $x_1_6 = "(5) = 222" ascii //weight: 1
        $x_1_7 = "(6) = 101" ascii //weight: 1
        $x_1_8 = "(7) = 23" ascii //weight: 1
        $x_1_9 = "(8) = 253" ascii //weight: 1
        $x_1_10 = "(9) = 195" ascii //weight: 1
        $x_1_11 = "(10) = 105" ascii //weight: 1
        $x_1_12 = "(11) = 242" ascii //weight: 1
        $x_1_13 = "(12) = 6" ascii //weight: 1
        $x_1_14 = ")).Run " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_13
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "MONE = KKGG + \"e\" & Chr(90 + haa + 30 + 1) & \"e\"" ascii //weight: 5
        $x_5_2 = "JNBBH = KKGG + \"\" & \"r\" & Chr(haa + 17 + 40 + 60) & \"f\"" ascii //weight: 5
        $x_5_3 = "ssBnbsandH = CreateObject(Chr(7 + 80) + \"or\" + \"d.Application\")" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_14
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RebootSystem1 = RebootSystem1 & Chr(ByValvDefault(i) - 5 * NothingOrNodeName - 5 - 555 - 5555 - 555)" ascii //weight: 1
        $x_1_2 = "Public Function IsFileADXRedist(ByValvDefault() As Variant, NothingOrNodeName As Integer) As String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_15
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 47 65 74 50 61 74 68 53 65 70 61 72 61 74 6f 72 28 29 20 41 73 20 53 74 72 69 6e 67 0d 0a 20 20 20 20 47 65 74 50 61 74 68 53 65 70 61 72 61 74 6f 72 20 3d 20 43 68 72 28 39 32 29 20 27 20 5c 0d 0a 20 20 20 20 20 53 65 74 20 4d 6f 64 75 6c 65 32 2e 68 61 79 73 74 61 63 6b 4a 6f 52 65 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 0d 0a 20 20 20 20 53 65 74 20 61 64 6f 64 62 53 74 72 65 61 6d 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 64 6f 64 62 2e 53 74 72 65 61 6d 22 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_2 = "tempFile = tempFolder + \"\\hizb32a.exe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_16
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LPT1 = SEEEGMATICKS122(IPPTDSH871, IPPTDSH999, vbNullString, vbNullString, 0)" ascii //weight: 1
        $x_1_2 = "LPT2 = SEEEGMATICKS1(LPT1, ITSFROM, vbNullString, 0, cCCc, 0)" ascii //weight: 1
        $x_1_3 = "SEEEGMATICKS21 LPT2, SA33LOOOOMMA442, IPPTDSH872, CDSFDFD" ascii //weight: 1
        $x_1_4 = "ITSFROM = KALLKKKASKAJJAS(WIIIN34DIS2, WIIIN34DIS4)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_17
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rIuyYMJDVSqL = Chr$(Val(Chr$(38) & Chr$(72) & Mid$(ODYNESdLLylLiv, GAeuMhAuk, 2)))" ascii //weight: 1
        $x_1_2 = "Public Function GhkbkjGJfg(ByVal ODYNESdLLylLiv As String) As String" ascii //weight: 1
        $x_1_3 = "qmxBPln = qmxBPln & rIuyYMJDVSqL" ascii //weight: 1
        $x_1_4 = "GhkbkjGJfg = qmxBPln" ascii //weight: 1
        $x_1_5 = "For GAeuMhAuk = 1 To Len(ODYNESdLLylLiv) Step 2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_18
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 41 73 20 56 61 72 69 61 6e 74 2c 20 42 79 56 61 6c 20 [0-21] 20 41 73 20 53 74 72 69 6e 67 29 [0-2] 53 65 74 20 [0-21] 20 3d 20 [0-21] 28 22 [0-3] 7a [0-3] 6e [0-3] 72 [0-3] 65 [0-3] 67 [0-56] 2e 54 79 70 65 20 3d 20 31 [0-2] 43 61 6c 6c 42 79 4e 61 6d 65 20 [0-80] 22 29 2c 20 56 62 4d 65 74 68 6f 64 [0-2] 43 61 6c 6c 42 79 4e 61 6d 65 20 [0-80] 22 29 2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-32] 43 61 6c 6c 42 79 4e 61 6d 65 20 [0-80] 22 29 2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-32] 2c 20 32 [0-2] 45 6e 64 20 53 75 62}  //weight: 2, accuracy: Low
        $x_1_2 = {43 61 6c 6c 42 79 4e 61 6d 65 20 [0-48] 2c 20 56 62 4d 65 74 68 6f 64 [0-2] 43 61 6c 6c 42 79 4e 61 6d 65 20 [0-48] 2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-32] 43 61 6c 6c 42 79 4e 61 6d 65 20 [0-48] 2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-32] 2c 20 32 [0-2] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Adnel_2147690585_19
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 29 20 41 73 20 56 61 72 69 61 6e 74 ?? ?? ?? ?? [0-15] 3d 20 41 72 72 61 79 28 05 00 2c 20 05 00 2c 20 05 00 2c 20 05 00}  //weight: 1, accuracy: Low
        $x_1_2 = {61 72 72 61 79 5f 62 6f 6f 73 74 65 72 2e 4f 70 65 6e 20 73 74 72 4c 69 6e 6b 54 61 62 6c 65 4e 61 6d 65 20 2b 20 50 75 73 68 5f 54 2c 20 47 65 74 53 74 72 69 6e 67 46 72 6f 6d 41 72 72 61 79 28 75 72 6c 41 72 2c 20 02 00 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 4f 70 65 6e 20 55 43 61 73 65 28 [0-21] 29 2c 20 70 69 6c 65 76 6f 5f 02 00 28 70 69 6c 65 76 6f 5f 02 00 2c 20 02 00 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 4f 70 65 6e 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 02 00 2e 43 61 70 74 69 6f 6e 2c 20 6b 69 73 6b 61 5f 02 00 28 6b 69 73 6b 61 5f 02 00 2c 20 02 00 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 4f 70 65 6e 20 53 61 6d 62 6f 46 2e 4c 61 62 65 6c 02 00 2e 43 61 70 74 69 6f 6e 2c 20 62 61 72 61 62 61 72 61 5f 02 00 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_20
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(145, 156, 155, 150, 95, 83, 82, 84, 81, 84, 77, 79, 81, 76, 73, 75, 82, 70, 72, 72, 68, 71, 71, 120, 116, 67, 67, 130, 65, 65, 127, 57, 65, 113, 113, 108, 106, 123, 49" ascii //weight: 1
        $x_1_2 = "(154, 165, 164, 159, 104, 92, 91, 159, 146, 142, 148, 156, 152, 138, 147, 137, 144, 144, 141, 128, 76, 128, 139, 136, 73, 151, 143, 124, 120, 68, 71, 71, 120, 116, 67, 67, 130" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_21
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 47 65 74 53 74 72 69 6e 67 46 72 6f 6d 41 72 72 61 79 28 66 72 6f 6d 41 72 72 28 29 20 41 73 20 56 61 72 69 61 6e 74 2c 20 4c 65 6e 4c 65 6e 20 41 73 20 49 6e 74 65 67 65 72 29 20 41 73 20 53 74 72 69 6e 67 0d 0a 20 20 20 20 44 69 6d 20 69 20 41 73 20 49 6e 74 65 67 65 72 0d 0a 20 20 20 20 44 69 6d 20 72 65 73 75 6c 74 20 41 73 20 53 74 72 69 6e 67 0d 0a 20 20 20 20 72 65 73 75 6c 74 20 3d 20 22 22 0d 0a 20 20 20 20 46 6f 72 20 69 20 3d 20 4c 42 6f 75 6e 64 28 66 72 6f 6d 41 72 72 29 20 54 6f 20 55 42 6f 75 6e 64 28 66 72 6f 6d 41 72 72 29 0d 0a}  //weight: 1, accuracy: High
        $x_1_2 = {20 20 20 20 20 20 20 20 72 65 73 75 6c 74 20 3d 20 72 65 73 75 6c 74 20 26 20 43 68 72 28 66 72 6f 6d 41 72 72 28 69 29 20 2d 20 4c 65 6e 4c 65 6e 20 2b 20 69 20 2a 20 32 29 0d 0a 20 20 20 20 4e 65 78 74 20 69 0d 0a 20 20 20 20 47 65 74 53 74 72 69 6e 67 46 72 6f 6d 41 72 72 61 79 20 3d 20 72 65 73 75 6c 74 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 0d 0a}  //weight: 1, accuracy: High
        $x_1_3 = "tempFile = tempFolder + \"\\shhg32c.exe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_22
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= StrReverse(\"TEG\")" ascii //weight: 1
        $x_1_2 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 [0-16] 2c 20 22 6f 70 65 6e 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-16] 2c 20 22 [0-48] 2f [0-15] 2e 65 78 65 22 2c 20 46 61 6c 73 65 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= CallByName(victor, \"open\", VbMethod, biographer, longepass, False)" ascii //weight: 1
        $x_1_4 = "= CallByName(alaskan, \"open\", VbMethod, ppepare, tron, False)" ascii //weight: 1
        $x_1_5 = "CallByName(obediant, \"open\", VbMethod, lhomme, pandemic, False)" ascii //weight: 1
        $x_1_6 = "= CallByName(moo, \"open\", VbMethod, couples, trickle, False)" ascii //weight: 1
        $x_1_7 = {2e 4f 70 65 6e 20 4b 4f 4c 4f 44 41 28 [0-12] 29 2c 20 53 41 6d 6f 65 74 75 74 50 72 6f 28 72 75 62 6c 69 6b 69 37 2c 20 [0-12] 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Adnel_2147690585_23
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel"
        threat_id = "2147690585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 47 65 74 53 74 72 69 6e 67 46 72 6f 6d 41 72 72 61 79 28 66 72 6f 6d 41 72 72 28 29 20 41 73 20 56 61 72 69 61 6e 74 2c 20 4c 65 6e 4c 65 6e 20 41 73 20 49 6e 74 65 67 65 72 29 20 41 73 20 53 74 72 69 6e 67 0d 0a 20 20 20 20 44 69 6d 20 69 20 41 73 20 49 6e 74 65 67 65 72 0d 0a 20 20 20 20 44 69 6d 20 72 65 73 75 6c 74 20 41 73 20 53 74 72 69 6e 67 0d 0a 20 20 20 20 72 65 73 75 6c 74 20 3d 20 22 22 0d 0a 20 20 20 20 46 6f 72 20 69 20 3d 20 4c 42 6f 75 6e 64 28 66 72 6f 6d 41 72 72 29 20 54 6f 20 55 42 6f 75 6e 64 28 66 72 6f 6d 41 72 72 29 0d 0a}  //weight: 1, accuracy: High
        $x_1_2 = {20 20 20 20 20 20 20 20 72 65 73 75 6c 74 20 3d 20 72 65 73 75 6c 74 20 26 20 43 68 72 28 66 72 6f 6d 41 72 72 28 69 29 20 2d 20 01 00 20 2a 20 4c 65 6e 4c 65 6e 20 2d 20 03 00 29 0d 0a 20 20 20 20 4e 65 78 74 20 69 0d 0a 20 20 20 20 47 65 74 53 74 72 69 6e 67 46 72 6f 6d 41 72 72 61 79 20 3d 20 72 65 73 75 6c 74 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 0d 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {65 78 69 74 31 3a 0d 0a 0d 0a 44 61 74 61 62 61 73 65 43 6f 6e 6e 65 63 74 69 6f 6e 48 61 6e 64 6c 65 2e 4f 70 65 6e 20 52 65 70 6c 61 63 65 28 52 65 70 6c 61 63 65 28 22 ?? 45 ?? 22 2c 20 22 00 22 2c 20 22 47 22 29 2c 20 22 01 22 2c 20 22 54 22 29 2c 20 47 65 74 53 74 72 69 6e 67 46 72 6f 6d 41 72 72 61 79 28 44 61 79 49 6e 64 65 78 32 2c 20 02 00 29 2c 20 46 6c 61 67 35 0d 0a 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Adnel_G_2147692977_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.G"
        threat_id = "2147692977"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-17] 28 43 68 72 24 28 [0-3] 29 20 2b 20 43 68 72 24 28 [0-3] 29 20 2b 20 43 68 72 24 28 [0-3] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 4f 70 65 6e 20 [0-17] 28 43 68 72 24 28 [0-3] 29 20 2b 20 43 68 72 24 28 [0-3] 29 20 2b 20 43 68 72 24 28 [0-3] 29 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 72 65 61 64 79 53 74 61 74 65 20 3d 20 28 [0-22] 29 20 41 6e 64 20 [0-16] 2e 53 74 61 74 75 73 20 3d 20 28 [0-22] 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_D_2147693758_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.D"
        threat_id = "2147693758"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 20 22 6c 69 63 61 74 69 6f 6e 22 29 0d 0a 6f 49 55 49 59 67 73 61 64 66 64 73 76 64 76 73 2e 4f 70 65 6e 20 45 6e 76 69 72 6f 6e 28 22 54 45 22 20 2b 20 22 4d 50 22 29 20 26 20 22 5c 64 73 66 66 66 66 64 2e 76 62 73 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_D_2147693758_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.D"
        threat_id = "2147693758"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Furyy.Nccyvpngvba" ascii //weight: 1
        $x_1_2 = "NQBQO.Fgernz" ascii //weight: 1
        $x_1_3 = "Fpevcgvat.SvyrFlfgrzBowrpg" ascii //weight: 1
        $x_1_4 = "ZFKZY2.KZYUGGC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_C_2147696345_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.C"
        threat_id = "2147696345"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EIMQhNDaX3g = smUW4wjlfZ(Chr(77) & Chr(105) & \"c\" & Chr(114) & \"o\" & Chr(115) & Chr(111) & \"f\" & \"t\" & \".\" & \"X\" & \"M\" & Chr(76) & Chr(72) & Chr(84) & \"T\" & \"P\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_E_2147696346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.E"
        threat_id = "2147696346"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 69 69 69 4f 49 48 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 74 73 61 70 2f 2f 3a 70 22 29 20 2b 20 6f 6f 75 69 6a 69 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 ?? ?? ?? ?? ?? ?? ?? ?? 3d 69 3f 70 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_F_2147697091_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.F"
        threat_id = "2147697091"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " = Chr(104) & Chr(116) & \"=\" & Chr(116) & Chr(112) & Chr(58) & \"/\" & \"</\" & " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_J_2147707562_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.J"
        threat_id = "2147707562"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If (13.5 + 641 + 13.5 - 641 + 13.5 + 641 + 13.5 - 641 - 1) = (13.5 + 645 + 13.5 - 645 + 13.5 + 645 + 13.5 - 645 - 1) Then" ascii //weight: 1
        $x_1_2 = "= 1 To (2500 + 417 + 2500 - 417 + 2500 + 417 + 2500 - 417 - 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_J_2147707562_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.J"
        threat_id = "2147707562"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 72 65 61 64 79 53 74 61 74 65 20 3d 20 28 [0-3] 20 2b 20 [0-3] 20 2b 20 [0-3] 20 2d 20 [0-3] 29 20 41 6e 64 20 [0-16] 2e 53 74 61 74 75 73 20 3d 20 28 [0-3] 20 2b 20 [0-3] 20 2b 20 [0-3] 20 2d 20 [0-3] 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-20] 28 43 68 72 24 28 [0-3] 29 20 2b 20 43 68 72 24 28 [0-3] 29 20 2b 20 43 68 72 24 28 [0-3] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {57 69 74 68 20 [0-20] 2e 63 52 65 61 74 65 74 65 58 74 66 49 6c 65 28}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-20] 28 43 68 72 24 28 [0-3] 29 20 2b 20 43 68 72 24 28 [0-3] 29 20 2b 20 43 68 72 24 28 [0-3] 29 20 2b 20 43 68 72 24 28 [0-3] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {43 68 72 24 28 [0-3] 29 20 2b 20 43 68 72 24 28 [0-3] 29 20 2b 20 43 68 72 24 28 [0-3] 29 2c 20 22 [0-20] 22 29 29 2e 52 75 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_K_2147708115_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.K"
        threat_id = "2147708115"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KoGz3OCng0I(NsUCbR - 1) = EL405HrLB0vh(NsUCbR - 1) Xor ((127.5 + 8 + 127.5 - 8) - EL405HrLB0vh(CltjhR1JiNlk - NsUCbR))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_L_2147708129_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.L"
        threat_id = "2147708129"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Chr(Asc(IXMLDOMElement7) - 23)" ascii //weight: 1
        $x_1_2 = "= Chr(Asc(IXMLDOMElement7) + 46)" ascii //weight: 1
        $x_1_3 = "Public Const IXMLDOMElement7 = \"E" ascii //weight: 1
        $x_1_4 = "Public Const IXMLDOMElement8 = \"m" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_M_2147708138_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.M"
        threat_id = "2147708138"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 20 44 49 4b 5f [0-16] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 22 20 2b 20 22 2e 58 4d 4c 48 54 54 50 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {53 65 74 20 44 49 4b 5f [0-16] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 64 6f 64 62 2e 53 74 72 65 61 6d 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {53 65 74 20 44 49 4b 5f [0-16] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 65 74 20 44 49 4b 5f [0-16] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 22 20 2b 20 43 68 72 28 44 49 4b 5f [0-16] 29 20 2b 20 22 53 68 65 6c 6c 22 29 2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 22 50 72 6f 63 22}  //weight: 1, accuracy: Low
        $x_1_5 = {44 49 4b 5f [0-16] 2e 4f 70 65 6e 20 43 68 72 28 44 49 4b 5f [0-16] 29 20 2b 20 43 68 72 28 44 49 4b 5f [0-16] 29 20 2b}  //weight: 1, accuracy: Low
        $x_1_6 = {44 49 4b 5f [0-16] 20 3d 20 44 49 4b 5f [0-16] 20 2b 20 43 68 72 28 44 49 4b 5f [0-16] 29 20 2b 20 22 [0-16] 22 20 2b 20 43 68 72 28 44 49 4b 5f [0-16] 29 20 2b 20 43 68 72 28 44 49 4b 5f [0-16] 29 20 2b 20 22 [0-16] 22 20 2b 20 43 68 72 28 44 49 4b 5f [0-16] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_N_2147708206_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.N"
        threat_id = "2147708206"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 30 20 54 6f 20 28 [0-5] 20 2b 20 [0-5] 20 2b 20 [0-5] 20 2d 20 [0-5] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {20 58 6f 72 20 28 [0-5] 20 2b 20 [0-5] 20 2b 20 [0-5] 20 2d 20 [0-5] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {49 66 20 45 72 72 2e 4e 75 6d 62 65 72 20 3d 20 28 [0-5] 20 2b 20 [0-5] 20 2b 20 [0-5] 20 2d 20 [0-5] 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 30 20 54 6f 20 28 [0-5] 20 2b 20 [0-5] 20 2b 20 [0-5] 20 2d 20 [0-5] 20 2b 20 [0-5] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {45 72 72 2e 4e 75 6d 62 65 72 20 3d 20 28 [0-5] 20 2b 20 [0-5] 20 2b 20 [0-5] 20 2d 20 [0-5] 20 2b 20 [0-5] 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 53 74 72 43 6f 6e 76 28 [0-16] 28 29 2c 20 28 [0-5] 20 2b 20 [0-5] 20 2b 20 [0-5] 20 2d 20 [0-5] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Adnel_O_2147708233_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.O"
        threat_id = "2147708233"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 65 74 56 65 63 74 6f 72 31 20 3d 20 73 65 74 56 65 63 74 6f 72 31 20 26 20 43 68 72 28 [0-16] 28 69 29 20 2d 20 [0-4] 20 2a 20 [0-32] 20 2d 20 [0-4] 20 2d 20 [0-4] 20 2d 20 [0-4] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {68 6f 6d 65 62 72 65 77 20 3d 20 41 72 72 61 79 28 ?? ?? ?? ?? 2c 20 ?? ?? ?? ?? 2c 20 ?? ?? ?? ?? 2c 20 ?? ?? ?? ?? 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 4f 70 65 6e 20 55 43 61 73 65 28 [0-16] 29 2c 20 [0-16] 28 68 6f 6d 65 62 72 65 77 2c 20 [0-4] 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_P_2147708482_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.P"
        threat_id = "2147708482"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= StrReverse(\"TEG\")" ascii //weight: 1
        $x_1_2 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 [0-16] 2c 20 [0-16] 2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-16] 2c 20 22 68 74 74 70 3a 2f 2f [0-48] 2f [0-48] 2e 65 78 65 22 2c 20 46 61 6c 73 65 29}  //weight: 1, accuracy: Low
        $x_1_3 = "+ StrReverse(\"mnorivnEd\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_Q_2147709163_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.Q"
        threat_id = "2147709163"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 6f 64 20 28 28 (30|2d|39) (30|2d|39) [0-3] 20 (2b|2d) 20 (30|2d|39) (30|2d|39) [0-3] 20 (2b|2d) 20 00 01 20 (2b|2d) 20 03 04 20 (2b|2d) 20 00 01 20 (2b|2d) 20 03 04}  //weight: 1, accuracy: Low
        $x_1_2 = {46 6f 72 20 [0-16] 20 3d 20 28 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2d 20 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2d 20 [0-4] 29 20 54 6f 20 28 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2d 20 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2d 20 [0-4] 20 2d 20 [0-4] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {29 20 3d 20 28 (30|2d|39) (30|2d|39) 2e [0-3] 20 (2b|2d) 20 (30|2d|39) (30|2d|39) [0-3] 20 (2b|2d) 20 00 2e 01 20 (2b|2d) 20 03 04 20 (2b|2d) 20 00 2e 01 20 (2b|2d) 20 03 04 [0-24] 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_R_2147709606_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.R"
        threat_id = "2147709606"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 53 74 72 52 65 76 65 72 73 65 28 [0-15] 28 22 73 65 6c 6f 2e 43 61 6d 72 65 53 74 44 4f 6a 41 6f 62 22 29 29 20 26 20 [0-10] 20 26 20 76 62 4e 65 77 4c 69 6e 65}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 [0-15] 28 22 3d 20 4c 20 55 52 6c 65 46 69 74 72 73 22 29 29 20 26 20 43 68 72 28 33 34 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 53 74 72 52 65 76 65 72 73 65 28 [0-15] 28 22 74 28 65 63 62 6a 65 4f 61 74 72 65 20 43 20 3d 61 6d 72 65 53 74 44 4f 6a 41 6f 62 74 20 53 65 20 22 29 29 20 26 20 43 68 72 28 33 34 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_S_2147710037_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.S"
        threat_id = "2147710037"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 69 64 24 28 [0-31] 2c 20 [0-31] 29 20 3d 20 43 68 72 24 28 [0-31] 28 4d 69 64 24 28 [0-31] 2c 20 [0-31] 2c 20 31 29 29 20 2d 20 [0-31] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {53 65 6c 65 63 74 20 43 61 73 65 20 [0-31] 28 55 43 61 73 65 24 28 4d 69 64 24 28 [0-31] 2c 20 [0-31] 2c 20 31 29 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {43 61 73 65 20 [0-31] 20 2b 20 [0-31] 20 54 6f 20 [0-31] 20 2b 20}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 [0-31] 2c 20 [0-31] 28 [0-31] 29 2c 20 56 62 47 65 74 29}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 34 35 20 2a 20 32 0d 0a 46 6f 72 20 [0-20] 20 3d 20 31 20 54 6f 20 4c 65 6e 28 [0-20] 29 0d 0a 53 65 6c 65 63 74 20 43 61 73 65}  //weight: 1, accuracy: Low
        $x_1_6 = {22 29 29 20 26 20 [0-20] 20 26 20 [0-20] 28 22}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 20 31 20 54 6f 20 4c 65 6e 28 [0-20] 29 0d 0a [0-20] 20 3d 20 4d 69 64 28 [0-20] 2c 20 [0-20] 2c 20 31 29 20 26 20 [0-20] 0d 0a 4e 65 78 74}  //weight: 1, accuracy: Low
        $n_100_8 = "ThisWorkbook.Unprotect Password:=der" ascii //weight: -100
        $n_100_9 = "www.ze-max.de" ascii //weight: -100
        $n_100_10 = "Attribute VB_Name = \"clsAdditionalBillingsColumns\"" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Adnel_A_2147711814_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.A"
        threat_id = "2147711814"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Result__1.Open constans_Result(" ascii //weight: 1
        $x_1_2 = "= CreateObject(constans_Result(3))" ascii //weight: 1
        $x_1_3 = "CallByName Freddy_Result," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Adnel_T_2147716551_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adnel.T"
        threat_id = "2147716551"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ", StrReverse(\"\"\" ridkm c/ dmc\") &" ascii //weight: 1
        $x_1_2 = "& Right(ActiveDocument.Name, 1) & \"ript.Sh\" & StrReverse(\"lle\"))" ascii //weight: 1
        $x_1_3 = "& StrReverse(\"tixe & \"\"\"), 0, True" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

