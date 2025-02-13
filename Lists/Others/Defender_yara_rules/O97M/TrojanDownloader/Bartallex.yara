rule TrojanDownloader_O97M_Bartallex_A_2147691746_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.A"
        threat_id = "2147691746"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"p\" + \"://146.185.213." ascii //weight: 1
        $x_1_2 = "/install\" + \".\" + Chr(Asc(\"e\"))" ascii //weight: 1
        $x_1_3 = "Temp\\\" + BART" ascii //weight: 1
        $x_1_4 = "Chr(Asc(\"e\")) + \"x\" + \"e\"" ascii //weight: 1
        $x_1_5 = "Kill MY_FILDIR" ascii //weight: 1
        $x_1_6 = "BART + Chr(34)" ascii //weight: 1
        $x_1_7 = "XPFILEDIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_A_2147691746_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.A"
        threat_id = "2147691746"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VBTXP = \"adobeacd-updatexp" ascii //weight: 1
        $x_1_2 = "Kill MY_FILEDIR" ascii //weight: 1
        $x_1_3 = "XPBARTFILEDIR" ascii //weight: 1
        $x_1_4 = "Print #FileNu," ascii //weight: 1
        $x_1_5 = "retVal = Shell(XPBARTFILEDIR, 0)" ascii //weight: 1
        $x_1_6 = "retVal = Shell(MY_FILEDIR, 0)" ascii //weight: 1
        $x_1_7 = "\"c:\\Windows\\Temp\\\" + BART" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_B_2147691747_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.B"
        threat_id = "2147691747"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kill my_fildir" ascii //weight: 1
        $x_1_2 = "Temp\\\" + BART + Chr(34)" ascii //weight: 1
        $x_1_3 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_2147691748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex"
        threat_id = "2147691748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 37 72 76 6d 6e 62 [0-40] 2f 61 66 2f 37 72 76 6d 6e 62 [0-40] 2f 61 66 2f 37 72 76 6d 6e 62 [0-40] 2f 37 72 76 6d 6e 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_2147691748_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex"
        threat_id = "2147691748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uggc://nyhpneqban.pbz/wf/ova.rkr" ascii //weight: 1
        $x_1_2 = "\\qfUUU.rkr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_2147691748_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex"
        threat_id = "2147691748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oPlKtRebGf = oGdyeJdhsdd.TextBox4 + iuyhgdfsdf + hyyuejkjs + yyeidsadf + yeuijjffsa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_2147691748_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex"
        threat_id = "2147691748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UG93ZXJTaGVsbCAtRXhlY3V0aW9uUG9saWN5IGJ5cGFzcyAtbm9wcm9maWxlIC13aW5kb3dzdHlsZSBoaWRkZW4g" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_2147691748_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex"
        threat_id = "2147691748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "For i = LBound(ByValvDefault) To UBound(ByValvDefault)" ascii //weight: 2
        $x_2_2 = "ObjIndex = ObjIndex & Chr(" ascii //weight: 2
        $x_1_3 = "WScript.Shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_2147691748_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex"
        threat_id = "2147691748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PHT = \"\" & \"ht\" & \"t\" & \"p://\" & \"\"" ascii //weight: 1
        $x_1_2 = "SPIC = \"\" & \"s\" & \"av\" & \"epi\" + \"c.su\" + \"/\"" ascii //weight: 1
        $x_1_3 = "LNSS = \"lns.txt\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_2147691748_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex"
        threat_id = "2147691748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "objProcess.Create \"power\" & \"shell\" & \".exe -ExecutionPolicy Bypass -WindowStyle Hidden -noprofile -noexit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_2147691748_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex"
        threat_id = "2147691748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell SfO0a3ua0qeB, 0" ascii //weight: 1
        $x_1_2 = "SfO0a3ua0qeB = SfO0a3ua0qeB & \"239,240,202,226,237,202,20,20,118,61,89,64,8,123,65,57,62" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_2147691748_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex"
        threat_id = "2147691748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fspresentationproducts.com/" ascii //weight: 1
        $x_1_2 = "\"chameleonpaintworks.com/w\" + \"p-con\" + \"tent/pl\" + \"ugins/w\" + \"p-jqu\" + \"ery-lig\" + \"htbox/sty\" + \"les/imag\" + \"es/he_IL/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_2147691748_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex"
        threat_id = "2147691748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"www.in\" + \"caltaminte.in\" + \"fo/w\" + \"p-content/upl\" + \"oads/201\" + \"5/0\" + \"6/\"" ascii //weight: 1
        $x_1_2 = "\"www.iscmo\" + \"ntegranaro.it/w\" + \"p-content/upl\" + \"oads/201\" + \"5/0\" + \"6/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_2147691748_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex"
        threat_id = "2147691748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "For i = LBound(ByValvDefault) To UBound(ByValvDefault)" ascii //weight: 1
        $x_1_2 = "ProcessKillOrder = ProcessKillOrder & Chr(ByValvDefault(i) - 33 * NothingOrNodeName - 5544 - 778 - 35)" ascii //weight: 1
        $x_1_3 = "WSAGetSelectEvent2 = ProcessKillOrder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_2147691748_11
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex"
        threat_id = "2147691748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr$(47) & Chr$(99) + Chr$(97) & Chr$(112) & Chr$(116) + Chr$(97) & Chr$(105)" ascii //weight: 1
        $x_1_2 = "Chr$(110) & Chr$(47) + Chr$(98) & Chr$(108) + Chr$(97)" ascii //weight: 1
        $x_1_3 = "Chr$(99) & Chr$(107) & Chr$(46) & Chr$(112) & Chr$(104) + Chr$(112)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_2147691748_12
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex"
        threat_id = "2147691748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 53 75 62 20 [0-15] 28 29 03 00 [0-31] 20 3d 20 53 70 6c 69 74 28 22 04 00 7c 04 00 7c 04 00 7c 04 00 7c 04 00 7c 04 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 6f 72 20 [0-15] 20 3d 20 4c 42 6f 75 6e 64 28 [0-15] 29 20 54 6f 20 55 42 6f 75 6e 64 28 01 29 [0-31] 20 3d 20 [0-31] 20 26 20 43 68 72 28 43 49 6e 74 28 01 28 [0-31] 29 29 20 2d 20 04 00 29}  //weight: 1, accuracy: Low
        $x_1_3 = {5f 31 2e 4f 70 65 6e 20 (68 75 62 61 62 75|4b 72 69 70 6f) 28 03 00 29 2c 20 [0-31] 5f 31 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_4 = {41 73 20 42 6f 6f 6c 65 61 6e [0-32] 5f 01 00 20 3d 20 53 70 6c 69 74 28 22 04 00 2c 04 00 2c 04 00 2c 04 00 2c 04 00 2c 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_2147691748_13
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex"
        threat_id = "2147691748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"mistatuajes.com.es/w\" + \"p-co\" + \"ntent/plu\" + \"gins/wor\" + \"dp\" + \"ress-seo/v\" + \"endor/yo\" + \"ast/lic\" + \"ense-man\" + \"ager/sa\" + \"mples/\"" ascii //weight: 1
        $x_1_2 = "\"misfrutales.com.es/w\" + \"p-co\" + \"nten\" + \"t/p\" + \"lugin\" + \"s/nin\" + \"ja-pop\" + \"ups/adm\" + \"in/cs\" + \"s/jqu\" + \"ery-ui-ari\" + \"sto/ima\" + \"ges/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_C_2147691901_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.C"
        threat_id = "2147691901"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "in.com/raw.php?i=" ascii //weight: 1
        $x_1_2 = "/us/file\" + SXE" ascii //weight: 1
        $x_1_3 = "CreateObject(\"MSXML2.ServerXMLHTTP\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_C_2147691901_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.C"
        threat_id = "2147691901"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Open MY_FILDIR For Output As" ascii //weight: 1
        $x_1_2 = "Module1." ascii //weight: 1
        $x_1_3 = "cintosh; Intel Mac OS X" ascii //weight: 1
        $x_1_4 = "Chr(34" ascii //weight: 1
        $x_1_5 = "Chr(111" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_C_2147691901_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.C"
        threat_id = "2147691901"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"pi\" + \"ng 1.1.2.2 -n\" & \" 2\"" ascii //weight: 1
        $x_1_2 = "\"del \" + Chr(34) + \"c\" & \":\\\" & \"W\" & \"ind\" & \"ows\\T\" & \"em\" & \"p\\\" + Chr(34) + \"%tar1%\" + \"\" & \"\"" ascii //weight: 1
        $x_1_3 = "(\"winmgmts:{impersonationLevel=impersonate}!\\\\\" & \".\\root\\cimv2\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_D_2147692684_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.D"
        threat_id = "2147692684"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BART + Chr(33 + 1)" ascii //weight: 1
        $x_1_2 = "Kill MY_FILENDIR" ascii //weight: 1
        $x_1_3 = "Chr(Asc(\"e\")) + Chr(Asc(\"x\")) + Chr(Asc(\"e\"))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_E_2147692708_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.E"
        threat_id = "2147692708"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BART + Chr(33 + 1)" ascii //weight: 1
        $x_1_2 = "Kill MY_FILENDIR" ascii //weight: 1
        $x_1_3 = "Chr(34) + \"4.e\" + Chr(34) + \"+\" + Chr(34) + \"xe\" + Chr(34)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_E_2147692708_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.E"
        threat_id = "2147692708"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Module1.Goabc(MOTOROLA) + KIPARIS" ascii //weight: 1
        $x_1_2 = "= Module1.Kalyma(BERILKA) + ANDOKANA" ascii //weight: 1
        $x_2_3 = "ATTH = hhr(Ndjs) + Chr(Ndjs + 12) + Chr(Ndjs + 12) + Chr(" ascii //weight: 2
        $x_2_4 = "BBTH = PH2 + MADRID + \".bat\"" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Bartallex_E_2147692708_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.E"
        threat_id = "2147692708"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Redistribute = Redistribute & Chr(Z(n) - 9 * oldLen" ascii //weight: 1
        $x_1_2 = " kmaDecodeURL = Replace(kmaDecodeURL, ESCString, Chr(ESCValue))" ascii //weight: 1
        $x_1_3 = "Sub autoopen()" ascii //weight: 1
        $x_1_4 = "WorkLongue = Array(5" ascii //weight: 1
        $x_1_5 = "DecodeGMTDate = DecodeGMTDate + CDate(WorkString) + 4 / 24" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_F_2147693046_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.F"
        threat_id = "2147693046"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set colOperatingSystems = objWMIService.ExecQuery(\"Select * from W" ascii //weight: 1
        $x_1_2 = "Print #FileNumber, \"objADOStream.Type = 1" ascii //weight: 1
        $x_1_3 = "Print #FileNs, \"c\" & \"sc\" & \"ri\" & \"pt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_F_2147693046_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.F"
        threat_id = "2147693046"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 65 61 72 63 68 65 6e 67 69 6e 65 73 65 72 76 61 6e 74 2e 63 6f 6d 2f 61 66 66 69 6c 69 61 74 65 73 2f 66 6f 6e 74 73 2f [0-16] 2e 74 78 74}  //weight: 10, accuracy: Low
        $x_10_2 = {73 63 6f 74 74 73 70 6f 74 73 6f 6e 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 63 65 72 74 69 66 69 63 61 74 65 73 2f [0-16] 2e 74 78 74}  //weight: 10, accuracy: Low
        $x_1_3 = "Chr(Asc(" ascii //weight: 1
        $x_1_4 = "Module1." ascii //weight: 1
        $x_1_5 = "cintosh; Intel Mac OS X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Bartallex_I_2147697235_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.I"
        threat_id = "2147697235"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Lib \"urlmon\" Alias \"URLDownloadToFileA\" (ByVal" ascii //weight: 1
        $x_1_2 = "Lib \"kernel32\" Alias \"GetTempPathA" ascii //weight: 1
        $x_1_3 = "HTTPfile = \"http://" ascii //weight: 1
        $x_1_4 = {4c 6f 63 61 6c 46 69 6c 65 20 3d 20 73 50 61 74 68 20 26 20 22 [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = "Shell LocalFile, vbHide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_J_2147697242_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.J"
        threat_id = "2147697242"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sleep Text, Environ$(\"tmp\") &" ascii //weight: 1
        $x_1_2 = "CreateObject(\"WScript.Shell\").Run joseph" ascii //weight: 1
        $x_1_3 = "Sub Sleep(ByVal james, joseph As String)" ascii //weight: 1
        $x_1_4 = "Text = \"ht\" & _" ascii //weight: 1
        $x_1_5 = "= \"\\\" & text1 & \".exe\"" ascii //weight: 1
        $x_1_6 = "ricardotamayo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_K_2147705957_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.K"
        threat_id = "2147705957"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 6f 6e 73 74 20 4f 30 30 31 31 31 31 31 31 30 31 30 30 30 31 30 30 30 31 30 30 31 30 30 30 30 30 31 30 30 30 20 3d 20 22 62 2d 56 44 3d 4b 49 ef bf bd 79 60 2d 4f 2e 2a 32 34 70 34 4b 22 0d 0a 50 75 62 6c 69 63 20 4f 30 31 31 31 30 31 30 31 30 30 31 31 31 31 30 30 31 30 30 31 31 31 31 31 31 31 31 30 31 31 20 41 73 20 53 74 72 69 6e 67 0d 0a 23 49 66 20 57 69 6e 36 34 20 54 68 65 6e 0d 0a 50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 5f 0d 0a 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 20 4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 28 42 79 56 61 6c 20 4f 30 30 31 31 31 31 31 31 31 30 31 31 31 30 30 31 30 31 30 30 31 30 31 30 31 31 31 30 31 30 20 41 73 20 4c 6f 6e 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_L_2147705992_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.L"
        threat_id = "2147705992"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 43 75 73 74 6f 6d 69 7a 61 62 6c 65 20 3d 20 54 72 75 65 0d 0a 50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 5f 0d 0a 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 20 5f 0d 0a 4c 69 62 20 22 75 72 6c 6d 6f 6e 2e 64 6c 6c 22 20 28 42 79 56 61 6c 20 5f}  //weight: 1, accuracy: High
        $x_1_2 = {50 72 69 76 61 74 65 20 5f 0d 0a 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 53 68 65 6c 6c 45 78 65 63 75 74 65 57 20 5f 0d 0a 4c 69 62 20 22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 28 42 79 56 61 6c 20 5f}  //weight: 1, accuracy: High
        $x_1_3 = "= \"ht||||tp:/" ascii //weight: 1
        $x_1_4 = "(\"||t|||||m||||||p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_M_2147706072_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.M"
        threat_id = "2147706072"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 5f 0d 0a 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 20 4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 28 20 5f 0d 0a 42 79 56 61 6c}  //weight: 1, accuracy: High
        $x_1_2 = {3d 20 30 20 54 68 65 6e 20 [0-20] 20 3d 20 5f 0d 0a 54 72 75 65 0d 0a 44 69 6d 20 5f 0d 0a [0-32] 3a 20 [0-32] 20 3d 20 53 68 65 6c 6c 28 [0-15] 2c 20 5f 0d 0a 31 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 30 0d 0a 46 6f 72 20 [0-20] 20 3d 20 5f 0d 0a 31 20 54 6f 20 4c 65 6e 28 [0-15] 29 0d 0a [0-32] 20 3d 20 5f 0d 0a 4d 69 64 28 20 5f 0d 0a [0-15] 2c 20 [0-20] 2c 20 5f 0d 0a 31 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3e 20 28 26 48 ?? ?? ?? ?? 20 2d 20 5f 0d 0a ?? ?? ?? ?? ?? 29 20 54 68 65 6e 20 [0-15] 20 3d 20 5f 0d 0a [0-15] 20 2d 20 28 26 48 ?? ?? ?? ?? 20 2d 20 ?? ?? ?? ?? ?? 29 0d 0a [0-32] 20 3d 20 5f 0d 0a 43 68 72 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_N_2147706208_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.N"
        threat_id = "2147706208"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 6f 72 20 4b 53 52 44 79 52 6a 4f 72 61 45 64 6b 7a 6d 6b 20 3d 20 39 39 38 35 20 2d 20 26 48 32 36 45 31 20 54 6f 20 5f 0d 0a 31 33 37 38 31 20 2d 20 5f 0d 0a 26 48 33 35 35 37 0d 0a 49 66 20 5f 0d 0a 49 6e 53 74 72 28 20 5f 0d 0a 70 6d 4b 56 6c 73 64 62 44 42 65 42 42 45 74 7a 76 2c 20 43 68 72 28 4b 53 52 44 79 52 6a 4f 72 61 45 64 6b 7a 6d 6b 29 29 20 3d 20 5f 0d 0a 30 20 54 68 65 6e 20 48 71 6a 75 58 46 55 4a 66 7a 78 46 51 67 78 69 4a 66 69 74 70 52 74 49 51 6e 78 50 46 46 48 20 3d 20 48 71 6a 75 58 46 55 4a 66 7a 78 46 51 67 78 69 4a 66 69 74 70 52 74 49 51 6e 78 50 46 46 48 20 26 20 43 68 72 28 20 5f 0d 0a 4b 53 52 44 79 52 6a 4f 72 61 45 64 6b 7a 6d 6b 29 0d 0a 4e 65 78 74 20 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_O_2147707002_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.O"
        threat_id = "2147707002"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+ \"://\"" ascii //weight: 1
        $x_1_2 = "+ \".b\" & \"at\"" ascii //weight: 1
        $x_1_3 = "+ \"x\" & \"t\"" ascii //weight: 1
        $x_1_4 = "= (a.responsetext)" ascii //weight: 1
        $x_1_5 = "= CStr(Int((a / 2 * Rnd) + a))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_P_2147707187_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.P"
        threat_id = "2147707187"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-5] 28 43 68 72 28 [0-3] 29 20 2b}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-5] 28 43 68 72 28 [0-3] 29 20 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 4f 70 65 6e 20 [0-5] 28 43 68 72 28 [0-3] 29 20 2b}  //weight: 1, accuracy: Low
        $x_1_4 = ".Status = 200 Then" ascii //weight: 1
        $x_1_5 = ".cReateteXtfIle(" ascii //weight: 1
        $x_1_6 = ")).Run \"\"\"\" &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_Q_2147707197_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.Q"
        threat_id = "2147707197"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "For i = 1 To Len(sData) Step 2" ascii //weight: 1
        $x_1_2 = "Chr$(Val(\"&H\" & Mid$(sData, i, 2)))" ascii //weight: 1
        $x_1_3 = {53 68 65 6c 6c 28 [0-16] 28 22 36 33 36 44 36 34 32 30 32 46 36 33 32 30 37 33 37 34 36 31 37 32 37 34 32 30 32 35 35 34 34 44 35 30 32 35 32 46 36 31 37 38 36 31 36 35 32 45 36 35 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {45 6e 76 69 72 6f 6e 28 [0-32] 29 20 26 20 [0-16] 28 22 32 46 36 31 37 38 36 31 36 35 32 45 36 35 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = "= \"tp:/\"" ascii //weight: 1
        $x_1_6 = "= \"etimg.p\"" ascii //weight: 1
        $x_1_7 = {2b 20 22 74 22 20 2b [0-16] 2b 20 22 2f 22 20 2b [0-16] 2b 20 22 2f 69 6d 61 67 65 73 2f 67 22 20 2b [0-16] 2b 20 22 68 70 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_R_2147707502_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.R"
        threat_id = "2147707502"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".resPonsebodY, vbUnicode)," ascii //weight: 1
        $x_1_2 = {2e 72 65 61 64 79 53 74 61 74 65 20 3d 20 34 20 41 6e 64 20 [0-16] 2e 53 74 61 74 75 73 20 3d 20 32 30 30 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 43 68 72 24 28 56 61 6c 28 43 68 72 24 28 [0-3] 29 20 26 20 43 68 72 24 28 [0-3] 29 20 26 20 4d 69 64 24 28 [0-16] 2c 20 [0-16] 2c 20 32 29 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = ".cReateteXtfIle(" ascii //weight: 1
        $x_1_5 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-16] 28 [0-16] 28 22}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-16] 28 [0-16] 28 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_S_2147707561_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.S"
        threat_id = "2147707561"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lib \"urlmon\" Alias \"URLDownloadToFileA\"" ascii //weight: 1
        $x_1_2 = "= 1 To Len(\"fyf/" ascii //weight: 1
        $x_1_3 = "= Mid(\"fyf/" ascii //weight: 1
        $x_1_4 = "ExpandEnvironmentStrings(\"%TEMP%\") & StrReverse(" ascii //weight: 1
        $x_1_5 = "& Chr(Asc(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_T_2147708234_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.T"
        threat_id = "2147708234"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " = \"Scripting.F\" + \"ileSy\" + \"s\"" ascii //weight: 1
        $x_1_2 = " = \"e\" + \"c\" + \"t\"" ascii //weight: 1
        $x_1_3 = " = \"tem\" + \"Ob\" + \"j\"" ascii //weight: 1
        $x_1_4 = " = \"Wi\" + \"n\"" ascii //weight: 1
        $x_1_5 = " = \"Http\" + \".\"" ascii //weight: 1
        $x_1_6 = {2e 53 74 61 74 75 73 20 3d 20 [0-3] 20 2b 20 [0-3] 20 2b 20 [0-3] 20 2b 20 [0-3] 20 54 68 65 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_U_2147708483_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.U"
        threat_id = "2147708483"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 65 70 6c 61 63 65 28 22 [0-16] 2e 74 78 74 22 2c 20 22 74 22 2c 20 22 65 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 4d 69 64 28 22 [0-16] 53 63 22 20 2b 20 22 72 69 70 74 22 20 2b 20 22 2e 53 68 22 20 2b 20 22 65 6c 6c [0-8] 22 20 2b 20 22 [0-16] 22 2c 20 37 2c 20 31 33 29 29 2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 4d 69 64 28}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 4f 70 65 6e 20 55 43 61 73 65 28 4d 69 64 28 22 [0-16] 22 2c 20 35 2c 20 32 29 29 20 2b [0-16] 2c 20 41 64 64 46 69 65 6c 64 54 6f 46 69 65 6c 64 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_V_2147708912_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.V"
        threat_id = "2147708912"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 65 70 6c 61 63 65 28 22 [0-16] 2e 74 78 74 22 2c 20 22 74 22 2c 20 22 65 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 41 72 72 61 79 28 05 00 2c 20 05 00 2c 20 05 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 4f 70 65 6e 20 56 6f 4c 28 02 00 29 2c 20 [0-20] 28 [0-16] 2c 20 03 00 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_4 = {20 26 20 43 68 72 28 [0-16] 28 [0-16] 29 20 2d 20 04 00 20 2d 20 [0-16] 20 2d 20 04 00 20 2d 20 04 00 20 2a 20 [0-16] 20 2d 20 04 00 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_W_2147709167_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.W"
        threat_id = "2147709167"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 41 72 72 61 79 28 05 00 2c 20 05 00 2c 20 05 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Split(UserForm1.Label1.Caption, \"/\")" ascii //weight: 1
        $x_1_3 = {52 65 70 6c 61 63 65 28 10 00 28 02 00 29 2c 20 22 74 22 2c 20 22 65 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 4f 70 65 6e 20 [0-16] 28 02 00 29 2c 20 [0-20] 5f 01 00 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_X_2147709168_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.X"
        threat_id = "2147709168"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 41 72 72 61 79 28 05 00 2c 20 05 00 2c 20 05 00}  //weight: 1, accuracy: Low
        $x_1_2 = {53 65 74 20 [0-20] 5f 01 00 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 10 00 28 02 00 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {53 65 74 20 [0-20] 5f 01 00 20 3d 20 [0-16] 2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 10 00 28 02 00 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 4f 70 65 6e 20 10 00 28 02 00 29 2c 20 [0-20] 5f 01 00 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_5 = {52 65 70 6c 61 63 65 28 10 00 28 02 00 29 2c 20 22 ?? 22 2c 20 22 ?? 22 29}  //weight: 1, accuracy: Low
        $x_1_6 = {53 70 6c 69 74 28 55 73 65 72 46 6f 72 6d 01 00 2e 4c 61 62 65 6c 01 00 2e 43 61 70 74 69 6f 6e 2c 20 22 ?? 22 29}  //weight: 1, accuracy: Low
        $x_1_7 = {43 61 6c 6c 42 79 4e 61 6d 65 28 [0-20] 5f 01 00 2c 20 10 00 28 02 00 29 2c 20 56 62 47 65 74 29}  //weight: 1, accuracy: Low
        $x_1_8 = {43 61 6c 6c 42 79 4e 61 6d 65 20 [0-20] 5f 01 00 2c 20 10 00 28 02 00 29 2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-20] 5f 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_Y_2147709204_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.Y"
        threat_id = "2147709204"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gorenebeda_4 = gorenebeda_3(onopridet(6))" ascii //weight: 1
        $x_1_2 = "gorenebeda_5 = gorenebeda_4 + Replace(onopridet(12), \"t\", \"e\")" ascii //weight: 1
        $x_1_3 = "onopridet = Split(UserForm1.Label1.Caption, \"/\")" ascii //weight: 1
        $x_1_4 = "Set gorenebeda_6 = CreateObject(onopridet(2))" ascii //weight: 1
        $x_1_5 = "CreateObject(onopridet(3))" ascii //weight: 1
        $x_1_6 = ".Environment(onopridet(4))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_Z_2147711421_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.Z"
        threat_id = "2147711421"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 66 20 35 05 00 20 3d 20 06 00 20 2b 20 31 20 54 68 65 6e 20 45 6e 64 0d 0a 49 66 20 04 00 20 3c 20 02 00 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {49 66 20 4c 65 6e 28 22 0f 00 22 29 20 3d 20 4c 65 6e 28 22 0f 00 22 29 20 54 68 65 6e 0d 0a 0f 00 4d 73 67 42 6f 78 20 28 22 45 72 72 6f 72 20 21 21 21 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {53 68 65 6c 6c 20 0f 00 2e 0f 00 20 2b 20 0f 00 2e 0f 00 20 2b 20 0f 00 2e 0f 00 2c 20 76 62 48 69 64 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_AA_2147712029_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.AA"
        threat_id = "2147712029"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 41 72 72 61 79 28 [0-33] 2c 20 [0-33] 2c 20}  //weight: 1, accuracy: Low
        $x_1_2 = "RunStuff(sNull, sProc," ascii //weight: 1
        $x_1_3 = "sProc = Environ(\"windir\") & \"\\\\SysWOW64\\\\rundll32.exe" ascii //weight: 1
        $x_1_4 = "rwxpage = AllocStuff(pInfo.hProcess, 0, UBound(myArray), &H1000, &H40)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_AA_2147712029_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.AA"
        threat_id = "2147712029"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Alias \"CreateRemoteThread\"" ascii //weight: 1
        $x_1_2 = "Alias \"VirtualAllocEx\"" ascii //weight: 1
        $x_1_3 = "Alias \"WriteProcessMemory\"" ascii //weight: 1
        $x_1_4 = "Alias \"CreateProcessA\"" ascii //weight: 1
        $x_1_5 = "& \"\\\\System32\\\\rundll32.exe\"" ascii //weight: 1
        $x_1_6 = ".hProcess, 0, " ascii //weight: 1
        $x_1_7 = {20 3d 20 41 72 72 61 79 28 [0-33] 2c 20 [0-33] 2c 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_AC_2147716756_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.AC"
        threat_id = "2147716756"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "If getString(\"v%b%o%x%s%e%r%v%i%c%e%.%e%x%e%|%v%b%o%x%t%r%a%y%.%e%x%e%|%v%m%t%o%o%l%s%d%.%e%x%e%|%v%m%w%a%r%e%t%r%a%y%.%e%x%e%|" ascii //weight: 1
        $x_1_2 = "getString(\"p%o%w%e%r%s%h%e%l%l%.%e%x%e% %(%N%e%w%-%O%b%j%e%c%t% %S%y%s%t%e%m%.%N%e%t%.%W%e%b%C%l%i%e%n%t%)%.%D%o%w%n%l%o%a%d%F%i%l%e%\")" ascii //weight: 1
        $x_1_3 = {67 65 74 53 74 72 69 6e 67 28 22 27 25 2c 25 27 25 22 29 20 26 20 [0-16] 20 26 20 22 [0-10] 2e 65 78 65 27 29 3b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 22 20 26 20 [0-16] 20 26 20 22 [0-10] 2e 65 78 65 27 22}  //weight: 1, accuracy: Low
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-32] 2f 66 69 6c 65 2e 6a 70 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bartallex_AD_2147749884_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bartallex.AD!MSR"
        threat_id = "2147749884"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bartallex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "https://marendoger.com" ascii //weight: 1
        $x_1_2 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 22 50 69 63 74 75 72 65 [0-3] 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "CStr(Environ(\"APPDATA\")" ascii //weight: 1
        $x_1_4 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

