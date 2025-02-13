rule TrojanDownloader_W97M_Bartallex_A_2147691371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.A"
        threat_id = "2147691371"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".44/upd/install" ascii //weight: 1
        $x_1_2 = "://91.220.131" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_A_2147691371_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.A"
        threat_id = "2147691371"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".35/upd/install" ascii //weight: 1
        $x_1_2 = "://146.185.213" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_A_2147691371_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.A"
        threat_id = "2147691371"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "BART = \"\" + BART2" ascii //weight: 1
        $x_1_2 = "Kill XPFILEDIR" ascii //weight: 1
        $x_1_3 = "\"c:\\Windows\\Temp\"" ascii //weight: 1
        $x_1_4 = {53 75 62 20 41 75 74 6f [0-2] 4f 70 65 6e 28 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_A_2147691371_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.A"
        threat_id = "2147691371"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "://91.220.131" ascii //weight: 2
        $x_1_2 = {2f 75 70 64 [0-1] 2f 69 6e 73 74 61 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "\"c:\\Windows\\Temp\\\" + BART" ascii //weight: 1
        $x_1_4 = "Kill XPFILEDIR" ascii //weight: 1
        $x_1_5 = "BART = \"\" + BART2 + Chr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_W97M_Bartallex_A_2147691371_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.A"
        threat_id = "2147691371"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(Asc(Chr(Asc(\"h\")))) + Chr(Asc(Chr(Asc(\"t\")))) + Chr(Asc(\"t\")) + Chr(Asc(Chr(Asc(\"p\")))) + \"://" ascii //weight: 1
        $x_1_2 = "\".e\" & \"x\" + \"e';" ascii //weight: 1
        $x_1_3 = "objXMLHTTP" ascii //weight: 1
        $x_1_4 = "objADOStream.Open" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_B_2147691607_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.B"
        threat_id = "2147691607"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "91.220.131.73/ca/file" ascii //weight: 1
        $x_1_2 = "Chr(Asc(\"p\")) + Chr(Asc(\"i\")) + \"f\" + Chr(34)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_B_2147691607_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.B"
        threat_id = "2147691607"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lasiguanas.com.mx/wp-content/plugins/chrome" ascii //weight: 1
        $x_1_2 = "CreateObject(\"MSXML2.ServerXMLHTTP\")" ascii //weight: 1
        $x_1_3 = "\".v\" + \"b\" + \"s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_B_2147691607_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.B"
        threat_id = "2147691607"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.ritschfisch.com/wp-content/uploads/2011/08/license" ascii //weight: 1
        $x_1_2 = "Chr(34) + \"4.e\" + Chr(34) + \"+\" + Chr(34) + \"xe\" + Chr(34)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_B_2147691607_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.B"
        threat_id = "2147691607"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vepic.su/" ascii //weight: 1
        $x_1_2 = "savepic.su/" ascii //weight: 1
        $x_1_3 = "objADOStream.Open" ascii //weight: 1
        $x_1_4 = "mp\\\" + BART" ascii //weight: 1
        $x_1_5 = "Kill XPFILEDIR" ascii //weight: 1
        $x_1_6 = "Kill UWGD" ascii //weight: 1
        $x_1_7 = "BART = \"\" + BART2 + Chr" ascii //weight: 1
        $x_1_8 = "://\" + URLLSK + \".\" + Chr(Asc(\"e\")) + Chr(Asc(\"x\")) + \"e\"" ascii //weight: 1
        $x_1_9 = "Kill MY_FILENDIR" ascii //weight: 1
        $x_1_10 = "Chr(Asc(\"x\")) + Chr(Asc(\"e\"))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_2147693602_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex"
        threat_id = "2147693602"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 48 52 30 63 44 6f 76 4c 33 56 74 61 57 4e 76 62 6e 52 79 62 32 77 75 59 32 39 74 4c 6d 4a 79 4c 32 52 76 59 33 4d 76 ?? ?? ?? ?? ?? 53 35 6c 65 47 55 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_2147693602_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex"
        threat_id = "2147693602"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/livesecondchance.press/sys/c1608ec875273d60346dd77602e50d3023e9a.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_2147693602_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex"
        threat_id = "2147693602"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = "& \".\" & \"e\" & \"x\" & \"e\"" ascii //weight: 1
        $x_1_3 = "= Environ(\"a\" & \"p\" & \"p\" & \"d\" & \"a\" & \"t\" & \"a\") &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_2147693602_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex"
        threat_id = "2147693602"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "bluefile.biz/downloads/e820105db960e65b7cd7e8e65e3e2f251798144.exe" ascii //weight: 4
        $x_1_2 = "y(\"ataDppA\"" ascii //weight: 1
        $x_1_3 = "\"PMET\"" ascii //weight: 1
        $x_1_4 = "\".exe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_W97M_Bartallex_2147693602_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex"
        threat_id = "2147693602"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uWVF8Cz6H()" ascii //weight: 1
        $x_1_2 = "TomjxJ9GDX1hrz.Open UserForm2.TextBox7" ascii //weight: 1
        $x_1_3 = "WL4Jo8Exw67vAD.HwOCx51cAz4q, 2" ascii //weight: 1
        $x_1_4 = ".xjSTdvPvoMcWMi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_2147693602_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex"
        threat_id = "2147693602"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ATTH = \"http\" & \"://\"" ascii //weight: 1
        $x_1_2 = "BQHJDQ = \"sa\" + \"vep\" + \"ic\" & Chr(46) & \"su\" + HUQD" ascii //weight: 1
        $x_1_3 = "TSTS = \".\" + \"tx\" + \"t\"" ascii //weight: 1
        $x_1_4 = "GNG = \".j\" & \"pg\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_2147693602_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex"
        threat_id = "2147693602"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ATTH = \"ht\" & \"t\" & \"\" & \"p\" & \":\" & \"/\" & Chr(47)" ascii //weight: 1
        $x_1_2 = "SXE = SXEE & SXAA & \"\" & \"xe\"" ascii //weight: 1
        $x_1_3 = "GNG = Chr(2 ^ 2 + 42) + \"jpg\"" ascii //weight: 1
        $x_1_4 = "TSTS = \".\" + \"t\" + \"xt\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_2147693602_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex"
        threat_id = "2147693602"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"h\" + iuyy + \"p:\" + bbvCCC + \"steb\" + oooidsf + \"m/\" + yyyysysy + \"hp?i=\"" ascii //weight: 1
        $x_1_2 = "& \"\\mNsdewee.vbs\"" ascii //weight: 1
        $x_1_3 = "Chr$(105) & Chr$(110) & Chr$(46) & Chr$(99) & Chr$(111)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_2147693602_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex"
        threat_id = "2147693602"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\"thuyduongspa.c\" & \"om/" ascii //weight: 3
        $x_3_2 = "\"thetunaslab.c\" & \"om/" ascii //weight: 3
        $x_1_3 = "p-admin/css/colors/midnight/" ascii //weight: 1
        $x_1_4 = "w\" & \"p-snapshots/\"" ascii //weight: 1
        $x_1_5 = "ATTH = ATTH + \"://\"" ascii //weight: 1
        $x_1_6 = "\"Te\" + \"mp\"" ascii //weight: 1
        $x_1_7 = "(ATTH + STT1 + LNSS)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_W97M_Bartallex_2147693602_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex"
        threat_id = "2147693602"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "w.mairiesaintgervais33.fr/tmp/67153178.txt\"" ascii //weight: 4
        $x_4_2 = "supremo.org.br/tmp/67153178.txt" ascii //weight: 4
        $x_4_3 = "ww.mairiesaintgervais33.fr/tmp/67153178.txt\"" ascii //weight: 4
        $x_1_4 = "Sub Auto_Open()" ascii //weight: 1
        $x_1_5 = "Module1.Bad(" ascii //weight: 1
        $x_1_6 = "\"\" & \"sav\" & \"epic.su/\"" ascii //weight: 1
        $x_1_7 = "= \"m\" & \"odule\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_W97M_Bartallex_2147693602_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex"
        threat_id = "2147693602"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " = StrReverse(\"t\") + StrReverse(\"pt\")" ascii //weight: 1
        $x_1_2 = " = StrReverse(\"//:\") + StrReverse(\"sap\")" ascii //weight: 1
        $x_1_3 = " = StrReverse(\"ib\") + StrReverse(\"oc.n\")" ascii //weight: 1
        $x_1_4 = " = StrReverse(\"n\") + StrReverse(\"aol\") + StrReverse(\"hp.d\") + StrReverse(\"=i?p\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_2147693602_11
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex"
        threat_id = "2147693602"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "WhiskyBar Lib \"urlmon\" Alias \"URLDownloadToFileA\"" ascii //weight: 4
        $x_2_2 = "tmp = tmp & Chr(Asc(x) - 1)" ascii //weight: 2
        $x_2_3 = "WhiskyBar(0, CheckNumbers" ascii //weight: 2
        $x_1_4 = "NewPath = \"C:\\Users\\Public\\Documents\"" ascii //weight: 1
        $x_1_5 = "Split(LotsofFuckingStringinallinOne)(4)" ascii //weight: 1
        $x_1_6 = "(AnotherShitisHereSaysthis)(4)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_W97M_Bartallex_2147693602_12
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex"
        threat_id = "2147693602"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChrW$(115) & ChrW$(116) & ChrW$(97) & ChrW$(114) & ChrW$(116) & ChrW$(32) & ChrW$(37) & ChrW$(84) & ChrW$(77) & ChrW$(80) & ChrW$(37) & ChrW$(47) & ChrW$(97) & ChrW$(98) & ChrW$(115) & ChrW$(50) & ChrW$(50) & ChrW$(46) & ChrW$(101) + \"xe\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_2147693602_13
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex"
        threat_id = "2147693602"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bgj67vffsdg: Set bgj67vffsdg = CreateObject(UserForm1.TextBox3.Text)" ascii //weight: 1
        $x_1_2 = {63 6d 64 73 20 3d 20 57 73 68 53 68 65 6c 6c 2e 52 75 6e 28 [0-16] 2c 20 30 2c 20 54 72 75 65 29}  //weight: 1, accuracy: Low
        $x_1_3 = ".Open UserForm1.TextBox2.Text, UserForm1.TextBox1.Text, False" ascii //weight: 1
        $x_2_4 = "Shell Module1.fxpsftfarakqh(callreturn()), 0" ascii //weight: 2
        $x_2_5 = "vIsijNnE = Shell(szlqVxcK(j1AuN), sDp9Wy3)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_W97M_Bartallex_2147693602_14
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex"
        threat_id = "2147693602"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Str = Str + \"AC0AYABUAHsAWgBWAHQAcwB6ADsAJwA7ACQAaQA9ADAAOwBbAG\"" ascii //weight: 1
        $x_1_2 = "+ \"MASABhAHIAWwBdAF0AJABCAD0AKABbAEMASABhAHIAWwBdAF0A\"" ascii //weight: 1
        $x_1_3 = "+ \"KAAkAFcAQwAuAEQATwBXAG4AbABPAEEARABTAHQAcgBJAG4AZw\"" ascii //weight: 1
        $x_1_4 = "+ \"AoACIAaAB0AHQAcAA6AC8ALwA1ADIALgAzADYALgAyADQANQAu\"" ascii //weight: 1
        $x_1_5 = "+ \"ADEANAA1ADoAOAAwADgAMAAvAGkAbgBkAGUAeAAuAGEAcwBwAC\"" ascii //weight: 1
        $x_1_6 = "+ \"IAKQApACkAfAAlAHsAJABfAC0AYgBYAE8AcgAkAGsAWwAkAEkA\"" ascii //weight: 1
        $x_1_7 = "+ \"\"KwArACUAJABrAC4ATABlAG4AZwB0AEgAXQB9ADsASQBFAFgAIA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_2147693602_15
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex"
        threat_id = "2147693602"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(99) & Chr(104) & \"l\" & \"o\" & Chr(101) & Chr(100) & \"e\" & Chr(115) & \"i\" & \"g\" & \"n\" & \";\" & Chr(46) & Chr(102) & Chr(114) & Chr(47) & Chr(51) & Chr(52) & Chr(53) & Chr(47)" ascii //weight: 1
        $x_1_2 = "\"w\" & Chr(114) & \"w\" & Chr(46) & Chr(61) & Chr(101) & Chr(60) & Chr(120) & Chr(101)" ascii //weight: 1
        $x_1_3 = "Chr(87) & \"<\" & \"S\" & Chr(99) & Chr(61) & Chr(114) & \"i\" & Chr(112) & \"t\" & \";\" & Chr(46) & Chr(83) & Chr(61) & \"h\" & Chr(101) & \"<\" & Chr(108) & \"l\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_D_2147694478_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.D"
        threat_id = "2147694478"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 68 72 28 31 30 34 29 20 2b 20 43 68 72 28 31 31 36 29 20 2b 20 43 68 72 28 31 31 36 29 20 2b 20 43 68 72 28 31 31 32 29 20 2b 20 43 68 72 28 35 38 29 20 2b 20 43 68 72 28 34 37 29 20 2b 20 43 68 72 28 34 37 29 20 2b 20 43 68 72 28 31 31 35 29 20 2b 20 43 68 72 28 39 37 29 20 2b 20 43 68 72 28 31 31 38 29 20 2b 20 43 68 72 28 31 30 31 29 20 2b 20 43 68 72 28 31 31 32 29 20 2b 20 43 68 72 28 31 30 35 29 20 2b 20 43 68 72 28 39 39 29 20 2b 20 43 68 72 28 34 36 29 20 2b 20 43 68 72 28 31 31 35 29 20 2b 20 43 68 72 28 31 31 37 29 20 2b 20 43 68 72 28 34 37 29 20 2b 20 22 [0-10] 2e 6a 70 67 22}  //weight: 1, accuracy: Low
        $x_1_2 = {54 69 6d 65 56 61 6c 75 65 28 22 ?? ?? ?? ?? ?? ?? ?? ?? 22 29 0d 0a 20 20 20 20 20 20 20 20 20 [0-16] 3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= \"Sh\" & \"el\"" ascii //weight: 1
        $x_1_4 = "& Chr(108) & \".Application\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_E_2147696270_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.E"
        threat_id = "2147696270"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(StrReverse(\"PTTHLMX.2LMXSM\"))" ascii //weight: 1
        $x_1_2 = "StrReverse(\"daolnwod/moc." ascii //weight: 1
        $x_1_3 = "+ StrReverse(\"p//:p\") + " ascii //weight: 1
        $x_1_4 = {53 74 72 52 65 76 65 72 73 65 28 22 [0-10] 3d 69 3f 70 68 70 2e 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = ".Open(StrReverse(\"TSOP\")," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_F_2147697247_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.F"
        threat_id = "2147697247"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"s\" + \"avep\" + \"ic\" & Chr(46) & \"s\" & \"u\" + " ascii //weight: 1
        $x_1_2 = "= Chr(60 + 24) & \"emp\"" ascii //weight: 1
        $x_1_3 = "= \"\" + \"USE\" & \"RPROFILE\"" ascii //weight: 1
        $x_1_4 = "\"\" & \"o\" & \"bject\"" ascii //weight: 1
        $x_1_5 = "= \".\" + \"tx\" + \"t\"" ascii //weight: 1
        $x_1_6 = "\"c\" + \"urrentFile = \" + Chr(34) +" ascii //weight: 1
        $x_1_7 = "= \".j\" & \"pg\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_H_2147697427_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.H"
        threat_id = "2147697427"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"://pas\"" ascii //weight: 1
        $x_1_2 = "= \"ttp\"" ascii //weight: 1
        $x_1_3 = "= StrReverse(ChrW$(61) & ChrW$(105) & ChrW$(63)" ascii //weight: 1
        $x_1_4 = ".Open(StrReverse(ChrW$(84) & ChrW$(83)" ascii //weight: 1
        $x_1_5 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-16] 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 57 24 28 31 31 35 29 20 26 20 43 68 72 57 24 28 39 38 29 20 26 20 43 68 72 57 24 28 31 31 38 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_I_2147697439_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.I"
        threat_id = "2147697439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "tcoyl.c\" & \"om/w\" & \"p-content/tubepress-content/\"" ascii //weight: 2
        $x_2_2 = "tamelagilbertmd.c\" & \"om/\"" ascii //weight: 2
        $x_1_3 = "\"66836487162\"" ascii //weight: 1
        $x_1_4 = "\".t\" & \"xt\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_W97M_Bartallex_I_2147697439_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.I"
        threat_id = "2147697439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ATTH = Chr(Ndjs) + Chr(Ndjs + 12) + Chr(Ndjs + 12) + Chr(Ndjs + 8) & " ascii //weight: 1
        $x_1_2 = "TSTS = \".\" + \"tx\" + \"t\"" ascii //weight: 1
        $x_1_3 = "TSTS = \"\" & \".tx\" + \"t\" + \"\"" ascii //weight: 1
        $x_1_4 = "LNSS = \"rara\" + TSTS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_I_2147697439_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.I"
        threat_id = "2147697439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"777763172631572\" + TSTS" ascii //weight: 1
        $x_1_2 = "PH2 + MADRID + \".vbs\"" ascii //weight: 1
        $x_1_3 = "(Ndjs + 12) + Chr(Ndjs + 8) + \":\" + \"//\"" ascii //weight: 1
        $x_1_4 = "Chr(Ndjs) + Chr(Ndjs + 12) + Chr(Ndjs + 12) + Chr(Ndjs + 8)" ascii //weight: 1
        $x_1_5 = "CDDD = \"8179826378126.txt\"" ascii //weight: 1
        $x_1_6 = "GGGR = hhr(Ndjs) + hhr(Ndjs" ascii //weight: 1
        $x_1_7 = "GEFORCE1 As String, GEFORCE2 As String, hdjshd As Integer" ascii //weight: 1
        $x_1_8 = "KIPARIS = Module2.hhr(" ascii //weight: 1
        $x_1_9 = "CStr(Int((a / 2 * Rnd) + a))" ascii //weight: 1
        $x_1_10 = "GEFORCE1 = Mid(CONT2, 1, i - 2)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_J_2147697727_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.J"
        threat_id = "2147697727"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 20 43 68 72 28 36 30 29 2c 20 22 22 29 0d 0a [0-144] 20 3d 20 52 65 70 6c 61 63 65 28 00 2c 20 43 68 72 28 36 31 29 2c 20 22 22 29 0d 0a 00 20 3d 20 52 65 70 6c 61 63 65 28 00 2c 20 43 68 72 28 35 39 29 2c 20 22 22 29 ff 03 70 61 74 68 49 73 41 62 73 6f 6c 75 74 65 5f 31 20 3d 20 68 43 75 72 44 69 72 5f 32 28 43 68 72 28 38 37 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_K_2147697787_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.K"
        threat_id = "2147697787"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"SXML2.X\"" ascii //weight: 1
        $x_1_2 = "= \"HTT\"" ascii //weight: 1
        $x_1_3 = {3d 20 22 4d 22 20 2b 20 [0-16] 20 2b 20 22 4d 4c 22 20 2b 20 [0-16] 20 2b 20 22 50 22}  //weight: 1, accuracy: Low
        $x_1_4 = {22 70 3a 2f 2f 70 22 20 2b 20 [0-16] 20 2b 20 22 65 62 69 22 20 2b 20 [0-16] 20 2b 20 22 6f 6d 2f 72 61 22 20 2b 20 [0-16] 20 2b 20 22 68 70 22 20 2b 20 [0-16] 20 2b 20 22 69 3d 22}  //weight: 1, accuracy: Low
        $x_1_5 = "\"ipting.FileSystem\"" ascii //weight: 1
        $x_1_6 = {22 53 63 72 22 20 2b 20 [0-16] 20 2b 20 22 4f 62 6a 65 63 74 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_L_2147705806_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.L"
        threat_id = "2147705806"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "strUnquote23 = ValToDicBin(Chr(77) & Chr(105) & Chr(60) & \"c\" & Chr(114)" ascii //weight: 1
        $x_1_2 = "strUnquote23.Open Chr(71) & Chr(69) & Chr(84), Chr(104) & Chr(116) & \"t\" & Chr(112) & Chr(58) & \"/\" & \"/\"" ascii //weight: 1
        $x_1_3 = "ParamsToBytes4.B(1) = 0 'fuk em..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_M_2147706151_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.M"
        threat_id = "2147706151"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 [0-4] 28 [0-4] 20 41 73 20 49 6e 74 65 67 65 72 29 0d 0a [0-4] 20 3d 20 43 68 72 28 [0-4] 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 10, accuracy: Low
        $x_1_2 = "& \"om/w\" & \"p-includes/theme-compat/\"" ascii //weight: 1
        $x_1_3 = "Int(" ascii //weight: 1
        $x_1_4 = "(ATTH + STT1 + LNSS)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_W97M_Bartallex_N_2147707305_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.N"
        threat_id = "2147707305"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Chr$(105) & Chr$(110) & Chr$(46) & Chr$(99) & Chr$(111)" ascii //weight: 1
        $x_1_2 = {45 6e 76 69 72 6f 6e 28 [0-16] 29 20 26 20 22 5c [0-16] 2e 76 62 73}  //weight: 1, accuracy: Low
        $x_1_3 = "= \"ell.Ap\"" ascii //weight: 1
        $x_1_4 = "= \"cati\"" ascii //weight: 1
        $x_1_5 = {3d 20 22 53 68 22 20 2b 20 [0-10] 20 2b 20 22 70 6c 69 22 20 2b 20 [0-10] 20 2b 20 22 6f 6e 22}  //weight: 1, accuracy: Low
        $x_1_6 = "= \"2.XM\"" ascii //weight: 1
        $x_1_7 = "= \"SX\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Bartallex_T_2147708347_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bartallex.T"
        threat_id = "2147708347"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bartallex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"Script\" + \"ing.FileSy\" + \"s\"" ascii //weight: 1
        $x_1_2 = "= \"temO\" + \"b\" + \"j\"" ascii //weight: 1
        $x_1_3 = "= \"Htt\" + \"p\" + \".\"" ascii //weight: 1
        $x_1_4 = "= \"Wi\" + \"n\"" ascii //weight: 1
        $x_1_5 = ".GetSpecialFolder(2) & \"\\\" + \"\\\"" ascii //weight: 1
        $x_1_6 = {2e 53 74 61 74 75 73 20 3d 20 [0-3] 20 2b 20 [0-3] 20 2b 20 [0-3] 20 2b 20 [0-3] 20 54 68 65 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

