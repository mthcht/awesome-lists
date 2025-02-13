rule TrojanDownloader_W97M_Adnel_C_2147690119_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel.C"
        threat_id = "2147690119"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ge\" & \".\" & \"tt/" ascii //weight: 1
        $x_1_2 = "FuckingString" ascii //weight: 1
        $x_1_3 = "ProudtoBecomeaNepaliReverseEngineer(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_C_2147690119_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel.C"
        threat_id = "2147690119"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"MSXML2.XMLHTTP\")" ascii //weight: 1
        $x_1_2 = "Environ(HEXTOSTRING(Chr$(53) & Chr$(52) & Chr$(52) & Chr$(53) & Chr$(52) & Chr$(68) & Chr$(53) & Chr$(48)))" ascii //weight: 1
        $x_1_3 = "CreateObject(HexToString(Chr$(52) & Chr$(68) & Chr$(53) & Chr$(51) & Chr$(53) & Chr$(56) & Chr$(52) & Chr$(68)" ascii //weight: 1
        $x_1_4 = ".Open HexToString(Chr$(52) & Chr$(55) & Chr$(52) & Chr$(53) & Chr$(53) & Chr$(52))," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_W97M_Adnel_C_2147690119_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel.C"
        threat_id = "2147690119"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 42 79 4e 61 6d 65 20 [0-16] 2c 20 43 68 72 28 37 39 29 20 26 20 43 68 72 28 31 31 32 29 20 26 20 22 65 22 20 26 20 43 68 72 28 31 31 30 29 2c 20 56 62 4d 65 74 68 6f 64 2c 20 43 68 72 28 37 31 29 20 26 20 43 68 72 28 36 39 29 20 26 20 43 68 72 28 38 34 29}  //weight: 1, accuracy: Low
        $x_1_2 = "Chr(115) & \"p\" & Chr(101) & \"a\" & Chr(107) & \"h\" & \"i\" & Chr(103) & \"h\" & \"l\" & \"y\" & Chr(46) & Chr(99) & \"o\" & Chr(109) & Chr(47) & Chr(52) & Chr(50) & Chr(47) & \"1\" & \"1\" & Chr(46) & \"e\" & Chr(120) & Chr(101)" ascii //weight: 1
        $x_1_3 = "Chr(126) & Chr(98) & Chr(97) & \"n\" & \"o\" & Chr(98) & Chr(97) & \"t\" & Chr(119) & Chr(111) & Chr(47) & Chr(52) & Chr(50) & Chr(47) & Chr(49) & Chr(49) & \".\" & Chr(101) & \"x\" & Chr(101)" ascii //weight: 1
        $x_1_4 = "Chr(92) & Chr(98) & Chr(105) & \"r\" & Chr(115) & Chr(97) & \"f\" & Chr(112) & \"c.e\" & Chr(120) & Chr(101)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.iphonetechie.com/wz/can/cawinn" ascii //weight: 1
        $x_1_2 = "\"\\SOkfdssd.ini\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://hpg.se/tmp/lns.txt" ascii //weight: 1
        $x_1_2 = "http://sundsvallsrk.nu/tmp/lns.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CIFExUyApYzs = VHe41U(LSexeAXW5PI, Sra1h)" ascii //weight: 1
        $x_1_2 = "Shell CIFExUyApYzs, 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LXu4AuYfm = Ukk2X(PNLOsEjicS8vlVmw6, KvkzrNhcswy8)" ascii //weight: 1
        $x_1_2 = "Shell LXu4AuYfm, 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GAUrRXx1c2Endo = YueMZAblJG(MWk3zA, BZb5YLaVTOb0)" ascii //weight: 1
        $x_1_2 = "Shell GAUrRXx1c2Endo, 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DdUi = P0IFOjLjLGUnX(Hb6GlI0Kgb3YH)" ascii //weight: 1
        $x_1_2 = "K623nbYinb = DdUi(XgdIBT, LgBLj9sufDl)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FCylEkwLS5UtSO = HVEK7kM0QWv(KJ9NQDXE169GkCsh, LX8p0)" ascii //weight: 1
        $x_1_2 = "Shell FCylEkwLS5UtSO, 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GAmB0MyZ7IvGVC = I4wPCpNiMY16(S6lFJEmD, XsVfuWab2gd2B7)" ascii //weight: 1
        $x_1_2 = "Shell GAmB0MyZ7IvGVC, 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = ".ro/cgi-bin/wed/1" ascii //weight: 4
        $x_1_2 = "Document_Open" ascii //weight: 1
        $x_1_3 = "Temp" ascii //weight: 1
        $x_1_4 = "Shell" ascii //weight: 1
        $x_1_5 = "Environ" ascii //weight: 1
        $x_1_6 = "URLDownloadToFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "a.pomf.se/" ascii //weight: 1
        $x_1_2 = "/dwnlvh\"" ascii //weight: 1
        $x_1_3 = "Environ(\"Temp\") & \"\\\" & \"startup.exe\"" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA 0, " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "I7Xqm6hOGW35lJ7lL = HR5Ma2E8qfp3(HB63lr8z53qzw8m, RwliYGtmlv)" ascii //weight: 1
        $x_1_2 = "Shell I7Xqm6hOGW35lJ7lL, 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_11
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(92) & Chr(98) & Chr(105) & \"r\" & Chr(115) & Chr(97) & \"f\" & Chr(112) & \"c.e\" & Chr(120) & Chr(101)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_12
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QHgORyluwQ2SZa7(DHGn2w6glE98p) = Xsr(Up8oALipiIJ)" ascii //weight: 1
        $x_1_2 = "IXLILiRjI = KEZqkqOjR3JfdpKI(RZiPrAE4, QHgORyluwQ2SZa7)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_13
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "StrReverse(\"i?php.daolnwod/moc.nibetsap//:p" ascii //weight: 3
        $x_1_2 = "StrReverse(\"tRagE7MK=\")" ascii //weight: 1
        $x_1_3 = "Environ(\"TEMP\") & \"\\wwwwwwwWWWefs.vbs\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_14
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "myURL = \"http://tukangecuprus.com/cr_file_inst.exe\"" ascii //weight: 1
        $x_1_2 = ".Open \"GET\", myURL, False, \"\", \"\"  '(\"username\", \"password\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_15
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UGiEQf = Chr$(Val(Chr$(38) & Chr$(72) & Mid$(kZtkbozi, TQmHIRcQAPjC, 2)))" ascii //weight: 1
        $x_1_2 = "ePUuigaspLiGL = ePUuigaspLiGL & UGiEQf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_16
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(92) & \"r\" & Chr(105) & Chr(100) & Chr(101) & Chr(98) & \"o\" & Chr(115) & Chr(53) & Chr(46) & Chr(101) & \"x\" & Chr(101)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_17
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "efaC74U68scS5qy = ZR5Bc05rsAg1ZAX.S99RyqLk(efaC74U68scS5qy, nNfJ9qBADiGPZh, dwwGQpA1J60vNKE)" ascii //weight: 1
        $x_1_2 = {2e 53 39 39 52 79 71 4c 6b 28 [0-24] 2c 20 [0-24] 2c 20 64 77 77 47 51 70 41 31 4a 36 30 76 4e 4b 45 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_18
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Chr(Asc(UCase(" ascii //weight: 10
        $x_1_2 = "= CreateObject(\"Microsoft.XMLHTTP\")" ascii //weight: 1
        $x_1_3 = "= CreateObject(\"Adodb.Stream\")" ascii //weight: 1
        $x_1_4 = "processEnv = CreateObject(\"WScript.Shell\").Environment(\"Process\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_19
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 02 00 53 68 65 6c 6c 20 28 22 63 6d 64 2e 65 78 65 20 2f 63 20 50 6f 57 65 72 53 48 45 6c 4c 20 28 6e 45 57 2d 6f 42 6a 45 63 54 20 73 59 73 54 65 4d 2e 6e 65 54 2e 77 45 42 63 4c 69 45 6e 54 29 2e 0f 00 28 27 68 74 74 70 3a 2f 2f [0-48] 2e 69 6e 66 6f 2f 4f 66 66 31 [0-5] 63 65 33 36 35 75 70 [0-5] 74 65 2e 65 78 65 27 2c 27 25 54 45 4d 50 25 5c 4f 66 66 31 0d 00 2e 65 78 65 27 29 3b 26 73 74 61 72 74 20 25 54 45 4d 50 25 5c 4f 66 66 31 05 2e 65 78 65 26 20 65 78 69 74 [0-5] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_20
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(104) & Chr(116) & \"t\" & \"p\"" ascii //weight: 1
        $x_1_2 = "\"T\" & Chr(69) & Chr(77) & \"P\"" ascii //weight: 1
        $x_1_3 = "\"e\" & Chr(120) & Chr(101)" ascii //weight: 1
        $x_1_4 = "\".X\" & Chr(77) & \"L\" & Chr(72) & Chr(84) & \"T\" & \"P\")" ascii //weight: 1
        $x_1_5 = "Chr(110), VbMethod, Chr(71) & \"E\" & \"T\", _" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_21
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 29 20 41 73 20 56 61 72 69 61 6e 74 ?? ?? ?? ?? ?? [0-5] 20 3d 20 41 72 72 61 79 28 [0-9] 2c 20 [0-9] 2c 20 [0-9] 2c 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-64] 29 02 00 68 74 74 70 52 65 71 75 65 73 74 2e 4f 70 65 6e 20 22 47 [0-100] 45 [0-6] 54 22 2c 20 47 65 74 53 74 72 69 6e 67 46 72 6f 6d 41 72 72 61 79 28 ?? ?? ?? ?? ?? [0-5] 2c 20 [0-9] 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_2 = "processEnv(\"TE\" + \"MP\")" ascii //weight: 1
        $x_1_3 = "tempFile = tempFolder + \"\\bluezone3.exe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_22
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MisterZALALU" ascii //weight: 1
        $x_1_2 = "ITSFROM" ascii //weight: 1
        $x_1_3 = "((ZINGMAH30 Mod Len(IIIIIBRDA1)) + 1), 1))" ascii //weight: 1
        $x_1_4 = "Chr(ZINGMAH300 Xor ZINGMAH3001)" ascii //weight: 1
        $x_1_5 = "Lib \"wininet.dll\" Alias \"InternetOpenA\"" ascii //weight: 1
        $x_1_6 = "Lib \"wininet.dll\" Alias \"InternetReadFile\"" ascii //weight: 1
        $x_1_7 = "Lib \"wininet.dll\" Alias \"InternetOpenUrlA\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_23
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr$(115) & Chr$(116) & Chr$(97) & Chr$(114) & Chr$(116) & Chr$(32) & Chr$(37) & Chr$(84) & Chr$(77) & Chr$(80) & Chr$(37) & Chr$(47) & Chr$(112) & Chr$(117) & Chr$(116) & Chr$(105) & Chr$(110) & Chr$(54) & Chr$(54) & Chr$(54) & Chr$(46) & Chr$(101)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_24
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6c 65 28 27 68 74 [0-2] 74 70 3a 2f 2f 65 73 73 65 6e 74 69 61 6c 6d 6d 2e 74 6f 70 2f [0-2] 6c 6c 2f [0-2] 6c 64 64 2e 70 68 70}  //weight: 2, accuracy: Low
        $x_1_2 = {2e 4e 22 20 26 20 22 65 [0-2] 22 20 26 20 22 74 [0-2] 22 20 26 20 22 2e [0-2] 22 20 26 20 22 57 [0-2] 22 20 26 20 22 65 [0-2] 22 20 26 20 22 62 [0-2] 22 20 26 20 22 63 [0-2] 22 20 26}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 22 73 22 20 26 20 22 [0-2] 68 22 20 26 20 22 [0-2] 65 22 20 26 20 22 [0-2] 6c 22 20 26 20 22 [0-2] 6c 22}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 22 63 22 20 26 20 22 6d 22 20 26 20 22 64 [0-6] 2e [0-6] 65 22 20 26 20 22 78 [0-6] 65 22 20 26 20 22 22}  //weight: 1, accuracy: Low
        $x_2_5 = "+ newform.mxmcmmvmv + \"m/kufma/sdogsodngsdlk.png\" + \"'\" + \",'\" + newName + \"');" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_W97M_Adnel_2147690439_25
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& Chr(47) & Chr(49) & Chr(50) & Chr(51) & Chr(47) & Chr(49) & Chr(49) & Chr(49) & Chr(49) & Chr(46) & \"e\" & Chr(120) & \"e\"" ascii //weight: 1
        $x_1_2 = "\"/\" & Chr(49) & \"2\" & Chr(51) & Chr(47) & Chr(49) & Chr(49) & \"1\" & \"1\" & Chr(46) & \"e\" & Chr(120) & \"e\"" ascii //weight: 1
        $x_1_3 = "Chr(104) & Chr(116) & \"t\" & Chr(112) & Chr(58) & \"/\" & \"/\"" ascii //weight: 1
        $x_1_4 = "Chr(71) & \"E\" & Chr(84)," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_26
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "computer = Array(140, 151, 150, 145, 90, 78, 77, 130, 142, 72, 144, 136, 70, 122, 133, 130, 67, 75, 72, 70, 71, 68, 69, 67, 65, 58, 64, 64, 61, 62, 60, 57, 57, 49, 103, 121, 101)" ascii //weight: 1
        $x_1_2 = {54 68 65 6e 20 [0-15] 20 3d 20 22 43 72 6f 77 53 6f 66 74 32 22 [0-15] 74 65 6d 70 46 69 6c 65 20 3d 20 22 5c 22 20 2b 20 00 20 2b 20 22 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_3 = {28 29 20 41 73 20 56 61 72 69 61 6e 74 ?? ?? ?? ?? [0-5] 3d 20 41 72 72 61 79 28 [0-9] 2c 20 [0-9] 2c 20 [0-9] 2c [0-223] 29 [0-246] 68 74 74 70 52 65 71 75 65 73 74 2e 4f 70 65 6e 20 22 47 45 54 22 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {70 72 6f 63 65 73 73 45 6e 76 28 22 54 22 [0-6] 45 [0-6] 4d 50 22 29 [0-15] 74 65 6d 70 46 69 6c 65 20 3d 20 74 65 6d 70 46 6f 6c 64 65 72 20 2b 20 22 [0-15] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_5 = {28 29 20 41 73 20 56 61 72 69 61 6e 74 ?? ?? ?? ?? [0-15] 3d 20 41 72 72 61 79 28 [0-9] 2c 20 [0-9] 2c 20 [0-9] 2c [0-255] 29 [0-2] 57 69 74 68 20 50 68 6f 74 6f 73 68 6f 70 45 78 74 65 6e 73 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {74 65 6d 70 46 6f 6c 64 65 72 20 3d 20 [0-15] 28 22 54 45 4d 50 22 29 [0-15] 47 61 74 65 77 61 79 52 65 73 6f 6c 76 65 72 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 47 65 74 53 74 72 69 6e 67 46 72 6f 6d 41 72 72 61 79 28 4f 70 65 6e 54 79 70 65 2c 20 34 38 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_27
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(92) & Chr(108) & Chr(117) & Chr(107) & \"i\" & \"p\" & \"o\" & \"n\" & Chr(99) & \"h\" & \".\" & Chr(101) & Chr(120) & \"e\"" ascii //weight: 1
        $x_1_2 = "Chr(92) & Chr(98) & Chr(105) & \"k\" & Chr(115) & Chr(97) & \"m\" & Chr(112) & \"c\" & Chr(46) & \"e\" & Chr(120) & Chr(101)" ascii //weight: 1
        $x_1_3 = "Chr(92) & Chr(116) & Chr(117) & Chr(98) & \"l\" & Chr(105) & Chr(110) & Chr(107) & Chr(114) & Chr(46) & Chr(101) & Chr(120) & Chr(101)" ascii //weight: 1
        $x_1_4 = "Chr(92) & Chr(107) & Chr(105) & Chr(108) & Chr(109) & Chr(110) & Chr(97) & Chr(100) & Chr(111) & Chr(46) & Chr(101) & Chr(120) & Chr(101)" ascii //weight: 1
        $x_1_5 = "Chr(92) & Chr(115) & Chr(105) & Chr(114) & Chr(111) & Chr(98) & Chr(103) & Chr(99) & Chr(46) & Chr(101) & Chr(120) & Chr(101)" ascii //weight: 1
        $x_1_6 = "\" & \"i\" & Chr(104) & Chr(104) & Chr(97) & Chr(100) & \"n\" & Chr(105) & Chr(99) & Chr(46) & \"e\" & Chr(120) & \"e\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_28
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hgFYyhhshu = ChrW(34 + 34) & ChrW(55.5 + 55.5) & ChrW(59.5 + 59.5) & ChrW(55 + 55) & ChrW(54 + 54) & ChrW(55.5 + 55.5) & ChrW(48.5 + 48.5) & ChrW(50 + 50) & ChrW(35 + 35) & ChrW(52.5 + 52.5)" ascii //weight: 1
        $x_1_2 = "& ChrW(54 + 54) & ChrW(50.5 + 50.5) & ChrW(20 + 20) & ChrW(19.5 + 19.5) & ChrW(52 + 52) & ChrW(58 + 58) & ChrW(58 + 58) & ChrW(56 + 56) & ChrW(29 + 29) & ChrW(23.5 + 23.5) & ChrW(23.5 + 23.5)" ascii //weight: 1
        $x_1_3 = "& ChrW(23.5 + 23.5) & ChrW(53 + 53) & ChrW(57.5 + 57.5) & ChrW(48.5 + 48.5) & ChrW(60 + 60) & ChrW(55.5 + 55.5) & ChrW(28 + 28) & ChrW(58.5 + 58.5) & ChrW(23.5 + 23.5) & ChrW(51.5 + 51.5)" ascii //weight: 1
        $x_1_4 = "& ChrW(25.5 + 25.5) & ChrW(28.5 + 28.5) & ChrW(49 + 49) & ChrW(25 + 25) & ChrW(49.5 + 49.5) & ChrW(60 + 60) & ChrW(23 + 23) & ChrW(50.5 + 50.5) & ChrW(60 + 60) & ChrW(50.5 + 50.5) & ChrW(19.5 + 19.5)" ascii //weight: 1
        $x_1_5 = "JHGUgisdc = GVhkjbjv + GYUUYIiii + hgFYyhhshu + GYiuudsuds + shdfihiof + doifhsoip" ascii //weight: 1
        $x_1_6 = "IUGuyguisdf = Shell(JHGUgisdc, 0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_2147690439_29
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel"
        threat_id = "2147690439"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(92) & Chr(115) & Chr(101) & Chr(103) & Chr(109) & Chr(97) & Chr(110) & \"d\" & Chr(46) & \"e\" & Chr(120) & Chr(101)" ascii //weight: 1
        $x_1_2 = "Chr(92) & \"g\" & Chr(105) & Chr(110) & Chr(107) & Chr(97) & Chr(110) & Chr(56) & Chr(54) & Chr(46) & Chr(101) & Chr(120) & Chr(101)" ascii //weight: 1
        $x_1_3 = "Chr(92) & Chr(114) & Chr(105) & Chr(109) & Chr(97) & Chr(110) & Chr(100) & Chr(111) & Chr(98) & Chr(46) & Chr(101) & Chr(120) & Chr(101)" ascii //weight: 1
        $x_1_4 = "Chr(98) & Chr(108) & \"o\" & Chr(103) & Chr(100) & Chr(121) & Chr(110) & Chr(97) & Chr(109) & \"o\" & Chr(111) & Chr(99) & \"o\" & Chr(109) & \".\" & \"e\" & \"x\" & Chr(101)" ascii //weight: 1
        $x_1_5 = "Chr(92) & Chr(107) & Chr(60) & Chr(105) & \"o\" & Chr(109) & Chr(110) & Chr(97) & Chr(100) & \"d\" & Chr(111) & Chr(46) & \"e\" & Chr(120) & Chr(101)" ascii //weight: 1
        $x_1_6 = "Chr(92) & Chr(109) & Chr(105) & Chr(107) & \"a\" & Chr(112) & Chr(111) & Chr(108) & Chr(110) & Chr(101) & Chr(46) & Chr(101) & Chr(120) & Chr(101)" ascii //weight: 1
        $x_1_7 = "Chr(92) & Chr(115) & Chr(117) & Chr(112) & Chr(117) & \"t\" & Chr(102) & Chr(56) & Chr(46) & Chr(101) & \"x\" & Chr(101)" ascii //weight: 1
        $x_1_8 = "tempFile = tempFolder + \"\\Mb5k9G0zH.exe\"" ascii //weight: 1
        $x_1_9 = "GetThisStringT = ServidrGEN9_2 & \"\\\" & \"vts\" & Chr(65) & \"bd.\" & \"e\" & Chr(120) & \"e\"" ascii //weight: 1
        $x_1_10 = "Chr(103) & Chr(105) & \"c\" & Chr(97) & \"g\" & \"e\" & Chr(46) & Chr(101) & \"x\" & Chr(101)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_W97M_Adnel_A_2147691657_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel.gen!A"
        threat_id = "2147691657"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://" ascii //weight: 1
        $x_1_2 = "Sub Auto_Open()" ascii //weight: 1
        $x_1_3 = "DownloadFile" ascii //weight: 1
        $x_1_4 = "CreateObject(\"WScript.Shell\").Run FullSavePath" ascii //weight: 1
        $x_1_5 = "If RunHide = False Then: OCX.Open \"GET\", GATE, False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_B_2147692303_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel.gen!B"
        threat_id = "2147692303"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f [0-64] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_2 = {57 48 45 52 45 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 22 20 26 20 22 [0-32] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_3 = "DownloadStatus = URLDownloadToFile(0, URL, WHERE, 0, 0)" ascii //weight: 1
        $x_1_4 = "CreateObject(\"WScript.Shell\").Run WHERE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_C_2147693036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel.gen!C"
        threat_id = "2147693036"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = ", 0, 0)" ascii //weight: 1
        $x_1_3 = {3d 20 45 6e 76 69 72 6f 6e 28 22 (41 70 70 44 61|54 65) 22 29 20 26 20 22 5c 22 20 26 20 22 [0-38] 2e [0-15] 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_4 = "Lib \"urlmon\" Alias \"URLDownloadToFileA\" _" ascii //weight: 1
        $x_1_5 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 [0-9] 72 69 70 74 2e 73 68 [0-15] 65 6c [0-15] 6c 22 29 [0-38] 2e (65 78|72)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_D_2147694480_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel.D"
        threat_id = "2147694480"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BARNEY = BARNEY + BRANDEN(NUMBERS, BUFORD)" ascii //weight: 1
        $x_1_2 = "BRANDEN = Chr(NUMBERS Xor BUFORD)" ascii //weight: 1
        $x_1_3 = "Public Const OCTAVIO = \"AUGUSTINEYOUNG" ascii //weight: 1
        $x_1_4 = "Function ULYSSES Lib \"wininet.dll\" Alias \"InternetReadFile\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_D_2147696163_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel.gen!D"
        threat_id = "2147696163"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 75 72 6c 6d 6f 6e 22 20 5f [0-4] 41 6c 69 61 73 20 5f [0-4] 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 5f [0-4] 41 6c 69 61 73 20 5f [0-4] 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22}  //weight: 1, accuracy: Low
        $x_1_3 = "6E65706F$" ascii //weight: 1
        $x_1_4 = "4558452E" ascii //weight: 1
        $x_1_5 = "= StrReverse(Hex2Str(\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_F_2147696251_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel.F"
        threat_id = "2147696251"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "directexe.com/351/pym_trmk" ascii //weight: 1
        $x_1_2 = "netraph.exe" ascii //weight: 1
        $x_1_3 = "Environ(\"Temp\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_F_2147697218_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel.gen!F"
        threat_id = "2147697218"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 28 42 79 56 61 6c 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (41|2d|5a|61|2d|7a) (41|2d|5a|61|2d|7a) [0-480] 20 41 73 20 4c 6f 6e 67}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 20 41 73 63 28 4d 69 64 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (41|2d|5a|61|2d|7a) (41|2d|5a|61|2d|7a) [0-480] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_G_2147705474_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel.G"
        threat_id = "2147705474"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lib \"shell32.dll\" Alias \"ShellExecuteA\" (ByVal" ascii //weight: 1
        $x_1_2 = "Lib \"urlmon\" Alias \"URLDownloadToFileA\" (ByVal" ascii //weight: 1
        $x_1_3 = "0, \"open\", Environ$(\"tmp\") &" ascii //weight: 1
        $x_1_4 = "\"), Environ(\"temp\") &" ascii //weight: 1
        $x_1_5 = "& Chr(Asc(Mid(" ascii //weight: 1
        $x_1_6 = ", 1)) - Asc(Mid(" ascii //weight: 1
        $x_1_7 = " = StrReverse(" ascii //weight: 1
        $x_1_8 = "\"), \"\", vbNullString, vbNormalFocus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_G_2147705749_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel.gen!G"
        threat_id = "2147705749"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "'< protected by www.CrunchCode.de" ascii //weight: 1
        $x_1_2 = {23 49 66 20 57 69 6e 36 34 20 54 68 65 6e 0d 0a 50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 20 4c 69 62 20 5f 0d 0a 22 75 72 6c 6d 6f 6e 22}  //weight: 1, accuracy: High
        $x_1_3 = {3d 20 53 68 65 6c 6c 28 [0-192] 2c 20 5f 0d 0a 31 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 0d 0a 53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a 41 75 74 6f 5f 4f 70 65 6e 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_H_2147706768_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel.H"
        threat_id = "2147706768"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(104) & Chr(116) & \"t\" & Chr(112) & Chr(58) & \"/\" & \"/\"" ascii //weight: 1
        $x_1_2 = "Chr(71) & \"E\" & Chr(84)," ascii //weight: 1
        $x_1_3 = "& Chr(46) & \"e\" & Chr(120) & \"e\", False" ascii //weight: 1
        $x_1_4 = ".Environment(Chr(80) & Chr(114) & \"o\" & Chr(99) & Chr(101) & \"s\" & \"s\")" ascii //weight: 1
        $x_1_5 = "\"T\" & Chr(69) & Chr(77) & Chr(80))" ascii //weight: 1
        $x_1_6 = "Chr(65) & \"do\" & Chr(100) & Chr(98) & Chr(46) & Chr(83) & Chr(116) & Chr(114) & Chr(101) & \"a\" & Chr(109)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_I_2147706819_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel.I"
        threat_id = "2147706819"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/fs05n5.sendspace.com/dl/8f350cadb8140b776b544073342411ba/561434e86a3f646e/qn4j6n/2222222222222.exe" ascii //weight: 1
        $x_1_2 = "Environ(\"AppData\") & \"\\\" & \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Adnel_Q_2147708961_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Adnel.Q"
        threat_id = "2147708961"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Adnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 6f 64 20 28 28 (30|2d|39) (30|2d|39) [0-3] 20 (2b|2d) 20 (30|2d|39) (30|2d|39) [0-3] 20 (2b|2d) 20 00 01 20 (2b|2d) 20 03 04 20 (2b|2d) 20 00 01 20 (2b|2d) 20 03 04}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 74 72 43 6f 6e 76 28 [0-8] 2c 20 28 (30|2d|39) (30|2d|39) [0-3] 20 (2b|2d) 20 (30|2d|39) (30|2d|39) [0-3] 20 (2b|2d) 20 01 02 20 (2b|2d) 20 04 05 20 (2b|2d) 20 01 02 20 (2b|2d) 20 04 05}  //weight: 1, accuracy: Low
        $x_1_3 = {29 20 3d 20 28 (30|2d|39) (30|2d|39) 2e [0-3] 20 (2b|2d) 20 (30|2d|39) (30|2d|39) [0-3] 20 (2b|2d) 20 00 2e 01 20 (2b|2d) 20 03 04 20 (2b|2d) 20 00 2e 01 20 (2b|2d) 20 03 04 [0-24] 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

