rule TrojanDownloader_O97M_Qakbot_DHA_2147753234_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.DHA!MTB"
        threat_id = "2147753234"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 [0-5] 20 2b 20 22 20 22 20 2b 20 [0-5] 2c 20 30 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 54 61 67 20 3d 20 [0-15] 28 22 [0-31] 22 29 20 2b 20 43 53 74 72 28 69 6e 64 29 20 2b 20 [0-15] 28 22 [0-15] 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 73 67 42 6f 78 20 28 22 [0-15] 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {44 69 72 28 [0-15] 28 22 [0-31] 22 29 2c 20 76 62 44 69 72 65 63 74 6f 72 79 29 20 3d 20 22 22}  //weight: 1, accuracy: Low
        $x_1_5 = "GoodNight T * 1000" ascii //weight: 1
        $x_1_6 = {2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 2e 54 61 67 20 3d 20 [0-15] 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 2e 43 61 70 74 69 6f 6e 20 2b 20 22 [0-5] 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_B_2147753959_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.B!MTB"
        threat_id = "2147753959"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "#If VBA7 Then" ascii //weight: 1
        $x_1_2 = {2e 4f 70 74 69 6f 6e 42 75 74 74 6f 6e 31 2e 54 61 67 20 3d 20 [0-21] 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e 20 2b 20 [0-21] 2e 4c 61 62 65 6c 31 2e 54 61 67}  //weight: 1, accuracy: Low
        $x_1_3 = {2a 20 53 69 6e 28 [0-18] 20 2b 20 [0-16] 20 2a 20 54 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2a 20 43 6f 73 28 [0-18] 20 2b 20 [0-16] 20 2a 20 54 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 2e 43 61 70 74 69 6f 6e 20 3d 20 22 [0-8] 22 [0-8] 44 69 6d}  //weight: 1, accuracy: Low
        $x_1_6 = {4d 69 64 24 28 [0-18] 2c 20 [0-2] 2c 20 [0-1] 29 20 3d 20 43 68 72 28 41 73 63 28 4d 69 64 24 28 [0-18] 2c 20 [0-1] 2c 20 [0-1] 29 29 20 2d 20 31 29}  //weight: 1, accuracy: Low
        $x_1_7 = {42 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 2e 54 61 67 20 2b 20 22 [0-2] 22 [0-16] 4e 65 78 74 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_YA_2147754913_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.YA!MTB"
        threat_id = "2147754913"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hertil.CreateTextFile(\"C:\\ProgramData\\OIUTFuy" ascii //weight: 1
        $x_1_2 = ".WriteLine (\"JerinTra\")" ascii //weight: 1
        $x_1_3 = "Rederest.Exec \"explorer.exe \" & Trest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_BQ_2147763159_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.BQ!MTB"
        threat_id = "2147763159"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= IYTGGDUGHDF.CreateTextFile(\"C:\\ProgramData\\OIUTFuy\", True)" ascii //weight: 1
        $x_1_2 = ".Exec \"explorer.exe \" & HETRIOOUIDBDTYFTFFSDFD.DefaultTargetFrame" ascii //weight: 1
        $x_1_3 = ".WriteLine (\"JerinTra\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_BQ_2147763159_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.BQ!MTB"
        threat_id = "2147763159"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= IYTGGDUGHDF.CreateTextFile(\"C:\\ProgramData\\OIUTFuy\", True)" ascii //weight: 1
        $x_1_2 = ".Exec \"explorer.exe \" & GFFGHFKFKfffkfdkdfDfdtydx.DefaultTargetFrame" ascii //weight: 1
        $x_1_3 = ".WriteLine (\"'BoliHas\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_SS_2147763975_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.SS!MTB"
        threat_id = "2147763975"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://onlinecompaniehouse.com/sorv.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_SS_2147763975_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.SS!MTB"
        threat_id = "2147763975"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://china.asiaspain.com/tertgev/" ascii //weight: 1
        $x_1_2 = "C:\\Test\\test2\\Fiksat.exe" ascii //weight: 1
        $x_1_3 = "1247015.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_SS_2147763975_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.SS!MTB"
        threat_id = "2147763975"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "online-companieshouse.com/ite.png" ascii //weight: 1
        $x_1_2 = "C:\\glimpi\\duot.poi" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "rundll32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_SS_2147763975_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.SS!MTB"
        threat_id = "2147763975"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uRlMon" ascii //weight: 1
        $x_1_2 = "CreateDirectoryA" ascii //weight: 1
        $x_1_3 = "FileProtocolHandler" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_10_5 = "http://bartstoppel.com/rqfardzsgihu/555555555.png" ascii //weight: 10
        $x_10_6 = "http://oceanbm.ca/hpplo/555555555.png" ascii //weight: 10
        $x_10_7 = "http://heavenlyhealinghands.org/beezxvdsxe/555555555.png" ascii //weight: 10
        $x_10_8 = "http://veteransplumbingandsewer.com/rvevbrpazcgj/555555555.png" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Qakbot_SS_2147763975_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.SS!MTB"
        threat_id = "2147763975"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"t\"&\"t\"&\"p\"&\"s://barnetcut.co.uk/SfCQDfYjWj/y.html" ascii //weight: 1
        $x_1_2 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://min6jembrana.com/eaMUGAXDtJ/y.html" ascii //weight: 1
        $x_1_3 = "h\"&\"t\"&\"t\"&\"p\"&\"s://biocomm.com.mx/1KtDYOUpkXm1/y.html" ascii //weight: 1
        $x_1_4 = "h\"&\"t\"&\"t\"&\"p\"&\"s://magnascakes.com.br/aQ6mO5EsFPz/yh.html" ascii //weight: 1
        $x_1_5 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://sherwinclothing.in/oqxIAZfo56z/yh.html" ascii //weight: 1
        $x_1_6 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://microtechzambia.com/utGI12nl/yh.html" ascii //weight: 1
        $x_1_7 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://klevvrtech.com/zxywJAC24KJ/ji.html" ascii //weight: 1
        $x_1_8 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://srkcampus.org/OYcMRJbL/ji.html" ascii //weight: 1
        $x_1_9 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://rstebet.co.id/fbmKk6n48G/ji.html" ascii //weight: 1
        $x_1_10 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://headlineproductions.ro/rOJX6ai7AkZE/op.html" ascii //weight: 1
        $x_1_11 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://jrcapital.uk/eft8gfFqw/op.html" ascii //weight: 1
        $x_1_12 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://lc-bilingua.com/8wp9k9RPDzn/op.html" ascii //weight: 1
        $x_1_13 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://projectgora.com/h02jMo6ez/li.html" ascii //weight: 1
        $x_1_14 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://twobudgettravelers.com/F9AOdLDgn7E/li.html" ascii //weight: 1
        $x_1_15 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://soringesprings.com/FKhpWSy3vQM/li.html" ascii //weight: 1
        $x_1_16 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://dostirealty.co/P9kjs85EJB/yy1.html" ascii //weight: 1
        $x_1_17 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://go.iscpelsalvador.org/hxIi071xf/yy2.html" ascii //weight: 1
        $x_1_18 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://system.sevenseriesmlm.com/AGsxCCeHHpI0/yy3.html" ascii //weight: 1
        $x_1_19 = "h\"&\"t\"&\"t\"&\"p\"&\":/\"&\"/do\"&\"cs\"&\"gy\"&\"an\"&\".c\"&\"o\"&\"m/w\"&\"p-i\"&\"n\"&\"cl\"&\"ud\"&\"es/6q\"&\"cI" ascii //weight: 1
        $x_1_20 = "h\"&\"t\"&\"t\"&\"p\"&\":/\"&\"/pi\"&\"lo\"&\"ts\"&\"ci\"&\"en\"&\"ce\"&\".c\"&\"o\"&\"m/Ha\"&\"li\"&\"ma\"&\"t/2R" ascii //weight: 1
        $x_1_21 = "h\"&\"t\"&\"t\"&\"p\"&\"://o\"&\"ne\"&\"au\"&\"di\"&\"o.w\"&\"or\"&\"ld\"&\"/su\"&\"bc\"&\"on\"&\"st\"&\"ab\"&\"le" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_AR_2147765290_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.AR!MTB"
        threat_id = "2147765290"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "1254750.png" ascii //weight: 10
        $x_10_2 = "C:\\Test\\test2\\Fiksat.exe" ascii //weight: 10
        $x_1_3 = "OpenURL" ascii //weight: 1
        $x_10_4 = "http://dimas.stifar.ac.id/vjrzzufsu/" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Qakbot_AR_2147765290_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.AR!MTB"
        threat_id = "2147765290"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLDownloadToFileA" ascii //weight: 1
        $x_10_2 = "C:\\COsuv\\Wegerb\\szvMhegn.exe" ascii //weight: 10
        $x_1_3 = "URLMon" ascii //weight: 1
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
        $x_10_5 = "http://tak-tik.site/crun20.gif" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Qakbot_AR_2147765290_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.AR!MTB"
        threat_id = "2147765290"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\Iopsd\\" ascii //weight: 10
        $x_20_2 = "http://traducerejuridica.ro/tenlxhlzpagc/D" ascii //weight: 20
        $x_20_3 = "http://traducerejuridica.ro/tenlxhlzpagc/625986.png" ascii //weight: 20
        $x_10_4 = {65 78 65 07 00 00 7a 69 70 66 6c 64 72 03 00 00 4d 6f 6e 06 00 00 4a 4a 43 43 43 4a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            ((1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Qakbot_YB_2147765631_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.YB!MTB"
        threat_id = "2147765631"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://www.crl-lhk.eus/bbvnoti/530340.png" ascii //weight: 2
        $x_2_2 = "https://www.notamuzikaletleri.com/19.gif" ascii //weight: 2
        $x_1_3 = "C:\\Datop\\" ascii //weight: 1
        $x_1_4 = "C:\\WErtu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Qakbot_YD_2147765996_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.YD!MTB"
        threat_id = "2147765996"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://jabba.fun/crun20.gif" ascii //weight: 2
        $x_1_2 = "C:\\COsuv\\Wegerb\\szvMhegn.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_RV_2147766024_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.RV!MTB"
        threat_id = "2147766024"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.domoportugal.com/abrvmf/5555555555.jpg" ascii //weight: 1
        $x_1_2 = "URLDownloadToFile 0, Guikghjgfh, Btdufjkhn, 0, 0" ascii //weight: 1
        $x_1_3 = "Loser = \"http://\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_RQ_2147767064_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.RQ!MTB"
        threat_id = "2147767064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"..\\Lifas.ver2\"" ascii //weight: 1
        $x_1_2 = "Sub auto_open()" ascii //weight: 1
        $x_1_3 = "Set Fera = Excel4IntlMacroSheets" ascii //weight: 1
        $x_1_4 = {6e 65 74 20 3d 20 22 75 52 22 0d 0a 6e 65 74 31 20 3d 20 22 4d 6f 6e 22 0d 0a 64 66 66 20 3d 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 22 0d 0a 64 66 66 31 20 3d 20 22 54 6f 46 69 6c 65 41 22}  //weight: 1, accuracy: High
        $x_1_5 = "\"=HALT()\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_RVA_2147767119_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.RVA!MTB"
        threat_id = "2147767119"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "regsvr32 /s  C:\\ProgramData\\Plo.ocx" ascii //weight: 5
        $x_5_2 = "regsvr32 /s  C:\\ProgramData\\Plo1.ocx" ascii //weight: 5
        $x_5_3 = "regsvr32 /s  C:\\ProgramData\\Plo2.ocx" ascii //weight: 5
        $x_1_4 = {75 52 6c 4d 6f 6e ?? ?? ?? 55 52 4c 44 20 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Qakbot_PQ_2147767218_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PQ!MTB"
        threat_id = "2147767218"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JRyf = \"E\" & \"\" & \"X\" & \"\" & \"E\" & \"\" & \"C" ascii //weight: 1
        $x_1_2 = "Jtruhrdrgdg = Nolert.Nikas.Caption & \" -silent ..\\Celod.wac" ascii //weight: 1
        $x_1_3 = "Sheets(\"Boolt\").Range(\"K18\") = \".d\" & \"a\" & \"t" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_GRA_2147767389_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.GRA!MTB"
        threat_id = "2147767389"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://erikvanwel.nl/xyqfosnmcmq/" ascii //weight: 1
        $x_1_2 = "C:\\Gravity\\Gravity2\\Fiksat.exe" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_RAE_2147767447_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.RAE!MTB"
        threat_id = "2147767447"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Gravity\\Gravity2\\Fiksat.exe" ascii //weight: 1
        $x_1_2 = "http://sglr2.revpdev.com/syaposot/" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_GRB_2147767762_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.GRB!MTB"
        threat_id = "2147767762"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.nowemiasteczko.pl/cigpndrozhm/" ascii //weight: 1
        $x_1_2 = "C:\\Gravity\\Gravity2\\Fiksat.exe" ascii //weight: 1
        $x_1_3 = "CreateDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_GDE_2147767798_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.GDE!MTB"
        threat_id = "2147767798"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "laravel.gallamoda.com/deflgrqanqmv/" ascii //weight: 1
        $x_1_2 = "CreateDirectoryA" ascii //weight: 1
        $x_1_3 = "C:\\Gravity\\Gravity2\\Fiksat.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_GRD_2147768547_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.GRD!MTB"
        threat_id = "2147768547"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bulkarabia.xyz/xzxuwtpvw/" ascii //weight: 1
        $x_1_2 = "C:\\Gravity\\Gravity2\\Fiksat.exe" ascii //weight: 1
        $x_1_3 = "CreateDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_RS_2147769223_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.RS!MTB"
        threat_id = "2147769223"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 68 6d 6e 63 62 64 2e 63 6f 6d 2f 64 73 2f 32 33 31 31 32 30 2e 67 69 66 3f 00 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 75 73 74 68 72 6e 67 2e 63 6f 6d 2f 64 73 2f 32 33 31 31 32 30 2e 67 69 66 3f 00 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {63 68 69 63 61 2e 6d 65 64 69 61 2f 64 73 2f 32 33 31 31 32 30 2e 67 69 66 3f 00 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_5_4 = "RLDownloadToFileA" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Qakbot_FIS_2147769297_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.FIS!MTB"
        threat_id = "2147769297"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://fisicamp.com/ds/231120.gif" ascii //weight: 1
        $x_1_2 = "https://boatssa.com/ds/231120.gif" ascii //weight: 1
        $x_1_3 = "https://feromon.shop/ds/231120.gif" ascii //weight: 1
        $x_1_4 = "https://avra.dtmh.gr/ds/231120.gif" ascii //weight: 1
        $x_1_5 = "http://panzr.tech/ds/231120.gif" ascii //weight: 1
        $x_1_6 = "https://kenas888.com/ds/231120.gif" ascii //weight: 1
        $x_1_7 = "https://rlink011.pw/ds/231120.gif" ascii //weight: 1
        $x_1_8 = "RLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_AJU_2147769585_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.AJU!MTB"
        threat_id = "2147769585"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f [0-4] 7a 6f 6e 61 2d 72 65 6c 61 78 2e 72 75 2f 69 72 6f 6a 72 6a 65 6a 6f 66 76 72 2f [0-4] 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\LotWin\\LotWin2\\Horsew.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_FIT_2147769632_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.FIT!MTB"
        threat_id = "2147769632"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://7pillars.in/ds/291120.gif" ascii //weight: 1
        $x_1_2 = "https://eylaw.ro/ds/291120.gif" ascii //weight: 1
        $x_1_3 = "C:\\giogti" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_FIL_2147769694_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.FIL!MTB"
        threat_id = "2147769694"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://tiesta.in/ds/291120.gif" ascii //weight: 1
        $x_1_2 = "http://expandcpa.com/ds/291120.gif" ascii //weight: 1
        $x_1_3 = "http://vytyazhki.by/ds/291120.gif" ascii //weight: 1
        $x_1_4 = "http://bagrover.com/ds/291120.gif" ascii //weight: 1
        $x_1_5 = "http://bumka.com.ua/ds/291120.gif" ascii //weight: 1
        $x_1_6 = "https://auroratd.cf/ds/291120.gif" ascii //weight: 1
        $x_1_7 = "http://dev.zemp.com/ds/291120.gif" ascii //weight: 1
        $x_1_8 = "http://micmart.store/ds/291120.gif" ascii //weight: 1
        $x_1_9 = "https://viraugra.com/ds/291120.gif" ascii //weight: 1
        $x_1_10 = "https://nyuscape.xyz/ds/291120.gif" ascii //weight: 1
        $x_1_11 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_AJV_2147769710_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.AJV!MTB"
        threat_id = "2147769710"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f [0-4] 77 77 77 2e 74 68 65 6a 72 67 73 2e 63 6f 6d 2f 70 6c 62 66 79 72 70 71 69 6f 2f [0-4] 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\Flopers\\Flopers2\\Bilore.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_ASL_2147770011_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.ASL!MTB"
        threat_id = "2147770011"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\gHnbfKt\\" ascii //weight: 1
        $x_1_2 = "htfBj.dll" ascii //weight: 1
        $x_1_3 = {68 74 74 70 3a 2f 2f [0-4] 6e 61 72 75 6d 69 2e 6d 6e 2f 64 73 2f 30 34 31 32 32 30 2e 67 69 66}  //weight: 1, accuracy: Low
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-4] 74 65 74 65 6b 2e 72 75 2f 64 73 2f 30 34 31 32 32 30 2e 67 69 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_BK_2147770047_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.BK!MTB"
        threat_id = "2147770047"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell a5D93y & \" \" & aZOe8a" ascii //weight: 1
        $x_1_2 = "= \"10.23.31.3.0.29.10.29\"" ascii //weight: 1
        $x_1_3 = "= Split(awoQn2, \".\")" ascii //weight: 1
        $x_1_4 = "= amGpi(a3ZlWG(acXTD0))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_BK_2147770047_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.BK!MTB"
        threat_id = "2147770047"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"10.23.31.3.0.29.10.29\"" ascii //weight: 1
        $x_1_2 = "Shell adNAj & \" \" & a2Uqik" ascii //weight: 1
        $x_1_3 = "= Split(a3dmi, \".\")" ascii //weight: 1
        $x_1_4 = "Call aB0nvd(a2Uqik, ahrU8V(aWfjHg))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_BK_2147770047_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.BK!MTB"
        threat_id = "2147770047"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "& \"xs\" & acf8Y" ascii //weight: 1
        $x_1_2 = "& \"com\"" ascii //weight: 1
        $x_1_3 = "CreateObject(\"wscript.shell\").exec ayaXI(" ascii //weight: 1
        $x_1_4 = {26 20 61 74 5a 68 51 28 22 63 6f 6d 6d 65 6e 74 73 22 29 20 26 20 61 6f 54 41 36 53 20 26 20 [0-10] 20 26 20 61 6f 54 41 36 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_BK_2147770047_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.BK!MTB"
        threat_id = "2147770047"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= aMSIO & \"\\m1.xsl\"" ascii //weight: 1
        $x_1_2 = "= aMSIO & \"\\m1.com\"" ascii //weight: 1
        $x_1_3 = "= CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_4 = "adFWA.run aXo4vp & aRlMyx(\"comments\") & amE2ak & a9Dz5t & amE2ak" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_BK_2147770047_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.BK!MTB"
        threat_id = "2147770047"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= aSGr0w & \"xs\" & acf8Y" ascii //weight: 1
        $x_1_2 = "= aSGr0w & \"com\"" ascii //weight: 1
        $x_1_3 = "CreateObject(\"wscript.shell\").exec ayaXI(axBTCF, aole0)" ascii //weight: 1
        $x_1_4 = "= axBTCF & atZhQ(\"comments\") & aoTA6S & aole0 & aoTA6S" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_BK_2147770047_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.BK!MTB"
        threat_id = "2147770047"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= a9t1m8 & \"\\h1.xsl\"" ascii //weight: 1
        $x_1_2 = "= a9t1m8 & \"\\h1.com\"" ascii //weight: 1
        $x_1_3 = "CreateObject(\"wscript.shell\").exec aqTf5d(a4UCwk, aXmKa0)" ascii //weight: 1
        $x_1_4 = "= a4UCwk & aD63BN(\"comments\") & agHu8 & aXmKa0 & agHu8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_BK_2147770047_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.BK!MTB"
        threat_id = "2147770047"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_2 = "= aGJxV(ajc9Rz(acBN3(aLVyH), 10))" ascii //weight: 1
        $x_1_3 = "Interaction.Shell \"C:\\Windows\\explorer.exe \" & aFoes" ascii //weight: 1
        $x_1_4 = "= Chr(\"\" & aBu0zs & \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_BK_2147770047_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.BK!MTB"
        threat_id = "2147770047"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"10.23.31.3.0.29.10.29\"" ascii //weight: 1
        $x_1_2 = "= Split(a9zoO, \".\")" ascii //weight: 1
        $x_1_3 = "= Split(apBfxW, \".\")" ascii //weight: 1
        $x_1_4 = "Shell aYHlk & \" \" & abySL4" ascii //weight: 1
        $x_1_5 = "Shell aIZJzl & \" \" & a8tRbq" ascii //weight: 1
        $x_1_6 = {3d 20 61 65 41 46 53 28 61 45 41 4a 62 28 [0-10] 28 [0-10] 29 2c 20 31 31 31 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_QAA_2147770242_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.QAA!MTB"
        threat_id = "2147770242"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\gHnbfKt\\" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "cOhtfBj" ascii //weight: 1
        $x_1_4 = "http://kliksini.web.id/ds/061220.gif" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_KIL_2147770359_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.KIL!MTB"
        threat_id = "2147770359"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://khaugalliindia.com/ds/0812.gif" ascii //weight: 1
        $x_1_2 = "RLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "rundll32" ascii //weight: 1
        $x_1_4 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_DST_2147770513_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.DST!MTB"
        threat_id = "2147770513"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {23 49 66 20 56 42 41 37 20 54 68 65 6e 02 00 50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = "Alias \"URLDownloadToFileA\" (ByVal pCaller As Long, ByVal szURL As String, _" ascii //weight: 1
        $x_1_3 = "Public Function Dasert()" ascii //weight: 1
        $x_1_4 = "imgsrc = \"http://\" & Sheets(\"Docs\").Range(\"A35\")" ascii //weight: 1
        $x_1_5 = "dlpath = Sheets(\"Docs\").Range(\"R2\")" ascii //weight: 1
        $x_1_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 69 6d 67 73 72 63 2c 20 64 6c 70 61 74 68 2c 20 30 2c 20 30 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_ALS_2147770515_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.ALS!MTB"
        threat_id = "2147770515"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"AutoDrom\").Range(\"H10\") = \"=Friskos(0,H24&K17&K18,G10,0,0)" ascii //weight: 1
        $x_1_2 = "Sheets(\"AutoDrom\").Range(\"H11\") = \"=Friskos(0,H25&K17&K18,G11,0,0)" ascii //weight: 1
        $x_1_3 = "Sheets(\"AutoDrom\").Range(\"H12\") = \"=Friskos(0,H26&K17&K18,G12,0,0)" ascii //weight: 1
        $x_1_4 = "Sheets(\"AutoDrom\").Range(\"H9\") = \"=\" & UserForm2.Tag & \"(I9,I10&J10,I11,I12,,1,9)" ascii //weight: 1
        $x_1_5 = "Sheets(\"AutoDrom\").Range(\"H17\") = \"=\" & UserForm1.Tag & \"(I17)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_VA_2147771204_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.VA!MTB"
        threat_id = "2147771204"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\gvnpsd" ascii //weight: 1
        $x_1_2 = "\\bravag.exe" ascii //weight: 1
        $x_1_3 = "JJCCCJJ" ascii //weight: 1
        $x_1_4 = "Rout" ascii //weight: 1
        $x_1_5 = "expl" ascii //weight: 1
        $x_1_6 = "URLDown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_VA_2147771204_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.VA!MTB"
        threat_id = "2147771204"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "urlmon" ascii //weight: 1
        $x_1_2 = {65 6c 69 78 65 72 64 69 67 69 74 61 6c 6c 2e 63 6f 6d 2f 64 73 2f [0-15] 2e 67 69 66}  //weight: 1, accuracy: Low
        $x_1_3 = "C:\\ervio\\copr.rsgs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_VA_2147771204_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.VA!MTB"
        threat_id = "2147771204"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 6f 6f 73 74 70 69 65 74 65 72 2e 63 6f 6d 2f 64 73 2f [0-15] 2e 67 69 66}  //weight: 10, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "rundll32" ascii //weight: 1
        $x_1_4 = "C:\\ervio\\copr.rsgs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Qakbot_VA_2147771204_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.VA!MTB"
        threat_id = "2147771204"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\JIOLAS.RRTTOOKK" ascii //weight: 1
        $x_10_2 = {6b 61 6e 67 61 72 6f 6f 2e 74 65 63 68 6f 6e 65 78 74 2e 63 6f 6d 2f [0-15] 2f [0-15] 2e 6a 70 67}  //weight: 10, accuracy: Low
        $x_1_3 = {62 61 63 68 73 2e 67 72 6f 75 70 2f [0-15] 2f [0-15] 2e 6a 70 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_VA_2147771204_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.VA!MTB"
        threat_id = "2147771204"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "urlmon" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "C:\\IntelCompany\\JIOLAS.RRTTOOKK" ascii //weight: 1
        $x_10_4 = {2e 63 6f 6d 2f [0-15] 2f 35 35 35 35 35 35 35 35 35 35 35 2e 6a 70 67}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_VA_2147771204_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.VA!MTB"
        threat_id = "2147771204"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "lsx.1\\atadmargorp\\:c" ascii //weight: 1
        $x_1_2 = "moc.1\\atadmargorp\\:c" ascii //weight: 1
        $x_1_3 = "exe.cimw\\mebw\\23metsys\\swodniw\\:c" ascii //weight: 1
        $x_1_4 = {2e 72 75 6e 20 [0-15] 28 [0-15] 29 20 26 20 [0-15] 28 22 63 6f 6d 6d 65 6e 74 73 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 69 6c 65 43 6f 70 79 28 [0-15] 28 [0-15] 29 2c 20 [0-15] 28 [0-15] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_VA_2147771204_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.VA!MTB"
        threat_id = "2147771204"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 61 6b 69 73 61 61 74 2e 63 6f 6d 2f [0-15] 2f [0-15] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_2 = {61 74 65 6c 69 65 72 73 70 75 7a 7a 6c 65 2e 63 6f 6d 2f [0-15] 2f [0-15] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_3 = {77 77 77 2e 64 6f 6d 6f 70 6f 72 74 75 67 61 6c 2e 63 6f 6d 2f [0-15] 2f [0-15] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_4 = {6d 61 65 73 74 72 6f 63 61 72 6c 6f 74 2e 6e 65 74 2f [0-15] 2f [0-15] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_5 = {67 61 6e 65 73 61 6e 64 2e 63 6f 6d 2f [0-15] 2f [0-15] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_10_6 = "C:\\IntelCompany\\JIOLAS.RRTTOOKK" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Qakbot_DAE_2147771294_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.DAE!MTB"
        threat_id = "2147771294"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Alias \"URLDownloadToFileA\" (ByVal pCaller As Long, _" ascii //weight: 1
        $x_1_2 = "Public Function tres()" ascii //weight: 1
        $x_1_3 = "Dipode = \"http://\"" ascii //weight: 1
        $x_1_4 = {47 75 69 6b 67 68 6a 67 66 68 20 3d 20 [0-8] 20 26 20 53 68 65 65 74 73 28 22 46 69 6c 65 73 22 29 2e 52 61 6e 67 65 28 22 42 36 30 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = "Btdufjkhn = Sheets(\"Files\").Range(\"B56\")" ascii //weight: 1
        $x_1_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 47 75 69 6b 67 68 6a 67 66 68 2c 20 42 74 64 75 66 6a 6b 68 6e 2c 20 30 2c 20 30 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_ERY_2147771495_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.ERY!MTB"
        threat_id = "2147771495"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Function Viurni()" ascii //weight: 1
        $x_1_2 = "& Sheets(\"Docs2\").Range(\"AA5\")" ascii //weight: 1
        $x_1_3 = "dlpath = Sheets(\"Docs3\").Range(\"AA13\")" ascii //weight: 1
        $x_1_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 [0-7] 2c 20 64 6c 70 61 74 68 2c 20 30 2c 20 30 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {23 49 66 20 57 69 6e 36 34 20 54 68 65 6e [0-8] 23 45 6c 73 65 [0-7] 23 45 6e 64 20 49 66 02 00 23 45 6c 73 65 02 00 23 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_6 = {23 49 66 20 56 42 41 37 20 54 68 65 6e 02 00 50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 5f}  //weight: 1, accuracy: Low
        $x_1_7 = "Alias \"URLDownloadToFileA\" (ByVal pCaller As Long, _" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_VAP_2147773086_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.VAP!MTB"
        threat_id = "2147773086"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "String = \"97,124,116,104,107,118,97,118\"" ascii //weight: 1
        $x_1_2 = {28 53 70 6c 69 74 28 [0-15] 2c 20 22 2c 22 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 43 68 72 28 [0-15] 28 [0-15] 29 20 58 6f 72 20 34 29}  //weight: 1, accuracy: Low
        $x_1_4 = ".ShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_ALQ_2147773550_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.ALQ!MTB"
        threat_id = "2147773550"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Const acXTD0 As String = \"10.23.31.3.0.29.10.29\"" ascii //weight: 1
        $x_1_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 61 72 44 49 4c 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 31 32 2e 38 35 2e 35 31 2e 33 31 2e 32 39 2e 30 2e 38 2e 32 39 2e 31 34 2e 32 2e 31 31 2e 31 34 2e 32 37 2e 31 34 2e 35 31 2e 31 34 2e [0-21] 2e 36 35 2e 37 2e 32 37 2e 31 34 22}  //weight: 1, accuracy: Low
        $x_1_3 = {46 75 6e 63 74 69 6f 6e 20 61 4f 53 68 72 28 [0-7] 2c 20 [0-7] 29 [0-16] 20 3d 20 54 72 69 6d 28 [0-7] 20 58 6f 72 20 [0-7] 29}  //weight: 1, accuracy: Low
        $x_1_4 = {44 69 6d 20 [0-7] 20 41 73 20 53 74 72 69 6e 67 [0-16] 20 3d 20 22 22}  //weight: 1, accuracy: Low
        $x_1_5 = "Sub aGeZvo()" ascii //weight: 1
        $x_1_6 = "= amGpi(a3ZlWG(acXTD0))" ascii //weight: 1
        $x_1_7 = {53 68 65 6c 6c 20 [0-7] 20 26 20 22 20 22 20 26 20 [0-16] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_8 = {3d 20 53 70 6c 69 74 28 [0-7] 2c 20 22 2e 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_ALH_2147773663_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.ALH!MTB"
        threat_id = "2147773663"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-8] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 33 30 23 33 23 31 31 23 32 33 23 32 30 23 39 23 33 30 23 39 22}  //weight: 1, accuracy: Low
        $x_1_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-7] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 32 34 23 36 35 23 33 39 23 31 31 23 39 23 32 30 23 32 38 23 39 23 32 36 23 32 32 23 33 31 23 32 36 23 31 35 23 32 36 23 33 39 23 32 36 23 35 34 23 32 39 23 34 37 23 37 39 23 31 39 23 38 35 23 31 39 23 31 35 23 32 36 22}  //weight: 1, accuracy: Low
        $x_1_3 = "Shell \"explorer \" &" ascii //weight: 1
        $x_1_4 = {44 69 6d 20 [0-7] 20 41 73 20 53 74 72 69 6e 67 [0-7] 20 3d 20 22 22 02 00 46 6f 72 20 [0-7] 20 3d 20 30 20 54 6f 20 55 42 6f 75 6e 64 28 [0-7] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 6d 79 66 2e 74 65 78 74 31 2e 76 61 6c 75 65 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-7] 28 [0-7] 29 02 00 44 69 6d}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 4c 65 6e 28 [0-7] 29 [0-16] 20 3d 20 22 22 02 00 46 6f 72}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 20 54 72 69 6d 28 43 68 72 28 22 22 20 26 20 [0-7] 29 29 02 00 45 6e 64 20 49 66 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_8 = {3d 20 53 70 6c 69 74 28 [0-7] 2c 20 22 23 22 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 53 75 62}  //weight: 1, accuracy: Low
        $x_1_9 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-7] 29 [0-7] 2e 57 72 69 74 65 4c 69 6e 65 20 [0-21] 2e 43 6c 6f 73 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_AZ_2147773674_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.AZ!MTB"
        threat_id = "2147773674"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Application.Run \"aWo1I3\", agFiZ, alfhuv & \"mat : \"\"\" & aRyON & \"\"\"\"" ascii //weight: 1
        $x_1_2 = "axQg6R = au6vsT(frm.payload.text)" ascii //weight: 1
        $x_1_3 = "Call aCu24Q.ShellExecute(aNEXs, aKLnjT, \" \", SW_HIDE)" ascii //weight: 1
        $x_1_4 = "aozex = Split(au6vsT(frm.paths.text), \"|\")" ascii //weight: 1
        $x_1_5 = "Set FSO = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_6 = "FSO.CopyFile aYgus, agFiZ, 1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PBA_2147773675_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PBA!MTB"
        threat_id = "2147773675"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set FSO = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_2 = "FSO.CopyFile aE8mM, a9hyI, 1" ascii //weight: 1
        $x_1_3 = "a3Fkg = Split(aWYJj(frm.paths.text), \"|\")" ascii //weight: 1
        $x_1_4 = "Call au0Dw.ShellExecute(akdZ3, ajeWl, \" \", SW_HIDE)" ascii //weight: 1
        $x_1_5 = "a5VlTr = aWYJj(frm.payload.text)" ascii //weight: 1
        $x_1_6 = "Application.Run \"abf5C\", a9hyI, aMY6vX & \"mat : \"\"\" & a84oF & \"\"\"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PBB_2147773676_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PBB!MTB"
        threat_id = "2147773676"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set FSO = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_2 = "FSO.CopyFile aQBmb, aBHMDc, 1" ascii //weight: 1
        $x_1_3 = "a0e58C = Split(au6vsT(frm.paths.text), \"|\")" ascii //weight: 1
        $x_1_4 = "Dim aPruEN As New Shell32.Shell" ascii //weight: 1
        $x_1_5 = "Call aPruEN.ShellExecute(ah8UA, aQioXF, \" \", SW_HIDE)" ascii //weight: 1
        $x_1_6 = "aDBVJ3 = au6vsT(frm.payload.text)" ascii //weight: 1
        $x_1_7 = "Application.Run \"aWo1I3\", aBHMDc, adDMc & \"mat : \"\"\" & aLYCV & \"\"\"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PBC_2147773677_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PBC!MTB"
        threat_id = "2147773677"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set FSO = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_2 = "FSO.CopyFile a0fDTl, areVh6, 1" ascii //weight: 1
        $x_1_3 = "aVvtQU = Split(au6vsT(frm.paths.text), \"|\")" ascii //weight: 1
        $x_1_4 = "Dim awCSD As New Shell32.Shell" ascii //weight: 1
        $x_1_5 = "Call awCSD.ShellExecute(aJtTdW, aGBMlK, \" \", SW_HIDE)" ascii //weight: 1
        $x_1_6 = "ap6E1 = au6vsT(frm.payload.text)" ascii //weight: 1
        $x_1_7 = "Application.Run \"aWo1I3\", areVh6, aF3uyp & \"mat : \"\"\" & a1ZMyU & \"\"\"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_SHM_2147773817_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.SHM!MTB"
        threat_id = "2147773817"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FSO.CopyFile a9XBN, ajZSxF, 1" ascii //weight: 1
        $x_1_2 = "Split(a9H64(frm.paths.text), \"|\")" ascii //weight: 1
        $x_1_3 = "Call aK3sin.ShellExecute(aoOt7, aVxhc, \" \", SW_HIDE)" ascii //weight: 1
        $x_1_4 = "a9H64(frm.payload.text)" ascii //weight: 1
        $x_1_5 = "Chr(34)" ascii //weight: 1
        $x_1_6 = ".Run \"a9468u\", ajZSxF, aFHj6i & \"mat : " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_FOF_2147773819_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.FOF!MTB"
        threat_id = "2147773819"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 20 46 53 4f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 02 00 46 53 4f 2e 43 6f 70 79 46 69 6c 65 20 [0-7] 2c 20 [0-7] 2c 20 31 02 00 45 6e 64 20 53 75 62 02 00 53 75 62 20 [0-7] 28 [0-7] 2c 20 [0-7] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {4f 70 65 6e 20 [0-7] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 02 00 50 72 69 6e 74 20 23 31 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {43 6c 6f 73 65 20 23 31 02 00 45 6e 64 20 53 75 62 02 00 46 75 6e 63 74 69 6f 6e 20 [0-7] 28 [0-7] 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 53 70 6c 69 74 28 [0-7] 28 66 72 6d 2e 70 61 74 68 73 2e 74 65 78 74 29 2c 20 22 7c 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {45 6e 64 20 49 66 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-7] 28 [0-7] 2c 20 [0-7] 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 02 00 27}  //weight: 1, accuracy: Low
        $x_1_6 = {44 69 6d 20 [0-7] 20 41 73 20 4e 65 77 20 53 68 65 6c 6c 33 32 2e 53 68 65 6c 6c 02 00 43 61 6c 6c 20 [0-7] 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 [0-7] 2c 20 [0-7] 2c 20 22 20 22 2c 20 53 57 5f 48 49 44 45 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 53 75 62 20 [0-7] 28 29}  //weight: 1, accuracy: Low
        $x_1_7 = "(frm.payload.text)" ascii //weight: 1
        $x_1_8 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 [0-7] 22 2c 20 [0-7] 2c 20 [0-7] 20 26 20 22 [0-7] 20 3a 20 22 20 26 20 [0-7] 20 26 20 [0-7] 20 26 20 [0-16] 27}  //weight: 1, accuracy: Low
        $x_1_9 = {26 20 22 22 20 26 20 4d 69 64 28 [0-7] 2c 20 [0-7] 2c 20 31 29 02 00 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PCD_2147773820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PCD!MTB"
        threat_id = "2147773820"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Split(a9H64(frm.paths.text), \"|\")" ascii //weight: 1
        $x_1_2 = "Call ahwtUm.ShellExecute(aK4ST, a6sD9, \" \", SW_HIDE)" ascii //weight: 1
        $x_1_3 = "Application.Run \"a9468u\", aPKJt1, aPFYT & \"mat : \" & a7Cn9G & aRbMt & a7Cn9G" ascii //weight: 1
        $x_1_4 = "= a9H64(frm.payload.text)" ascii //weight: 1
        $x_1_5 = "Set FSO = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_6 = "FSO.CopyFile a4ewPq, aPKJt1, 1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_BIK_2147773822_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.BIK!MTB"
        threat_id = "2147773822"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Application.Run \"a9468u\", ajnzcW, aCmQ1 & \"mat : \" & azMfU & azW1X & azMfU" ascii //weight: 1
        $x_1_2 = "Call ab79M.ShellExecute(asKlrh, apvmc, \" \", SW_HIDE)" ascii //weight: 1
        $x_1_3 = "= Split(a9H64(frm.paths.text), \"|\")" ascii //weight: 1
        $x_1_4 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_RSA_2147774130_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.RSA!MTB"
        threat_id = "2147774130"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {65 6c 69 74 65 62 6c 6f 67 73 70 6f 74 2e 63 6f 6d 2f 64 73 2f 30 37 30 32 2e 67 69 66 30 00 4b 65 72 6e 65 6c 33 32 25 ?? ?? 68 74 74 70 73 3a 2f 2f}  //weight: 5, accuracy: Low
        $x_5_2 = {73 79 69 66 61 62 69 6f 64 65 72 6d 61 2e 63 6f 6d 2f 64 73 2f 30 39 30 32 2e 67 69 66 30 00 4b 65 72 6e 65 6c 33 32 25 ?? ?? 68 74 74 70 73 3a 2f 2f}  //weight: 5, accuracy: Low
        $x_1_3 = "\\iojhsfgv.dvers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Qakbot_RVD_2147774311_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.RVD!MTB"
        threat_id = "2147774311"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Application.Run Sheets(\"Fredi\").Range(\"H3\")" ascii //weight: 1
        $x_1_2 = "Nolert.Nikas.Caption & \" ..\\Celod.wac\"" ascii //weight: 1
        $x_1_3 = ".Range(\"I10\") = \"U\" & \"RL\" & \"Do\" & \"wn\" & \"lo\" & \"ad\" & \"To\" & \"Fi\" & \"le\" & \"A\"" ascii //weight: 1
        $x_1_4 = "Sheets(\"Fredi\").Range(\"A1:M100\").Font.Color = vbWhite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PUB_2147775934_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PUB!MTB"
        threat_id = "2147775934"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JJCCCJJ" ascii //weight: 1
        $x_1_2 = "JJCCBB" ascii //weight: 1
        $x_1_3 = "zipfldr" ascii //weight: 1
        $x_1_4 = "https://q1s0oci49jo.xyz/gutpage.php" ascii //weight: 1
        $x_1_5 = "C:\\roiwns" ascii //weight: 1
        $x_1_6 = "\\dsfsei.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PUE_2147775948_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PUE!MTB"
        threat_id = "2147775948"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JJCCCJJ" ascii //weight: 1
        $x_1_2 = "JJCCBB" ascii //weight: 1
        $x_1_3 = "zipfldr" ascii //weight: 1
        $x_1_4 = "https://yc1op3jh39r.xyz/gutpag.php" ascii //weight: 1
        $x_1_5 = "C:\\mvorp" ascii //weight: 1
        $x_1_6 = "\\oojfj.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PUF_2147775968_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PUF!MTB"
        threat_id = "2147775968"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "erServer" ascii //weight: 1
        $x_1_2 = "rundll3" ascii //weight: 1
        $x_1_3 = "URLMon" ascii //weight: 1
        $x_1_4 = "31.214.157.170/22." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PUH_2147776044_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PUH!MTB"
        threat_id = "2147776044"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\risno" ascii //weight: 1
        $x_1_2 = "\\isnos.exe" ascii //weight: 1
        $x_1_3 = "pfldr" ascii //weight: 1
        $x_1_4 = "teTheCall" ascii //weight: 1
        $x_1_5 = "JJCCCJJ" ascii //weight: 1
        $x_1_6 = "https://d7fv8iu3ovn.xyz/index.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_QDC_2147776239_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.QDC!MTB"
        threat_id = "2147776239"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 49 45 55 44 4c 4b 2e 43 4a 46 [0-4] 67 69 66}  //weight: 1, accuracy: Low
        $x_1_2 = "rundll3" ascii //weight: 1
        $x_1_3 = "DllR" ascii //weight: 1
        $x_1_4 = "LMon" ascii //weight: 1
        $x_1_5 = "erServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_QGW_2147776321_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.QGW!MTB"
        threat_id = "2147776321"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 49 45 55 44 4c 4b 2e 43 4a 46 [0-4] 67 69 66 [0-4] 72 75 6e [0-4] 64 6c 6c 33}  //weight: 1, accuracy: Low
        $x_1_2 = "DllR" ascii //weight: 1
        $x_1_3 = "erServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_RVF_2147776648_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.RVF!MTB"
        threat_id = "2147776648"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t\"&\"t\"&\"p://n\"&\"oe\"&\"lw\"&\"or\"&\"ks.c\"&\"o\"&\"m/b\"&\"an\"&\"d/4\"&\"4/\",\"" ascii //weight: 1
        $x_1_2 = "t\"&\"t\"&\"p://o\"&\"me\"&\"ga-a\"&\"na\"&\"ly\"&\"ti\"&\"cs.c\"&\"o\"&\"m/c\"&\"g\"&\"i-b\"&\"in/n\"&\"l1\"&\"aa\"&\"7G\"&\"D2\"&\"6O\"&\"R9/\",\"" ascii //weight: 1
        $x_1_3 = "t\"&\"t\"&\"p://w\"&\"w\"&\"w.o\"&\"rd\"&\"in\"&\"ar\"&\"ym\"&\"ag\"&\"az\"&\"in\"&\"e.o\"&\"r\"&\"g/_no\"&\"te\"&\"s/o\"&\"Mh\"&\"fA\"&\"AW\"&\"IB\"&\"Lr\"&\"Cz\"&\"a/\",\"" ascii //weight: 1
        $x_1_4 = "t\"&\"t\"&\"p://o\"&\"sh\"&\"o\"&\"p.e\"&\"s/t\"&\"es\"&\"t/yL\"&\"T3\"&\"Xj\"&\"ra\"&\"35\"&\"2k\"&\"y/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_RVG_2147776649_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.RVG!MTB"
        threat_id = "2147776649"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//u\"&\"ni\"&\"ro\"&\"ss.s\"&\"it\"&\"e/S\"&\"Vm\"&\"GtF\"&\"WU\"&\"NW\"&\"s/I.p\"&\"n\"&\"g\",\"" ascii //weight: 1
        $x_1_2 = "//al\"&\"ex\"&\"ad\"&\"ri\"&\"vi\"&\"ng\"&\"sc\"&\"ho\"&\"ol.o\"&\"nl\"&\"in\"&\"e/Vi\"&\"aa\"&\"wN\"&\"B\"&\"w/I.p\"&\"n\"&\"g\",\"" ascii //weight: 1
        $x_1_3 = "//a\"&\"db\"&\"oa\"&\"t.li\"&\"v\"&\"e/T\"&\"CA\"&\"1o\"&\"iq\"&\"k\"&\"A/I.p\"&\"n\"&\"g\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_VAV_2147776653_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.VAV!MTB"
        threat_id = "2147776653"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JJCCCJJ" ascii //weight: 1
        $x_1_2 = "Rout" ascii //weight: 1
        $x_1_3 = "eTheCall" ascii //weight: 1
        $x_1_4 = "expl" ascii //weight: 1
        $x_1_5 = ".xyz/index.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_VAV_2147776653_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.VAV!MTB"
        threat_id = "2147776653"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\iskne" ascii //weight: 1
        $x_1_2 = "\\osmwd.exe" ascii //weight: 1
        $x_1_3 = "JJCCCJJ" ascii //weight: 1
        $x_1_4 = "Rout" ascii //weight: 1
        $x_1_5 = "explorer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_RVB_2147780874_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.RVB!MTB"
        threat_id = "2147780874"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://renwinautovaluers.com/jQti5hjVS/PomK.png\"," ascii //weight: 1
        $x_1_2 = "://buy-100mgviagra.com/0cpRIDGdkB/PomK.png\"," ascii //weight: 1
        $x_1_3 = "://timeinindianow.com/2RZvX0fN33u/PomK.png\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_NQRT_2147794245_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.NQRT!MTB"
        threat_id = "2147794245"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"Sheet3\").Range(\"G12\") = \"..\\Xertis2.dll\"" ascii //weight: 1
        $x_1_2 = "Sheets(\"Sheet3\").Range(\"I17\") = \"regsvr32 -silent ..\\Xertis.dll\"" ascii //weight: 1
        $x_1_3 = "Sheets(\"Sheet3\").Range(\"H9\") = \"=REGISTER(I9,I10&J10,I11,I12,,1,9)\"" ascii //weight: 1
        $x_1_4 = "Sheets(\"Sheet3\").Range(\"K18\") = \".dat\"" ascii //weight: 1
        $x_1_5 = "Application.Run Sheets(\"Sheet3\").Range(\"H1\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDS_2147794431_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDS!MTB"
        threat_id = "2147794431"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 49 6d 63 68 74 72 69 61 5c 4e 69 74 75 62 73 72 74 61 5c [0-10] 6e 73 65 62 2e 4f 4f 4f 4f 4f 43 43 43 43 43 58 58 58 58 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_NQRS_2147794438_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.NQRS!MTB"
        threat_id = "2147794438"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"Sheet5\").Range(\"I17\") = \"regsvr32 -silent ..\\Xertis.dll\"" ascii //weight: 1
        $x_1_2 = "Sheets(\"Sheet5\").Range(\"H10\") = \"=Byukilos(0,H24&K17&K18,G10,0,0)\"" ascii //weight: 1
        $x_1_3 = "& \"EXEC(I17)\"" ascii //weight: 1
        $x_1_4 = "Sheets(\"Sheet5\").Range(\"K18\") = \".dat\"" ascii //weight: 1
        $x_1_5 = ".Range(\"H24\") = UserForm1.Label1.Caption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_NQTT_2147794439_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.NQTT!MTB"
        threat_id = "2147794439"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"Sheet5\").Range(\"I19\") = \"regsvr32 -silent ..\\Xertis2.dll\"" ascii //weight: 1
        $x_1_2 = "Sheets(\"Sheet5\").Range(\"H9\") = Drezden & \"REGISTER(I9,I10&J10,I11,I12,,1,9)\"" ascii //weight: 1
        $x_1_3 = "& \"EXEC(I18)\"" ascii //weight: 1
        $x_1_4 = "Sheets(\"Sheet5\").Range(\"K18\") = \".dat\"" ascii //weight: 1
        $x_1_5 = ".Range(\"H26\") = UserForm1.Label4.Caption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_NQRW_2147794463_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.NQRW!MTB"
        threat_id = "2147794463"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "regsvr32 -silent ..\\Xertis.dll" ascii //weight: 1
        $x_1_2 = "regsvr32 -silent ..\\Fiosa.der" ascii //weight: 1
        $x_1_3 = "regsvr32 -silent ..\\Violaf.der" ascii //weight: 1
        $x_1_4 = "UserForm1.Label3.Caption" ascii //weight: 1
        $x_1_5 = "REGISTER(I9,I10&J10,I11,I12,,1,9)" ascii //weight: 1
        $x_1_6 = "Byukilos" ascii //weight: 1
        $x_1_7 = ".Font.Color = vbWhite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_NQRX_2147794651_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.NQRX!MTB"
        threat_id = "2147794651"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Range(\"H25\") = UserForm2.Label3.Caption" ascii //weight: 1
        $x_1_2 = "regsvr32 -silent ..\\Drezd.red" ascii //weight: 1
        $x_1_3 = "(I9,I10&J10,I11,I12,,1,9)" ascii //weight: 1
        $x_1_4 = "Byukilos" ascii //weight: 1
        $x_1_5 = ".Font.Color = vbWhite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_NQRZ_2147795181_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.NQRZ!MTB"
        threat_id = "2147795181"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"..\\Celod.wac1" ascii //weight: 1
        $x_1_2 = "(I9,I10&J10,I11,I12,,1,9)" ascii //weight: 1
        $x_1_3 = "= \".d\" & \"a\" & \"t" ascii //weight: 1
        $x_1_4 = "= UserForm2.Label3.Caption" ascii //weight: 1
        $x_1_5 = ".Font.Color = vbWhite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_KAQA_2147795363_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.KAQA!MTB"
        threat_id = "2147795363"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bytruy = \"R\" & \"E\" & \"G\" & \"I\" & \"STER" ascii //weight: 1
        $x_1_2 = "Sheets(\"Diolare\").Range(\"K18\") = \".d\" & \"a\" & \"t" ascii //weight: 1
        $x_1_3 = "Sheets(\"Diolare\").Range(\"A1:M100\").Font.Color = vbWhite" ascii //weight: 1
        $x_1_4 = "Sheets(\"Diolare\").Range(\"I12\") = \"Byukilos" ascii //weight: 1
        $x_1_5 = "Sheets(\"Diolare\").Range(\"I19\") = Loiu & \"2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_KAQB_2147795364_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.KAQB!MTB"
        threat_id = "2147795364"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"Diolare\").Range" ascii //weight: 1
        $x_1_2 = "= UserForm2.Blost.Caption" ascii //weight: 1
        $x_1_3 = "Application.Run Sheets(\"Diolare\").Range" ascii //weight: 1
        $x_1_4 = "Sheets(\"Dashboard\").Protect Password:=Sheets(\"Dashboard\").Range" ascii //weight: 1
        $x_1_5 = "Sheets(\"Diolare\").Range(\"H25\") = UserForm2.Label3.Caption" ascii //weight: 1
        $x_1_6 = "= UserForm2.Label5.Caption & \"2\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_DOLE_2147796274_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.DOLE!MTB"
        threat_id = "2147796274"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "regsvr32\" & \" -silent ..\\Celod.wac" ascii //weight: 1
        $x_1_2 = "= \"Byukilos" ascii //weight: 1
        $x_1_3 = "= \".d\" & \"a\" & \"t" ascii //weight: 1
        $x_1_4 = "I9,I10&J10,I11,I12,,1,9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_DOLF_2147796275_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.DOLF!MTB"
        threat_id = "2147796275"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"h\" & \"tt\" & \"p\" & \":/\" & \"/190.14.37.202/" ascii //weight: 1
        $x_1_2 = "= \"h\" & \"tt\" & \"p\" & \":/\" & \"/185.244.150.174/" ascii //weight: 1
        $x_1_3 = "-silent ..\\Celod.wac" ascii //weight: 1
        $x_1_4 = "= Nolert.Label5.Caption & \"1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_DOLG_2147796566_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.DOLG!MTB"
        threat_id = "2147796566"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"re\" & \"gs\" & \"vr\" & \"32\" & \" -s\" & \"il\" & \"en\" & \"t ..\" & \"\\C\" & \"el\" & \"od\" & \".w\" & \"ac" ascii //weight: 1
        $x_1_2 = "= \"R\" & \"E\" & \"G\" & \"I\" & \"STER" ascii //weight: 1
        $x_1_3 = "= \".d\" & \"a\" & \"t" ascii //weight: 1
        $x_1_4 = "I9,I10&J10,I11,I12,,1,9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_DOLH_2147796567_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.DOLH!MTB"
        threat_id = "2147796567"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"Boolt\").Range(\"H24\") = \"h\" & \"tt\" & \"p\" & \":/\" & \"/190.14.37.226" ascii //weight: 1
        $x_1_2 = "Sheets(\"Boolt\").Range(\"H25\") = \"h\" & \"tt\" & \"p\" & \":/\" & \"/5.149.248.24" ascii //weight: 1
        $x_1_3 = "ddddddddd = \"h\" & \"tt\" & \"p\" & \":/\" & \"/176.31.87.211" ascii //weight: 1
        $x_1_4 = "Sheets(\"Boolt\").Range(\"A1:M100\").Interior.Color = vbBlack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDQ_2147796677_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDQ!MTB"
        threat_id = "2147796677"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "intconjsc.com/TBFQsJiVAv/Pmnhf.png" ascii //weight: 1
        $x_1_2 = "ktd-auto.com/vNQEgKwUwti8/Pmnhf.png" ascii //weight: 1
        $x_1_3 = "enoktextile.com/hjeBrBwMdY/Pmnhf.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_DOLI_2147796718_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.DOLI!MTB"
        threat_id = "2147796718"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bytruy = \"R\" & \"E\" & \"G\" & \"I\" & \"STER" ascii //weight: 1
        $x_1_2 = "agadfg = \" -s\" & \"il\" & \"en\" & \"t" ascii //weight: 1
        $x_1_3 = "dfdsaf = \" ..\" & \"\\C\" & \"el\" & \"od\" & \".w\" & \"ac" ascii //weight: 1
        $x_1_4 = "I9,I10&J10,I11,I12,,1,9" ascii //weight: 1
        $x_1_5 = "= \".d\" & \"a\" & \"t" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_DOLJ_2147796719_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.DOLJ!MTB"
        threat_id = "2147796719"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Application.Run Sheets(\"Boolt\").Range(\"H3\")" ascii //weight: 1
        $x_1_2 = "Sheets(\"Boolt\").Range(\"I10\") = \"U\" & \"RL\" & \"Do\" & \"wn\" & \"lo\" & \"ad\" & \"To\" & \"Fi\" & \"le\" & \"A" ascii //weight: 1
        $x_1_3 = "= Nolert.Label5.Caption & \"1" ascii //weight: 1
        $x_1_4 = "=Kopast(0,H24&K17&K18,G10,0,0)" ascii //weight: 1
        $x_1_5 = "C\" & \"el\" & \"od\" & \".w\" & \"ac" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_DOLK_2147796720_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.DOLK!MTB"
        threat_id = "2147796720"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"Boolt\").Range(\"H24\") = \"h\" & \"tt\" & \"p\" & \":/\" & \"/190.14.37.236/" ascii //weight: 1
        $x_1_2 = "Sheets(\"Boolt\").Range(\"H25\") = \"h\" & \"tt\" & \"p\" & \":/\" & \"/101.99.90.73/" ascii //weight: 1
        $x_1_3 = "ddddddddd = \"h\" & \"tt\" & \"p\" & \":/\" & \"/194.36.191.16/" ascii //weight: 1
        $x_1_4 = "Sheets(\"Boolt\").Range(\"A1:M100\").Interior.Color = vbBlack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_DOLL_2147796721_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.DOLL!MTB"
        threat_id = "2147796721"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Private Sub ssaaInitWorkbookssaa()" ascii //weight: 1
        $x_1_2 = "Excel4IntlMacroSheets.Add.Name = \"Boolt" ascii //weight: 1
        $x_1_3 = "Sheets(\"Boolt\").Range(\"I11\") = \"J\" & \"J\" & \"C\" & \"C\" & \"B\" & \"B" ascii //weight: 1
        $x_1_4 = "Sheets(\"Boolt\").Range(\"I12\") = \"Kopast" ascii //weight: 1
        $x_1_5 = "= Jtruhrdrgdg & agadfg & dfdsaf & \"2" ascii //weight: 1
        $x_1_6 = "Jtruhrdrgdg = \"re\" & \"gs\" & \"vr\" & \"32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_TADC_2147796858_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.TADC!MTB"
        threat_id = "2147796858"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "agadfg = \" -\" & \"s\" & \"i\" & \"l\" & \"e\" & \"n\" & \"t" ascii //weight: 1
        $x_1_2 = "dfdsaf = \" ..\" & \"\\C\" & \"el\" & \"od\" & \".w\" & \"ac" ascii //weight: 1
        $x_1_3 = "I9,I10&J10,I11,I12,,1,9" ascii //weight: 1
        $x_1_4 = "= \".d\" & \"a\" & \"t" ascii //weight: 1
        $x_1_5 = "= \"E\" & \"X\" & \"E\" & \"C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_TADD_2147796859_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.TADD!MTB"
        threat_id = "2147796859"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"..\\Celod.wac" ascii //weight: 1
        $x_1_2 = "= \"..\\Celod.wac\" & \"1" ascii //weight: 1
        $x_1_3 = "= \"..\\Celod.wac\" & \"2" ascii //weight: 1
        $x_1_4 = ".d\" & \"a\" & \"t\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_TADE_2147796860_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.TADE!MTB"
        threat_id = "2147796860"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"Noieetfdhg\").Range(\"H24\") = dgdgerwrh & \"p\" & \":/\" & \"/190.14.37.244" ascii //weight: 1
        $x_1_2 = "Sheets(\"Noieetfdhg\").Range(\"H25\") = dgdgerwrh & \"p\" & \":/\" & \"/194.36.191.35" ascii //weight: 1
        $x_1_3 = "Application.Run Sheets(\"Noieetfdhg\").Range(\"H3\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_TADF_2147796861_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.TADF!MTB"
        threat_id = "2147796861"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"Noieetfdhg\").Range(\"H10\") = \"=Kopast(0,H24&K17&K18,G10,0,0)" ascii //weight: 1
        $x_1_2 = "Sheets(\"Noieetfdhg\").Range(\"H11\") = \"=Kopast(0,H25&K17&K18,G11,0,0)" ascii //weight: 1
        $x_1_3 = "Sheets(\"Noieetfdhg\").Range(\"H12\") = \"=Kopast(0,H26&K17&K18,G12,0,0)" ascii //weight: 1
        $x_1_4 = "C\" & \"el\" & \"od\" & \".w\" & \"ac" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_ALT_2147796978_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.ALT!MTB"
        threat_id = "2147796978"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set Nolan = Excel4IntlMacroSheets" ascii //weight: 1
        $x_1_2 = "Sheets(\"AutoDrom\").Range(\"H24\") = \"http://190.14.37.253" ascii //weight: 1
        $x_1_3 = "Sheets(\"AutoDrom\").Range(\"H25\") = \"http://94.140.112.172" ascii //weight: 1
        $x_1_4 = "Sheets(\"AutoDrom\").Range(\"H26\") = \"http://91.242.229.229" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_DOLP_2147797074_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.DOLP!MTB"
        threat_id = "2147797074"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dio = \"=Kopast" ascii //weight: 1
        $x_1_2 = "Sheets(\"Fikop\").Range(\"H10\") = Dio & \"(0,H24&K17&K18,G10,0,0)" ascii //weight: 1
        $x_1_3 = "Sheets(\"Fikop\").Range(\"H11\") = Dio & \"(0,H25&K17&K18,G11,0,0)" ascii //weight: 1
        $x_1_4 = "Sheets(\"Fikop\").Range(\"H12\") = Dio & \"(0,H26&K17&K18,G12,0,0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_DOLQ_2147797075_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.DOLQ!MTB"
        threat_id = "2147797075"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"Fikop\").Range(\"I9\") = net & \"l\" & net1" ascii //weight: 1
        $x_1_2 = "Sheets(\"Fikop\").Range(\"K18\") = \".d" ascii //weight: 1
        $x_1_3 = "Sheets(\"Fikop\").Range(\"K17\") = \"=N" ascii //weight: 1
        $x_1_4 = "Sheets(\"Fikop\").Range(\"I10\") = \"U\" & \"R\" & \"L\" & \"D\" & \"o\" & \"w\" & \"n\" & \"l\" & \"o\" & \"a\" & \"d\" & \"T\" & \"o\" & \"F\" & \"i\" & \"l\" & \"e\" & \"A" ascii //weight: 1
        $x_1_5 = "Sheets(\"Fikop\").Range(\"I10\") = \"U\" + \"R\" + \"L\" + \"D\" + \"o\" + \"w\" + \"n\" + \"l\" + \"o\" + \"a\" + \"d\" + \"T\" + \"o\" + \"F\" + \"i\" + \"l\" + \"e\" + \"A" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_DOLR_2147797076_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.DOLR!MTB"
        threat_id = "2147797076"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"Fikop\").Range(\"G10\") = \"..\\GiCelod.waGic" ascii //weight: 1
        $x_1_2 = "Sheets(\"Fikop\").Range(\"G11\") = \"..\\GiCelod.waGic\"" ascii //weight: 1
        $x_1_3 = "Sheets(\"Fikop\").Range(\"G12\") = \"..\\GiCelod.waGic\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_DOLT_2147797077_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.DOLT!MTB"
        threat_id = "2147797077"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dgdgerwrh = \"h\" & \"t\" & \"t\" & \"p\" & \":\" & \"/\" & \"/\"" ascii //weight: 1
        $x_1_2 = "Sheets(\"Fikop\").Range(\"H24\") = dgdgerwrh & \"190.14.37.247" ascii //weight: 1
        $x_1_3 = "Sheets(\"Fikop\").Range(\"H25\") = dgdgerwrh & \"51.89.115.113" ascii //weight: 1
        $x_1_4 = ".Interior.Color = vbBlack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_DOLV_2147797078_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.DOLV!MTB"
        threat_id = "2147797078"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Application.Run Sheets(\"Fikop\").Range(\"H3\")" ascii //weight: 1
        $x_1_2 = "GiC\" & \"el\" & \"od\" & \".w\" & \"aGic" ascii //weight: 1
        $x_1_3 = "JRyf = \"E\" & \"X\" & \"E\" & \"C" ascii //weight: 1
        $x_1_4 = "Bytruy = \"R\" & \"E\" & \"G\" & \"I\" & \"STER" ascii //weight: 1
        $x_1_5 = "& \"s\" & \"i\" & \"l\" & \"e\" & \"n\" & \"t" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_DOLZ_2147797468_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.DOLZ!MTB"
        threat_id = "2147797468"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GiCelod.waGic" ascii //weight: 1
        $x_1_2 = "Application.Run Sheets(\"Fikop\").Range(\"H3\")" ascii //weight: 1
        $x_1_3 = ".Interior.Color = vbBlack" ascii //weight: 1
        $x_1_4 = "Sheets(\"Fikop\").Delete" ascii //weight: 1
        $x_1_5 = "Set Fera = Excel4IntlMacroSheets" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_ALJ_2147798086_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.ALJ!MTB"
        threat_id = "2147798086"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"AutoDrom\").Range(\"H9\") = \"=\" & UserForm2.Tag & \"(I9,I10&J10,I11,I12,,1,9)" ascii //weight: 1
        $x_1_2 = "Sheets(\"AutoDrom\").Range(\"H17\") = \"=\" & UserForm1.Tag & \"(I17)" ascii //weight: 1
        $x_1_3 = "Sheets(\"AutoDrom\").Range(\"H18\") = \"=\" & UserForm1.Tag & \"(I18)" ascii //weight: 1
        $x_1_4 = "Application.Run Sheets(\"AutoDrom\").Range(\"H1\")" ascii //weight: 1
        $x_1_5 = "Sheets(\"AutoDrom\").Range(\"K18\") = \".dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_ANML_2147798275_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.ANML!MTB"
        threat_id = "2147798275"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"Nosto\").Range(\"K18\") = \".dat" ascii //weight: 1
        $x_1_2 = "Sheets(\"Nosto\").Range(\"G10\") = UserForm4.Caption" ascii //weight: 1
        $x_1_3 = "Sheets(\"Nosto\").Range(\"G11\") = UserForm4.Caption & \"1" ascii //weight: 1
        $x_1_4 = "Sheets(\"Nosto\").Range(\"G12\") = UserForm4.Caption & \"2" ascii //weight: 1
        $x_1_5 = "Sheets(\"Nosto\").Range(\"I18\") = UserForm3.Caption & \"1" ascii //weight: 1
        $x_1_6 = "Sheets(\"Nosto\").Range(\"I19\") = UserForm3.Caption & \"2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_ANMM_2147798276_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.ANMM!MTB"
        threat_id = "2147798276"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"Nosto\").Range(\"I12\") = \"Friskos" ascii //weight: 1
        $x_1_2 = "Sheets(\"Nosto\").Range(\"H10\") = \"=Friskos(0,H24&K17&K18,G10,0,0)" ascii //weight: 1
        $x_1_3 = "Sheets(\"Nosto\").Range(\"H11\") = \"=Friskos(0,H25&K17&K18,G11,0,0)" ascii //weight: 1
        $x_1_4 = "Sheets(\"Nosto\").Range(\"H12\") = \"=Friskos(0,H26&K17&K18,G12,0,0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_ANMN_2147798277_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.ANMN!MTB"
        threat_id = "2147798277"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"Nosto\").Range(\"H9\") = \"=\" & UserForm4.Tag & \"(I9,I10&J10,I11,I12,,1,9)" ascii //weight: 1
        $x_1_2 = "Sheets(\"Nosto\").Range(\"H17\") = \"=\" & UserForm3.Tag & \"(I17)" ascii //weight: 1
        $x_1_3 = "Sheets(\"Nosto\").Range(\"H18\") = \"=\" & UserForm3.Tag & \"(I18)" ascii //weight: 1
        $x_1_4 = "Sheets(\"Nosto\").Range(\"H19\") = \"=\" & UserForm3.Tag & \"(I19)" ascii //weight: 1
        $x_1_5 = "Application.Run Sheets(\"Nosto\").Range(\"H1\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_AAMM_2147798456_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.AAMM!MTB"
        threat_id = "2147798456"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"Mipopla\").Range(\"G10\") = \"..\\Popol.gors" ascii //weight: 1
        $x_1_2 = "Sheets(\"Mipopla\").Range(\"K18\") = \".\" & \"d\" & \"a\" & \"t\"" ascii //weight: 1
        $x_1_3 = "Application.Run Sheets(\"Mipopla\").Range(\"H1\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_JAAC_2147798537_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.JAAC!MTB"
        threat_id = "2147798537"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "regsvr32.exe -e -n -i:\" & RNum & \" ..\\Popol.ocx\" & \"3" ascii //weight: 1
        $x_1_2 = "regsvr32.exe -e -n -i:\" & RNum & \" ..\\Popol.ocx\" & \"4" ascii //weight: 1
        $x_1_3 = "regsvr32.exe -e -n -i:\" & RNum & \" ..\\Popol.ocx\" & \"5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_POXO_2147798559_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.POXO!MTB"
        threat_id = "2147798559"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-silent ..\\Popol.gors" ascii //weight: 1
        $x_1_2 = "-silent ..\\Popol.gors1" ascii //weight: 1
        $x_1_3 = "-silent ..\\Popol.gors2" ascii //weight: 1
        $x_1_4 = "Popol.ocx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_POXL_2147798612_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.POXL!MTB"
        threat_id = "2147798612"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"r\" & \"e\" & \"gs\" & \"v\" & \"r3\" & \"2 -silent ..\\Flos.det" ascii //weight: 1
        $x_1_2 = "= \"r\" & \"e\" & \"gs\" & \"v\" & \"r3\" & \"2 -silent ..\\Flos.det1" ascii //weight: 1
        $x_1_3 = "= \"r\" & \"e\" & \"gs\" & \"v\" & \"r3\" & \"2 -silent ..\\Flos.det2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_POXL_2147798612_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.POXL!MTB"
        threat_id = "2147798612"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 65 74 73 28 22 [0-32] 22 29 2e 52 61 6e 67 65 28 22 [0-8] 22 29 20 3d 20 22 72 22 20 26 20 22 65 22 20 26 20 22 67 73 22 20 26 20 22 76 22 20 26 20 22 72 33 22 20 26 20 22 32 20 2d 73 69 6c 65 6e 74 20 2e 2e 5c 50 6f 70 6f 6c 2e 67 6f 72 73}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 65 65 74 73 28 22 [0-32] 22 29 2e 52 61 6e 67 65 28 22 [0-8] 22 29 20 3d 20 22 72 22 20 26 20 22 65 22 20 26 20 22 67 73 22 20 26 20 22 76 22 20 26 20 22 72 33 22 20 26 20 22 32 20 2d 73 69 6c 65 6e 74 20 2e 2e 5c 50 6f 70 6f 6c 2e 67 6f 72 73 31}  //weight: 1, accuracy: Low
        $x_1_3 = {53 68 65 65 74 73 28 22 [0-32] 22 29 2e 52 61 6e 67 65 28 22 [0-8] 22 29 20 3d 20 22 72 22 20 26 20 22 65 22 20 26 20 22 67 73 22 20 26 20 22 76 22 20 26 20 22 72 33 22 20 26 20 22 32 20 2d 73 69 6c 65 6e 74 20 2e 2e 5c 50 6f 70 6f 6c 2e 67 6f 72 73 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_POXM_2147798613_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.POXM!MTB"
        threat_id = "2147798613"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 65 74 73 28 22 [0-32] 22 29 2e 52 61 6e 67 65 28 22 [0-8] 22 29 20 3d 20 22 72 22 20 26 20 22 65 22 20 26 20 22 67 73 22 20 26 20 22 76 22 20 26 20 22 72 33 22 20 26 20 22 32 2e 65 78 65 20 2d 65 20 2d 6e 20 2d 69 3a 22 20 26 20 52 4e 75 6d 20 26 20 22 20 2e 2e 5c 50 6f 70 6f 6c 2e 6f 63 78 33}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 65 65 74 73 28 22 [0-32] 22 29 2e 52 61 6e 67 65 28 22 [0-8] 22 29 20 3d 20 22 72 22 20 26 20 22 65 22 20 26 20 22 67 73 22 20 26 20 22 76 22 20 26 20 22 72 33 22 20 26 20 22 32 2e 65 78 65 20 2d 65 20 2d 6e 20 2d 69 3a 22 20 26 20 52 4e 75 6d 20 26 20 22 20 2e 2e 5c 50 6f 70 6f 6c 2e 6f 63 78 34}  //weight: 1, accuracy: Low
        $x_1_3 = {53 68 65 65 74 73 28 22 [0-32] 22 29 2e 52 61 6e 67 65 28 22 [0-8] 22 29 20 3d 20 22 72 22 20 26 20 22 65 22 20 26 20 22 67 73 22 20 26 20 22 76 22 20 26 20 22 72 33 22 20 26 20 22 32 2e 65 78 65 20 2d 65 20 2d 6e 20 2d 69 3a 22 20 26 20 52 4e 75 6d 20 26 20 22 20 2e 2e 5c 50 6f 70 6f 6c 2e 6f 63 78 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_2147798679_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot"
        threat_id = "2147798679"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 72 22 26 22 65 22 26 22 67 [0-4] 73 22 26 22 76 22 26 22 72}  //weight: 1, accuracy: Low
        $x_1_2 = "=\"ur\"&\"ld\"&\"ow\"&\"n\"&\"lo\"&\"ad\"&\"to\"&\"fi\"&\"le\"&\"a\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_SSMA_2147805660_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.SSMA!MTB"
        threat_id = "2147805660"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f [0-32] 2e 63 6f 6d 2f [0-15] 2f [0-2] 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f [0-48] 2e 63 6f 6d 2f [0-15] 2f [0-4] 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_RPQ_2147805750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.RPQ!MTB"
        threat_id = "2147805750"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cetdrd.OOOOCCCCXXXX" ascii //weight: 1
        $x_1_2 = "Regsvr32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_RVE_2147808483_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.RVE!MTB"
        threat_id = "2147808483"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttps://moreproducts.com/KRGhfH3IEEsj/nfvbhN.png\",\"" ascii //weight: 1
        $x_1_2 = "ttps://gxlive.ca/naURwuXk/nfvbhN.png\",\"" ascii //weight: 1
        $x_1_3 = "ttps://fontelife.com.br/lxTCcmdsLW/nfvbhN.png\",\"" ascii //weight: 1
        $x_1_4 = "ttp://interstatephoto.com/v-web/Rf8D20v/\",\"" ascii //weight: 1
        $x_1_5 = "ttp://iosincorporated.com/_borders/ZIMU/\",\"" ascii //weight: 1
        $x_1_6 = "ttp://ipirangaonline.com.br/wp-content/CddFMv/\",\"" ascii //weight: 1
        $x_1_7 = "ttp://inydesign.sk/G/2MVRGP/\",\"" ascii //weight: 1
        $x_1_8 = "ttp://iskontech.com/downloadtest/lRG8Dqer/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDI_2147810185_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDI!MTB"
        threat_id = "2147810185"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "liketickets.com/fDjIGgWEQpk/DnvhnhO.png" ascii //weight: 1
        $x_1_2 = "auto95.net/roDIBRTsXzJB/DnvhnhO.png" ascii //weight: 1
        $x_1_3 = "canu.mobi/UZXU81xP/DnvhnhO.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDJ_2147811277_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDJ!MTB"
        threat_id = "2147811277"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sferaoptical.com/HLlyJ513zu/Cnhfnvmh.png" ascii //weight: 1
        $x_1_2 = "duddas.com.br/FMPhmkD9g2wZ/Cnhfnvmh.png" ascii //weight: 1
        $x_1_3 = "iraq-mas.com/qJ9yPcX3dn/Cnhfnvmh.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDK_2147811894_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDK!MTB"
        threat_id = "2147811894"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bongoandroidapk.com/cCCaniTOjH/Ehrnf.png" ascii //weight: 1
        $x_1_2 = "nityahandicrafts.com/jn46oAFrTTpv/Ehrnf.png" ascii //weight: 1
        $x_1_3 = "deep-cure.com/QBjDegiPIa/Ehrnf.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDL_2147812032_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDL!MTB"
        threat_id = "2147812032"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "elblogdeloscachanillas.com.mx/S3sY8RQ10/Ophn.png" ascii //weight: 1
        $x_1_2 = "lalualex.com/ApUUBp1ccd/Ophn.png" ascii //weight: 1
        $x_1_3 = "lizety.com/mJYvpo2xhx/Ophn.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDM_2147812514_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDM!MTB"
        threat_id = "2147812514"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Mertio\\Juadost\\Kiense.ooooooooooooooooocccccccccccccccccccccccccccccccxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PKJA_2147812951_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PKJA!MTB"
        threat_id = "2147812951"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 63 6f 6d 6d 65 72 63 65 73 68 6f 70 2e 63 6f 6d 2f [0-20] 2f 42 76 4d 6e 68 4f 6e 2e 70 6e 67 22 2c 22}  //weight: 1, accuracy: Low
        $x_1_2 = {64 63 72 69 61 63 6f 65 73 2e 63 6f 6d 2e 62 72 2f [0-20] 2f 42 76 4d 6e 68 4f 6e 2e 70 6e 67 22 2c 22}  //weight: 1, accuracy: Low
        $x_1_3 = {63 6f 62 72 61 6d 6f 74 6f 73 2e 63 6f 6d 2e 62 72 2f [0-20] 2f 42 76 4d 6e 68 4f 6e 2e 70 6e 67 22 2c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PKJA_2147812951_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PKJA!MTB"
        threat_id = "2147812951"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"h\"&\"tt\"&\"ps://groce\"&\"ry\"&\"expr\"&\"ess.n\"&\"e\"&\"t/D2A\"&\"GySOh\"&\"fNE\"&\"Z/e\"&\"ty.p\"&\"ng\",\"" ascii //weight: 1
        $x_1_2 = "\"h\"&\"ttp\"&\"s://proj\"&\"evall\"&\"e.co\"&\"m.br/u5D\"&\"qWR\"&\"qH\"&\"P/ety.p\"&\"ng\",\"" ascii //weight: 1
        $x_1_3 = "\"h\"&\"ttp\"&\"s://pi\"&\"pef\"&\"lo\"&\"w.c\"&\"l/M0m\"&\"4x0\"&\"HO1\"&\"NQ\"&\"M/e\"&\"ty.p\"&\"ng\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDN_2147813154_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDN!MTB"
        threat_id = "2147813154"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ordisos.com/9bVAa06WXzsj/Knhfn.png" ascii //weight: 1
        $x_1_2 = "ncelltech.com/qVFmE4M5BR/Knhfn.png" ascii //weight: 1
        $x_1_3 = "deco2hk.com/eh3dKBSPS6/Knhfn.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDO_2147813328_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDO!MTB"
        threat_id = "2147813328"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 52 6c 4d 6f 6e [0-3] 72 65 [0-3] 67 73 76 [0-3] 72 33 32}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\Merto\\Byrost\\Veonse.OOOCCCXXX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDP_2147813364_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDP!MTB"
        threat_id = "2147813364"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sahlonline.com/0f6eAzyWLUL/Lkmn.png" ascii //weight: 1
        $x_1_2 = "faproadvisors.com/vtfLDJvyF5g/Lkmn.png" ascii //weight: 1
        $x_1_3 = "truckmate.org/PD6TAp7csO/Lkmn.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDR_2147813600_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDR!MTB"
        threat_id = "2147813600"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "newthinkconectores.com.br/FZayiWyMa/Cbvnh.png" ascii //weight: 1
        $x_1_2 = "trucker.fit/fo8Lwyr0/Cbvnh.png" ascii //weight: 1
        $x_1_3 = "marcioidalino.com.br/czAzb2BcXg/Cbvnh.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDU_2147813786_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDU!MTB"
        threat_id = "2147813786"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Nhrgogor.Ooccxx" ascii //weight: 1
        $x_1_2 = "\\Nhrgogor1.Ooccxx" ascii //weight: 1
        $x_1_3 = "\\Nhrgogor2.Ooccxx" ascii //weight: 1
        $x_1_4 = "URLDownloadToFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDV_2147813865_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDV!MTB"
        threat_id = "2147813865"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Eghejdor.ddllll" ascii //weight: 1
        $x_1_2 = "\\Eghejdor1.ddllll" ascii //weight: 1
        $x_1_3 = "\\Eghejdor2.ddllll" ascii //weight: 1
        $x_1_4 = "URLDownloadToFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_BHQ_2147813994_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.BHQ!MTB"
        threat_id = "2147813994"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 2f 2f 73 75 70 65 72 62 69 6b 65 7a 2e 6e 6c 2f 64 30 54 4a 73 47 73 4a 77 2f 67 68 6e 2e 70 6e 67 [0-10] 43 3a 5c 41 6f 74 5c [0-6] 2e 6f 63 78}  //weight: 1, accuracy: Low
        $x_1_2 = {3a 2f 2f 6b 65 72 72 76 69 6c 6c 65 74 75 65 73 64 61 79 74 65 6e 6e 69 73 2e 63 6f 6d 2f 53 7a 41 75 4f 63 54 37 63 39 58 2f 67 68 6e 2e 70 6e 67 [0-10] 43 3a 5c 41 6f 74 5c [0-6] 2e 6f 63 78}  //weight: 1, accuracy: Low
        $x_1_3 = {3a 2f 2f 65 74 68 6e 69 63 63 72 61 66 74 61 72 74 2e 63 6f 6d 2f 4b 73 44 48 43 51 6a 6f 34 38 2f 67 68 6e 2e 70 6e 67 [0-10] 43 3a 5c 41 6f 74 5c [0-6] 2e 6f 63 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDA_2147814501_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDA!MTB"
        threat_id = "2147814501"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://campingoasis.cl/j058gDRty3C7/6.pn\"&\"g" ascii //weight: 1
        $x_1_2 = "://3639optical.ga/41ypRER4/6.pn\"&\"g" ascii //weight: 1
        $x_1_3 = "://ampductwork.com/eO9TWNAUzS/6.pn\"&\"g" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDB_2147814600_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDB!MTB"
        threat_id = "2147814600"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://michelletaxservices.com/Q6SBX24ZHSN1/4.png" ascii //weight: 1
        $x_1_2 = "://nourishinghandscare.com/xtHnTg53T/4.png" ascii //weight: 1
        $x_1_3 = "://tlnetworkingsolutions.com/ti8oaQaCM/4.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDC_2147814616_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDC!MTB"
        threat_id = "2147814616"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://plokoto.cf/IB61RO0Z6C/33.png" ascii //weight: 1
        $x_1_2 = "://3635optical.ga/YFPzuOmr/33.png" ascii //weight: 1
        $x_1_3 = "://leoedelucca.com.br/JSHi41WBfv/33.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDD_2147814676_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDD!MTB"
        threat_id = "2147814676"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://fvrmcleaning.com/bMV2pzMI/090322.gif" ascii //weight: 1
        $x_1_2 = "://fiorewlkfix.gq/XjLiTfgYn/090322.gif" ascii //weight: 1
        $x_1_3 = "://ksindesign.com.br/4XWLQ0Itz/090322.gif" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDE_2147814943_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDE!MTB"
        threat_id = "2147814943"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://termaslospozones.com/iz4oQnZkQo4X/1.pn\"&\"g" ascii //weight: 1
        $x_1_2 = "://nilopera.ml/bJhLRPHSSfm4/1.pn\"&\"g" ascii //weight: 1
        $x_1_3 = "://healthywaylab.in/PxvPlCn2liWp/1.pn\"&\"g" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDG_2147814951_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDG!MTB"
        threat_id = "2147814951"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://mus\"&\"taf\"&\"aks\"&\"oy.c\"&\"o\"&\"m/UM\"&\"WPp\"&\"ecHvg/gmkox.p\"&\"ng" ascii //weight: 1
        $x_1_2 = "://b\"&\"ritc\"&\"ap.c\"&\"om/S\"&\"4A\"&\"BFgx\"&\"nW\"&\"O/gm\"&\"kox.p\"&\"ng" ascii //weight: 1
        $x_1_3 = "://au\"&\"topl\"&\"ac\"&\"asd\"&\"il\"&\"ger.c\"&\"om.b\"&\"r/EC\"&\"g8\"&\"m6\"&\"oX\"&\"27/gm\"&\"kox.p\"&\"ng" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_BHR_2147815127_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.BHR!MTB"
        threat_id = "2147815127"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://56to\"&\"dd\"&\"hil\"&\"l.c\"&\"o\"&\"m/FW\"&\"JV\"&\"pW\"&\"IA\"&\"KXs/tht\"&\"Nh\"&\"n.p\"&\"n\"&\"g" ascii //weight: 1
        $x_1_2 = "://st\"&\"hole\"&\"fou\"&\"ndat\"&\"ion.o\"&\"r\"&\"g/aO\"&\"YrB\"&\"Va\"&\"nH\"&\"Yr/th\"&\"tNh\"&\"n.p\"&\"ng" ascii //weight: 1
        $x_1_3 = "://fre\"&\"ec\"&\"pama\"&\"rke\"&\"ting\"&\"cour\"&\"se.t\"&\"ec\"&\"h/XDV\"&\"k70\"&\"YB3\"&\"8Z\"&\"3/th\"&\"tN\"&\"hn.p\"&\"ng" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_BHS_2147815128_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.BHS!MTB"
        threat_id = "2147815128"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://my\"&\"pri\"&\"ntson\"&\"ality.c\"&\"o\"&\"m/hjp\"&\"lRg1\"&\"Q1V\"&\"hA/Fn\"&\"h\"&\"bn.p\"&\"ng" ascii //weight: 1
        $x_1_2 = "://bl\"&\"ua\"&\"spe\"&\"ct.c\"&\"o\"&\"m/S8\"&\"yu21\"&\"Fjtr/Fn\"&\"hb\"&\"n.p\"&\"ng" ascii //weight: 1
        $x_1_3 = "://n\"&\"ew\"&\"do\"&\"or-ve\"&\"nture\"&\"s.c\"&\"om/cD\"&\"84a\"&\"a5E/F\"&\"nh\"&\"bn.p\"&\"ng" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_RQQ_2147815724_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.RQQ!MTB"
        threat_id = "2147815724"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"https://d\"&\"uk\"&\"ul.c\"&\"o\"&\"m/ve\"&\"0a0\"&\"8C\"&\"g/v\"&\"bh\"&\"Nh\"&\"n.png\"" ascii //weight: 1
        $x_1_2 = "\"http\"&\"s://d\"&\"pa\"&\"ula\"&\"fo\"&\"od\"&\"s.c\"&\"o\"&\"m.b\"&\"r/flt\"&\"Kqd\"&\"W\"&\"P3v\"&\"h/vbh\"&\"Nhn.png\"" ascii //weight: 1
        $x_1_3 = "\"https://ar\"&\"den\"&\"tsp\"&\"ort.c\"&\"o\"&\"m/lP\"&\"aqe\"&\"iD\"&\"5j\"&\"UY/vb\"&\"h\"&\"Nh\"&\"n.png\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PKJB_2147815792_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PKJB!MTB"
        threat_id = "2147815792"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "m\"&\"e\"&\"ste\"&\"rm\"&\"ust\"&\"ra.r\"&\"o/M\"&\"c\"&\"vmG\"&\"TW\"&\"B4\"&\"8/Nc\"&\"ho\"&\"nh\"&\"Nh.p\"&\"n\"&\"g\",\"" ascii //weight: 1
        $x_1_2 = "em\"&\"brat\"&\"eg.c\"&\"o\"&\"m/8V\"&\"UrJ\"&\"k0a/N\"&\"c\"&\"h\"&\"on\"&\"h\"&\"N\"&\"h.p\"&\"n\"&\"g\",\"" ascii //weight: 1
        $x_1_3 = "e2\"&\"ek\"&\"iju\"&\"to\"&\"l.t\"&\"k/tb\"&\"Tc\"&\"C1\"&\"D\"&\"RW\"&\"Tm\"&\"C/N\"&\"ch\"&\"on\"&\"hN\"&\"h.p\"&\"n\"&\"g\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDH_2147816024_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDH!MTB"
        threat_id = "2147816024"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://dguconsult.com/le6WSgUDXRO/VfnbG.png" ascii //weight: 1
        $x_1_2 = "://pagarbeton.com/kzCI3NWGz/VfnbG.png" ascii //weight: 1
        $x_1_3 = "://jkipl.in/NOOdheb8/VfnbG.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_ALA_2147818210_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.ALA!MTB"
        threat_id = "2147818210"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "44686.4802978009.dat" ascii //weight: 1
        $x_1_2 = ".OOOCCCXXX" ascii //weight: 1
        $x_1_3 = "DirectoryA" ascii //weight: 1
        $x_1_4 = {75 52 6c 4d 6f 6e [0-47] 72 33 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PDT_2147818699_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PDT!MTB"
        threat_id = "2147818699"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".OOOCCCXXX" ascii //weight: 1
        $x_1_2 = "44694,4985144676.dat" ascii //weight: 1
        $x_1_3 = {75 52 6c 4d 6f 6e [0-3] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_SSMK_2147818992_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.SSMK!MTB"
        threat_id = "2147818992"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tps://mi-xiaomi.live/yTiN2JL7/K.png" ascii //weight: 1
        $x_1_2 = "ttps://dev.apb.com.la/S1dBTV1yT/K.png" ascii //weight: 1
        $x_1_3 = "ttps://assamcareer.news/PCYxZBpbfwN/K.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_SSMK_2147818992_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.SSMK!MTB"
        threat_id = "2147818992"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttps://uniross.site/SVmGtFWUNWs/I.png" ascii //weight: 1
        $x_1_2 = "ttps://alexadrivingschool.online/ViaawNBw/I.png" ascii //weight: 1
        $x_1_3 = "ttps://adboat.live/TCA1oiqkA/I.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_SSMK_2147818992_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.SSMK!MTB"
        threat_id = "2147818992"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttps://myphamcuatui.com/assets/z1b9YfHoX7Fp/" ascii //weight: 1
        $x_1_2 = "ttp://myramark.com/mail/rhEPylXD8BuTA/" ascii //weight: 1
        $x_1_3 = "ttps://myechoproject.com/pitterpatter/bNx/" ascii //weight: 1
        $x_1_4 = "ttp://mybiscotto.com/images/BDcjQT/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Qakbot_PUD_2147898430_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Qakbot.PUD!MTB"
        threat_id = "2147898430"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "JJCCCJJ" ascii //weight: 1
        $x_1_2 = "JJCCBB" ascii //weight: 1
        $x_1_3 = "zipfldr" ascii //weight: 1
        $x_1_4 = {68 74 74 70 73 3a 2f 2f [0-15] 2e 78 79 7a 2f 67 75 74 70 61 67 ?? 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

