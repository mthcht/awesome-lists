rule TrojanDownloader_O97M_Dridex_SS_2147758261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SS!MTB"
        threat_id = "2147758261"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(\"MSXMLKsq%p,2.XMLHTTP\", \"Ksq%p,\", \"\")" ascii //weight: 1
        $x_1_2 = "= Replace(\"rungJIpg_XdgJIpg_Xll32.exg" ascii //weight: 1
        $x_1_3 = "Msg = \"Thank You!" ascii //weight: 1
        $x_1_4 = "MsgBox Msg, , \"OK\", Err.HelpFile, Err.HelpContext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_SS_2147758261_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SS!MTB"
        threat_id = "2147758261"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 69 74 68 20 47 65 74 4f 62 6a 65 63 74 28 [0-15] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 53 70 6c 69 74 28 [0-15] 2c 20 [0-14] 2c 20 [0-15] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-15] 2c 20 [0-15] 2c 20 [0-15] 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 43 72 65 61 74 65 20 [0-23] 2c 20 4e 75 6c 6c 2c 20}  //weight: 1, accuracy: Low
        $x_1_5 = {46 6f 72 20 [0-14] 20 3d 20 30 20 54 6f 20 43 4c 6e 67 28 28}  //weight: 1, accuracy: Low
        $x_1_6 = {78 6c 44 69 61 6c 6f [0-47] 20 58 6f 72 20}  //weight: 1, accuracy: Low
        $x_1_7 = "= Environ(" ascii //weight: 1
        $x_1_8 = ")))) * Rnd + CLng((" ascii //weight: 1
        $x_1_9 = " = Hex(CLng((CLng((" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_SS_2147758261_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SS!MTB"
        threat_id = "2147758261"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 45 78 65 63 20 28 22 6d 73 68 74 61 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 45 6e 76 69 72 6f 6e 28 22 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 71 44 69 61 6c 6f 67 47 61 6c 6c 65 72 79 53 63 61 74 74 65 72 2e 73 63 74 22 20 26 20 43 68 72 28 33 34 29 29 [0-3] 45 6e 64 20 57 69 74 68}  //weight: 1, accuracy: Low
        $x_1_2 = "qAxis = qAxis & Chr(qIMEModeAlphaFull.Value)" ascii //weight: 1
        $x_1_3 = "With CreateObject(\"Wscript.Shell\")" ascii //weight: 1
        $x_1_4 = {71 47 72 69 64 2e 57 72 69 74 65 20 28 71 41 78 69 73 29 [0-3] 71 47 72 69 64 2e 43 6c 6f 73 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_SS_2147758261_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SS!MTB"
        threat_id = "2147758261"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "u = u & Chr(Asc(Mid(n, X, 1)) + k): Next" ascii //weight: 1
        $x_1_2 = "Debug.Print Replace(E, \"[\", \"J\")" ascii //weight: 1
        $x_1_3 = "IR = Split(u, \">\")" ascii //weight: 1
        $x_1_4 = "a(j% + 1) = X%" ascii //weight: 1
        $x_1_5 = "rs = rs & [MID(\"ABCD EFGH IJKL MNO PQRS TUVWX YZabc defghi jklmno pqrstu vwxyz\",RANDBETWEEN(1,62),1)]" ascii //weight: 1
        $x_1_6 = "inn = Chr(Asc(a(X)) - 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_SS_2147758261_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SS!MTB"
        threat_id = "2147758261"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(\"A@-#8VWp@-#8VWpData\", \"@-#8VW\", \"\")" ascii //weight: 1
        $x_1_2 = "= Replace(\"Offl5TR8LLi5TR8LLne5TR8LL5TR8LLF5TR8LLilesStar5TR8LLt\", \"5TR8LL\", \"\")" ascii //weight: 1
        $x_1_3 = "= Replace(\"Wscrip3!4FIt3!4FI.Shell\", \"3!4FI\", \"\")" ascii //weight: 1
        $x_1_4 = "= Replace(\"wmic process call create 'run$3&pR+dll32.exe \", \"$3&pR+\", \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_SS_2147758261_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SS!MTB"
        threat_id = "2147758261"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(\"\\1QM:)38ZQM:)38Z1981.QM:)38Zdll\", \"QM:)38Z\", \"\")" ascii //weight: 1
        $x_1_2 = "= Replace(\"z8g*B77Az8g*B77pz8g*B77pData\", \"z8g*B77\", \"\")" ascii //weight: 1
        $x_1_3 = "= Replace(\"Of $eM%flin $eM%eF $eM%il $eM% $eM%e $eM%sStart\", \" $eM%\", \"\")" ascii //weight: 1
        $x_1_4 = "Msg = \"Thank You!" ascii //weight: 1
        $x_1_5 = "MsgBox Msg, , \"OK\", Err.HelpFile, Err.HelpContext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_SS_2147758261_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SS!MTB"
        threat_id = "2147758261"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 52 65 70 6c 61 63 65 28 22 [0-47] 2e 64 6c 6c 22 2c 20 22 [0-10] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "= Replace(" ascii //weight: 1
        $x_1_3 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 4f 70 65 6e 20 [0-30] 2e}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 52 75 6e 20 [0-32] 2e [0-33] 28 [0-15] 29 2c 20 43 4c 6e 67 28 28}  //weight: 1, accuracy: Low
        $x_1_6 = "If Err.Number <> 0 Then" ascii //weight: 1
        $x_1_7 = "Msg = \"Thank You!\"" ascii //weight: 1
        $x_1_8 = "MsgBox Msg, , \"OK\", Err.HelpFile, Err.HelpContext" ascii //weight: 1
        $x_1_9 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 [0-32] 2e [0-33] 28 29 20 26}  //weight: 1, accuracy: Low
        $x_1_10 = {29 20 26 20 43 68 72 28 43 4c 6e 67 28 28 [0-32] 29 29 29 20 26 20 22 20 22 20 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_SS_2147758261_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SS!MTB"
        threat_id = "2147758261"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(\"https://mosaicuschin+rn6/a.co+rn6/m/wp-conte+rn6/nt/plug+rn6/ins/wpml-string-translation/locale/+rn6/orig/afFzHwIPlCs5+rn6/b.php\", \"+rn6/\", \"\")" ascii //weight: 1
        $x_1_2 = "https://dstarindia.com/a/inc/svgs/brands/u026njYbCU.phpteJ3ZCK/" ascii //weight: 1
        $x_1_3 = "https://congxepsaigon.net/wp-content/themes/twentynineteen/sass/blocks/cMRovqbpE.php>SZ8-O$:h=RIvE!C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_SS_2147758261_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SS!MTB"
        threat_id = "2147758261"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Msg = \"Thank You!" ascii //weight: 1
        $x_1_2 = "MsgBox Msg, , \"OK\", Err.HelpFile, Err.HelpContext" ascii //weight: 1
        $x_1_3 = "= Replace(\"<cIfR\\37637.dll<cIfR<cIfR\", \"<cIfR\", \"\")" ascii //weight: 1
        $x_1_4 = "= Replace(\"GETi/MTGi/MTGi/MTGi/MTGi/MTG\", \"i/MTG\", \"\")" ascii //weight: 1
        $x_1_5 = "= Replace(\"wmic process call creat-Z2lAe 'r-Z2lAundll32.exe \", \"-Z2lA\", \"\")" ascii //weight: 1
        $x_1_6 = "= Replace(\"q$/ag\\582q$/agq$/agq$/ag91.q$/agdq$/agll\", \"q$/ag\", \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_SS_2147758261_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SS!MTB"
        threat_id = "2147758261"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(\"DllCanUscwx-WnloadNow\", \"scwx-W\", \"\")" ascii //weight: 1
        $x_1_2 = "= Replace(\"WscrofF=Jipt.ofF=JShelofF=Jl\", \"ofF=J\", \"\")" ascii //weight: 1
        $x_1_3 = "= Replace(\"GE0dr>6|4T\", \"0dr>6|4\", \"\")" ascii //weight: 1
        $x_1_4 = "Msg = \"Thank You!" ascii //weight: 1
        $x_1_5 = "MsgBox Msg, , \"OK\", Err.HelpFile, Err.HelpContext" ascii //weight: 1
        $x_2_6 = "= Replace(\"W8JN.|rosc8JN.|roript8JN.|ro.Shel8JN.|rol\", \"8JN.|ro\", \"\")" ascii //weight: 2
        $x_1_7 = "= Replace(\"G,0EH-lET\", \",0EH-l\", \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Dridex_SS_2147758261_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SS!MTB"
        threat_id = "2147758261"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 52 65 70 6c 61 63 65 28 22 [0-47] 2e 64 6c 6c 22 2c 20 22 [0-10] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 4f 70 65 6e 20 [0-30] 2e}  //weight: 1, accuracy: Low
        $x_1_4 = "= Replace(" ascii //weight: 1
        $x_1_5 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 [0-32] 2e [0-33] 28 29 20 26}  //weight: 1, accuracy: Low
        $x_1_6 = "If Err.Number <> 0 Then" ascii //weight: 1
        $x_1_7 = "Msg = \"Thank You!\"" ascii //weight: 1
        $x_1_8 = "MsgBox Msg, , \"Good\", Err.HelpFile, Err.HelpContext" ascii //weight: 1
        $x_1_9 = {2e 70 68 70 22 2c 20 22 [0-10] 22 2c 20 22 22 29 [0-21] 20 3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 [0-21] 29 29}  //weight: 1, accuracy: Low
        $x_1_10 = "AppData" ascii //weight: 1
        $x_1_11 = {29 20 26 20 43 68 72 28 43 4c 6e 67 28 28 [0-32] 29 29 29 20 26 20 22 20 22 20 26}  //weight: 1, accuracy: Low
        $x_1_12 = {2e 52 75 6e 20 [0-32] 2e [0-33] 28 [0-15] 29 2c 20 43 4c 6e 67 28 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_SS_2147758261_11
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SS!MTB"
        threat_id = "2147758261"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 52 65 70 6c 61 63 65 28 22 [0-47] 2e 64 6c 6c 22 2c 20 22 [0-10] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 4f 70 65 6e 20 [0-30] 2e}  //weight: 1, accuracy: Low
        $x_1_4 = "= Replace(" ascii //weight: 1
        $x_1_5 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 [0-32] 2e [0-33] 28 29 20 26}  //weight: 1, accuracy: Low
        $x_1_6 = "If Err.Number <> 0 Then" ascii //weight: 1
        $x_1_7 = "Msg = \"Thank You!\"" ascii //weight: 1
        $x_1_8 = "MsgBox Msg, , \"Good\", Err.HelpFile, Err.HelpContext" ascii //weight: 1
        $x_1_9 = "MsgBox Msg, , \"OK\", Err.HelpFile, Err.HelpContext" ascii //weight: 1
        $x_1_10 = {53 65 74 20 [0-21] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-15] 29 [0-3] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_11 = {2e 70 68 70 22 2c 20 22 [0-10] 22 2c 20 22 22 29 [0-21] 20 3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 [0-21] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_SS_2147758261_12
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SS!MTB"
        threat_id = "2147758261"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(\"\\40398x;yCwo.dx;yCwoll\", \"x;yCwo\", \"\")" ascii //weight: 1
        $x_1_2 = "= Replace(\"AppDaqwQW>ta\", \"qwQW>\", \"\")" ascii //weight: 1
        $x_1_3 = "= Replace(\"rundll3GCIo0.2.GCIo0.exGCIo0.e" ascii //weight: 1
        $x_1_4 = "Msg = \"Thank You!\"" ascii //weight: 1
        $x_1_5 = "MsgBox Msg, , \"Good\", Err.HelpFile, Err.HelpContext" ascii //weight: 1
        $x_1_6 = "= Replace(\"A,l6SE-ppp,l6SE-pDa,l6SE-pta\", \",l6SE-p\", \"\")" ascii //weight: 1
        $x_1_7 = "Replace(\"/k0*nKW/k0*nKscript.S/k0*nKhell\", \"/k0*nK\", \"\")" ascii //weight: 1
        $x_1_8 = "= Replace(\"https://promotecksa.EKN3#@6com/cssjs/siKdqFMZ.php\", \"EKN3#@6\", \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_SS_2147758261_13
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SS!MTB"
        threat_id = "2147758261"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic process call create 'rundll32.exe" ascii //weight: 1
        $x_3_2 = "= Replace(\"QeSq6QeSq6\\63398.dllQeSq6QeSq6\", \"QeSq6\", \"\")" ascii //weight: 3
        $x_3_3 = "= Replace(\"v<.vCwIv<.vCwI\\45499.dllv<.vCwIv<.vCwI\", \"v<.vCwI\", \"\")" ascii //weight: 3
        $x_3_4 = "= Replace(\"\\19649.dll\\Wq<$@\\Wq<$@\\Wq<$@\", \"\\Wq<$@\", \"\")" ascii //weight: 3
        $x_3_5 = "= Mid(\"jlJi(|\\2288.dllBD%\\COa\", CLng((Not -8)), CLng((" ascii //weight: 3
        $x_3_6 = "= Mid(\"FfF<AR0F.Rq*mug\\64105.dll0r*w3-40 \", CLng((" ascii //weight: 3
        $x_3_7 = "= Replace(\"\\44266.dllPNuHhPNuHhPNuHhPNuHhPNuHh\", \"PNuHh\", \"\")" ascii //weight: 3
        $x_3_8 = "= Replace(\" $h&-Me $h&-Me\\49907.dll $h&-Me\", \" $h&-Me\", \"\")" ascii //weight: 3
        $x_3_9 = "= Replace(\"0DbsrP<J0DbsrP<J0DbsrP<J0DbsrP<J0DbsrP<J\\30985.dll\", \"0DbsrP<J\", \"\")" ascii //weight: 3
        $x_3_10 = "= Replace(\"uNwrR<GuNwrR<GuNwrR<G\\13858.dlluNwrR<G\", \"uNwrR<G\", \"\")" ascii //weight: 3
        $x_3_11 = "= Mid(\"WbF\\;F1BFdJYKy\\30254.dll*#OaWibe\", CLng((" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Dridex_SS_2147758261_14
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SS!MTB"
        threat_id = "2147758261"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(\"https://kapr<M&oURaywala.ga/website/wp-includes/j<M&oURs/jquery/u<M&oURi/kk919Q3Ead7kgFQ.php\", \"<M&oUR\", \"\")" ascii //weight: 1
        $x_1_2 = "= Replace(\"https://niirit.com/COPPV8#-9YRIGHTPV8#-9/gqXs0Qm8PV8#-95xPV8#-9.php\", \"PV8#-9\", \"\")" ascii //weight: 1
        $x_1_3 = "= Replace(\"https://tricommanagement.org/fonts/font-awesome-4.7.0;WMk/G/css/zhk1GWedvcwJJJ.;WMk/Gphp\", \";WMk/G\", \"\")" ascii //weight: 1
        $x_1_4 = "= Replace(\"https://secknH0uUaudknH0uUit.e-m2.net/wp-content/themes/finvision-knH0uUchilknH0uUd/templaknH0uUteknH0uU-parts/blog-regular/Rib3TgWd3v.php\", \"knH0uU\", \"\")" ascii //weight: 1
        $x_1_5 = "= Replace(\"https://limarija-das.hr/wXA/#iv/p-content/plugins/wp-optimize/js/handlebars/CJrMovjhM.php\", \"XA/#iv/\", \"\")" ascii //weight: 1
        $x_1_6 = "= Replace(\"https://sharmina.sharmina.org/wp-content/plugins/all-io%^KNmn-one-wp-migration/lib/conto%^KNmroller/9MuUJGgZqj.php\", \"o%^KNm\", \"\")" ascii //weight: 1
        $x_1_7 = "= Replace(\"https://dev1.whoatemyI^cA@lunch.org/wp-includes/js/tinyI^cA@mce/themes/inlite/hxXHK0N6.php\", \"I^cA@\", \"\")" ascii //weight: 1
        $x_1_8 = "= Replace(\"https://asgvprotecao.com.br/wa_php/clZ&LpN-omp/klbd5vxr6mf38o/YxSlZ&LpN-slZ&LpN-9udRlZ&LpN-8U.plZ&LpN-hp\", \"lZ&LpN-\", \"\")" ascii //weight: 1
        $x_1_9 = "\"https://creative-island.e-m2.net/wp-content/themes/creative_island/js/vc-composer/RUpDObeysEFp8.php" ascii //weight: 1
        $x_1_10 = "\"https://limarija-das.hr/wp-content/plugins/wp-optimize/js/handlebars/CJrMovjhM.phpMXynE" ascii //weight: 1
        $x_1_11 = "(\"https://l%%8Kvfcrl%%8Kvfyptl%%8Kvfoexpert.work/core/venl%%8Kvfl%%8Kvfdor/doctrine/lexer/lib/cpf9PlDnI8yTl%%8Kvf4tE.php" ascii //weight: 1
        $x_1_12 = "= Replace(\"https:/Ch1U:zT/tricomenergy.com.pk/fonts/font-awesome-4.7.0/css/QblbClNi.php\", \"Ch1U:zT\", \"\")" ascii //weight: 1
        $x_1_13 = "= Replace(\"httpsC&O3*y://greenfieldphC&O3*yarmaC&O3*y.com/old/WeBuilC&O3*yd/3XU6PEm6AwhC&O3*yeZ2B.php\", \"C&O3*y\", \"\")" ascii //weight: 1
        $x_1_14 = "= Replace(\"7X/iChttps7X/iC://arteecaligrafia.com.b7X/iCr/imagens/fotos/thumbs/MupJ4cZzxo7X/iCElmn.php\", \"7X/iC\", \"\")" ascii //weight: 1
        $x_1_15 = "https://podcast.oigaprofe.com.mx/wp-includes/sodium_compat/src/Core32/ChaCha20/KlrIU42g.php" ascii //weight: 1
        $x_1_16 = "https://property.appskeeper.com/wp-content/plugins/lite-cache/3Rx12s64qbadA.php" ascii //weight: 1
        $x_1_17 = "https://irecruiter.immentia.com/storage/framework/cache/data/0e/nC7vWe43YwJjj.php" ascii //weight: 1
        $x_1_18 = "https://evolvingdesk.nl/GoogleAPI/vendor/symfony/polyfill-intl-normalizer/Resources/JsWPVLZw9qr9GFE.php" ascii //weight: 1
        $x_1_19 = "= Replace(\"https://ticket.webstudiotechnology.com/sc/wp-includes/SimplePie/XML/Declaration/ytUsz4l0Qo.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_YD_2147760452_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.YD!MTB"
        threat_id = "2147760452"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ExecuteExcel4Macro (mj(\"$\", d3, \"X\", sg, mj(\";\", kk, \"'\", d2, hh)))" ascii //weight: 1
        $x_1_2 = "nm = vo(Cells(j, 1), Int((4 - 1 + 1) * Rnd + 1))" ascii //weight: 1
        $x_1_3 = "ww = StrConv(aw, vbFromUnicode)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_YG_2147760839_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.YG!MTB"
        threat_id = "2147760839"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rom In E: fk = Len(ExecuteExcel4Macro(rom)): Next: Application.WindowState" ascii //weight: 1
        $x_1_2 = "imaggi = imaggi & Chr(T): T = \"\": Next: E = Split(imaggi, o)" ascii //weight: 1
        $x_1_3 = "cis = Cells(a, K): If IsEmpty(cis)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_RDX_2147766592_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.RDX!MTB"
        threat_id = "2147766592"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "k = k + Chr(s.Column)" ascii //weight: 1
        $x_1_2 = {45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 20 52 65 70 6c 61 63 65 28 [0-15] 2c 20 22 3f 22 2c 20 70 69 70 6f 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= Split(t(0), \"!\")" ascii //weight: 1
        $x_1_4 = "ecgho = Split(namer, \"!\")" ascii //weight: 1
        $x_1_5 = "Sub epson()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_DA_2147766789_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.DA!MTB"
        threat_id = "2147766789"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "numm = Split(zoo, \"=\"):" ascii //weight: 1
        $x_1_2 = "= Replace(Europe, v, UK):" ascii //weight: 1
        $x_1_3 = "Debug.Print v &" ascii //weight: 1
        $x_1_4 = "ExecuteExcel4Macro(\"\" & affiliates)" ascii //weight: 1
        $x_1_5 = "= Split(cityone, \"!\")" ascii //weight: 1
        $x_1_6 = "= delivers(undoo):" ascii //weight: 1
        $x_1_7 = "= Split(numm(0), \"!\"):" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_RD_2147767652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.RD!MTB"
        threat_id = "2147767652"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Find(What:=\"*\", LookIn:=xlValues" ascii //weight: 1
        $x_1_2 = " = Split(ji, \"!\")" ascii //weight: 1
        $x_1_3 = "& ExecuteExcel4Macro(Replace(a, \"?\", e)), 1, 1)" ascii //weight: 1
        $x_1_4 = " = Chr(Asc(Mid(a, i, 1)) + 2)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_RD_2147767652_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.RD!MTB"
        threat_id = "2147767652"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " = \"=RE\": " ascii //weight: 1
        $x_1_2 = " = \"=\" & Replace(E, \"[\", \"J\"): Run (mg & \"o_ibn2\")" ascii //weight: 1
        $x_1_3 = " = mg & \"o_ibn2\": c = fu + fu + fu:" ascii //weight: 1
        $x_1_4 = "u = u & Chr(Asc(Mid(n, X, fu)) + k): " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_RD_2147767652_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.RD!MTB"
        threat_id = "2147767652"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oo & chao_s(Z, Mid(e, mk, v))" ascii //weight: 1
        $x_1_2 = "= Split(oo, areacliento)" ascii //weight: 1
        $x_1_3 = "(ExecuteExcel4Macro(\"\" & Replace(O, milow_s, report_rep)), 1, 2)" ascii //weight: 1
        $x_1_4 = "= Chr(Asc(s) + g)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_SM_2147768923_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SM!MTB"
        threat_id = "2147768923"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://euro-office.net/AwI3uwiwuU6.php" ascii //weight: 1
        $x_1_2 = "https://lamiragereception.com.au/ABs8dJ2ZJ3jgv0n.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_SM_2147768923_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SM!MTB"
        threat_id = "2147768923"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 53 70 6c 69 74 28 [0-15] 2c 20 [0-14] 2c 20 [0-15] 29}  //weight: 1, accuracy: Low
        $x_1_2 = " = Join(Array(Chr(CLng((" ascii //weight: 1
        $x_1_3 = "& ChrW(CLng((AscW(\"P\"))))" ascii //weight: 1
        $x_1_4 = {2e 43 72 65 61 74 65 20 [0-23] 2c 20 4e 75 6c 6c 2c 20}  //weight: 1, accuracy: Low
        $x_1_5 = "Chr(CLng((Asc(\"r\"))))" ascii //weight: 1
        $x_1_6 = "ChrW(CLng((Asc(\"t\"))))" ascii //weight: 1
        $x_1_7 = {57 69 74 68 20 47 65 74 4f 62 6a 65 63 74 28 [0-15] 29}  //weight: 1, accuracy: Low
        $x_1_8 = {3d 20 52 65 70 6c 61 63 65 28 [0-15] 2c 20 [0-15] 2c 20 [0-15] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_SM_2147768923_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SM!MTB"
        threat_id = "2147768923"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 53 70 6c 69 74 28 [0-15] 28 30 29 2c 20 [0-21] 28 4f 61 29 29 29 2c 20 31 29 2c 20 41 5f 6d 69 6e 5f 31 20 26 20 22 5c 22 20 26 20 76 65 67 61 2c 20 67 69 2c 20 67 69}  //weight: 1, accuracy: Low
        $x_1_2 = "URLDownloadToFileA\" (" ascii //weight: 1
        $x_1_3 = {52 75 6e 20 28 [0-15] 20 26 20 22}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 53 70 6c 69 74 28 [0-15] 2c 20 22 51 22 20 26 20 22 23 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 22 52 22 20 26 20 22 5e 22 [0-3] 49 66 20 [0-3] 20 3d 20 32 20 54 68 65 6e 20 [0-15] 20 3d 20 22 2b 2b 22}  //weight: 1, accuracy: Low
        $x_1_6 = {46 6f 72 20 61 20 3d 20 30 20 54 6f 20 55 42 6f 75 6e 64 28 [0-15] 29 20 2d 20 4c 42 6f 75 6e 64 28 00 29 20 2b 20 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_SM_2147768923_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SM!MTB"
        threat_id = "2147768923"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+ Chr(CLng((Asc(\"P\")))) + Chr(CLng((Not" ascii //weight: 1
        $x_1_2 = "Debug.Print j6LUrshoxxfh" ascii //weight: 1
        $x_1_3 = "i = Join(Array(JstTRYzT & \"RYIVnhOxEW5U MsNzYSUmlMAN\", cng1GZwISr5, ym5x_Y1L_Uszx & \"NqMW8_7hmU E9ma_qQo_pSq_t44t\"))" ascii //weight: 1
        $x_1_4 = "Open m4eP0_di0 For Binary As #CLng((xlValidateWholeNumber Or xlOutline))" ascii //weight: 1
        $x_1_5 = "Chr(CLng((AscW(\"o\")))) + Chr(CLng((AscW(\"c\")))) + " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PD_2147769083_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PD!MTB"
        threat_id = "2147769083"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(1).Cells(6, 1).value = j & m: mg = \"Aut\"" ascii //weight: 1
        $x_1_2 = "Sheets(1).Cells(1, 1).Name = mg & \"o_io22\"" ascii //weight: 1
        $x_1_3 = "Sheets(1).Cells(1, 1).value = \"=\" & Replace(E, \"[\", \"J\")" ascii //weight: 1
        $x_1_4 = "u = u & Chr(Asc(Mid(n, X, 1)) + k): Next" ascii //weight: 1
        $x_1_5 = "Run (mg & \"o_io22\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_TOR_2147769695_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.TOR!MTB"
        threat_id = "2147769695"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Attribute VB_Control = \"stampa_salve_pago, 23, 0, MSForms, MultiPage\"" ascii //weight: 1
        $x_1_2 = "Function sphereChat() As String" ascii //weight: 1
        $x_1_3 = "sphereChat = \"revis\"" ascii //weight: 1
        $x_1_4 = "m = \"TORNO()\": Sheets(at).Cells(6, at).value = j & m:" ascii //weight: 1
        $x_1_5 = "Sheets(at).Cells(at, at).Name = sphereChat & \"sione\": ed = at * 3:" ascii //weight: 1
        $x_1_6 = "For Each l In ActiveSheet.UsedRange.SpecialCells(xlCellTypeConstants): b = b & l: Next" ascii //weight: 1
        $x_1_7 = "Sub Logica()" ascii //weight: 1
        $x_1_8 = "g = Run(\"\" & sphereChat & \"sione\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_SM_2147769959_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.SM!MSR"
        threat_id = "2147769959"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {52 61 6e 64 6f 6d 69 7a 65 3a 20 74 69 72 20 3d 20 31 3a 20 [0-16] 20 3d 20 79 75 28 49 6e 74 28 28 55 42 6f 75 6e 64 28 79 75 29 20 2b 20 74 69 72 29 20 2a 20 52 6e 64 29 29}  //weight: 3, accuracy: Low
        $x_3_2 = {6e 6e 6b 20 3d 20 53 70 6c 69 74 28 [0-9] 2c 20 22 21 22 29 3a 20 6f 6b 64 20 3d 20 53 70 6c 69 74 28 6e 6e 6b 28 [0-9] 29 2c 20 22 5d 22}  //weight: 3, accuracy: Low
        $x_1_3 = {53 68 65 65 74 73 28 [0-9] 29 2e 43 65 6c 6c 73 28 [0-9] 2c 20 [0-9] 29 2e 76 61 6c 75 65 20 3d 20 22 3d 22 20 26 20 52 65 70 6c 61 63 65 28 69 6d 6e 2c 20 22 3f 22 2c 20 [0-16] 28 53 70 6c 69 74 28 6e 6e 6b 28 30 29 2c 20 22 24 22 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {66 6f 72 6d 73 73 20 3d 20 52 75 6e 28 22 22 20 26 20 [0-9] 20 26 20 22 [0-9] 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_TOS_2147770170_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.TOS!MTB"
        threat_id = "2147770170"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(jj).Cells(sometime, jj).Name = voltAmrp & \"ok\":" ascii //weight: 1
        $x_1_2 = "jo = 9: sde = Split(yy, \"!\"): Ada = Split(sde(jj), hio(sometime))" ascii //weight: 1
        $x_1_3 = "Sheets(jj).Cells(sometime, jj).value = \"=\" & Replace(Vo, \"?\", notmalDdot(Split(sde(0), hio(jo))))" ascii //weight: 1
        $x_1_4 = "On Error Resume Next: MsgBox (Run(\"\" + voltAmrp & \"ok\"))" ascii //weight: 1
        $x_1_5 = "notmalDdot = cc(Int((UBound(cc) + mc) * Rnd))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_DR_2147770349_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.DR!MTB"
        threat_id = "2147770349"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Replace(\"htS7Q9Wtps://voyS7Q9Wya.comS7Q9W.mx/wp-content/themes/Divi/incluS7Q9Wdes/S7Q9WS7Q9Wbuilder/Fv14xgpeLe8s7gz.php\", \"S7Q9W\", \"\")" ascii //weight: 1
        $x_1_2 = "Replace(\"https://bitcoinsocietZw/ZI:zy.rbreviews.in/fonts/7pP1Kz7t9JQP.php\", \"Zw/ZI:z\", \"\")" ascii //weight: 1
        $x_1_3 = "Replace(\"https://r,bG7u7techforcedxb.com/wp-content/plur,bG7u7gins/wordr,bG7u7r,bG7u7press-seo/src/configr,bG7u7/K4IBJ7vLN7kr,bG7u7wM.php\", \"r,bG7u7\", \"\")" ascii //weight: 1
        $x_1_4 = "Replace(\"https://evolvingdesk.nus^jjs(l/GoogleAPI/vendor/symfony/pous^jjs(lyfill-intl-normalizer/Resources/JsWPus^jjs(VLZw9qr9GFE.php\", \"us^jjs(\", \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PIL_2147770352_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PIL!MTB"
        threat_id = "2147770352"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "listFr = \"$\"" ascii //weight: 1
        $x_1_2 = "If h = pilotprc Then listFr = \"]\"" ascii //weight: 1
        $x_1_3 = "Sheets(sik).Cells(pilotprc, sik).Name = selectedown & \"note\":" ascii //weight: 1
        $x_1_4 = "If IsEmpty(Cells(u, s)) = False Then m = m & Chr(Cells(u, s).value - 1)" ascii //weight: 1
        $x_1_5 = "jo = 9: sde = Split(m, \"!\"): Boxsize2 = Split(sde(sik), listFr(pilotprc))" ascii //weight: 1
        $x_1_6 = "Sheets(sik).Cells(pilotprc, sik).value = \"=\" & Replace(Vo, \"?\", HelpPrint(Split(sde(0), listFr(jo))))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_RV_2147771617_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.RV!MTB"
        threat_id = "2147771617"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"ht\" & \"t\" & \"p\" & \"s://\"" ascii //weight: 1
        $x_1_2 = {52 65 70 6c 61 63 65 28 53 74 72 69 6e 67 28 74 2c 20 [0-10] 29 2c 20 [0-10] 2c 20 75 29}  //weight: 1, accuracy: Low
        $x_1_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 28 22 [0-5] 22 20 26 20 22 [0-5] 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "= \"J1:J3\"" ascii //weight: 1
        $x_1_5 = {53 70 6c 69 74 28 65 2c 20 [0-15] 28 22 2b 22 2c 20 34 29 29}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 4c 65 6e 28 [0-7] 29 20 5c 20 78 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_VIS_2147773365_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.VIS!MTB"
        threat_id = "2147773365"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//app6.salesdatagenerator.com/wp-content/plugins/wp-all-import-pro/classes/PHPExcel/D09Po1Rg.php" ascii //weight: 1
        $x_1_2 = "//wolfix.ga/wp-includes/sodium_compat/src/Core/Base64/49WW5rPyD.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_VIS_2147773365_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.VIS!MTB"
        threat_id = "2147773365"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://magento2.thebrandrepublic.store/setup/pub/fonts/opensans/bold/I36IMIUtI.php" ascii //weight: 1
        $x_1_2 = "https://cookingschoolalovestory.com/wp-content/uploads/2020/08/MJzzWMTN0q53.php" ascii //weight: 1
        $x_1_3 = "https://getitsolutions.in/lib/bootstrap/css/9ddjb7IZFH.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_BSK_2147773502_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.BSK!MTB"
        threat_id = "2147773502"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FindWindowExA" ascii //weight: 1
        $x_1_2 = "user32.dll" ascii //weight: 1
        $x_1_3 = "ChrW(CLng((Not" ascii //weight: 1
        $x_1_4 = "Debug.Print" ascii //weight: 1
        $x_1_5 = "= Join(Array(Chr(CLng" ascii //weight: 1
        $x_1_6 = "= Len(Join(Array(wTvGr_1I2V_KoiG" ascii //weight: 1
        $x_1_7 = "= Len(Join(Array(YQxEyuO0wDOiSO4" ascii //weight: 1
        $x_1_8 = "= Len(Join(Array(flPpG_ug8" ascii //weight: 1
        $x_1_9 = "= Len(Join(Array(\"xNdjc_OZV" ascii //weight: 1
        $x_1_10 = "= Len(Join(Array(\"GvqL5K1EfGqUKZKeq4jvlCpnOM4" ascii //weight: 1
        $x_1_11 = "= Len(Join(Array(\"BgcJNQXez46GjtG0YO9XKToD5jY" ascii //weight: 1
        $x_1_12 = "= VMVxt_alj.zUub_fuZf_Ywz_r2c" ascii //weight: 1
        $x_1_13 = "= s4uliINljT0c4.hTZ8aMBEc" ascii //weight: 1
        $x_1_14 = "= yI2PJ_NEbV_qgUV_wWBo.tkj6qvt" ascii //weight: 1
        $x_1_15 = "= C1vn56f5.J6isN_mu0l_E3Q_xW4" ascii //weight: 1
        $x_1_16 = "= YlY8PQfE_Sd4KAA_lqyYT7_2V4iErI.Z6rw60V_grEeHPh" ascii //weight: 1
        $x_1_17 = "= ZBessGSn_d7a8Pk_WvjU9k.otWzlgtk_Ksn2zo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_BTK_2147773504_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.BTK!MTB"
        threat_id = "2147773504"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FindWindowExA" ascii //weight: 1
        $x_1_2 = "user32.dll" ascii //weight: 1
        $x_1_3 = "ChrW(CLng((Not" ascii //weight: 1
        $x_1_4 = "Debug.Print" ascii //weight: 1
        $x_1_5 = "= Join(Array(Chr(CLng" ascii //weight: 1
        $x_1_6 = "= Len(Join(Array(ZoIctfqa6D" ascii //weight: 1
        $x_1_7 = "= Len(Join(Array(N3L271VG6lH" ascii //weight: 1
        $x_1_8 = "= Len(Join(Array(WDrT3weJDYOegD" ascii //weight: 1
        $x_1_9 = "= Len(Join(Array(rqv2G_GkQc_F08" ascii //weight: 1
        $x_1_10 = "= MON2mI2Q.SWGE_EVV" ascii //weight: 1
        $x_1_11 = "= V1oIs_rXI.Oi0xPecbE0L0Zy" ascii //weight: 1
        $x_1_12 = "= zz9P0_QCD_H1FB.TqH8B0K" ascii //weight: 1
        $x_1_13 = "= DiHCv13e.XBGL3_LyVf_d77_GdM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_AJS_2147773606_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.AJS!MTB"
        threat_id = "2147773606"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub Zprint_one_page()" ascii //weight: 1
        $x_1_2 = "RoLo = Split(RTrim(last_pay_jan), Ok_Print1(\")\"))" ascii //weight: 1
        $x_1_3 = "Private Declare PtrSafe Function Next_Page_calc Lib \"urlmon\" _" ascii //weight: 1
        $x_1_4 = "Debug.Print findDate(deposit_a(Split(RoLo(0), Ok_Print1(\"D\"))))" ascii //weight: 1
        $x_1_5 = "Sheets(1).Cells(3, 1).Name = \"CARGO_\" & \"s\"" ascii //weight: 1
        $x_1_6 = "furmis = Split(RoLo(1), Ok_Print1(\"+\"))" ascii //weight: 1
        $x_1_7 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 02 00 53 68 65 65 74 73 28 31 29 2e 43 65 6c 6c 73 28 33 2c 20 31 29 2e 56 61 6c 75 65 20 3d 20 22 3d 22 20 26 20 66 75 72 6d 69 73 28 41 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_AJT_2147773607_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.AJT!MTB"
        threat_id = "2147773607"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Run (\"CARGO_\" & \"s\")" ascii //weight: 1
        $x_1_2 = "Next_Page_calc 0, findDate(deposit_a(Split(RoLo(0), Ok_Print1(\"D\")))), A_min_1 & \"\\\" & vega, 0, 0" ascii //weight: 1
        $x_1_3 = "order_to_order = Sheets(1).Range(\"B1:B5\").SpecialCells(xlCellTypeConstants)" ascii //weight: 1
        $x_1_4 = "Randomize: df = 2 - 1: deposit_a = nimo(Int((UBound(nimo) + df) * Rnd))" ascii //weight: 1
        $x_1_5 = "last_pay_jan = RTrim(rezzzult)" ascii //weight: 1
        $x_1_6 = "rezzzult = rezzzult & termsAnd(What_east, u) & termsAnd(overdue_2021, u) & termsAnd(Only_for_print, u)" ascii //weight: 1
        $x_1_7 = "Ok_Print1 = Replace(String(4, \"Z\"), \"Z\", df)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_AJU_2147773650_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.AJU!MTB"
        threat_id = "2147773650"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#If VBA7 And Win64 Then" ascii //weight: 1
        $x_1_2 = "Private Declare PtrSafe Function yellow_pages Lib \"urlmon\" _" ascii //weight: 1
        $x_1_3 = "Alias \"URLDownloadToFileA\" ( _" ascii //weight: 1
        $x_1_4 = "= Split(RTrim(first_prepayment), progress_bars(\")\"))" ascii //weight: 1
        $x_1_5 = "Sheets(1).Cells(3, 1).Value = \"=\" & storages(A)" ascii //weight: 1
        $x_1_6 = "Run (\"ForA_\" & \"s\")" ascii //weight: 1
        $x_1_7 = "progress_bars = Replace(String(4, \"Z\"), \"Z\", df)" ascii //weight: 1
        $x_1_8 = "rezzzult = rezzzult & book_rebook(cooperation, u) &" ascii //weight: 1
        $x_1_9 = "re_order = Sheets(1).Range(\"B1:B5\").SpecialCells(xlCellTypeConstants)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PCA_2147773685_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PCA!MTB"
        threat_id = "2147773685"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Join(Array(ChrW(CLng((xlExcel3 Xor ((" ascii //weight: 1
        $x_1_2 = "Debug.Print Mi23Gu9fTm4mfMLvv" ascii //weight: 1
        $x_1_3 = "= Abs(CLng((Not" ascii //weight: 1
        $x_1_4 = "Asc(Left$(Mid$(lRTQ_qKn_iMQ4_5jR, IMTMW0b3ZI0vA)" ascii //weight: 1
        $x_1_5 = "Lib \"user32.dll\" Alias \"PostMessageA\" (ByVal YxGZA_LUz_H2Ni As Long" ascii //weight: 1
        $x_1_6 = "Lib \"user32.dll\" Alias \"FindWindowExA\" (ByVal vnhm_2Yc_3xN_y3vj As Long" ascii //weight: 1
        $x_1_7 = "Environ(V5u4o_EXm_5yg_F7T4)" ascii //weight: 1
        $x_1_8 = ".Create Ddzpr0y, Null, CG0Vu_0kL_YYK_FP0" ascii //weight: 1
        $x_1_9 = "ChrW(CLng((Asc(\" \")))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PCA_2147773685_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PCA!MTB"
        threat_id = "2147773685"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CLng((xlPrimary Xor xlWorksheet4))" ascii //weight: 1
        $x_1_2 = "Debug.Print Y0s0ARxebRQvyW" ascii //weight: 1
        $x_1_3 = "= Abs(CLng((Not xlClipboardFormatEmbeddedObject)))" ascii //weight: 1
        $x_1_4 = ".Create Sl4a_ILIj, Null, IM27C_FIW0" ascii //weight: 1
        $x_1_5 = "Lib \"user32.dll\" Alias \"PostMessageA\" (ByVal ZHIP_Xvzw_8zo As Long, ByVal J0m75RQ As Long" ascii //weight: 1
        $x_1_6 = "Lib \"user32.dll\" Alias \"FindWindowExA\" (ByVal KV6r_pLxL_30D_0bLF As Long" ascii //weight: 1
        $x_1_7 = "Join(Array(RLBhhWvsrzwfx2NC ^ dwGECUCL" ascii //weight: 1
        $x_1_8 = {29 29 29 29 20 2a 20 52 6e 64 20 2b 20 43 4c 6e 67 28 28 [0-5] 20 58 6f 72 20 [0-6] 29 29 29 29}  //weight: 1, accuracy: Low
        $x_1_9 = "& Chr(CLng((Asc(\" \")))) & ChrW(CLng(((" ascii //weight: 1
        $x_1_10 = "Asc(Left$(Mid$(nT3o_rddp_fjoI, LIHi8l6UF2KyRmrq), CLng((" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_AJV_2147777303_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.AJV!MTB"
        threat_id = "2147777303"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cMis = Split(RTrim(v_mall_a(v_mall_a(Cells(200, 10)))), graph_zoom(\"!\", 5))" ascii //weight: 1
        $x_1_2 = "Sheets(1).Cells(3, 1).Name = \"Zoom_\" & \"and\"" ascii //weight: 1
        $x_1_3 = "Application.Run (\"Zoom_\" & \"and\")" ascii //weight: 1
        $x_1_4 = "email_client 0, next_orders(one_price(Split(cMis(0), \"GG\" & \"\"))), EchoOne & \"\\\" & bbBars, 0, 0" ascii //weight: 1
        $x_1_5 = "graph_zoom = Replace(String(t, Cx), Cx, u)" ascii //weight: 1
        $x_1_6 = "next_orders = \"htt\" & \"p\" & \"s://\" & vv" ascii //weight: 1
        $x_1_7 = "= Split(e, graph_zoom(\"+\", 4))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_DBK_2147778793_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.DBK!MTB"
        threat_id = "2147778793"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= IsDate(" ascii //weight: 1
        $x_1_2 = "= Join(Array(" ascii //weight: 1
        $x_1_3 = {49 73 45 72 72 6f 72 20 28 22 [0-20] 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 52 65 70 6c 61 63 65 28 [0-35] 2e [0-20] 2e 54 65 78 74 2c 20 22 [0-20] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 43 72 65 61 74 65 20 [0-30] 2e [0-35] 20 26 20 43 68 72 28 33 34 29 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68}  //weight: 1, accuracy: Low
        $x_1_6 = {4f 70 65 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 [0-22] 2e [0-15] 20 46 6f 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_RVA_2147778984_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.RVA!MTB"
        threat_id = "2147778984"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Replace(\"https://surustore.com/imageY9a<%7/cache/catalog/demo/bannersY9a<%7/h0dD8T2aNRz.php\", \"Y9a<%7\", \"\")" ascii //weight: 1
        $x_1_2 = "'rundll3L^O<$H>2.exe \", \"L^O<$H>\"," ascii //weight: 1
        $x_1_3 = "= Replace(\"W,<6d4O7scri,<6d4O7pt.Sh,<6d4O7ell\", \",<6d4O7\", \"\")" ascii //weight: 1
        $x_1_4 = "Environ(mythopoesesback.corpulentlyiceb(unpaperanodonti))" ascii //weight: 1
        $x_1_5 = ".Open wigglerscowardl.bronzitescyclaz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_RVB_2147779125_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.RVB!MTB"
        threat_id = "2147779125"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "process call create \"mshta.exe C:\\ProgramData\\FjEKVOTrGMfCpaEfPTy.rtf\"" ascii //weight: 2
        $x_1_2 = {70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 20 22 6d 73 68 74 61 2e 65 78 65 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-25] 2e 72 74 66 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Dridex_RVB_2147779125_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.RVB!MTB"
        threat_id = "2147779125"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Replace(\"httpsOeUZMp://clientOeUZMpe13.vetcarOeUZMpebaOeUZMphia.com/OeUZMpmidias/anexos/3/4/0WfGc8OeUZMp3H0Y.php\", \"OeUZMp\", \"\")" ascii //weight: 1
        $x_1_2 = "Replace(\"https:Iuke)Iuke)//vulkanvegasbIuke)onus.nIuke)anodatos.cl/css/phE8Iuke)yZOiU.phIuke)P\", \"Iuke)\", \"\")" ascii //weight: 1
        $x_1_3 = "Replace(\"https://grandvilaformosa.comNOuxgc/NOuxgcwp-contenNOuxgct/pluginsNOuxgc/woNOuxgcrdpress-seo/css/disNOuxgct/y9Od0UaBeWZ1.php\", \"NOuxgc\", \"\")" ascii //weight: 1
        $x_1_4 = "Replace(\"https://main.bgsr.site/wp-rR:/!includes/sodium_comrR:/!patrR:/!/src/Core32/CharR:/!Cha20/d68Tou3ui1RoUA.php\", \"rR:/!\", \"\")" ascii //weight: 1
        $x_1_5 = "Replace(\"https://sitiomorKlr-+adadosanjos.com.br/site/wa_Klr-+p_albums/p_album_jKlr-+ua5tam80/jua5rcb3bzKlr-+8x5s/thumb/Klr-+GxbFZiKIXwFV.php\", \"Klr-+\", \"\")" ascii //weight: 1
        $x_1_6 = "Replace(\"httOcV^KTips://central.ganhatempoOcV^KTi.com/tpl/imOcV^KTiOcV^KTig/brands/TMjlbOcV^KTitMx.php\", \"OcV^KTi\", \"\")" ascii //weight: 1
        $x_1_7 = "Replace(\"yte6;https://arabictv.ml/catalog/controlyte6;ler/payment/mollie-api-client/build/YS0LfExPc7MJU3.php\", \"yte6;\", \"\")" ascii //weight: 1
        $x_1_8 = "Replace(\"https://forbeslegalg%CCFYpowerlist20g%CCFY20.g%CCFYcom/imgg%CCFY/icons/u3BYBjeabtg%CCFYMx.php\", \"g%CCFY\", \"\")" ascii //weight: 1
        $x_1_9 = "Replace(\"https://wordpress.greekstrading.com/wp-content/plugins/megamenu/integ%oS)IaGrati%oS)IaGon/twentyseventee%oS)IaGn/bfCZUizZWh9sEim.php\", \"%oS)IaG\", \"\")" ascii //weight: 1
        $x_1_10 = "Replace(\"https://wo/kSsxo!r/kSsxo!dpress.greekstrading.com/wp-content/plugins/megamenu//kSsxo!integration/twentyseventeen/bfCZUizZWh9sEim/kSsxo!.php\", \"/kSsxo!\", \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_RVC_2147779126_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.RVC!MTB"
        threat_id = "2147779126"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Replace(\"httpr:z0Ls://adamjeecommodir:z0Lties.cor:z0Lm/wp-content/r:z0Lthemes/adamjeecom/inc/options/kUQIZCFicsJ.php\", \"r:z0L\", \"\")" ascii //weight: 1
        $x_1_2 = "Replace(\"_z+.\\90https://adamjeecommoditi_z+.\\90es.com/wp-cont_z+.\\90ent/themes_z+.\\90/adamjeecom/inc/opt_z+.\\90ions/kUQIZCFicsJ.php\",\"_z+.\\90\", \"\")" ascii //weight: 1
        $x_1_3 = "Replace(\"htWrVi4+tps://kaWrVi4+praywala.ga/website/wp-includes/js/jquery/uiWrVi4+/kk919Q3Ead7kgFQ.php\", \"WrVi4+\", \"\")" ascii //weight: 1
        $x_1_4 = "Replace(\"https://crea.N_Dativa.N_De-island.e-m2.net/wp-contena.N_Da.N_Dt/ta.N_Dhemes/creative_a.N_Disland/js/vc-composer/RUpDObeysEFp8.php\", \"a.N_D\", \"\")" ascii //weight: 1
        $x_1_5 = "Replace(\"ht@!fXg%$tps://arteecaligrafia.co@!fXg%$m.br/imagens/fo@!fXg%$tos/thumbs/MupJ4cZzxoElmn.php\", \"@!fXg%$\", \"\")" ascii //weight: 1
        $x_1_6 = "Replace(\"https:jdzpk//hartlejdzpkpooltjdzpkaxi.co.uk/TaxiShop/modules/corjdzpkeupdajdzpkter/views/js/bbKt3OpktVRAFnjdzpki.php\", \"jdzpk\", \"\")" ascii //weight: 1
        $x_1_7 = "Replace(\"https://ahdmsport.^viKU+scom/bootstrap/scripts/_notes/Xwi4K0BrmwX6hf.php\", \"^viKU+s\", \"\")" ascii //weight: 1
        $x_1_8 = "Replace(\"(F0Zc/Nhttps:/(F0Zc/N/steriglass.stigmatinesafrica.org/wp-i(F0Zc/Nncl(F0Zc/Nudes/sodium_compat/namespaced/Core/ChaCha20/KITDlCQHVyI.php\", \"(F0Zc/N\", \"\")" ascii //weight: 1
        $x_1_9 = "Replace(\"+*<);3>https://asgvprotecao.c+*<);3>om.br/wa_php/co+*<);3>mp/klbd5vx+*<);3>r6mf38o/YxSs9udR8U.php\", \"+*<);3>\", \"\")" ascii //weight: 1
        $x_1_10 = "Replace(\"https://arteecaligrafia.vI&8&$Ocom.br/imagens/fotos/thumbs/MupJ4cvI&8&$OZzxoElmn.php\", \"vI&8&$O\", \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_RVD_2147780337_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.RVD!MTB"
        threat_id = "2147780337"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Replace(\"https://cleacLO@1@Zorreaadvocacia.com/plLO@1@Zugins/LO@1@ZswiperLO@1@Z/srLO@1@Zc/modules/browser/lfGaQmV8zuLO@1@ZyVs.php\", \"LO@1@Z\", \"\")" ascii //weight: 1
        $x_1_2 = "Replace(\"httphNTu)s://cmmotvis2hNTu).nhNTu)gsoftweb.in/images/bg/zl91FhNTu)LR6o2r4.php\", \"hNTu)\", \"\")" ascii //weight: 1
        $x_1_3 = "Replace(\"https://cryptotreasurytrust.com/vnV|Blptendor/symfony/console/Tests/Command/rQE8fkl3GfA.php\", \"nV|Blpt\", \"\")" ascii //weight: 1
        $x_1_4 = "Replace(\"cf@fWhttpscf@fW://mosaicf@fWcuschina.com/wp-content/plucf@fWgins/wpml-cf@fWstring-translacf@fWtion/locale/orig/afFzHwIPlCs5b.php\", \"cf@fW\", \"\")" ascii //weight: 1
        $x_1_5 = "Replace(\"htQ%^A6|tps://cleacorreaadvocacia.com/plugQ%^A6|iQ%^A6|nQ%^A6|s/swiper/src/modules/browser/WWc1M3SnW.php\", \"Q%^A6|\", \"\")" ascii //weight: 1
        $x_1_6 = "Replace(\"ht+/ANi tps:+/ANi //designwaala.pk/wp-includes/+/ANi sodium_compat/src/Core32/ChaCha20+/ANi /pLNd7f7CpRUW1Z.php\", \"+/ANi \", \"\")" ascii //weight: 1
        $x_1_7 = "Replace(\"https://gatipackers-movers.com/wp-content/plugins/(|BojB2elementor/m(|BojB2(|BojB2odules/admin-bar/N(|BojB2YWf4q0eq6D9P.php\", \"(|BojB2\", \"\")" ascii //weight: 1
        $x_1_8 = "Replace(\"https://jaypalsinh.ngsoftweb.eEvvmU%in/OLD_07032021/classeEvvmU%es/PHPExcel/Calculation/Token/pm4Cb7WAPp8.php\", \"eEvvmU%\", \"\")" ascii //weight: 1
        $x_1_9 = "Replace(\"https://poOsKYsdcast.oigaprofe.com.mx/wp-includes/sodiumOsKYs_comOsKYspat/src/Core32/ChaCha20/KlrIU42g.php\", \"OsKYs\", \"\")" ascii //weight: 1
        $x_1_10 = "Replace(\"https://voyya.com.mx/wp-content/themes/Divi/incl(,L;hciudes/builder/Fv14xgpeLe8s7gz.php\", \"(,L;hci\", \"\")" ascii //weight: 1
        $x_1_11 = "Replace(\"https://sis.ieadar.com.br-$r)r/Igreja-master/agendaSec/css/Sq4D0WfbvSitsO.php\", \"r-$r)\", \"\")" ascii //weight: 1
        $x_1_12 = "Replace(\"h&TFhF1=ttps://titancontractin&TFhF1=gllc.a&TFhF1=quaclients.com/wp-content/plugins/woocommerce/includes/abstracts/ppEWp5gHg.php\", \"&TFhF1=\", \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_RVE_2147780886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.RVE!MTB"
        threat_id = "2147780886"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Action.Arguments = Module2.u_te_pzneqdutc(kbfetpgixuipegb) & Module2.eke_lrjzty_nyg(alioam_d_vhgqrm) " ascii //weight: 1
        $x_1_2 = "Action.Arguments = Module2.qpufdj_ahk_xa(bmrqxmznmfj_mw) & Module3.qkbfdj_czxmroo(zaxtnacihmyqylh)" ascii //weight: 1
        $x_1_3 = "Action.Arguments = Module2.wetuwweqvng_xk(dn_fuw__pvdo_y) & Module3.wafqafxokb_irnh(pk_trspluv_vwuh)" ascii //weight: 1
        $x_1_4 = "Action.Arguments = Module2.znkaweeblvugzag(cmtii_ko_wcskf) & Module2.hnbcowlkfnncgjx(tbzghdqn_puyfi)" ascii //weight: 1
        $x_1_5 = {43 61 6c 6c 20 72 6f 6f 74 46 6f 6c 64 65 72 2e 52 65 67 69 73 74 65 72 54 61 73 6b 44 65 66 69 6e 69 74 69 6f 6e 28 20 5f 0d 0a 20 20 20 20 22 54 65 73 74 20 54 69 6d 65 54 72 69 67 67 65 72 22 2c 20 74 61 73 6b 44 65 66 69 6e 69 74 69 6f 6e 2c 20 36 2c 20 2c 20 2c 20 33 29}  //weight: 1, accuracy: High
        $x_1_6 = "trigger.ExecutionTimeLimit = \"PT5M\"" ascii //weight: 1
        $x_1_7 = "service = CreateObject(\"Schedule.Service\")" ascii //weight: 1
        $x_1_8 = "time = DateAdd(\"n\", 10, Now)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_RU_2147781191_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.RU!MTB"
        threat_id = "2147781191"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://staging.filterfresh.co.nz/orzdr6kswwk4tct.php" ascii //weight: 1
        $x_1_2 = "https://camilajauja.com/wp-content/endurance-page-cache/demo/profile/register/b54wa0tl7f.php" ascii //weight: 1
        $x_1_3 = "https://clinicasaludmasculina.com/phone/css/avgj1irwsza5cuw.php" ascii //weight: 1
        $x_1_4 = "https://theforesthub.com/wp-content/themes/omeli/templates/content/l5cjfhilk.php" ascii //weight: 1
        $x_1_5 = "https://telecodepa.es/wp-content/themes/twentytwentyone/template-parts/content/anhuydql74.php" ascii //weight: 1
        $x_1_6 = "https://landingpages.pontodata.com.br/wp-content/plugins/duracelltomi-google-tag-manager/integration/whichbrowser/src/analyser/header/useragent/device/npimchmquv.php" ascii //weight: 1
        $x_1_7 = "https://partnersca.co.za/about-us/desktop/ggigi6tzyntu.php" ascii //weight: 1
        $x_1_8 = "https://wolfix.ga/wp-includes/sodium_compat/src/core/base64/49ww5rpyd.php" ascii //weight: 1
        $x_1_9 = "https://iteksa.com/wp-content/plugins/revslider/includes/instagramscraper/9vmr6spbrbe.php" ascii //weight: 1
        $x_1_10 = "https://marksmenpackaging.com/seashorepackaging.com/wp-content/uploads/wp-file-manager-pro/fm_backup/q6n6fst3lktl.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_NYKC_2147781675_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.NYKC!MTB"
        threat_id = "2147781675"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {3d 20 52 65 70 6c 61 63 65 28 22 [0-15] 68 74 74 70 73 3a 2f 2f 6e 65 77 7a 72 6f 6f 74 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 74 68 65 6d 65 73 2f 73 61 68 69 66 61 2f 63 73 73 2f 69 6c 69 67 68 74 62 6f 78 2f 6f 74 6c 44 68 36 4f 76 34 67 49 6d 5a 30 74 2e 70 68 70}  //weight: 3, accuracy: Low
        $x_3_2 = {3d 20 4d 69 64 28 22 [0-15] 28 68 74 74 70 73 3a 2f 2f 66 61 74 65 2e 73 61 2f 32 45 57 5a 31 67 7a 4b 62 6b 2e 70 68 70}  //weight: 3, accuracy: Low
        $x_1_3 = {3d 20 4d 69 64 28 22 [0-10] 41 70 70 44 61 74 61}  //weight: 1, accuracy: Low
        $x_5_4 = {64 65 2f 6f 56 57 6a 4f 72 31 5a 33 5a 2e 70 68 70 28 00 68 74 74 70 73 3a 2f 2f 63 6f 65 6e 69 67 6c 69 63 68 2e}  //weight: 5, accuracy: Low
        $x_1_5 = "wmic process call create 'rundll32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Dridex_NYLC_2147781676_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.NYLC!MTB"
        threat_id = "2147781676"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2e 63 6f 6d 2e 62 72 2f 73 69 74 65 62 75 69 6c 64 65 72 2f 49 57 75 31 73 33 63 68 51 6f 61 58 71 2e 70 68 70 4b 00 68 74 74 70 73 3a 2f 2f [0-10] 2e 63 6f 6d 2e 62 72 2f 6c 6f 6a 61 6d 75 73 69 63}  //weight: 5, accuracy: Low
        $x_5_2 = {2e 63 6f 6d 2f 33 49 50 6b 34 54 6d 32 41 73 2e 70 68 70 32 00 68 74 74 70 73 3a 2f 2f 6d 61 68 69 6e 75 72 2e 6e 75 63 6c 65 75 73 74 65 63 68 62 64}  //weight: 5, accuracy: Low
        $x_5_3 = {2e 6e 65 74 2f 41 77 49 33 75 77 69 77 75 55 36 2e 70 68 70 28 00 68 74 74 70 73 3a 2f 2f 65 75 72 6f 2d 6f 66 66 69 63 65}  //weight: 5, accuracy: Low
        $x_1_4 = {3d 20 4d 69 64 28 22 [0-15] 41 70 70 44 61 74 61}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 52 65 70 6c 61 63 65 28 22 [0-10] 77 6d 69 63 20 70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 20 27 72 75 6e 64 6c 6c 33 32 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 52 65 70 6c 61 63 65 28 22 [0-15] 4f 66 66 6c 69 6e 65 46 69 6c 65 73 53 74 61 72 74}  //weight: 1, accuracy: Low
        $x_5_7 = {2e 63 6f 2e 6b 65 2f 32 55 75 64 45 63 68 77 63 78 61 37 64 66 2e 70 68 70 2d 00 68 74 74 70 73 3a 2f 2f 62 69 7a 6f 6d 61 74 65}  //weight: 5, accuracy: Low
        $x_5_8 = {2e 63 6f 6d 2e 62 72 2f 68 50 41 72 31 31 69 5a 2e 70 68 70 32 00 68 74 74 70 73 3a 2f 2f 77 65 62 6d 61 69 6c 2e 65 6c 65 74 72 69 63 61 76 6f 6c 74}  //weight: 5, accuracy: Low
        $x_5_9 = {2e 63 6f 6d 2f 63 73 73 2f 66 6f 6e 74 73 2f 49 4e 56 52 68 77 64 75 55 61 46 53 2e 70 68 70 37 00 68 74 74 70 73 3a 2f 2f 6d 61 72 62 69 61 64 65 73 69 67 6e}  //weight: 5, accuracy: Low
        $x_5_10 = {2e 63 6f 6d 2e 74 77 2f 69 6d 61 67 65 73 2f 69 65 38 2d 70 61 6e 65 6c 2f 44 72 72 76 45 53 41 30 73 45 65 2e 70 68 70 3c 00 68 74 74 70 73 3a 2f 2f 66 6c 79 69 6e 67 6c 6f 76 65}  //weight: 5, accuracy: Low
        $x_1_11 = {3d 20 4d 69 64 28 22 [0-10] 73 63 72 69 70 74 2e 53 68 65 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Dridex_NYMC_2147781677_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.NYMC!MTB"
        threat_id = "2147781677"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 6a 73 2f 74 69 6e 79 6d 63 65 2f 73 6b 69 6e 73 2f 6c 69 67 68 74 67 72 61 79 2f 41 32 6a 56 49 55 66 69 66 41 37 7a 77 52 2e 70 68 70 5a 00 68 74 74 70 73 3a 2f 2f 61 69 6d 73 31 2e 65 7a 69 63 6f 64 65 73}  //weight: 5, accuracy: Low
        $x_5_2 = {2e 63 6f 6d 2f 66 69 72 6d 61 73 2f 69 6d 67 2f 55 69 67 6e 75 4e 37 4e 54 5a 73 53 2e 70 68 70 3c 00 68 74 74 70 73 3a 2f 2f 63 61 6e 74 65 72 61 73 70 61 6c 6f 6d 69 6e 6f}  //weight: 5, accuracy: Low
        $x_1_3 = {3d 20 4d 69 64 28 22 [0-15] 57 73 63 72 69 70 74 2e 53 68 65 6c 6c}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 52 65 70 6c 61 63 65 28 22 [0-15] 41 70 70 44 61 74 61}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 52 65 70 6c 61 63 65 28 22 [0-30] 2e 64 6c 6c 22 2c}  //weight: 1, accuracy: Low
        $x_5_6 = {2e 75 73 2f 37 36 61 37 53 67 36 41 41 5a 52 58 2e 70 68 70 28 00 68 74 74 70 73 3a 2f 2f 6d 61 69 6c 2d 63 61 6c 6c}  //weight: 5, accuracy: Low
        $x_5_7 = {63 6f 6d 2e 63 6f 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 73 68 6f 72 74 63 6f 64 65 73 2d 75 6c 74 69 6d 61 74 65 2f 69 6e 63 2f 63 6f 72 65 2f 4b 32 6b 47 58 4b 69 36 76 35 72 43 2e 70 68 70 5a 00 68 74 74 70 73 3a 2f 2f 63 69 61 74 72 61 6e 2e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Dridex_NYNC_2147781696_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.NYNC!MTB"
        threat_id = "2147781696"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 6d 2f 6f 6c 64 2d 64 61 74 61 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 6a 73 2f 74 69 6e 79 6d 63 65 2f 6c 61 6e 67 73 2f 49 30 55 4d 37 6a 42 4b 6d 5a 6d 4a 42 2e 70 68 70 5a 00 68 74 74 70 73 3a 2f 2f 62 6f 6e 73 61 69 73 75 70 72 65 6d 65 2e}  //weight: 1, accuracy: Low
        $x_1_2 = "wmic process call create 'rundll32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_VS_2147781708_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.VS!MSR"
        threat_id = "2147781708"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "respots_steevest_epigynous = Replace(\"(FoPjp(FoPjp(FoPjp(FoPjphttps://impress-hrd.mysoftheaven.com/FVejFYrwrP7gXx.php\", \"(FoPjp\", \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_NYYC_2147781750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.NYYC!MTB"
        threat_id = "2147781750"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {68 74 74 70 73 [0-10] 3a 2f 2f 66 6f 72 77 65 69 2e 63 6f [0-10] 6d 2f 69 6d 61 67 65 2f 63 61 63 68 65 2f 64 61 74 61 2f 56 61 72 69 [0-10] 6f 73 2f 43 61 62 6c 65 73 2f 30 59 47 77 72 45 52 79 [0-10] 2e 70 68 70}  //weight: 20, accuracy: Low
        $x_20_2 = {68 74 74 70 73 3a 2f 2f 63 61 6e 61 76 65 72 61 6c 73 [0-10] 2e 74 6f 75 72 73 2f 77 70 73 [0-10] 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 62 69 72 63 68 73 63 68 65 64 75 6c 65 73 [0-10] 2f 69 6e 63 6c 75 64 65 73 2f 6d 6f 64 65 6c 2f 6e 43 53 4a 4c 59 76 76 47 4a 77 2e 70 68 70}  //weight: 20, accuracy: Low
        $x_20_3 = {68 74 74 70 73 3a 2f 2f 61 64 65 67 74 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 73 6f 64 69 75 6d 5f 63 6f [0-10] 6d 70 [0-10] 61 74 2f 6e 61 6d 65 73 70 61 63 65 64 2f 43 [0-10] 6f 72 65 2f 43 68 61 43 68 61 32 30 2f 65 44 4b 67 6f 69 5a 6f 76 38 32 46 54 2e 70 68 70}  //weight: 20, accuracy: Low
        $x_20_4 = {68 74 74 70 73 3a 2f 2f 6f 75 72 63 6f 6d 6d 2e 63 6f 2e 75 6b 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 62 75 64 64 79 62 6f 73 73 2d 70 6c 61 74 66 6f [0-10] 72 6d 2f 62 [0-10] 70 2d 6d 6f 64 65 72 61 74 69 6f [0-10] 6e 2f [0-10] 63 6c 61 73 73 65 73 2f [0-10] 53 58 44 65 74 6b 67 73 6e 50 50 2e 70 68 70}  //weight: 20, accuracy: Low
        $x_20_5 = {68 74 74 70 73 3a 2f 2f 74 61 63 74 6f 63 [0-10] 6f 6e 73 63 69 65 6e 74 [0-10] 65 2e 6e 65 74 2f 77 70 2d 63 6f 6e 74 65 6e 74 [0-10] 2f 70 6c 75 67 69 6e [0-10] 73 2f 6a 73 5f [0-10] 63 6f 6d 70 6f 73 65 72 2f 63 6f 6e 66 69 67 2f 62 75 74 74 6f 6e 73 2f 4c 39 4f 34 [0-10] 4b 6c 63 38 31 65 63 4c 2e 70 68 70}  //weight: 20, accuracy: Low
        $x_20_6 = {68 74 74 70 73 3a 2f 2f 6f 72 67 61 6e 69 67 72 61 6d 61 2e 67 75 61 6c 64 61 2e 63 6f 6d [0-10] 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 63 6f 64 65 70 72 65 73 73 2d 61 64 6d 69 6e 2d 63 6f 6c 75 6d 6e 73 2f 63 6c 61 73 73 65 73 2f 41 64 6d 69 6e 2f 57 6c 38 67 6e 76 48 77 51 37 7a 2e 70 68 70}  //weight: 20, accuracy: Low
        $x_1_7 = {3d 20 52 65 70 6c 61 63 65 28 22 57 73 [0-10] 63 [0-10] 72 [0-10] 69 [0-10] 70 74 [0-10] 2e [0-10] 53 68 65 6c 6c}  //weight: 1, accuracy: Low
        $x_4_8 = {3d 20 52 65 70 6c 61 63 65 28 22 [0-10] 77 6d 69 63 20 70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 29 [0-10] 20 27 72 75 6e 64 6c 6c 33 32 2e 65 78 65}  //weight: 4, accuracy: Low
        $x_20_9 = {68 74 74 70 73 3a 2f 2f 6c 61 62 72 69 65 2d 73 61 62 65 74 74 65 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 73 6f 64 69 75 [0-10] 6d 5f [0-10] 63 6f 6d 70 61 74 [0-10] 2f 6e 61 6d 65 73 70 61 63 65 64 2f 43 6f [0-10] 72 65 2f 43 68 61 43 68 61 32 30 2f 67 70 [0-10] 35 79 48 [0-10] 72 42 70 2e 70 68 70}  //weight: 20, accuracy: Low
        $x_20_10 = {68 74 74 70 73 3a 2f 2f 6b 77 65 72 61 6c 74 64 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 [0-10] 2f 77 6f 6f 63 6f 6d 6d [0-10] 65 72 63 65 2d 64 65 6c 69 76 65 72 79 2d 6e 6f 74 65 73 2f 69 6e 63 6c 75 64 65 73 2f 63 6f [0-10] 6d 70 6f 6e 65 6e 74 2f 75 36 33 52 [0-10] 38 34 68 4d 2e 70 68 70}  //weight: 20, accuracy: Low
        $x_4_11 = {3d 20 52 65 70 6c 61 63 65 28 22 [0-10] 41 70 70 44 61 74 61}  //weight: 4, accuracy: Low
        $x_1_12 = {3d 20 52 65 70 6c 61 63 65 28 22 [0-10] 5c [0-40] 2e [0-10] 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_13 = {3d 20 52 65 70 6c 61 63 65 28 22 [0-20] 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: Low
        $x_1_14 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f [0-80] 2f [0-80] 2e 70 68 70 22 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_4_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Dridex_NYZC_2147781761_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.NYZC!MTB"
        threat_id = "2147781761"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 73 [0-10] 75 72 75 73 74 6f 72 65 2e 63 6f 6d 2f 69 6d 61 67 65 2f 63 61 63 68 65 [0-10] 2f 63 61 74 61 6c 6f 67 2f 64 65 6d 6f 2f 62 61 6e 6e 65 72 73 2f 68 30 64 44 38 54 32 61 4e 52 7a 2e 70 68 70 22 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 76 69 74 69 6c 69 67 6f 6d 61 74 63 68 2e 63 6f 6d 2f 77 70 76 69 74 69 6c 69 67 6f 6d 61 74 63 68 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 63 73 73 2f 64 [0-10] 69 73 74 2f 62 6c 6f 63 6b 2d 64 69 72 65 63 74 6f 72 79 2f 51 61 4c 55 49 55 6b 78 6f 6d 58 2e 70 68 [0-10] 70 22 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 63 61 6e 61 76 65 72 61 6c 2e 74 6f 75 72 73 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 62 69 72 63 68 73 63 68 65 64 75 6c 65 2f 69 6e 63 6c 75 64 65 73 2f 6d 6f 64 65 [0-10] 6c 2f 6e 43 53 4a 4c 59 76 76 47 4a 77 2e 70 68 70 22 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 65 6d 70 6f 77 65 72 70 69 6c 61 74 65 73 73 74 75 64 69 6f 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 [0-10] 65 6e 74 2f 70 6c 75 67 [0-10] 69 6e 73 2f [0-10] 65 6c 65 6d 65 6e 74 6f 72 2d 70 72 6f 2f 6d 6f 64 75 6c 65 73 2f 61 6e 69 6d 61 74 65 64 2d 68 [0-10] 65 61 64 6c 69 6e 65 2f 71 66 63 46 4a 79 6e 47 61 6b 33 4f 2e 70 68 70 22 2c}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 [0-10] 73 3a 2f 2f 70 72 65 64 [0-10] 69 63 74 69 6f 6e 32 30 32 30 2e 63 6f 6d 2f 77 70 2d [0-10] 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 [0-10] 6e 73 2f 72 65 61 6c 6c 79 2d 73 69 6d 70 [0-10] 6c 65 2d 73 73 6c 2f 74 65 73 74 73 73 6c 2f 63 6c 6f 75 64 66 6c 61 72 65 2f 6a 44 4e 36 77 6d 46 69 64 47 36 35 2e 70 68 70 22 2c}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 6f 70 63 61 62 64 2e 6f 72 67 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 74 68 65 6d 65 73 2f [0-10] 74 77 65 6e 74 79 73 65 76 65 6e 74 65 65 6e 2f 74 65 6d 70 6c 61 74 65 2d 70 61 72 [0-10] 74 70 48 2d 6c 57 5f 73 2f 66 6f 6f 74 65 72 2f 38 42 55 50 62 6c 53 35 43 52 47 6d 2e 70 68 70 22 2c}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 6f 6f 74 61 73 68 6f 70 2e 63 6f 6d 2f 63 61 74 61 6c 6f 67 2f [0-10] 6c 61 6e 67 75 61 67 65 2f 61 72 2f 65 78 74 65 6e 73 69 6f 6e 2f 63 61 70 74 63 68 61 2f 49 7a 34 30 43 61 43 46 78 2e 70 68 70 22 2c}  //weight: 1, accuracy: Low
        $x_1_8 = {3d 20 52 65 70 6c 61 63 65 28 22 [0-10] 68 74 74 70 73 3a 2f 2f 6d 61 72 63 6f 69 [0-10] 73 6c 61 [0-10] 6e 64 67 75 69 64 65 62 6f 6f 6b 2e 63 [0-10] 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 6a 73 2f 74 69 6e 79 6d 63 65 2f 70 6c 75 67 69 6e 73 [0-15] 2f 63 68 61 72 6d 61 70 2f 78 6c 74 47 72 4a 57 69 4b 2e 70 68 70 22 2c}  //weight: 1, accuracy: Low
        $x_1_9 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 73 72 69 76 69 6e 61 [0-10] 79 73 61 6c 69 61 6e 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f [0-10] 63 61 74 [0-10] 63 68 [0-10] 2d 69 6e 73 74 61 67 72 61 6d 2d 66 65 65 64 2d 67 61 6c 6c 65 72 79 2d 77 69 64 67 65 74 [0-10] 2f 70 75 62 [0-10] 6c 69 63 2f 63 73 73 2f 6a 59 66 65 34 62 39 69 6d 42 2e 70 68 70 22 2c}  //weight: 1, accuracy: Low
        $x_1_10 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 62 65 6c 6c 61 6c 6f [0-10] 76 65 62 6f 75 74 69 71 75 65 2e 63 6f 6d 2f 77 70 2d 63 [0-10] 6f 6e 74 65 6e 74 2f 74 68 65 6d 65 73 2f 73 61 6c [0-10] 69 65 [0-10] 6e 74 2f 69 6e 63 6c 75 64 65 73 2f 70 61 72 [0-10] 74 69 61 6c 73 2f 74 67 [0-10] 54 7a 4b 64 71 7a 47 69 76 75 5a 39 2e 70 68 70 22 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_NYZD_2147781765_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.NYZD!MTB"
        threat_id = "2147781765"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 6f 70 63 61 62 64 2e 6f 72 [0-10] 67 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 74 68 65 6d 65 73 2f 74 77 65 6e 74 79 73 65 76 65 6e 74 65 65 6e 2f 74 65 6d 70 6c 61 74 65 2d 70 61 72 74 73 2f 66 6f 6f 74 65 72 2f 38 42 55 50 62 6c 53 35 43 52 47 6d 2e 70 68 70 22 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_NYZD_2147781765_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.NYZD!MTB"
        threat_id = "2147781765"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(\"https://www.j!I.U<matteico.com/NMI_beta/wpj!I.U<-contenj!I.U<t/plugins/wp-smuj!I.U<j!I.U<shit/_src/BNtsMfSe12.php\", \"j!I.U<\", \"\")" ascii //weight: 1
        $x_1_2 = "= Replace(\"qLSeD=dhtqLSeD=dtps://houzzlink.comqLSeD=d/wp-content/plugins/osen-wc-mpesa-qLSeD=dmaster/updatqLSeD=des/Puc/KqLSeD=dOmZGbynRtPJ.php\", \"qLSeD=d\", \"\")" ascii //weight: 1
        $x_1_3 = "= Replace(\"https://adegt.com/wp-incY|Rn5rludes/sodium_compat/namespaced/CY|Rn5rore/ChaCY|Rn5rha20/eDKgoiZov82FT.php\", \"Y|Rn5r\", \"\")" ascii //weight: 1
        $x_1_4 = "= Replace(\"hqQBW>SZttps://opcabd.org/wp-coqQBW>SZntent/themes/twentyseventeen/qQBW>SZtemplate-parts/footeqQBW>SZr/qQBW>SZ8BUPblS5CRGm.php\", \"qQBW>SZ\", \"\")" ascii //weight: 1
        $x_1_5 = "= Replace(\"https://menuiserie-lemoineduIYvEP.bzduIYvEPh/wp-duIYvEPcontent/themes/twentynineteen/template-parts/conduIYvEPtent/x0XxEduIYvEPHWGdeyPBEj.php\", \"duIYvEP\", \"\")" ascii //weight: 1
        $x_1_6 = "= Replace(\"https:/T!N13j,/empT!N13j,owerpilatT!N13j,essT!N13j,tudio.com/wp-content/plugins/elementor-prT!N13j,o/modules/animated-headline/qfcFJynGak3O.php\", \"T!N13j,\", \"\")" ascii //weight: 1
        $x_1_7 = "= Replace(\"https://ntfJ,:Rb.9J,:Rb.9.gov.sb/components/com_acysms/views/unsubscrJ,:Rb.9ibeJ,:Rb.9/tmpl/8Wa80ysYUvJ,:Rb.96Klh.php\", \"J,:Rb.9\", \"\")" ascii //weight: 1
        $x_1_8 = "= Replace(\"htkNj(dtps://tackNj(dtoconscientekNj(dkNj(d.net/wp-content/plkNj(dugins/js_composer/config/bkNj(duttons/L9O4Klc81ecL.php\", \"kNj(d\", \"\")" ascii //weight: 1
        $x_1_9 = "= Replace(\"httpy0Q/( as://www.matteico.com/NMI_beta/wp-content/plugins/wp-smushit/_src/BNty0Q/( asMfSe12.php\", \"y0Q/( a\", \"\")" ascii //weight: 1
        $x_1_10 = "= Replace(\"https://enlazador.com.es/wp-content1=A8bM2/themes/twentyn1=A8bM2inetee1=A8bM2n/s1=A8bM2ass/blocks/mLrfH3gL5MqmI.php\", \"1=A8bM2\", \"\")" ascii //weight: 1
        $x_1_11 = "= Replace(\"https://nmq!N_marcoislandnmq!N_guidebook.com/wp-nmq!N_includes/js/tinymce/plugins/charmap/xltGrJWiK.nmq!N_php\", \"nmq!N_\", \"\")" ascii //weight: 1
        $x_1_12 = "= Replace(\"https://bycec.in/wp-inclH;.J2udes/js/tinymce/plugins/charmap/1MRWRA8z2S2Ajv.php\", \"H;.J2\", \"\")" ascii //weight: 1
        $x_1_13 = "= Replace(\"https:/6ynDtVp/canaveral.tours/wp-content/6ynDtVpplugins/birchschedule/includes/model/nCSJLYvvGJw.php\", \"6ynDtVp\", \"\")" ascii //weight: 1
        $x_1_14 = "= Replace(\"https://adegt.com/wp-includ8ej9DC3e8ej9DC3s/sodium_compat/namespaced/Core/ChaCha20/eDKgoiZov82FT.php\", \"8ej9DC3\", \"\")" ascii //weight: 1
        $x_1_15 = "= Replace(\"https://dinratnews.n>Gkx4ret/wp-content/uploads/2020/05/thumbnail>Gkx4rs/br>Gkx4rCyRumj.php\", \">Gkx4r\", \"\")" ascii //weight: 1
        $x_1_16 = "= Replace(\"https:HhxuI//HhxuIvitiligomatch.com/wpvitHhxuIiligomatch/wp-includes/css/dist/block-diHhxuIrectory/HhxuIHhxuIQaLUIUkxomX.php\", \"HhxuI\", \"\")" ascii //weight: 1
        $x_1_17 = "= Replace(\"https://vitiligomatch.com/wpvi%+/$^Ntiligo%+/$^Nmatch/wp-includes/css/%+/$^Ndist/block-di%+/$^Nrectory/QaLUIUkxomX.php\", \"%+/$^N\", \"\")" ascii //weight: 1
        $x_1_18 = "= Replace(\"https://canaveral.tours/wp-xN =eicontent/plugins/birchschedule/ixN =eincludes/model/nCSJLYvvGxN =eiJw.php\", \"xN =ei\", \"\")" ascii //weight: 1
        $x_1_19 = "= Replace(\"https://prediction2020.com/wp-content/pluginFi64.Ls/really-simple-ssl/testssl/cloudflare/jDN6Fi64.LwmFidG65.php\", \"Fi64.L\", \"\")" ascii //weight: 1
        $x_1_20 = "= Replace(\"https://emCVaz;,powerpilatesstudio.com/wp-content/plugins/eleCVaz;,mentor-pro/modules/animated-headline/qfcFJynGak3O.php\", \"CVaz;,\", \"\")" ascii //weight: 1
        $x_1_21 = "= Replace(\"https://tineo.gal/wp-content/plBtpq;Yugins/wordpress-seo/vendor/composer/installers/tests/Composer/Installers/lSNBjeKdHn.php\", \"Btpq;Y\", \"\")" ascii //weight: 1
        $x_1_22 = "= Replace(\"https://dinratnews.net/wp-content/uploads/2020/05/thu9RbRE<mbnails/brCyR9RbRE<umj.php\", \"9RbRE<\", \"\")" ascii //weight: 1
        $x_1_23 = "= Replace(\"https://r;cbn|,its;cbn|,-sa.co.za/wp-conte;cbn|,nt/plugins/fullwidth-templates/templates/default/QK1X320RxB.php\", \";cbn|,\", \"\")" ascii //weight: 1
        $x_1_24 = "= Replace(\"https:/CF$BFSt/www.akseral.com/yonetim/vendors/iconCF$BFStfonts/font-awesome/css/wjM7uzNc3U8doR.pCF$BFSthp\", \"CF$BFSt\", \"\")" ascii //weight: 1
        $x_1_25 = "= Replace(\"https://tactoconscient+W^JBe.net/wp-content/plugins/js_composer/config/buttons/L9O4Klc81ecL.php\", \"+W^JB\", \"\")" ascii //weight: 1
        $x_1_26 = "= Replace(\"https://kw--eMZseraltd.com/wp-content/plugins/woocommerce--eMZs-delivery-notes/incl--eMZsudes/component/u63R84hM.p--eMZshp\", \"--eMZs\", \"\")" ascii //weight: 1
        $x_1_27 = "= Replace(\"htt,Ys*nmps://,Ys*nmforwei.c,Ys*nmo,Ys*nmm/image,Ys*nm/cache/data/Va,Ys*nmrios/Cables/0YGwrERy.php\", \",Ys*nm\", \"\")" ascii //weight: 1
        $x_1_28 = "= Replace(\"https://aspilosel>A*THaia.cfser>A*THver3.net/wp-content/plug>A*THi>A*THns/>A*THpolylang/js/build/ek117gB>A*THgoNad.php\", \">A*TH\", \"\")" ascii //weight: 1
        $x_1_29 = "= Replace(\"https://Abidshakir.co.uk/wp-content/plugins/elementQf#7O&5or/includes/admin-templates/22VemIrdTrquwKE.php\", \"Qf#7O&5\", \"\")" ascii //weight: 1
        $x_1_30 = "= Replace(\"https://enlazador.com.es/wp-content/themes/twentynineteen/sass/blocks/mLrfH3gL5MqmI.phIxv_X*^p\", \"Ixv_X*^\", \"\")" ascii //weight: 1
        $x_1_31 = "= Replace(\"https://ourcomm.co.uyFvSLLk/wp-content/plyFvSLLugins/buddyboss-platform/bp-moderation/classes/SXDetkgsnPP.php\", \"yFvSLL\", \"\")" ascii //weight: 1
        $x_1_32 = "= Replace(\"E@|PnWhttps://tineo.gal/wE@|PnWp-content/plugins/wordpress-seo/vendor/composer/iE@|PnWnstallers/tests/Composer/InstalleE@|PnWrs/lSNBjeKdHn.php\", \"E@|PnW\", \"\")" ascii //weight: 1
        $x_1_33 = "= Replace(\"https://brandsites.gu dL,(bKnweb dL,(bKhosting.com.au/site/wp-includes/Text/Diff/Engine/eUhebviTSOzDZ.php\", \" dL,(bK\", \"\")" ascii //weight: 1
        $x_1_34 = "= Replace(\"https:/DXuUO:V/www.matteico.com/NMI_beDXuUO:Vta/wp-content/plugins/wp-smuDXuUO:VDXuUO:Vshit/_src/BNtsMfSe12.php\", \"DXuUO:V\", \"\")" ascii //weight: 1
        $x_1_35 = "= Replace(\"https://www.akseral.com/yone3n/E2tim/vendors/iconfonts/font-awesome/css/w3n/E2jM7uzNc3U8doR.php\", \"3n/E2\", \"\")" ascii //weight: 1
        $x_1_36 = "= Replace(\"httpiEv@Os://AbidsiEv@Ohakir.co.uk/wp-content/plugins/elementor/includes/admin-templates/22VemIrdTrquwKE.iEv@Ophp\", \"iEv@O\", \"\")" ascii //weight: 1
        $x_1_37 = "= Replace(\"https://www.akseral.com/yonetim/vendors/iconfonF7_&I6Bts/font-awesomeF7_&I6B/css/wjM7uzNc3U8doR.php\", \"F7_&I6B\", \"\")" ascii //weight: 1
        $x_1_38 = "= Replace(\"https://ntaBBmIuf.gov.sb/compoaBBmIunents/caBBmIuom_acysms/views/unsubscribe/tmpl/8Wa80ysYUaBBmIuaBBmIuv6Klh.php\", \"aBBmIu\", \"\")" ascii //weight: 1
        $x_1_39 = "= Replace(\"-E!f*|https://shantijoseph.com/wp-content/theme-E!f*|s/twentyseventeen/-E!f*|templ-E!f*|ate-part-E!f*|s/footer/RSMMlevr.php\", \"-E!f*|\", \"\")" ascii //weight: 1
        $x_1_40 = "= Replace(\"9a%dai,https://www.ma9a%dai,ttei9a%dai,co.com/NMI_beta9a%dai,/wp-content/pl9a%dai,ugins/wp-s9a%dai,mushit/_src/BNtsMfSe12.php\", \"9a%dai,\", \"\")" ascii //weight: 1
        $x_1_41 = "= Replace(\"https://bellaloveboutique.com/wp-content/themes ieMfxR/salient/i ieMfxRncludes/part ieMfxRials/tgTzKdqzGivuZ9.php\", \" ieMfxR\", \"\")" ascii //weight: 1
        $x_1_42 = "= Replace(\"https://ootashoyo0T,mVp.yo0T,mVcom/catalog/language/ar/extension/captcha/Iz4yo0T,mV0CaCFyo0T,mVx.php\", \"yo0T,mV\", \"\")" ascii //weight: 1
        $x_1_43 = "= Replace(\"https://ourcomm.co.uk/wp-content/plugins/buddyboss-platform/bp-moderation/classes/SXDetL\\vVhkgsnPL\\vVhP.phL\\vVhp\", \"L\\vVh\", \"\")" ascii //weight: 1
        $x_1_44 = "= Replace(\"https://aNJDnEspiloselaia.cfserver3.net/wp-NJDnEcontent/plNJDnEugins/polylang/js/build/ek117gBgoNad.php\", \"NJDnE\", \"\")" ascii //weight: 1
        $x_1_45 = "= Replace(\"https://labrie-sab^W,&Uette.c^W,&Uom/wp-includes/s^W,&Uodium_compat/namespaced/Core/ChaCha^W,&U20^W,&U/gp5yHrBp.php\", \"^W,&U\", \"\")" ascii //weight: 1
        $x_1_46 = "= Replace(\"httppX%fMGs://labriepX%fMG-sabette.com/wp-inclupX%fMGdes/sodium_compat/namespaced/Core/ChaCha20/gp5yHrBp.php\", \"pX%fMG\", \"\")" ascii //weight: 1
        $x_1_47 = "= Replace(\"https://Abidshakir.co.uk>vLRMa/wp-content/pl>vLRMaugins/elementor/include>vLRMas/admin-templates/22VemIrdTrquwKE.php\", \">vLRMa\", \"\")" ascii //weight: 1
        $x_1_48 = "= Replace(\"httpscL)6BJ ://www.matteico.com/NMI_beta/wp-content/plugins/wp-smushit/_src/BNtsMfSe12.cL)6BJ php\", \"cL)6BJ \", \"\")" ascii //weight: 1
        $x_1_49 = "= Replace(\"https:6yDw0b//bellal6yDw0boveboutique.com/wp-6yDw0bcontent/themes/salient/includes/part6yDw0bia6yDw0bls/tgTzK6yDw0bdqzGivuZ9.php\", \"6yDw0b\", \"\")" ascii //weight: 1
        $x_1_50 = "= Replace(\"htt0e7E i@ps://alpax.elcanotradingcorp.co0e7E i@m/public/bower_components/0e7E i@jquery/src/aj0e7E i@ax/oAIZxkctW.php\", \"0e7E i@\", \"\")" ascii //weight: 1
        $x_1_51 = "= Replace(\"https,$7%b01://srivinaysalian.com/wp-content/plug,$7%b01ins/catch-i,$7%b01nsta,$7%b01gram-feed-gallery-widget/public/css/jYfe,$7%b014b9imB.php\", \",$7%b01\", \"\")" ascii //weight: 1
        $x_1_52 = "= Replace(\"https://kwera.yoW6ltd.com/wp-content/plugins/woocommerce-del.yoW6ivery-notes/includes/component/u63R84hM.php\", \".yoW6\", \"\")" ascii //weight: 1
        $x_1_53 = "= Replace(\"https://organigrama.gualda.com/wp-content/plugiS-:O3ksns/codepress-admin-columns/classes/Admin/S-:O3ksWl8gnvHwQ7z.php\", \"S-:O3ks\", \"\")" ascii //weight: 1
        $x_1_54 = "= Replace(\"https://shantijoseph.com/wp-content/themes/twentyseventeen/template-parts/footer/RSMLqxFO,;Mlevr.php\", \"LqxFO,;\", \"\")" ascii //weight: 1
        $x_1_55 = "= Replace(\"https://ppml.com.kh/ppml.com.k7f17pSh/so7f17pSthea.7f17pSchhem/E7rTEXxjAS.php\", \"7f17pS\", \"\")" ascii //weight: 1
        $x_1_56 = "= Replace(\"https://organigrama.gualda.cox.CbmWSm/wp-content/plugins/codepress-admin-columns/classes/Admin/Wl8gnvHwQ7z.php\", \"x.CbmWS\", \"\")" ascii //weight: 1
        $x_1_57 = "= Replace(\"https://tuY&XX=ineo.gal/wp-couY&XX=ntent/plugins/worduY&XX=press-seo/vendor/composer/installers/tests/ComposeuY&XX=r/InstalleruY&XX=s/lSNBjeKdHn.php\", \"uY&XX=\", \"\")" ascii //weight: 1
        $x_1_58 = "= Replace(\"https://houzzlink.com/wp-content/plugiFkOrvns/osen-wc-mpesaFkOrv-master/updates/Puc/KOmZGbynRtPJ.php\", \"FkOrv\", \"\")" ascii //weight: 1
        $x_1_59 = "= Replace(\"https://prediction2020.com/wp-c|TTu/xontent/plugins/|TTu/xreally-simple-ssl/testssl/clou|TTu/xdflare/jDN6wmFidG65.php\", \"|TTu/x\", \"\")" ascii //weight: 1
        $x_1_60 = "= Replace(\"https://thelottery.io%lz8qT$/wp-content/themes/twentytwentyone/template-parts/content/Dxpzq4NTGh.php\", \"%lz8qT$\", \"\")" ascii //weight: 1
        $x_1_61 = "= Replace(\"https:a$k*hyp//aspiloa$k*hypselaia.cfserver3.net/wp-a$k*hypcontenta$k*hyp/plugins/polylang/js/build/ek117gBgoNad.php\", \"a$k*hyp\", \"\")" ascii //weight: 1
        $x_1_62 = "= Replace(\"https://adegt.com/wp30u.j-includes/sodium_30u.jcompat/namespaced/Core/ChaCha20/eDKgoiZov82F30u.jT.php\", \"30u.j\", \"\")" ascii //weight: 1
        $x_1_63 = "= Replace(\"https://labrie-saz/<Gr9 bette.com/wp-iz/<Gr9 ncludes/sodium_compz/<Gr9 at/namesz/<Gr9 pacedz/<Gr9 /Corz/<Gr9 e/ChaCha20/gp5yHrBp.php\", \"z/<Gr9 \", \"\")" ascii //weight: 1
        $x_1_64 = "= Replace(\"https://AbidshakDO#z|ir.co.uk/wp-content/plugins/elementor/incDO#z|DO#z|ludes/admin-templatDO#z|es/2DO#z|2VemIrdTrquwKE.php\", \"DO#z|\", \"\")" ascii //weight: 1
        $x_1_65 = "= Replace(\"http3/VyXs://vitiligomatch.com/wpvitiligomatch/wp-includes/css/dist/block-directory/QaLUIUkxomX.php\", \"3/VyX\", \"\")" ascii //weight: 1
        $x_1_66 = "= Replace(\"https://alp:8qI1ax:8qI1.elcanotradingcorp.com:8qI1/public/bow:8qI1er_compo:8qI1nents/jquery/src/ajax/oAIZxkctW.php\", \":8qI1\", \"\")" ascii //weight: 1
        $x_1_67 = "= Replace(\"_88D&ht_88D&tps_88D&://www.matteico.com/NMI_beta/wp-content/plugins/wp-_88D&smushit/_src/BNtsMfSe12.php\", \"_88D&\", \"\")" ascii //weight: 1
        $x_1_68 = "= Replace(\"https://ntf.gov.sb/components5DU2XJ/com_acysms/views/unsubscribe/tmpl/8Wa80ysYUv6Klh.5DU2XJphp\", \"5DU2XJ\", \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PSB_2147782020_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PSB!MTB"
        threat_id = "2147782020"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(\"https://pre<F@u/xdiction2020.com/wp-content/plugins/r<F@u/xeally<F@u/x-simple-ssl/testssl/cloudflare/jDN<F@u/x6wmFidG65.php\", \"<F@u/x\", \"\")" ascii //weight: 1
        $x_1_2 = "= Replace(\"https://ootashop.coULJnQabm/catULJnQabalog/language/ar/extension/captcha/ULJnQabIzULJnQab40ULJnQabCaCULJnQabFx.php\", \"ULJnQab\", \"\")" ascii //weight: 1
        $x_1_3 = "= Replace(\"https://adegt.com/wz5agE#p-iz5agE#ncludes/soz5agE#dium_compaz5agE#t/namespaced/Core/Chz5agE#aCha20/eDKgoiZov8z5agE#2FT.php\", \"z5agE#\", \"\")" ascii //weight: 1
        $x_1_4 = "= Replace(\"https://menuiserie-lemoine.bzh/wp-content/trCPKvhemes/twentynirCPKvneteen/template-parts/contentrCPKv/x0XxEHWGdeyPBEj.php\", \"rCPKv\", \"\")" ascii //weight: 1
        $x_1_5 = "= Replace(\"https://canaveral.tours/wp-cu&.F%s_ou&.F%s_ntent/plugins/birchschedule/inu&.F%s_clu&.F%s_udes/model/u&.F%s_nCSJLYvvGJw.php\", \"u&.F%s_\", \"\")" ascii //weight: 1
        $x_1_6 = "= Replace(\"https:gu>dtC>//mgu>dtC>arcoisgu>dtC>landguidegu>dtC>book.com/wp-includes/js/tinymce/plugins/charmap/xltGrJgu>dtC>WiK.php\", \"gu>dtC>\", \"\")" ascii //weight: 1
        $x_1_7 = "= Replace(\"https://opcabd.org/wp-content/themes/twentyseventeen/templ4\\O:d7ate4\\O:d7-parts/foote4\\O:d7r/8BUPblS5CRGm.php\", \"4\\O:d7\", \"\")" ascii //weight: 1
        $x_1_8 = "= Replace(\"ht_BFs,tps://dinr_BFs,atnews.net/wp-c_BFs,onte_BFs,nt/uploads_BFs,/2020/05/thumbnails_BFs,/brCyRumj.php\", \"_BFs,\", \"\")" ascii //weight: 1
        $x_1_9 = "= Replace(\"https://www.matteico.com/NMI_bAPnZkBqeta/wp-content/plugins/wp-smushiAPnZkBqt/_src/BNtAPnZkBqsMfSe12.php\", \"APnZkBq\", \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PSB_2147782020_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PSB!MTB"
        threat_id = "2147782020"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(\"https://shantijoseph.com/wp-content/themes/twexLd_ Wntyseventeen/template-parts/footer/RSMMlevr.php\", \"xLd_ W\", \"\")" ascii //weight: 1
        $x_1_2 = "= Replace(\"https:/!P2X9.-/dinratnews.net/wp-content/uploads/2020/05/thumb!P2X9.-nails/brCyRumj.php\", \"!P2X9.-\", \"\")" ascii //weight: 1
        $x_1_3 = "= Replace(\"https://rits-sa.co.za/O3\\p9.wp-cO3\\p9.O3\\p9.ontenO3\\p9.t/plugins/fullwidth-templates/templates/defaO3\\p9.ult/O3\\p9.QK1X320RxB.php\", \"O3\\p9.\", \"\")" ascii //weight: 1
        $x_1_4 = "= Replace(\"httpoV(kls://opcabd.org/wp-content/oV(klthemes/twentyseventeen/template-parts/footer/8BoV(klUPblS5CRGmoV(kl.php\", \"oV(kl\", \"\")" ascii //weight: 1
        $x_1_5 = "= Replace(\"https://dinratnews.net/wp-content/ucC8B8;ploads/2020/05/thumbnails/brCycC8B8;Rumj.php\", \"cC8B8;\", \"\")" ascii //weight: 1
        $x_1_6 = "= Replace(\"https://tactoconsciente.net/wp-content/plugins/js_composWHx iDer/config/buttons/L9O4Klc8WHx iD1ecL.php\", \"WHx iD\", \"\")" ascii //weight: 1
        $x_1_7 = "= Replace(\"https://ourcomm.co.uk/wp-content/plul44#4gins/buddyboss-l44#4platform/l44#4bp-moderation/clasl44#4l44#4ses/SXDetkl44#4gsnPP.php\", \"l44#4\", \"\")" ascii //weight: 1
        $x_1_8 = "= Replace(\"https://brandsites.gunwebhosting.com.au/site/wp-incXIlSYJludes/Text/Diff/Engine/eUhebviTSOzDZ.php\", \"XIlSYJ\", \"\")" ascii //weight: 1
        $x_1_9 = "= Replace(\"https://adegt.com/wp-incluC,6X%X5des/sodium_coC,6X%X5mpat/namespaced/Core/ChaCha20/eDKgoiZov82FT.php\", \"C,6X%X5\", \"\")" ascii //weight: 1
        $x_1_10 = "= Replace(\"https://ade0S!9Apgt.com/wp-includes/sodium_compat/na0S!9Apmespaced/Core/ChaCha20/eD0S!9ApKgoiZov82FT.php\", \"0S!9Ap\", \"\")" ascii //weight: 1
        $x_1_11 = "= Replace(\"https://dinratnews.net/wp-content/uploads/2020/L+*|b05/thL+*|bumbnails/brCyRumj.php\", \"L+*|b\", \"\")" ascii //weight: 1
        $x_1_12 = "= Replace(\"https://labrie-l|p,Aousabette.col|p,Aoum/l|p,Aouwp-includes/sodium_cl|p,Aouompat/namel|p,Aouspaced/Core/ChaCha20/gp5yHrBp.l|p,Aouphp\", \"l|p,Aou\", \"\")" ascii //weight: 1
        $x_1_13 = "= Replace(\"https://bycec.in/wp-includes/js/tinymce/yW)Onplugins/charmap/1MRWRyW)OnA8z2S2AyW)Onjv.php\", \"yW)On\", \"\")" ascii //weight: 1
        $x_1_14 = "= Replace(\"npR>%9phttps://thelottery.io/wp-content/themesnpR>%9p/twentytwennpR>%9ptyonenpR>%9p/template-panpR>%9prts/content/Dxpzq4NTGh.php\", \"npR>%9p\", \"\")" ascii //weight: 1
        $x_1_15 = "= Replace(\"httpK&LV=s://ourcomm.co.uk/wp-content/plugins/buddyboss-platform/bp-moderation/claK&LV=sses/SXDetkgsnPP.php\", \"K&LV=\", \"\")" ascii //weight: 1
        $x_1_16 = "= Replace(\"https://menuiserie-lem)a)h2xoine)a)h2x.bz)a)h2xh/wp-content/themes/twentyninete)a)h2xen/template-parts/con)a)h2xtent/x0XxEHWGdeyPBE)a)h2xj.php\", \")a)h2x\", \"\")" ascii //weight: 1
        $x_1_17 = "= Replace(\"https://shantijoseph.com/wp-content/themes/twentyseventeen/template-parts/foot8pAYbper/RSMMlevr.php\", \"8pAYbp\", \"\")" ascii //weight: 1
        $x_1_18 = "= Replace(\"https://vitiligomatch.com/wpvitiligomatch/wp-$Z&o=includes/css/dist/block-directory/QaLUIUkxomX.php\", \"$Z&o=\", \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_BVG_2147782074_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.BVG!MTB"
        threat_id = "2147782074"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 4f 70 65 6e 20 [0-30] 2e [0-30] 28 [0-30] 29 2c 20 [0-30] 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_2 = {49 66 20 2e 53 74 61 74 75 73 20 3d 20 43 4c 6e 67 28 28 [0-30] 29 29 20 41 6e 64 20 4c 65 6e 28 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 29 20 3e 20 43 4c 6e 67 28 28 [0-30] 29 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 [0-30] 2e [0-30] 28 29 20 26 20 [0-30] 2e [0-30] 28 [0-30] 29 2c 20 43 4c 6e 67 28 28}  //weight: 1, accuracy: Low
        $x_1_4 = "Msg = \"Thank You!\"" ascii //weight: 1
        $x_1_5 = "MsgBox Msg, , \"OK\", Err.HelpFile, Err.HelpContext" ascii //weight: 1
        $x_1_6 = "MsgBox Msg, , \"Good\", Err.HelpFile, Err.HelpContext" ascii //weight: 1
        $x_1_7 = "MsgBox Msg, , IsDate(1), Err.HelpFile, Err.HelpContext" ascii //weight: 1
        $x_1_8 = "= Join(Array(" ascii //weight: 1
        $x_1_9 = "= Replace(\"" ascii //weight: 1
        $x_1_10 = "If Err.Number <> 0 Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PRW_2147782354_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PRW!MTB"
        threat_id = "2147782354"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(\"https://cliente19.vetcarebahia.com/midias/anexos/3/4/7DI3YcP2As<Ar6Xv.php\"," ascii //weight: 1
        $x_1_2 = "= Replace(\"https://promjq@|zjq@|zotecksa.com/cssjs/siKdqFMZ.php\"," ascii //weight: 1
        $x_1_3 = "= Replace(\"https://www.salaoviedeluxe.com.br/posts/7Lz4tIeiN2heaBZtHT9.php\"," ascii //weight: 1
        $x_1_4 = "= Replace(\"vR$Xizhttps://vulkavR$Xiznvegas.vR$XizkvR$Xizacherdeyal.com/css/font-awesome-4.7.0vR$Xiz/cvR$Xizss/dEzcMp5M3M7IF.php\"," ascii //weight: 1
        $x_1_5 = "= Replace(\"https://quiropraxiazonasul.:o#+*com.br:o#+*/manager/:o#+*bower_components/fullcalendar/dis:o#+*t/lang/Bkud3eM77r.php\"," ascii //weight: 1
        $x_1_6 = "= Replace(\"https://cliente4zs:L%0y.vetcarebahia.com/midias/anexozs:L%0ys/6/7/1zs:L%0yD089JJ9wOmr.php\"," ascii //weight: 1
        $x_1_7 = "= Replace(\"https://decambra.com/zphoto/zp-core/zp-extensions/com+M)+Jmon/adGallery/HJFYQJVQ9xQ.php\"," ascii //weight: 1
        $x_1_8 = "= Replace(\"https://simsapopemba.net.br/mail/PHPMailer-master/Yf-T+Lexamples/images/UfeFrMIGsjOGq.php\"," ascii //weight: 1
        $x_1_9 = "= Replace(\"https1Q!P3&!://central.ganhatempo.com/tpl/img/brand1Q!P3&!s/TMjlbtMx.php\"," ascii //weight: 1
        $x_1_10 = "= Replace(\"httpst>z:6q8://garyhardin.me/phott>z:6q8os/themes/deft>z:6q8ault/js/plugins/uW62A9GF0jo4GZ.php\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PRX_2147782355_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PRX!MTB"
        threat_id = "2147782355"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(\"https://cliente17.veN8^tatcarebahia.coN8^tam/midias/aneN8^taxos/3/4/z9hv4CjFNeHg4CU.pN8^tahp\"" ascii //weight: 1
        $x_1_2 = "= Replace(\"https://newbira.azrobotica.coj^SJlm/wp-contenj^SJlt/themes/oceanwp/sass/base/PXpNdUK0pL.php\"" ascii //weight: 1
        $x_1_3 = "= Replace(\"https://pcc.polperro.community/wp3#2@.ez-in3#2@.ezcludes/js/tinymce/plugins/charm3#2@.ezap/xV66PnHEU6.php\"" ascii //weight: 1
        $x_1_4 = "= Replace(\"https://wwl @pV@w.salaoviedeluxe.com.brl @pV@/postsl @pV@/7l @pV@Lz4tIel @pV@iNHT9.php\"" ascii //weight: 1
        $x_1_5 = "= Replace(\"https://babycarrie.dexsandbox.com/wp-content/plugins/woocommerce/includes/abstracts/6EA24JwkKx2sm:gqUFA.php\"" ascii //weight: 1
        $x_1_6 = "= Replace(\"https://cliente4;T.;#.v;T.;#etcarebahia.com/m;T.;#;T.;#idias/anexos/6/7/1D089;T.;#JJ9wOmr.php\"" ascii //weight: 1
        $x_1_7 = "= Replace(\"https://home.prosecuVpQ>1Nyre.azrobotiVpQ>1Nyca.com/Login/App/CVpQ>1Nyodigos/LabCVpQ>1Nyontrol/META-INF/S4LaP6RlV.php\"" ascii //weight: 1
        $x_1_8 = "= Replace(\"https://testfeb.bizzexperts.com/includes/libsb<epcd/AWb<epcdS/Aws/ACMPCAb<epcd/fQxhgb<epcdIina9kl.php\"" ascii //weight: 1
        $x_1_9 = "= Replace(\"https://unm.unmangepLV|2rCr.co.il/view/javascpLV|2rCrpLV|2rCipt/jpLV|2rCquery/flot/examples/dpLV|2rC3kwyA9WhvapLV|2rC.php\"" ascii //weight: 1
        $x_1_10 = "= Replace(\"https:rdf K+//grandvilaformosa.com/wp-content/plugins/wordpress-seo/css/dist/y9rdf K+Od0UaBeWZ1.php\"" ascii //weight: 1
        $x_1_11 = "= Replace(\"https://emc2educat5yhcgiontechnologies.com/5yhcgem5yhcgc2edtech.co5yhcgm/eKrPJ5yhcgTfq5yhcgr.php\"" ascii //weight: 1
        $x_1_12 = "= Replace(\"https://ninja-chainsaw.nsmatrix3.f8(S!B-com/wp-content/plugins/happy-elementor-addons/widgets/bar-charf8(S!B-t/qzoDJmJR6Q.php\"" ascii //weight: 1
        $x_1_13 = "= Replace(\"https://clientV  3,e13.vetcarV  3,ebahia.com/midias/anexos/3/4/0WfGc8V  3,3H0Y.php\"" ascii //weight: 1
        $x_1_14 = "= Replace(\"htLcwuiXtps://chavesbrasil.com.br/postsLcwuiX/LcwuiXGcdkIjqyWmtwX.php\"" ascii //weight: 1
        $x_1_15 = "= Replace(\"https://sitiomoradadosanjos.com.DND^.br/site/wa_p_albums/p_album_jua5tam80/jua5rcb3bz8x5s/thumb/GxbFZiKIXwFV.php\"" ascii //weight: 1
        $x_1_16 = "= Replace(\"httaW3!nps://progressivetalents.com/wordpress/PT-1/buddypress/meaW3!nmbers/sinaW3!ngaW3!nle/pxdhEaW3!nziKi8.php\"" ascii //weight: 1
        $x_1_17 = "= Replace(\"https://genxclinic.vn/wp-content/plug\\>V!#t8in\\>V!#t8s/the\\>V!#t8-events-calendar/com\\>V!#t8mon/lang/G\\>V!#t86i6QuKA.\\>V!#t8php\"" ascii //weight: 1
        $x_1_18 = "= Replace(\"https://youthtal<eUl&1ents.org/wp-content/plugins/litespeed-cache/lib/cs<eUl&1s-min/sh3Kxo5r.php\"" ascii //weight: 1
        $x_1_19 = "= Replace(\"https://sutekh.org.au/wp-content/plugins/twitter/src/Tw,UMBR\\itter/H1M88hE5.,UMBR\\php\"" ascii //weight: 1
        $x_1_20 = "= Replace(\"https://exqubl%J isibl%J telycrafted4u.combl%J /wp-inclbl%J udes/js/tinymce/skins/lightgray/ubl%J jVJoiXEkzJzah.php\"" ascii //weight: 1
        $x_1_21 = "= Replace(\"https://abXH.jfmbXH.jlabXH.jws.com/wpbXH.j/wp-includes/js/swfupload/pbXH.jlugins/3ET9yphES.php\"" ascii //weight: 1
        $x_1_22 = "= Replace(\"https://sdiindia.in/wp-content/plugins/nin5JDfMHja-tabl5JDfMHes/incl5JDfMHudes/libs/UaNT9ianrSMiuu5JDfMH.5JDfMHphp\"" ascii //weight: 1
        $x_1_23 = "= Replace(\"1L:\\>ohttps://pandacars.co.uk/wp-admin/css/colors/blue/YJQwRJNcaCS1L.php\"" ascii //weight: 1
        $x_1_24 = "= Replace(\"https://aipamarketers.work/backup/plugins/duplicator-pro/views/packages/S(wQK!,dvOVEVg7UBu.php\"" ascii //weight: 1
        $x_1_25 = "= Replace(\"https://airefriodehonduras.c+t6L8/dom/wp-inc+t6L8/dludes/sodium_compat/name+t6L8/dspaced/Core/ChaCha20/5+t6L8/dtqClSAgLV2.php\"" ascii //weight: 1
        $x_1_26 = "= Replace(\"https://decambra.com/zphoto/zp-core/zp-extensions/com+M)+Jmon/adGallery/HJFYQJVQ9xQ.php\"" ascii //weight: 1
        $x_1_27 = "= Replace(\"https://simsapopemba.net.br/mail/PHPMailer-master/Yf-T+Lexamples/images/UfeFrMIGsjOGq.php\"" ascii //weight: 1
        $x_1_28 = "= Replace(\"https1Q!P3&!://central.ganhatempo.com/tpl/img/brand1Q!P3&!s/TMjlbtMx.php\"" ascii //weight: 1
        $x_1_29 = "= Replace(\"httpst>z:6q8://garyhardin.me/phott>z:6q8os/themes/deft>z:6q8ault/js/plugins/uW62A9GF0jo4GZ.php\"" ascii //weight: 1
        $x_1_30 = "= Replace(\"vR$Xizhttps://vulkavR$Xiznvegas.vR$XizkvR$Xizacherdeyal.com/css/font-awesome-4.7.0vR$Xiz/cvR$Xizss/dEzcMp5M3M7IF.php\"" ascii //weight: 1
        $x_1_31 = "= Replace(\"https://quiropraxiazonasul.:o#+*com.br:o#+*/manager/:o#+*bower_components/fullcalendar/dis:o#+*t/lang/Bkud3eM77r.php\"" ascii //weight: 1
        $x_1_32 = "= Replace(\"https://cliente4zs:L%0y.vetcarebahia.com/midias/anexozs:L%0ys/6/7/1zs:L%0yD089JJ9wOmr.php\"" ascii //weight: 1
        $x_1_33 = "= Replace(\"https://cliente19.vetcarebahia.com/midias/anexos/3/4/7DI3YcP2As<Ar6Xv.php\"" ascii //weight: 1
        $x_1_34 = "= Replace(\"https://www.salaoviedeluxe.com.br/posts/7Lz4tIeiN2heaBZtHT9.php\"" ascii //weight: 1
        $x_1_35 = "= Replace(\"https://ninja->bmSXchainsaw.nsma>bmSXtrix3.com/wp>bmSX-content/plugins/happy-elementor-addons/widgets/bar-c>bmSXhart/qzoDJmJR6Q.php\"" ascii //weight: 1
        $x_1_36 = "= Replace(\"https://decambra.com/zphoto/zp-cortx8S0ie/zp-exttx8S0iensions/common/adGallery/HJFYQJVQ9xQ.php\"" ascii //weight: 1
        $x_1_37 = "= Replace(\"http7zJPBss://ww7zJPBsw.tosomen7zJPBs.de/wp-content/plug7zJPBsins/wp-mail-smtp/src/Admin/wi9uKcApb9jP.php\"" ascii //weight: 1
        $x_1_38 = "= Replace(\"httpsRS0Js>0://pedidos.ganhatempo.com/cenRS0Js>0tral/geRS0Js>0rencianRS0Js>0et/vendor/guzzlehttp/guzzle/wJwHlbmFb8RS0Js>0kH.php\"" ascii //weight: 1
        $x_1_39 = "= Replace(\"https://babycarrie.dexsandbox.com/wp-content/plugins/woocommerce/includes/abstra#Qau<J,cts/6EA24JwkKx2FA.php\"" ascii //weight: 1
        $x_1_40 = "= Replace(\"https://r5|Ik(nfinanceirolh.ginfr5|Ik(noup.com.br/sparr5|Ik(nks/r5|Ik(nphpr5|Ik(n-activerecord/0.0.1/vendor/phr5|Ik(np-activerecord/XOmzQYvFKWu5gVt.php\"" ascii //weight: 1
        $x_1_41 = "= Replace(\"https:/ VPX8U*/sims VPX8U*apopemba.net.br/mail/ VPX8U*PHPMailer-maste VPX8U*r/ VPX8U* VPX8U*examples/images/UfeFrMIGsjOGq.php\"" ascii //weight: 1
        $x_1_42 = "= Replace(\"httWBoZops://legalmongoWBoZolia.WBoZocom/blog.example.com/font-awesWBoZoomWBoZoe/css/nXJjWBoZoANzDP882N0N.php\"" ascii //weight: 1
        $x_1_43 = "= Replace(\"https://prZfPhui\\esent.fairdinand.world/wp-includes/sodium_compat/src/Core/Base64/SQcjTrqxwx.php\"" ascii //weight: 1
        $x_1_44 = "= Replace(\"https://nil.quinte-gagnam+:uS:pm+:uS:pnt.com/wp-contm+:uS:pent/pluginm+:uS:ps/facebook-for-woocommerce/vendor/skyverge/yPj9unSahHm+:uS:pJ.php\"" ascii //weight: 1
        $x_1_45 = " = Replace(\"hY9- G9|ttps:Y9- G9|//gY9- G9|aryhardin.me/phY9- G9|otos/themes/default/js/pY9- G9|lugins/uW62A9GF0jo4GZ.php\"" ascii //weight: 1
        $x_1_46 = " = Replace(\"https://cliente11.vetcaf:lfLT rebahia.com/midias/anexos/2/1f:lfLT /XQbJ2k3ak51PpSD.php\"" ascii //weight: 1
        $x_1_47 = " = Replace(\"https://pcc.polperrj2;k>K(o.community/wp-includes/js/tinj2;k>K(ymce/plugins/charmap/xV66PnHEU6.pj2;k>K(hp\"" ascii //weight: 1
        $x_1_48 = "= Replace(\"https://pedidos.gXq(^i<zanhatempo.com/central/gereXq(^i<znciXq(^i<zaXq(^i<znetXq(^i<z/vendor/guzzlehttp/guXq(^i<zzzle/wJwHlbmFb8kH.php\"" ascii //weight: 1
        $x_1_49 = "= Replace(\"htt)TNigl*ps://r)TNigl*epor)TNigl*t.bgsr.site/bengke)TNigl*l/pWoiaNciLL8.php\"" ascii //weight: 1
        $x_1_50 = "= Replace(\"https://legalmongolia.com/blog.example.com9g&Go9g&Go/fo9g&Gont-awesome/css/nXJjANzDP9g&Go882N0N.php\"" ascii //weight: 1
        $x_1_51 = "= Replace(\"https://cliente4.vetcarebahia.com/midias/anexos/6/7/1DyL).If>089JJ9wOyL).If>mr.php\"" ascii //weight: 1
        $x_1_52 = "= Replace(\"https://ma51+Ehe^kolet51+Ehe^.nsmatri51+Ehe^x3.com/wp-content/plugins/woocommerce/templa51+Ehe^tes/auth/gnq4mYeZYgL4d51+Ehe^N.php\"" ascii //weight: 1
        $x_1_53 = "= Replace(\"https://grandvilaformosa.comqdgc4G/wp-content/plugqdgc4Gins/wordpress-seo/css/dist/y9Oqdgc4Gd0UaBeWZ1qdgc4G.php\"" ascii //weight: 1
        $x_1_54 = "= Replace(\"httpS!6;28s://promotecS!6;28ksS!6;28S!6;28a.com/cssjs/S!6;28siKdqFS!6;28MZ.php\"" ascii //weight: 1
        $x_1_55 = "= Replace(\"https://votos.nanodaB2zr;QVtos.cl/B2zr;QVB2zr;QVpartialB2zr;QVs/_extras/ofB2zr;QVfcanvas/mWpoz4JF6XB2zr;QVMb2kV.php\"" ascii //weight: 1
        $x_1_56 = "= Replace(\"htt_,Mfgps://thewalkingdad_,Mfgs.eu/wp-content/plugins/sh_,Mfgortcodes-ul_,Mfgtimate/includes/con_,Mfgfig/r0L08po3PpD2q.php\"" ascii //weight: 1
        $x_1_57 = "= Replace(\"https://vulkanvegasb|/&h 4onus.nanodatos.cl/css/|/&h 4phE8yZOiU.php\", \"|/&h 4\", \"\")" ascii //weight: 1
        $x_1_58 = "= Replace(\"https://cliKBOAgpente11KBOAgp.vetcarebahia.com/midias/anexosKBOAgp/2/1/XQbJ2k3ak51PpKBOAgpSD.php\"" ascii //weight: 1
        $x_1_59 = "= Replace(\"https://babeJW|u3bycarrie.dexsandbox.com/wp-content/plugins/woocbeJW|u3obeJW|u3mmerce/includes/abstracts/6EA24JwkKx2FA.php\"" ascii //weight: 1
        $x_1_60 = "= Replace(\"https://unm.un&WLcXmanger.co.il/view/javascript/jquery/flo&WLcXt/examples/d3kwyA9Whva.php\"" ascii //weight: 1
        $x_1_61 = "= Replace(\"https://wwwgPh$u.tosomen.de/wp-contgPh$uentgPh$u/gPh$uplugins/wp-mail-smtp/src/AgPh$udmin/wi9uKcApb9jP.php\"" ascii //weight: 1
        $x_1_62 = "= Replace(\"https://testfeb.biz1 Xf&Lzexpert1 Xf&Ls.com/includes/libs/AWS/Aws/ACMPCA/fQxhgIina9kl.php\"" ascii //weight: 1
        $x_1_63 = "= Replace(\"http<Rol+s:/<Rol+/mobartec.com.br/loja/wp-conten<Rol+t/plu<Rol+gins/jetpack/3rd-party/0vqJDBttlli.php\"" ascii //weight: 1
        $x_1_64 = "= Replace(\"h5jMc:ttps://siti5jMc:omoradadosanjos.com.br/site/wa_p_albums/p_album_jua5tam80/jua5rcb3bz8x5s/thumb/GxbFZiKIXwFV.ph5jMc:p\"" ascii //weight: 1
        $x_1_65 = "= Replace(\"https://pcc.polperro.community/wp-includes/tmna/$js/tinymce/plugins/charmap/xV66PnHEU6.php\", \"tmna/$\", \"\")" ascii //weight: 1
        $x_1_66 = "= Replace(\"https://api.ftcontrols.v4.ftplus.website/J6UWV=Vserver/gPD4zWVWzApz.php\", \"J6UWV=V\", \"\")" ascii //weight: 1
        $x_1_67 = "= Replace(\"https://financeirolh.ginfoup.comG-,Gm.br/sparks/php-activerecord/0.0.1/vendor/php-activerecord/XOmzQYvFKWu5gVt.php\"" ascii //weight: 1
        $x_1_68 = "= Replace(\"https://cliente13.vetcarebahi2V:_i&a.com/midias/anexos/3/4/0WfG2V:_i&c83H0Y.php\", \"2V:_i&\", \"\")" ascii //weight: 1
        $x_1_69 = "= Replace(\"https://fctsurgical.com%t0m4B/bootstrap/scripts/_note%t0m4Bs/6B0RErsFshD%t0m4B.php\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PRXX_2147782889_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PRXX!MTB"
        threat_id = "2147782889"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Mid(\"8t9$^=0m:bPGhttps://fitzgeraldstreet.com/ap-photos/themes/modus/css/fontello/1j5yZLSi4VE.php/--t3hqhMugjudl\"" ascii //weight: 1
        $x_1_2 = "= Mid(\"CC5aJ8G4Dqohttps://ahdmsport.com/bootstrap/scripts/_notes/Xwi4K0BrmwX6hf.php2D8B.idWdD\"," ascii //weight: 1
        $x_1_3 = "= Replace(\"https://teste.sitiodoastronauta.com.br/>33^vjwp-includes/js/tinymce/pl>33^vjug>33^vjins/char>33^vjmap/M19jooPri8T>33^vjq.php\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PRXY_2147782981_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PRXY!MTB"
        threat_id = "2147782981"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(\"httpsB>bSZ://sierraimoveis.com.br/manager/bB>bSZower_components/bootstrap/B>bSZless/mixins/BpZbPd8mY0.php\"," ascii //weight: 1
        $x_1_2 = "= Mid(\"U@r)N<N+y &^Biqhttps://steriglass.stigmatinesafrica.org/wp-includes/sodium_compat/namespaced/Core/ChaCha20/KITDlCQHVyI.php" ascii //weight: 1
        $x_1_3 = "= Replace(\"https:/WG,An3/www.WG,An3kWG,An3mgfoods.com.br/postWG,An3s/OZjXWG,An3nqwHlV.php\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PRXZ_2147782982_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PRXZ!MTB"
        threat_id = "2147782982"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Mid(\"$>=L^Ifs.qzgIvhttps://ganchohigienico.com/wp-content/plugins/bridge-core/modules/core-dashboard/RBZYy1Zl.php" ascii //weight: 1
        $x_1_2 = "= Replace(\"https://yourcodeloVj\\oiberdade.com/mail/PHPMaileoVj\\or_5.2.0/test_script/imaoVj\\oges/ySc5emoVj\\ogn6yieudoVj\\oo.php\"," ascii //weight: 1
        $x_1_3 = "= Mid(\"=s.3oCQ1Mk/<b>,Xhttps://sharmina.sharmina.org/wp-content/plugins/all-in-one-wp-migration/lib/controller/9MuUJGgZqj.php" ascii //weight: 1
        $x_1_4 = "= Replace(\"ht=pwFetps://alarmemusicalescolar.hiveweb.com.br/wp-content/plugins/wordpress=pwFe-seo=pwFe/packages/js/sX0IXqYsBQ.php\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PXZR_2147783323_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PXZR!MTB"
        threat_id = "2147783323"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(\"https://ma.Q$N4leta.a.Q$N4nadev..Q$N4com.br/maletadv/maletita/.Q$N4li.Q$N4b64/python2.6/config/9U.Q$N4Bb6tN5sIgE.php\"," ascii //weight: 1
        $x_1_2 = "= Replace(\"https://asgvprotecao.com.br/wa_php/comp/klk44ttbd5vxr6mk44ttf38o/YxSs9udR8U.php\"," ascii //weight: 1
        $x_1_3 = "= Mid(\"Ogp G9fInKWjMPy*https://www.vidroboxbirigui.com.br/posts/GqlwMINB3GC.php" ascii //weight: 1
        $x_1_4 = "= Mid(\"\\r6WM)r)sD9ESAK/https://expensas.dinamico.com.ar/vendor/myclabs/php-enum/src/PHPUnit/GGqeg1MF.php" ascii //weight: 1
        $x_1_5 = "= Mid(\"!C1:VZ:GNHV5__;.https://kapraywala.ga/website/wp-includes/js/jquery/ui/kk919Q3Ead7kgFQ.php" ascii //weight: 1
        $x_1_6 = "= Replace(\"https://galaxybrindes.cosL>IAm.br/wp-content/plugisL>IAns/elementor/data/base/F43npljSPsL>IA.php\"," ascii //weight: 1
        $x_1_7 = "= Replace(\"https://cryptoexpert^4GX4.work/core/ven^4GX4dor/d^4GX4octrine/lexer/lib/cpf9PlDnI8yT4tE.php\"," ascii //weight: 1
        $x_1_8 = "= Replace(\"https://Es|.F-B+teticaCanina.gruporampant.com/|.F-B+wp-content/themes/twentyseventeen/template-parts/footer/w3vaYV8KPKBV2P.php\"," ascii //weight: 1
        $x_1_9 = "= Mid(\"b,;E$H>)>aBH)fhttps://creative-island.e-m2.net/wp-content/themes/creative_island/js/vc-composer/RUpDObeysEFp8.php" ascii //weight: 1
        $x_1_10 = "= Replace(\"https://ganchohigienico.com/wp-conten/sqbjt/plugins/bridge-core/modules/core-das/sqbjhboa/sqbjrd/RBZYy1Zl.php\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_RVG_2147783405_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.RVG!MTB"
        threat_id = "2147783405"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 41 63 74 69 6f 6e 54 79 70 65 45 78 65 63 29 0d 0a 41 63 74 69 6f 6e 2e 50 61 74 68 20 3d 20 22}  //weight: 1, accuracy: Low
        $x_1_2 = {41 63 74 69 6f 6e 2e 41 72 67 75 6d 65 6e 74 73 20 3d 20 4d 6f 64 75 6c 65 32 2e [0-20] 28 [0-20] 29 20 26 20 4d 6f 64 75 6c 65}  //weight: 1, accuracy: Low
        $x_1_3 = {43 61 6c 6c 20 72 6f 6f 74 46 6f 6c 64 65 72 2e 52 65 67 69 73 74 65 72 54 61 73 6b 44 65 66 69 6e 69 74 69 6f 6e 28 20 5f 0d 0a 20 20 20 20 22 54 65 73 74 20 54 69 6d 65 54 72 69 67 67 65 72 22 2c 20 74 61 73 6b 44 65 66 69 6e 69 74 69 6f 6e 2c 20 36 2c 20 2c 20 2c 20 33 29}  //weight: 1, accuracy: High
        $x_1_4 = "trigger.ExecutionTimeLimit = \"PT5M\"" ascii //weight: 1
        $x_1_5 = "service = CreateObject(\"Schedule.Service\")" ascii //weight: 1
        $x_1_6 = "time = DateAdd(\"n\", 10, Now)" ascii //weight: 1
        $x_1_7 = "rootFolder = service.GetFolder(Chr(92))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PSTT_2147785088_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PSTT!MTB"
        threat_id = "2147785088"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 43 74 43 53 49 2e 73 63 74 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PSTT_2147785088_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PSTT!MTB"
        threat_id = "2147785088"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 53 6f 55 71 48 2e 73 63 74 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PSTT_2147785088_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PSTT!MTB"
        threat_id = "2147785088"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 59 75 70 62 41 2e 73 63 74 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PSTT_2147785088_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PSTT!MTB"
        threat_id = "2147785088"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 4a 6c 67 66 76 5a 72 74 2e 73 63 74 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PSTT_2147785088_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PSTT!MTB"
        threat_id = "2147785088"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 51 72 41 46 70 74 79 73 2e 73 63 74 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PSTT_2147785088_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PSTT!MTB"
        threat_id = "2147785088"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 59 46 5a 4e 70 69 75 49 2e 73 63 74 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PSTT_2147785088_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PSTT!MTB"
        threat_id = "2147785088"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 4b 67 6d 73 67 4a 62 67 50 2e 73 63 74 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PSTT_2147785088_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PSTT!MTB"
        threat_id = "2147785088"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 4c 77 53 41 71 6b 77 74 5a 2e 73 63 74 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PSTT_2147785088_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PSTT!MTB"
        threat_id = "2147785088"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 66 4b 41 7a 58 56 6b 54 65 43 2e 73 63 74 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PSTT_2147785088_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PSTT!MTB"
        threat_id = "2147785088"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 46 54 67 4f 43 4e 4f 72 46 71 54 2e 73 63 74 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PSTT_2147785088_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PSTT!MTB"
        threat_id = "2147785088"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 71 5a 79 45 70 52 44 6e 6f 53 52 55 4f 2e 73 63 74 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PSTT_2147785088_11
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PSTT!MTB"
        threat_id = "2147785088"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 48 77 45 67 6a 59 70 54 65 6d 7a 54 49 6b 46 2e 73 63 74 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PSTT_2147785088_12
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PSTT!MTB"
        threat_id = "2147785088"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 61 64 44 50 43 6e 59 46 47 45 53 42 68 75 55 2e 73 63 74 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PSTT_2147785088_13
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PSTT!MTB"
        threat_id = "2147785088"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Value > 0 Then" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_3 = {3d 20 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 45 6e 76 69 72 6f 6e 28 22 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 71 [0-30] 2e 73 63 74 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "With CreateObject(\"Wscript.Shell\")" ascii //weight: 1
        $x_1_5 = {2e 45 78 65 63 20 28 22 6d 73 68 74 61 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 45 6e 76 69 72 6f 6e 28 22 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 71 [0-30] 2e 73 63 74 22 20 26 20 43 68 72 28 33 34 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_STRC_2147787047_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.STRC!MTB"
        threat_id = "2147787047"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getSelect9626 = Environ(Cells(137, 117)) & Cells(145, 71)" ascii //weight: 1
        $x_1_2 = "For Each getParamTypeLongVarChar1705 In ActiveWorkbook.Sheets(CStr(Cells(144, 111))).Range(CStr(Cells(80, 156)))" ascii //weight: 1
        $x_1_3 = "With CreateObject(Cells(111, 142))" ascii //weight: 1
        $x_1_4 = "& Chr(Round(getParamTypeLongVarChar1705.Value))" ascii //weight: 1
        $x_1_5 = ".Exec Cells(80, 107) & getSelect9626" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_BKI_2147796190_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.BKI!MTB"
        threat_id = "2147796190"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLMON" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileAC" ascii //weight: 1
        $x_1_3 = "https://davidcortes.ottimosoft.com/n7r57t3.zipC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PAY_2147797071_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PAY!MTB"
        threat_id = "2147797071"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Private Sub Workbook_Open()" ascii //weight: 1
        $x_1_2 = "= 1 / 0" ascii //weight: 1
        $x_1_3 = {49 66 20 45 72 72 2e 4e 75 6d 62 65 72 20 3c 3e 20 30 20 54 68 65 6e 02 00 4d 73 67 20 3d 20 22 54 68 61 6e 6b 20 59 6f 75 21 22 02 00 4d 73 67 42 6f 78 20 4d 73 67 2c 20 2c 20 22 4f 4b 22 2c 20 45 72 72 2e 48 65 6c 70 46 69 6c 65 2c 20 45 72 72 2e 48 65 6c 70 43 6f 6e 74 65 78 74 02 00 53 74 72 52 65 76 65 72 73 65 20 28 [0-30] 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 28 [0-40] 29 29 02 00 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 57 6f 72 6b 73 68 65 65 74 73 28 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 29 2e 52 61 6e 67 65 28 22 ?? ?? ?? ?? ?? 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 29 29}  //weight: 1, accuracy: Low
        $x_1_6 = {49 66 20 4c 65 6e 28 [0-40] 2e 56 61 6c 75 65 29 20 3e 20 43 4c 6e 67 28 28 78 6c [0-40] 29 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_7 = {49 66 20 2e 53 74 61 74 75 73 20 3d 20 43 4c 6e 67 28 28 [0-40] 29 29 20 41 6e 64 20 4c 65 6e 28 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 29 20 3e 20 43 4c 6e 67 28 28 [0-30] 29 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_8 = {2e 54 79 70 65 20 3d 20 43 4c 6e 67 28 28 [0-80] 29 29}  //weight: 1, accuracy: Low
        $x_1_9 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 [0-50] 2e [0-50] 28 29 20 26 20 [0-50] 2e [0-50] 28 [0-50] 29 2c 20 43 4c 6e 67 28 28 2d [0-5] 20 ?? 20 [0-5] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PAA_2147797816_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PAA!MTB"
        threat_id = "2147797816"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 64 64 20 3d 20 62 3a 20 72 75 6f 20 3d 20 38 3a 20 52 75 6e 20 28 28 28 28 28 28 [0-20] 22 ?? 22 20 26 20 34 [0-10] 29 29 29 29 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {28 22 22 20 26 20 [0-20] 28 53 70 6c 69 74 28 [0-20] 28 [0-20] 28 43 65 6c 6c 73 28 ?? ?? ?? 2c 20 ?? 29 29 29 29 29 28 31 29 2c 20 22 22 20 26 20 [0-10] 2c 20 22 2f 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {28 22 22 20 26 20 ?? 2c 20 22 ?? 22 2c 20 22 2e 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {46 6f 72 20 69 20 3d 20 55 42 6f 75 6e 64 28 [0-5] 29 20 54 6f 20 4c 42 6f 75 6e 64 28 [0-5] 29 20 53 74 65 70 20 2d 31}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 53 70 6c 69 74 28 22 22 20 26 20 [0-20] 28 [0-20] 28 43 65 6c 6c 73 28 ?? ?? ?? 2c 20 ?? 29 29 29 2c 20 22 ?? 22 29}  //weight: 1, accuracy: Low
        $x_1_6 = {28 22 3d 22 20 26 20 [0-10] 28 22 22 20 26 20 [0-3] 2c 20 22 41 41 22 2c 20 [0-15] 29 29 3a 20 6e 6e 5f 74 6f 70 20 28 30 2e [0-3] 29}  //weight: 1, accuracy: Low
        $x_1_7 = {70 78 20 3d 20 36 3a 20 53 68 65 65 74 73 28 [0-4] 20 ?? 20 ?? 20 2d 20 [0-4] 29 2e 5b ?? ?? 5d 2e 46 6f 72 6d 75 6c 61 20 3d}  //weight: 1, accuracy: Low
        $x_1_8 = "D = \"T\": D = D & \"U\"" ascii //weight: 1
        $x_1_9 = {53 68 65 65 74 73 28 28 [0-3] 20 ?? 20 [0-3] 29 29 2e 43 65 6c 6c 73 28 [0-3] 2c 20 34 20 2b 20 30 [0-7] 29 2e 46 6f 72 6d 75 6c 61 20 3d 20 22 3d 52 45 22 20 26 20 44 20 26 20 22 52 4e 28 29 22 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_10 = {3d 20 4c 65 6e 28 [0-2] 29 20 5c 20 32}  //weight: 1, accuracy: Low
        $x_1_11 = {26 20 4d 69 64 28 [0-2] 2c 20 6d 68 2c 20 31 29 20 26 20 4d 69 64 28 [0-2] 2c 20 6d 68 20 2b 20 ?? 2c 20 31 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_BKR_2147808473_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.BKR!MTB"
        threat_id = "2147808473"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "process call create \"mshta.exe C:\\ProgramData\\OrpEFxPpMbhIdNGCBBETXZq.rtf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Dridex_PDA_2147808545_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.PDA!MTB"
        threat_id = "2147808545"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "COVID-19 Funeral Assistance Helpline 844-684-6333" ascii //weight: 1
        $x_1_2 = "C:\\ProgramData\\AjdjQNeZpdwb.rtf" ascii //weight: 1
        $x_1_3 = "C:\\ProgramData\\ydobzfnTqJmnXtObLzZPy.rtf" ascii //weight: 1
        $x_1_4 = "C:\\ProgramData\\aMuSfswUkXuG.rtf" ascii //weight: 1
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
        $x_1_6 = "wmic.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Dridex_VSM_2147813806_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dridex.VSM!MTB"
        threat_id = "2147813806"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "create \"mshta.exe C:\\ProgramData\\lzQBgYKlvOPnoDrvJAGgwPO.rtf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

