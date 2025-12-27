rule TrojanDownloader_W97M_Donoff_2147689998_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff"
        threat_id = "2147689998"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Auto_Open" ascii //weight: 10
        $x_1_2 = "Chr(1" ascii //weight: 1
        $x_1_3 = "Chr(4" ascii //weight: 1
        $x_1_4 = "Sgn(" ascii //weight: 1
        $x_10_5 = "\" + \"\" + \"" ascii //weight: 10
        $x_10_6 = "\" & \"" ascii //weight: 10
        $x_10_7 = ".Open \"GET\"" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Donoff_2147689998_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff"
        threat_id = "2147689998"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hBqtftpiq:/Rf/hBfpsqaqfz.iicqoqm/qis5ysift5emBR/qcqacVBh5e5/iwqorRVdB.e5fxeR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Donoff_2147689998_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff"
        threat_id = "2147689998"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":280/46au.exe" ascii //weight: 1
        $x_1_2 = "\"TMP\") & \"\\LWGKAI.exe" ascii //weight: 1
        $x_1_3 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a 41 75 74 6f 5f 4f 70 65 6e 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Donoff_2147689998_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff"
        threat_id = "2147689998"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bot.jar" ascii //weight: 1
        $x_1_2 = "Environ$(\"tmp\") & \"\\\" &" ascii //weight: 1
        $x_1_3 = "ChangeText 0, \"open\", _" ascii //weight: 1
        $x_1_4 = "\"invoice.jar\"" ascii //weight: 1
        $x_1_5 = "= \"192.99.181." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_W97M_Donoff_2147689998_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff"
        threat_id = "2147689998"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StrReverse(Hex2Str(\"544547\"))" ascii //weight: 1
        $x_1_2 = "Hex2Str(\"687474703A2F2F32343766696E616E63656465616C2E636F6D2F64627573742E657865\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Donoff_2147689998_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff"
        threat_id = "2147689998"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 4f 70 65 6e [0-12] 28 37 31 29 [0-12] 28 36 39 29 [0-12] 28 38 34 29 [0-12] 28 31 30 34 29 [0-12] 28 31 31 36 29}  //weight: 1, accuracy: Low
        $x_1_2 = ".write" ascii //weight: 1
        $x_1_3 = ".savetofile" ascii //weight: 1
        $x_1_4 = ".Type" ascii //weight: 1
        $x_1_5 = ".Environ" ascii //weight: 1
        $x_1_6 = {28 34 36 29 [0-12] 28 31 30 31 29 [0-32] 28 31 30 31 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Donoff_2147689998_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff"
        threat_id = "2147689998"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "computer = Array(" ascii //weight: 1
        $x_1_2 = {72 65 73 75 6c 74 20 3d 20 72 65 73 75 6c 74 20 26 20 43 68 72 28 66 72 6f 6d 41 72 72 28 69 29 20 2d 20 [0-4] 20 2b 20 69 29}  //weight: 1, accuracy: Low
        $x_1_3 = "Open \"GET\", GetStringFromArray(computer), False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Donoff_2147689998_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff"
        threat_id = "2147689998"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f [0-64] 3a [0-5] 2f [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "URLDownloadToFile" ascii //weight: 1
        $x_1_3 = "Auto_Open" ascii //weight: 1
        $x_1_4 = "Environ" ascii //weight: 1
        $x_1_5 = "Shell" ascii //weight: 1
        $n_100_6 = "http://www.nissay.co.jp/kojin/shohin" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Donoff_2147689998_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff"
        threat_id = "2147689998"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 43 44 46 20 3d 20 50 55 76 64 20 2b 20 75 42 49 6e 7a 7a 4f 53 56 4e 6d 42 75 65 4c 4f 6a 4c 50 65 28 [0-16] 29 20 2b 20 45 45 57 45 46 20 2b 20 75 42 49 6e 7a 7a 4f 53 56 4e 6d 42 75 65 4c 4f 6a 4c 50 65 28}  //weight: 1, accuracy: Low
        $x_1_2 = "Call PPuiyfhFsdf.Open(uBInzzOSVNmBueLOjLPe(\"]\\`a\"), CCDF, False)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Donoff_2147689998_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff"
        threat_id = "2147689998"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-16] 2e 54 65 78 74 42 6f 78}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 4f 70 65 6e 20 [0-16] 2e 54 65 78 74 42 6f 78 [0-1] 2c 20 [0-16] 2e 54 65 78 74 42 6f 78 [0-1] 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = {45 6e 76 69 72 6f 6e 28 [0-16] 2e 54 65 78 74 42 6f 78 [0-1] 29 20 26 20 22 2f 6b 66 63 22 20 2b 20 [0-16] 2e 54 65 78 74 42 6f 78}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 53 68 65 6c 6c 28 [0-16] 2e 54 65 78 74 42 6f 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Donoff_2147689998_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff"
        threat_id = "2147689998"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 4f 70 65 6e [0-12] 28 37 31 29 [0-32] 28 31 30 34 29 [0-32] 28 31 31 36 29}  //weight: 1, accuracy: Low
        $x_1_2 = ".responseBody" ascii //weight: 1
        $x_1_3 = {28 34 36 29 [0-12] 28 31 30 31 29 [0-32] 28 31 30 31 29}  //weight: 1, accuracy: Low
        $x_1_4 = {28 38 34 29 [0-32] 28 38 30 29}  //weight: 1, accuracy: Low
        $x_1_5 = {28 38 33 29 [0-12] 28 31 30 34 29 [0-12] 28 31 30 31 29 [0-12] 28 31 30 38 29 [0-12] 28 31 30 38 29}  //weight: 1, accuracy: Low
        $x_1_6 = {28 31 30 31 29 [0-32] 28 31 30 30 29 [0-16] 56 62 4d 65 74 68 6f 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Donoff_2147689998_11
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff"
        threat_id = "2147689998"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 70 6c 69 74 28 22 [0-32] 2e [0-3] 2f 38 37 74 33 34 66 2b [0-32] 2e [0-3] 2f 38 37 74 33 34 66 2b [0-32] 2e [0-3] 2f 38 37 74 33 34 66 22 2c 20 66 69 72 6d 2e 42 6f 72 4c 62 6c 2e 43 61 70 74 69 6f 6e 29}  //weight: 1, accuracy: Low
        $x_1_2 = {22 73 22 20 2b 20 05 00 [0-21] 20 2b 20 22 69 6c 65 22 2c 20 56 62 4d 65 74 68 6f 64 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {52 65 70 6c 61 63 65 28 [0-21] 28 31 32 29 2c 20 22 2e 22 2c 20 43 53 74 72 28 50 72 6f 6a 65 63 74 [0-10] 29 20 2b 20 22 2e 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Donoff_2147689998_12
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff"
        threat_id = "2147689998"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call Sorry" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileW 0&, StrPtr(Replace(Shazam, \"|\", \"\"))," ascii //weight: 1
        $x_1_3 = "ShellExecuteW 0&, StrPtr(\"Open\"), StrPtr(Skype)," ascii //weight: 1
        $x_1_4 = "\"Por favor le solicitamos que ignore este correo/documento.\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_W97M_Donoff_2147689998_13
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff"
        threat_id = "2147689998"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 31 30 34 29 [0-16] 74 [0-16] 43 68 72 28 31 31 36 29 [0-16] 70 [0-16] 28 35 38 29}  //weight: 1, accuracy: Low
        $x_1_2 = {28 34 36 29 [0-12] 28 31 30 31 29 [0-12] 28 31 32 30 29 [0-12] 28 31 30 31 29}  //weight: 1, accuracy: Low
        $x_1_3 = {28 37 39 29 [0-12] 28 31 31 32 29 [0-32] 28 31 30 31 29 [0-32] 28 31 31 30 29}  //weight: 1, accuracy: Low
        $x_1_4 = {28 37 31 29 [0-12] 28 36 39 29 [0-32] 28 38 34 29}  //weight: 1, accuracy: Low
        $x_1_5 = {28 38 34 29 [0-12] 28 36 39 29 [0-32] 28 37 37 29 [0-32] 28 38 30 29}  //weight: 1, accuracy: Low
        $x_1_6 = {28 31 31 30 29 [0-12] 28 31 31 38 29 [0-32] 28 31 30 35 29 [0-32] 28 31 31 30 29}  //weight: 1, accuracy: Low
        $x_1_7 = {28 31 30 30 29 [0-12] 6d [0-32] 28 31 30 35 29 [0-32] 28 31 31 30 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Donoff_2147689998_14
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff"
        threat_id = "2147689998"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 22 6e 74 72 22 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 22 63 72 69 22 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 22 72 69 70 22 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 22 6f 6e 74 22 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 22 4a 53 63 22 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 22 74 43 6f 22 00 00}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 20 22 72 6f 6c 22 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {3d 20 22 2e 53 63 22 00 00}  //weight: 1, accuracy: Low
        $x_1_9 = {3d 20 22 4d 53 53 22 00 00}  //weight: 1, accuracy: Low
        $x_1_10 = {3d 20 22 70 74 43 22 20 00 00}  //weight: 1, accuracy: Low
        $x_3_11 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 06 00 29 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-4] 2e 4c 61 6e 67 75 61 67 65 20 3d 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-6] 2e 45 76 61 6c 20 28}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 9 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_W97M_Donoff_2147689998_15
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff"
        threat_id = "2147689998"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set DhAXmemS278B6 = fAQaVGJfCYUL(Chr(77) & \"i\" & Chr(99) & Chr(114) & \"o\" & Chr(115) & Chr(111) & Chr(102) & \"t\" & Chr(46) & Chr(88) & \"M\" & \"L\" & \"H\" & Chr(84) & Chr(84) & Chr(80))" ascii //weight: 1
        $x_1_2 = "CallByName DhAXmemS278B6, \"O\" & Chr(112) & Chr(101) & Chr(110), VbMethod, Chr(71) & Chr(69) & Chr(84), _" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Donoff_2147689998_16
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff"
        threat_id = "2147689998"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 0f 00 28 42 79 56 61 6c 20 0f 00 20 41 73 20 56 61 72 69 61 6e 74 2c 20 42 79 56 61 6c 20 0f 00 20 41 73 20 4c 6f 6e 67 29 20 41 73 20 56 61 72 69 61 6e 74}  //weight: 2, accuracy: Low
        $x_2_2 = {4f 6e 20 45 72 72 6f 72 20 47 6f 54 6f 20 [0-31] 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e [0-31] 3d [0-31] 45 78 69 74 20 46 75 6e 63 74 69 6f 6e [0-31] 3a [0-31] 3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e}  //weight: 2, accuracy: Low
        $x_2_3 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 0f 00 28 42 79 56 61 6c 20 0f 00 20 41 73 20 56 61 72 69 61 6e 74 2c 20 42 79 56 61 6c 20 0f 00 20 41 73 20 56 61 72 69 61 6e 74 2c 20 42 79 56 61 6c 20 0f 00 20 41 73 20 56 61 72 69 61 6e 74 29 20 41 73 20 56 61 72 69 61 6e 74}  //weight: 2, accuracy: Low
        $x_2_4 = {28 42 79 56 61 6c 20 0f 00 20 41 73 20 4f 62 6a 65 63 74 2c 20 42 79 56 61 6c 20 0f 00 20 41 73 20 53 74 72 69 6e 67 2c 20 42 79 56 61 6c 20 0f 00 20 41 73 20 56 61 72 69 61 6e 74 2c 20 42 79 56 61 6c 20 0f 00 20 41 73 20 56 61 72 69 61 6e 74 [0-48] 29 [0-4] 43 61 6c 6c 42 79 4e 61 6d 65 20 00 2c 20 01 2c 20 31 2c 20 02}  //weight: 2, accuracy: Low
        $x_2_5 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-15] 28 22 [0-15] 2e [0-15] 22 2c 20 ?? ?? ?? 29 29}  //weight: 2, accuracy: Low
        $x_1_6 = "Err.Raise Number:=1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_W97M_Donoff_A_2147693768_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff.gen!A"
        threat_id = "2147693768"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"urlmon\" Alias " ascii //weight: 1
        $x_1_2 = "\"shell32.dll\" Alias " ascii //weight: 1
        $x_1_3 = "ChangeText" ascii //weight: 1
        $x_1_4 = "ChangeNumber" ascii //weight: 1
        $x_1_5 = "URLDownloadToFile 0, a, b, 0, 0" ascii //weight: 1
        $x_1_6 = {22 62 6c 61 68 90 01 01 2e 65 78 65 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_W97M_Donoff_B_2147695122_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff.B"
        threat_id = "2147695122"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub Document_Open()" ascii //weight: 1
        $x_1_2 = "ResidentEvilFour" ascii //weight: 1
        $x_1_3 = "LinkTwo = \"://jornalregional.net" ascii //weight: 1
        $x_1_4 = {4c 69 6e 6b 54 68 72 65 65 20 3d 20 22 2f 69 6d 61 67 65 73 2f 41 6d 61 7a 6f 6e 2f [0-16] 2f 61 6c 69 6d 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = " TempFourth = \"svchost" ascii //weight: 1
        $x_1_6 = "executionBegin = Shell(Management" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Donoff_C_2147707160_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff.C"
        threat_id = "2147707160"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 65 6d 70 46 69 6c 65 20 3d 20 74 65 6d 70 46 6f 6c 64 65 72 20 2b 20 22 5c 64 72 61 77 22 20 26 20 22 [0-12] 2e 22 20 2b 20 22 22 20 2b 20 22 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_2 = {73 68 65 6c 6c 41 70 70 2e 4f 70 65 6e 20 28 74 65 6d 70 46 69 6c 65 29 0d 0a 45 78 69 74 20 53 75 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Donoff_D_2147710659_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff.D"
        threat_id = "2147710659"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Environ(\"appdata\") & \"\\\"" ascii //weight: 1
        $x_1_2 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 [0-16] 28 4f 70 74 69 6f 6e 61 6c 20 [0-78] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 [0-142] 22 29 20 41 73 20 56 61 72 69 61 6e 74}  //weight: 1, accuracy: Low
        $x_1_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 20 30 26 2c 20 22 68 74 74 70 3a 2f 2f [0-48] 22 2c 20 [0-16] 20 26 20 53 74 72 52 65 76 65 72 73 65 28 [0-78] 29 2c 20 30 26 2c 20 30 26}  //weight: 1, accuracy: Low
        $x_1_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 20 30 26 2c 20 53 74 72 50 74 72 28 22 4f 70 65 6e 22 29 2c 20 53 74 72 50 74 72 28 [0-16] 20 26 20 53 74 72 52 65 76 65 72 73 65 28 [0-78] 29 29 2c 20 53 74 72 50 74 72 28 22 22 29 2c 20 53 74 72 50 74 72 28 22 22 29 2c 20 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Donoff_H_2147716253_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Donoff.H"
        threat_id = "2147716253"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "If Application.RecentFiles.Count < 3 Then Module1." ascii //weight: 4
        $x_2_2 = "Err.Raise Number:=4, Description:=s(" ascii //weight: 2
        $x_3_3 = "ZMwb.Open(s(\"TEG\", 17, 23)," ascii //weight: 3
        $x_2_4 = "Public Function s(ByVal tWZG As String, ByVal fBpp As Integer," ascii //weight: 2
        $x_3_5 = "cOuh = ZMwb.ResponseText" ascii //weight: 3
        $x_1_6 = "Public Sub Document_Close()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

