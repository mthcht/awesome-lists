rule TrojanDownloader_Win32_Renos_JH_2147799748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.JH"
        threat_id = "2147799748"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Copyright (C) Microsoft Corp. 1981-1999" wide //weight: 1
        $x_1_2 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 20 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 65 00 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_JH_2147799748_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.JH"
        threat_id = "2147799748"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 1a 5b f7 f3 8b 5d 08 8a 44 15 ce 8b 55 f8 88 04 1a 8d 57 ff 3b f2 7d 05}  //weight: 1, accuracy: High
        $x_1_2 = {8b 30 0f af 37 46 89 30 8b 09 8b 74 24 0c 8b 06 0f b7 4c 8a 02}  //weight: 1, accuracy: High
        $x_2_3 = {c7 00 35 4e 5a 01 83 23 00}  //weight: 2, accuracy: High
        $x_2_4 = "a \"..\\%s.rar\" *" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_ES_2147799792_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.ES"
        threat_id = "2147799792"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\WinAntiVirus Pro 2007" ascii //weight: 1
        $x_1_2 = "Software\\WinAntiSpyware 2007" ascii //weight: 1
        $x_1_3 = "Software\\ErrorProtector" ascii //weight: 1
        $x_1_4 = "Software\\MalwareStopper" ascii //weight: 1
        $x_1_5 = "http://go.winantivirus.com/" ascii //weight: 1
        $x_1_6 = "http://go.drivecleaner.com" ascii //weight: 1
        $x_1_7 = "http://go.systemdoctor.com" ascii //weight: 1
        $x_1_8 = "http://go.errorsafe.com" ascii //weight: 1
        $x_1_9 = "http://go.errorprotector.com" ascii //weight: 1
        $x_1_10 = "Warning! Potential Spyware Operation!" ascii //weight: 1
        $x_1_11 = "Your computer is making unauthorized copies of your system and" ascii //weight: 1
        $x_1_12 = "Internet files. Run full scan now to pervent any unathorised access" ascii //weight: 1
        $x_1_13 = "to your files! Click here to download spyware remover ..." ascii //weight: 1
        $x_1_14 = "Windows Security Alert" ascii //weight: 1
        $x_1_15 = "%windir%\\system32\\winav.exe" ascii //weight: 1
        $x_1_16 = "{ABCDECF0-4B15-11D1-ABED-709549C10000}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule TrojanDownloader_Win32_Renos_ES_2147799792_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.ES"
        threat_id = "2147799792"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\WinAntiVirus Pro 2007" ascii //weight: 1
        $x_1_2 = {57 69 6e 41 56 58 00 00 5c 70 72 69 6e 74 65 72 2e 65 78 65 00 00 00 00 5c 57 69 6e 41 76 58 58 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\WINDOWS\\SYSTEM32\\WinAvXX.exe" ascii //weight: 1
        $x_1_4 = "%windir%\\system32\\winav.exe" ascii //weight: 1
        $x_1_5 = {68 74 74 70 3a 2f 2f 67 6f 2e 77 69 6e 61 6e 74 69 76 69 72 75 73 2e 63 6f 6d 2f 4d 54 59 32 4e 6a 55 3d 2f 32 2f 36 30 31 38 2f 61 78 3d 31 2f 65 64 3d 31 2f 65 78 3d 31 2f ?? ?? ?? 2f}  //weight: 1, accuracy: Low
        $x_1_6 = "CLSID\\{ABCDECF0-4B15-11D1-ABED-709549C10000}\\InProcServer32" ascii //weight: 1
        $x_1_7 = {57 61 72 6e 69 6e 67 21 20 50 6f 74 65 6e 74 69 61 6c 20 53 70 79 77 61 72 65 20 4f 70 65 72 61 74 69 6f 6e 21 0a 0a 59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 6d 61 6b 69 6e 67 20 75 6e 61 75 74 68 6f 72 69 7a 65 64 20 63 6f 70 69 65 73 20 6f 66 20 79 6f 75 72 20 73 79 73 74 65 6d 20 61 6e 64 0a 49 6e 74 65 72 6e 65 74 20 66 69 6c 65 73 2e 20 52 75 6e 20 66 75 6c 6c 20 73 63 61 6e 20 6e 6f 77 20 74 6f 20 70 65 72 76 65 6e 74 20 61 6e 79 20 75 6e 61 74 68 6f 72 69 73 65 64 20 61 63 63 65 73 73 0a 74 6f 20 79 6f 75 72 20 66 69 6c 65 73 21 20 43 6c 69 63 6b 20 [0-4] 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 20 73 70 79 77 61 72 65 20 72 65 6d 6f 76 65 72 20 2e 2e 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_Win32_Renos_2147799811_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "22C-42BD-A8CB-7" ascii //weight: 3
        $x_3_2 = "wspdl.com" ascii //weight: 3
        $x_1_3 = "xtwaP\\Mic" ascii //weight: 1
        $x_1_4 = "^^es.+/pay/%s" ascii //weight: 1
        $x_1_5 = "?type=main&p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_2147799811_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "76086C05-4D0A-4B92-9219-2E3FE8C553F9" ascii //weight: 3
        $x_3_2 = "BhoNew.Bho.1 = s 'BHO.tbl" ascii //weight: 3
        $x_1_3 = "'Browser Helper Objects'" ascii //weight: 1
        $x_1_4 = "15C7D7AD-A87A-4C0D-9D8B-637FCD3488EF" ascii //weight: 1
        $x_1_5 = "ProgID = s 'BhoNew.Bho.1'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_2147799811_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 00 75 72 6c 6d 6f 6e 2e 64 6c 6c}  //weight: 10, accuracy: High
        $x_10_2 = {66 69 72 73 74 2d 72 65 61 73 6f 6e 2e 25 73 00 63 6f 6d 2f 75 70 2e 70 68 70 3f 61 64 76 69 64 3d}  //weight: 10, accuracy: High
        $x_2_3 = {69 53 53 44 5f 43 4d 00 43 3a 5c 53 65 74 75 70 2e 65 78 65}  //weight: 2, accuracy: High
        $x_2_4 = {68 74 74 70 3a 2f 2f 00 56 52 53 49 4e}  //weight: 2, accuracy: High
        $x_1_5 = "GetTempFileNameA" ascii //weight: 1
        $x_1_6 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_7 = "GetStartupInfoA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_2147799811_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "visa" ascii //weight: 10
        $x_10_2 = "mastercard" ascii //weight: 10
        $x_10_3 = "System Error!" ascii //weight: 10
        $x_10_4 = "antivirus" ascii //weight: 10
        $x_1_5 = "VersionIndependentProgID = s 'BhoNew.BhoApp'" ascii //weight: 1
        $x_1_6 = "CurVer = s 'BhoNew.BhoApp" ascii //weight: 1
        $x_1_7 = {6e 69 63 68 65 70 61 73 73 00 00 00 77 6e 75 2e 63 6f 6d 00 73 65 67 70 61 79 00 00 76 65 72 69 66 69 65 64 70 61 79 6d 65 6e 74 73 6f 6c 75 74 69 6f 6e 73 6f 6e 6c 69 6e 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_2147799811_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 00 68 00 65 00 72 00 69 00 66 00 66 00 2e 00 65 00 78 00 65 00 00 00 77}  //weight: 10, accuracy: High
        $x_10_2 = "InternetGetConnectedState" ascii //weight: 10
        $x_10_3 = "gethostbyname" ascii //weight: 10
        $x_1_4 = "System error: spyware intrusion detected!" ascii //weight: 1
        $x_1_5 = "Critical error: system in danger!" ascii //weight: 1
        $x_1_6 = "Windows has detected spyware" ascii //weight: 1
        $x_1_7 = "System Alert!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_2147799811_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "208"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "P*\\AD:\\Master\\ADWARA_NEW\\idle_componet.vbp" wide //weight: 100
        $x_100_2 = "CreateToolhelp32Snapshot" ascii //weight: 100
        $x_3_3 = "MakeFakeVirus" ascii //weight: 3
        $x_2_4 = "http://antispysolutions.com/?aid=" wide //weight: 2
        $x_2_5 = "http://vnmxjcx.com/config.ini" ascii //weight: 2
        $x_1_6 = "copy c:\\windows\\system32\\shell32.dll c:\\shell32.dll1" ascii //weight: 1
        $x_1_7 = "copy c:\\windows\\system32\\shell32.dll c:\\shell32.dll2" ascii //weight: 1
        $x_1_8 = "copy c:\\windows\\system32\\shell32.dll c:\\shell32.dll3" ascii //weight: 1
        $x_1_9 = "del c:\\shell32.dll1" ascii //weight: 1
        $x_1_10 = "del c:\\shell32.dll2" ascii //weight: 1
        $x_1_11 = "del c:\\shell32.dll3" ascii //weight: 1
        $x_1_12 = "\\idleserv.exe" ascii //weight: 1
        $x_1_13 = {00 49 73 50 72 6f 63 52 75 6e 00}  //weight: 1, accuracy: High
        $x_1_14 = "MakeItAll" ascii //weight: 1
        $x_1_15 = {00 64 6f 77 73 5c 73 79 73 74 65 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 8 of ($x_1_*))) or
            ((2 of ($x_100_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_100_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_100_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_100_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_2147799811_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IEHlprObj.IEHlprObj.1 = s 'IEHlprObj Class'" ascii //weight: 1
        $x_1_2 = "CLSID = s '{ABCDECF0-4B15-11D1-ABED-709549C10000}'" ascii //weight: 1
        $x_1_3 = "IEHlprObj.IEHlprObj = s 'IEHlprObj Class'" ascii //weight: 1
        $x_1_4 = "CurVer = s 'IEHlprObj.IEHlprObj.1'" ascii //weight: 1
        $x_1_5 = "ForceRemove {ABCDECF0-4B15-11D1-ABED-709549C10000} = s 'IEHlprObj Class'" ascii //weight: 1
        $x_1_6 = "ProgID = s 'IEHlprObj.IEHlprObj.1'" ascii //weight: 1
        $x_1_7 = "VersionIndependentProgID = s 'IEHlprObj.IEHlprObj'" ascii //weight: 1
        $x_1_8 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 49 00 45 00 48 00 45 00 4c 00 50 00 45 00 52 00 00 00 00 00 42 00 0f 00 01 00 4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 31 00 39 00 39 00 37 00 00 00 00 00 42 00 0d 00 01 00 4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 49 00 45 00 48 00 45 00 4c 00 50 00 45 00 52 00 2e 00 44 00 4c 00 4c 00 00 00 00 00 40 00 10 00 01 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 49 00 45 00 48 00 65 00 6c 00 70 00 65 00 72 00 20 00 4d 00 6f 00 64 00 75 00 6c 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_2147799811_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "GET /trial.php?rest=%u&ver=%u&a=00000129 HTTP/1.0" ascii //weight: 5
        $x_5_2 = "GET /download.php?&advid=00000357&u=%u&p=%u HTTP/1.0" ascii //weight: 5
        $x_5_3 = "C:\\winstall.exe" ascii //weight: 5
        $x_5_4 = "C:\\Windows\\xpupdate.exe" ascii //weight: 5
        $x_3_5 = "C:\\Program Files\\BraveSentry\\BraveSentry.exe" ascii //weight: 3
        $x_5_6 = "Windows has detected spyware infection!" ascii //weight: 5
        $x_5_7 = "Windows Security Center has detected spyware/adware infection!" ascii //weight: 5
        $x_5_8 = "69.50.175.178" ascii //weight: 5
        $x_5_9 = "69.50.175.181" ascii //weight: 5
        $x_3_10 = "Host: hyyd" ascii //weight: 3
        $x_3_11 = "Host: download.bravesentry.com" ascii //weight: 3
        $x_2_12 = "Your computer is infected!" ascii //weight: 2
        $x_2_13 = "Your computer is in Danger!" ascii //weight: 2
        $x_1_14 = "Click here to protect your computer from spyware!" ascii //weight: 1
        $x_1_15 = "Click here to install the latest protection tools!" ascii //weight: 1
        $x_1_16 = "It is strongly recommended to use special antispyware tools to prevent data loss." ascii //weight: 1
        $x_1_17 = "Your c" ascii //weight: 1
        $x_1_18 = "ompute" ascii //weight: 1
        $x_1_19 = "r is infe" ascii //weight: 1
        $x_1_20 = "cted!" ascii //weight: 1
        $x_1_21 = "Windows has detec" ascii //weight: 1
        $x_1_22 = "ted spyw" ascii //weight: 1
        $x_1_23 = "are inf" ascii //weight: 1
        $x_1_24 = "ection!" ascii //weight: 1
        $x_1_25 = "It is recom" ascii //weight: 1
        $x_1_26 = "mende" ascii //weight: 1
        $x_1_27 = "d to use sp" ascii //weight: 1
        $x_1_28 = "ecial anti" ascii //weight: 1
        $x_1_29 = "spyware too" ascii //weight: 1
        $x_1_30 = "ls to prev" ascii //weight: 1
        $x_1_31 = "ent data l" ascii //weight: 1
        $x_1_32 = "oss. Wind" ascii //weight: 1
        $x_1_33 = "ows will now" ascii //weight: 1
        $x_1_34 = " download an" ascii //weight: 1
        $x_1_35 = "d install t" ascii //weight: 1
        $x_1_36 = "he most up-t" ascii //weight: 1
        $x_1_37 = "o-date anti" ascii //weight: 1
        $x_1_38 = "are for" ascii //weight: 1
        $x_1_39 = "Click h" ascii //weight: 1
        $x_1_40 = "ere to protect yo" ascii //weight: 1
        $x_1_41 = "ur comput" ascii //weight: 1
        $x_1_42 = "er from spyw" ascii //weight: 1
        $x_1_43 = "Sheri" ascii //weight: 1
        $x_1_44 = "eriff" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((20 of ($x_1_*))) or
            ((1 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_3_*) and 17 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_3_*) and 14 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_3_*) and 11 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 15 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_2147799811_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 07 c1 c0 07 0f af c0 69 c0 44 33 22 11 c1 c8 0f 69 c0 11 33 22 44 c1 c8 05 0f af c0 69 c0 13 13 00 00 ae e2 da}  //weight: 1, accuracy: High
        $x_1_2 = {ff e0 8b d8 81 eb ?? ?? ?? ?? 8d bb ?? ?? ?? ?? b9 40 00 00 00 81 37 ?? ?? ?? ?? af e2 f7 e8 24 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {75 06 ff 80 b8 00 00 00 33 c0 c2 10 00 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 cc 64 8f 05 00 00 00 00 5f 8b 3c 24 b9 ?? ?? ?? ?? 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Renos_2147799811_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "75"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Virus Activity!!! System on your PC is infected." ascii //weight: 10
        $x_10_2 = "InternetOpenUrlA" ascii //weight: 10
        $x_10_3 = "ShellExecuteA" ascii //weight: 10
        $x_10_4 = "Shell_NotifyIconA" ascii //weight: 10
        $x_10_5 = "DisplayIcon" ascii //weight: 10
        $x_10_6 = {6c 6f 61 64 00}  //weight: 10, accuracy: High
        $x_10_7 = {61 6c 6c 65 72 74 00}  //weight: 10, accuracy: High
        $x_5_8 = "tmxxxh.dll" ascii //weight: 5
        $x_5_9 = "http://www." ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_2147799811_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Windows\\xpupdate.exe" ascii //weight: 10
        $x_10_2 = {4e 6f 43 68 61 6e 67 69 6e 67 57 61 6c 6c 70 61 70 65 72 [0-16] 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 41 63 74 69 76 65 44 65 73 6b 74 6f 70}  //weight: 10, accuracy: Low
        $x_10_3 = {46 6f 72 63 65 41 63 74 69 76 65 44 65 73 6b 74 6f 70 4f 6e [0-16] 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72}  //weight: 10, accuracy: Low
        $x_1_4 = "69.50.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_2147799811_11
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Host: download.%s.com" ascii //weight: 1
        $x_1_2 = "C:\\Windows\\xpupdate.exe" ascii //weight: 1
        $x_1_3 = "Windows update loader" ascii //weight: 1
        $x_1_4 = "C:\\Install" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Internet Explorer\\Desktop\\General" ascii //weight: 1
        $x_1_6 = {47 45 54 20 2f [0-8] 2e 70 68 70 3f 26 61 64 76 69 64 3d}  //weight: 1, accuracy: Low
        $x_1_7 = {47 45 54 20 68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 25 73 2e 63 6f 6d 2f [0-8] 2e 70 68 70 3f 26 61 64 76 69 64 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_Win32_Renos_2147799811_12
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {47 45 54 20 2f [0-8] 2e 70 68 70 3f 26 61 64 76 69 64 3d}  //weight: 10, accuracy: Low
        $x_10_2 = "Windows update loader" ascii //weight: 10
        $x_10_3 = {4e 6f 43 68 61 6e 67 69 6e 67 57 61 6c 6c 70 61 70 65 72 [0-16] 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 41 63 74 69 76 65 44 65 73 6b 74 6f 70}  //weight: 10, accuracy: Low
        $x_10_4 = {46 6f 72 63 65 41 63 74 69 76 65 44 65 73 6b 74 6f 70 4f 6e [0-16] 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72}  //weight: 10, accuracy: Low
        $x_1_5 = "69.50.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_2147799811_13
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "106"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {8b 44 24 14 0f be 14 3e 0f be 4c 37 01 31 ca 88 14 18 43 83 c7 02 89 f1 83 c8 ff 40 80 3c 01 00 75 f9 39 c7 72 da}  //weight: 100, accuracy: High
        $x_3_2 = "windows xp amigo yo man friends hello go-go" ascii //weight: 3
        $x_3_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\System Alert Popup" ascii //weight: 3
        $x_2_4 = "\\\\.\\pipe\\ipctest" ascii //weight: 2
        $x_2_5 = "Software\\MicrosoftWindowsXp2003" ascii //weight: 2
        $x_1_6 = "hirtellous" ascii //weight: 1
        $x_1_7 = "Error Load hDelete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_2147799811_14
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "webinst.dll" ascii //weight: 1
        $x_1_2 = "4A3D609A-43B8-4406-B793-84F244246325" wide //weight: 1
        $x_1_3 = "AxNameTrackLib" ascii //weight: 1
        $x_1_4 = "IWebInstallW" ascii //weight: 1
        $x_2_5 = "1A26F07F-0D60-4835-91CF-1E1766A0EC56" ascii //weight: 2
        $x_2_6 = "7543FBD5-2279-4D03-8F29-EB21531FA2FE" ascii //weight: 2
        $x_2_7 = "AxNameTrack.dll" ascii //weight: 2
        $x_3_8 = "VirtualProtect" ascii //weight: 3
        $x_3_9 = "DllRegisterServer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_2147799811_15
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "215"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "download.php?&advid=" ascii //weight: 100
        $x_50_2 = "C:\\Windows\\xpupdate.exe" ascii //weight: 50
        $x_10_3 = "ForceActiveDesktopOn" ascii //weight: 10
        $x_10_4 = "SOFTWARE\\Microsoft\\Internet Explorer\\Desktop\\General" ascii //weight: 10
        $x_10_5 = "WallpaperFileTime" ascii //weight: 10
        $x_10_6 = "Windows update loader" ascii //weight: 10
        $x_10_7 = "SOFTWARE\\Install" ascii //weight: 10
        $x_5_8 = "ProxyServer" ascii //weight: 5
        $x_5_9 = "ProxyEnable" ascii //weight: 5
        $x_5_10 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_2147799811_16
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {78 3a 5c 44 65 76 5f 43 50 50 5c 57 6f 72 6b 5c 56 53 5f 4b 6e 7a 53 74 72 5f 41 64 77 61 72 65 5c 52 65 6c 65 61 73 65 5c 56 53 5f 57 6f 72 6b ?? 2e 70 64 62}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 14 85 c0 0f 8c 4b 01 00 00 83 f8 01 0f 84 42 01 00 00 83 f8 24 0f 8f 39 01 00 00 85 c0 75 2a 80 fb 30 74 09 c7 45 14 0a 00 00 00 eb 34}  //weight: 10, accuracy: High
        $x_5_3 = "safe-strip-download.com" ascii //weight: 5
        $x_1_4 = {72 65 67 65 64 69 74 20 2d 73 20 72 65 67 ?? 2e 72 65 67 20}  //weight: 1, accuracy: Low
        $x_1_5 = {52 45 47 20 49 4d 50 4f 52 54 20 72 65 67 ?? 2e 72 65 67 20}  //weight: 1, accuracy: Low
        $x_1_6 = {65 72 61 73 65 20 72 65 67 ?? 2e 72 65 67 20}  //weight: 1, accuracy: Low
        $x_1_7 = {65 72 61 73 65 20 72 65 67 78 ?? 2e 62 61 74 20}  //weight: 1, accuracy: Low
        $x_1_8 = "WARNING: Your computer is infected" ascii //weight: 1
        $x_1_9 = "Windows has detected spyware infection!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_2147799811_17
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "68"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "{ABCDECF0-4B15-11D1-ABED-709549C10000}" ascii //weight: 10
        $x_10_2 = "{393921-e939391-3919139-3d3a738-11}" ascii //weight: 10
        $x_10_3 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 10
        $x_10_4 = "DisableRegistryTools" ascii //weight: 10
        $x_10_5 = "EnableBalloonTips" ascii //weight: 10
        $x_5_6 = "\\drivers\\etc\\hosts" ascii //weight: 5
        $x_3_7 = "windowsupdate.microsoft.com" ascii //weight: 3
        $x_3_8 = "kaspersky.com" ascii //weight: 3
        $x_3_9 = "mcafee.com" ascii //weight: 3
        $x_3_10 = "symantec.com" ascii //weight: 3
        $x_1_11 = "192.168.200.3" ascii //weight: 1
        $x_1_12 = "Warning! Potential Spyware Operation!" ascii //weight: 1
        $x_1_13 = "Your computer is making unauthorized copies of your system and" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_2147799811_18
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos"
        threat_id = "2147799811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 6f 52 65 6d 6f 76 65 20 41 70 70 49 44 ?? ?? ?? ?? ?? ?? ?? ?? 27 25 41 50 50 49 44 25 27 20 3d 20 73 20 27 53 70 79 53 68 72 65 64 64 65 72 27 ?? ?? ?? ?? 27 77 65 62 69 6e 73 74 2e 64 6c 6c 27}  //weight: 1, accuracy: Low
        $x_1_2 = {53 70 79 53 68 72 65 64 64 65 72 2e 57 65 62 49 6e 73 74 61 6c 6c 2e 31 20 3d 20 73 20 27 57 65 62 49 6e 73 74 61 6c 6c 20 43 6c 61 73 73 27 ?? ?? ?? ?? ?? ?? ?? ?? 43 4c 53 49 44 20 3d 20 73 20 27 7b 33 34 33 43 45 32 31 34 2d 39 39 39 38 2d 34 42 32 31 2d 41 31 35 31 2d 46 46 45 39 37 30 31 36 37 32 39 37 7d 27}  //weight: 1, accuracy: Low
        $x_1_3 = {53 70 79 53 68 72 65 64 64 65 72 2e 57 65 62 49 6e 73 74 61 6c 6c 20 3d 20 73 20 27 57 65 62 49 6e 73 74 61 6c 6c 20 43 6c 61 73 73 27 ?? ?? ?? ?? ?? ?? ?? ?? 43 4c 53 49 44 20 3d 20 73 20 27 7b 33 34 33 43 45 32 31 34 2d 39 39 39 38 2d 34 42 32 31 2d 41 31 35 31 2d 46 46 45 39 37 30 31 36 37 32 39 37 7d 27}  //weight: 1, accuracy: Low
        $x_1_4 = {43 75 72 56 65 72 20 3d 20 73 20 27 53 70 79 53 68 72 65 64 64 65 72 2e 57 65 62 49 6e 73 74 61 6c 6c 2e 31 27 ?? ?? ?? ?? ?? ?? ?? 4e 6f 52 65 6d 6f 76 65 20 43 4c 53 49 44 ?? ?? ?? ?? ?? ?? ?? ?? 46 6f 72 63 65 52 65 6d 6f 76 65 20 7b 33 34 33 43 45 32 31 34 2d 39 39 39 38 2d 34 42 32 31 2d 41 31 35 31 2d 46 46 45 39 37 30 31 36 37 32 39 37 7d 20 3d 20 73 20 27 57 65 62 49 6e 73 74 61 6c 6c 20 43 6c 61 73 73 27}  //weight: 1, accuracy: Low
        $x_1_5 = {50 72 6f 67 49 44 20 3d 20 73 20 27 53 70 79 53 68 72 65 64 64 65 72 2e 57 65 62 49 6e 73 74 61 6c 6c 2e 31 27 ?? ?? ?? ?? ?? 56 65 72 73 69 6f 6e 49 6e 64 65 70 65 6e 64 65 6e 74 50 72 6f 67 49 44 20 3d 20 73 20 27 53 70 79 53 68 72 65 64 64 65 72 2e 57 65 62 49 6e 73 74 61 6c 6c 27}  //weight: 1, accuracy: Low
        $x_1_6 = "'TypeLib' = s '{D2436533-33F9-495C-9CD9-DAF21E67FFEB}'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_LT_2147799814_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.LT"
        threat_id = "2147799814"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SSHNAS" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Handle" ascii //weight: 1
        $x_1_3 = "<url crypt=\"on\" post=\"on\">http" ascii //weight: 1
        $x_1_4 = ".php?e=</url><url get=\"on\">" ascii //weight: 1
        $x_1_5 = {c7 46 0c 76 54 32 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Renos_KX_2147800831_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.KX"
        threat_id = "2147800831"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "POST /mnhbckjmdhckj.php?" ascii //weight: 2
        $x_2_2 = "=v26MmjSyS" ascii //weight: 2
        $x_2_3 = "data=ujnT32O/F9qsDyA" ascii //weight: 2
        $x_1_4 = "User-Agent: wget 3.0" ascii //weight: 1
        $x_2_5 = "POST /fakbwq.php?" ascii //weight: 2
        $x_2_6 = "data=vzjcw2q/" ascii //weight: 2
        $x_2_7 = "POST /bskcua.php?" ascii //weight: 2
        $x_1_8 = "User-Agent: Mozilla/6.0 (Windows; wget 3.0)" ascii //weight: 1
        $x_2_9 = "=v22MkjPnG" ascii //weight: 2
        $x_1_10 = {2e 70 68 70 3f [0-3] 3d 76 32 32 4d}  //weight: 1, accuracy: Low
        $x_2_11 = "data=sS+M523hC9qxBWA" ascii //weight: 2
        $x_1_12 = {3d 3d 20 48 54 54 50 2f 31 2e 31 0d 0a 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64}  //weight: 1, accuracy: High
        $n_100_13 = "Magnet.Content.Artifacts.dll" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_HO_2147800857_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.HO"
        threat_id = "2147800857"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 c6 44 24 0c 25 c6 44 24 0f 78 c6 44 24 0d 30 c6 44 24 10 00 c6 44 24 0e 38 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {66 ba 58 56 ed 89 5d e4 5b c7 45 fc ff ff ff ff 33 c0 81 7d e4 68 58 4d 56 0f 94 c0}  //weight: 1, accuracy: High
        $x_1_3 = {99 b9 00 50 00 00 f7 f9 52 ff 15 ?? ?? ?? ?? 83 c4 0c 8d 54 24 08 68 ?? ?? ?? ?? 52 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {33 c0 88 45 e4 89 45 fc 53 bb 00 00 00 00 b8 01 00 00 00 0f 3f 07}  //weight: 1, accuracy: High
        $x_1_5 = {6a 0c 51 68 00 14 2d 00 56 ff 15}  //weight: 1, accuracy: High
        $x_1_6 = {33 c0 b1 20 8a 90 ?? ?? ?? ?? 8a 98 ?? ?? ?? ?? 02 d1 02 d9 88 90 ?? ?? ?? ?? 88 98 ?? ?? ?? ?? 40 3d ff 00 00 00 7c dc}  //weight: 1, accuracy: Low
        $x_1_7 = {77 67 65 74 20 33 2e 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Renos_KH_2147800904_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.KH"
        threat_id = "2147800904"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 51 51 51 6a 06 ff d0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 14 2d 00 ff 74 24 ?? ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 44 24 08 23 c8 89 0d ?? ?? ?? 00 8a 0d ?? ?? ?? 00 22 0d ?? ?? ?? 00 88 0d ?? ?? ?? 00 8b 0d ?? ?? ?? 00 03 c1 66 a3 ?? ?? ?? 00 0f bf c0 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {04 5a 0f b6 c0 83 c0 03 23 c6 e8 ?? ?? ?? ?? 8b c4 57 50 e8 ?? ?? ?? ?? 8b f8 57 e8 ?? ?? ?? ?? 83 c4 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Renos_FU_2147800911_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.FU"
        threat_id = "2147800911"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\\\.\\C:" ascii //weight: 2
        $x_2_2 = {68 00 14 2d 00 03 00 6a 0c}  //weight: 2, accuracy: Low
        $x_1_3 = {68 58 4d 56 0f 94 c0}  //weight: 1, accuracy: High
        $x_1_4 = {68 4d 56 00 00 68 68 58 00 00}  //weight: 1, accuracy: High
        $x_2_5 = {40 3d ff 00 00 00 7c ea 10 00 [0-10] d1 88}  //weight: 2, accuracy: Low
        $x_1_6 = {8a 8d 00 04 00 00 8d 85 00 04 00 00 3a cb 75 16 38 1e 74 12 68 00 04 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {25 6c 75 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_LS_2147800931_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.LS"
        threat_id = "2147800931"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {05 72 06 00 00 05 df 1a 00 00 35 65 18 00 00 19 c0 11 c0 85 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_LN_2147800957_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.LN"
        threat_id = "2147800957"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 53 48 4e 41 53 00 [0-4] 42 61 63 6b 75 70 52 65 61 64 57 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3c 69 66 72 61 6d 65 20 66 72 61 6d 65 62 6f 72 64 65 72 3d 22 30 22 20 77 69 64 74 68 3d 22 30 22 20 68 65 69 67 68 74 3d 22 30 22 20 73 72 63 3d 22 00}  //weight: 1, accuracy: High
        $x_2_3 = {53 53 48 4e 41 53 00 00 42 61 63 6b 75 70 52 65 61 64 57 00 20 00 00 00 68 74 74 70 3a 2f 2f 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 00 00 49 44 00}  //weight: 2, accuracy: High
        $x_1_4 = {53 53 48 4e 41 53 00 [0-4] 42 65 65 70 31 36 00}  //weight: 1, accuracy: Low
        $x_1_5 = "<url post=\"on\">http" ascii //weight: 1
        $x_2_6 = {53 53 48 4e 41 53 00 00 42 65 65 70 31 36 00 00 20 00 00 00 68 74 74 70 3a 2f 2f 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 00}  //weight: 2, accuracy: High
        $x_1_7 = "</url><url get=\"on\">http://" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_JS_2147801020_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.JS"
        threat_id = "2147801020"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {50 68 00 14 2d 00 02 00 6a (0c|18)}  //weight: 4, accuracy: Low
        $x_4_2 = {bb 00 01 00 00 ?? ?? ?? ?? ?? ?? ?? 40 3b c3 72 f4}  //weight: 4, accuracy: Low
        $x_4_3 = {8a 06 0f b6 4e ff c1 e0 08 0b c1}  //weight: 4, accuracy: High
        $x_4_4 = {ff 45 f8 83 c7 04 83 7d f8 03 72 ?? eb}  //weight: 4, accuracy: Low
        $x_4_5 = {68 8e 02 00 00 68 56 03 00 00 6a 40}  //weight: 4, accuracy: High
        $x_4_6 = {68 58 4d 56 c7 45 ?? 58 56 00 00}  //weight: 4, accuracy: Low
        $x_1_7 = {8a 04 37 34 ?? 88 06 46 ?? 75}  //weight: 1, accuracy: Low
        $x_1_8 = {88 06 46 ff ?? ?? 75 05 00 8a 04 ?? 34}  //weight: 1, accuracy: Low
        $x_1_9 = {88 07 47 ff ?? ?? 75 05 00 8a 04 ?? 34}  //weight: 1, accuracy: Low
        $x_1_10 = {48 41 5f 25 30 38 78 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_JM_2147801022_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.JM"
        threat_id = "2147801022"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 6f 72 64 42 75 6c (01|6c) 00}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 6f 6e 6f 70 6f 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {64 69 61 53 6f 6c 61 72 69 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {48 41 5f 25 30 38 78 00}  //weight: 1, accuracy: High
        $x_1_5 = {3c 62 6f 74 20 6e 61 6d 65 3d 22 (62 61 6e 6e|68) 62 6f 74 22 3e}  //weight: 1, accuracy: Low
        $x_1_6 = {52 65 73 74 61 72 74 20 66 61 69 6c 65 64 00 00 42 61 6e 6e 65 72 42 6f 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {64 8b 1d 30 00 00 00 8a 43 02 0f b6 d8 89 (9d|5d)}  //weight: 1, accuracy: Low
        $x_1_8 = {64 8b 0d 30 00 00 00 [0-8] 8a 41 02 [0-8] 0f b6 c8 [0-8] 89 4d}  //weight: 1, accuracy: Low
        $x_1_9 = {64 8b 1d 30 00 00 00 [0-4] 8a 43 02 [0-4] 0f b6 d8 [0-4] 89 (5d|9d)}  //weight: 1, accuracy: Low
        $x_1_10 = {0f b6 c0 83 c0 03 24 fc e8 04 00 8a 06 (04|2c)}  //weight: 1, accuracy: Low
        $x_1_11 = {0f b6 c0 83 c0 03 83 e0 fc e8 04 00 8a 06 (04|2c)}  //weight: 1, accuracy: Low
        $x_1_12 = {ff 45 f4 8b 73 04 83 c3 04 89 07 83 c7 04 ff 45 fc 85 f6 75 ?? 83 45 f8 04 ff 45 fc 81 7d f8}  //weight: 1, accuracy: Low
        $x_1_13 = {64 a1 30 00 00 00 [0-4] 8a 40 02 [0-4] 0f b6 c0 [0-4] 89 45}  //weight: 1, accuracy: Low
        $x_1_14 = {cd 41 66 3b (45 ??|85 ?? ??) [0-4] 0f 94 c0 0f b6 (c0|c8|d8)}  //weight: 1, accuracy: Low
        $x_1_15 = {83 f8 32 7c 0c 83 7d ?? 01 0f 82 ?? ?? ff ff eb}  //weight: 1, accuracy: Low
        $x_1_16 = {3d 00 00 00 d0 [0-6] 77 ?? 3d 00 00 00 80 [0-6] 73 ?? [0-6] ff 15 ?? ?? ?? ?? 2b c7 (eb|e9)}  //weight: 1, accuracy: Low
        $x_1_17 = {83 c7 04 83 7d f0 0a [0-12] 0f 82}  //weight: 1, accuracy: Low
        $x_1_18 = {00 d0 77 08 81 ?? 00 00 00 80 73 ?? ff 15 04 00 81 ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_19 = {2d 00 00 00 80 [0-8] 3d 00 00 00 50 76 0a ff 15}  //weight: 1, accuracy: Low
        $x_1_20 = {86 f3 00 00 0a 00 c7 45 ?? 4f 00 00 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_21 = {43 83 c7 04 83 fb 0a 72 [0-32] 32 c0}  //weight: 1, accuracy: Low
        $x_1_22 = {68 1f 00 02 00 ?? ?? (50|2d|57) (50|2d|57) 68 01 00 00 80 ff 15 ?? ?? ?? ?? 85 c0 (74|75) (02|2d|7f)}  //weight: 1, accuracy: Low
        $x_1_23 = {68 1f 00 02 00 ?? ?? (50|2d|57) (50|2d|57) 68 01 00 00 80 ff ?? 85 c0 (74|75) (02|2d|7f)}  //weight: 1, accuracy: Low
        $x_1_24 = {68 1f 00 02 00 ?? ?? (50|2d|57) (50|2d|57) 68 01 00 00 80 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 66 a3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 0f bf c0}  //weight: 1, accuracy: Low
        $x_1_25 = {68 00 14 2d 00 03 05 06 01 ff 75 ?? ff 74 24 ?? 56 (ff 15 ?? ?? ?? ??|ff d0) 85 c0 (0f 84|74)}  //weight: 1, accuracy: Low
        $x_1_26 = {c1 e8 1a c1 e6 06 8a 80 ?? ?? ?? ?? [0-8] 88 (07|47 01)}  //weight: 1, accuracy: Low
        $x_1_27 = {c1 e9 1a c1 e0 06 8a 89 ?? ?? ?? ?? [0-8] 88 0e}  //weight: 1, accuracy: Low
        $x_1_28 = {c1 e8 1a c1 e1 06 8a 80 ?? ?? ?? ?? [0-8] 89 0a}  //weight: 1, accuracy: Low
        $x_1_29 = {25 ff 00 00 00 83 c0 03 24 fc e8 04 00 8a 06 2c}  //weight: 1, accuracy: Low
        $x_1_30 = {88 4f 01 c1 e6 06 09 00 8a 88 ?? ?? ?? ?? 80 f1}  //weight: 1, accuracy: Low
        $x_1_31 = {68 00 14 2d 00 ff 74 24 ?? ff 54 24 ?? 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_32 = {8b c8 c1 e9 1a c1 e0 06 0b c8 03 cb}  //weight: 1, accuracy: High
        $x_1_33 = {80 7c 1f ff 3d 8d 04 1f 74 [0-32] 8d 04 76}  //weight: 1, accuracy: Low
        $x_1_34 = {80 78 fe 3d 75 [0-32] 8d 44 76 fe eb}  //weight: 1, accuracy: Low
        $x_1_35 = {68 00 14 2d 00 ff 74 24 40 ff 54 24 38}  //weight: 1, accuracy: High
        $x_1_36 = {68 00 14 2d 00 ff 75 ?? ff [0-4] 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_37 = {0f b6 c0 8a 84 05 ?? ?? ff ff 32 04 (19|39|31|11) 88 (03|07|06|02)}  //weight: 1, accuracy: Low
        $x_1_38 = {8d 4d d4 51 33 c9 51 51 51 6a 06 ff d0 8b 45 d4 83 f8 0a 0f 87 ?? ?? 00 00 0f 84 ?? ?? 00 00 48 83 f8 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Renos_JE_2147801373_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.JE"
        threat_id = "2147801373"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 ff ff af 16 68 ff ff c9 4e e8 ?? ?? ff ff 68 ff ff 87 29 68 ff ff 1b f2}  //weight: 1, accuracy: Low
        $x_1_2 = {03 00 42 00 49 00 4e 00 4d 5a 50 00 02}  //weight: 1, accuracy: High
        $x_2_3 = {03 00 42 00 49 00 4e 00 c2 d2 9c 7a 90 90 21 eb 83 a9 b1 b5 ad 38 e3 5d a8 4c b6 1f fb 3a 6a 63 ac 25 12 79 5e 44 ca aa 34 d6 35 24 d6 7f 8b 94 4b 88 25 08 c6 38 d4 72 65 33 dd de 1c 21 59 8f e3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_DJ_2147801424_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.DJ"
        threat_id = "2147801424"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/log3.php?tm=%d" ascii //weight: 10
        $x_10_2 = "OS:%d.%d, BLD:%d," ascii //weight: 10
        $x_10_3 = "BxLoader.Loader" ascii //weight: 10
        $x_10_4 = "'%APPID%' = s 'AxLoader'" ascii //weight: 10
        $x_1_5 = "scaner" wide //weight: 1
        $x_10_6 = "www.winifixer.com" ascii //weight: 10
        $x_10_7 = "ActiveLoader V" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_GF_2147801426_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.GF"
        threat_id = "2147801426"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 45 fc 0f be 08 81 f1 ?? ?? ?? ?? 88 4d f8 8b 55 0c 03 55 fc 8a 45 f8 88 02 0f be 4d f8 85 c9 75 02}  //weight: 10, accuracy: Low
        $x_1_2 = {3d 35 05 00 00 73 29 c7 45 f4 00 00 00 00 e8 ?? ?? ?? ?? 89 45 f4 81 7d f4 00 00 00 d0 77 0f 81 7d f4 00 00 00 80 72 06}  //weight: 1, accuracy: Low
        $x_1_3 = {86 f3 c7 45 fc 02 00 00 00 8b 85 ?? ?? ?? ?? cd 41}  //weight: 1, accuracy: Low
        $x_1_4 = {33 c0 50 0f 01 4c 24 fe 58 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_GQ_2147801427_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.GQ"
        threat_id = "2147801427"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "InternetConnectA" ascii //weight: 10
        $x_10_2 = "HttpSendRequestA" ascii //weight: 10
        $x_2_3 = "/ck.php" ascii //weight: 2
        $x_2_4 = "%s/r.php?&v=" ascii //weight: 2
        $x_1_5 = "Flash Video Object" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\%s" ascii //weight: 1
        $x_1_7 = {00 62 68 6f 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_PG_2147801471_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.PG"
        threat_id = "2147801471"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {68 00 80 00 00 6a 00 8b 45 c8 8b 40 20 50 8b 45 c8 ff 50 54 68 00 80 00 00 6a 00 8b 45 08 50 8b 45 c8 ff 50 54 8b 55 f8 8b 65 f4 8d 84 24 00 fc ff ff 6a 00 39 c4 75 fa 81 ec 00 fc ff ff 31 c0 ff e2}  //weight: 4, accuracy: High
        $x_2_2 = {6a 10 8b 45 c8 83 c0 0c 50 8b 45 cc 50 8b 45 c8 ff 50 58}  //weight: 2, accuracy: High
        $x_1_3 = "; rv:5.0) Gecko/20100101 Firefox/5.0" ascii //weight: 1
        $x_1_4 = {2e 69 6e 2f 3f 69 6e 69 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_PT_2147801504_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.PT"
        threat_id = "2147801504"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c0 81 c0 4d 5a 50 00}  //weight: 1, accuracy: High
        $x_1_2 = {b8 af ba ff ff f7 d0}  //weight: 1, accuracy: High
        $x_2_3 = {fb ff ff f7 ?? 83 ?? 04 c7 ?? 00 00 00 00 83 ?? 04 75 f2 ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_X_2147802474_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.X"
        threat_id = "2147802474"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "webspyshield.com" ascii //weight: 5
        $x_5_2 = "http://webspyshield.com/a/setup.exe" ascii //weight: 5
        $x_10_3 = "software\\microsoft\\windows\\currentversion\\internet settings" ascii //weight: 10
        $x_10_4 = "netsupp.dll" ascii //weight: 10
        $x_10_5 = "InternetReadFile" ascii //weight: 10
        $x_10_6 = {69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_10_7 = "%s&%X.%X.%X.%X.%X" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_DU_2147802633_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.DU"
        threat_id = "2147802633"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c7 45 fc 00 00 00 00 eb 09 8b ?? fc 83 ?? 01 89 ?? fc 8b ?? fc 3b ?? f8 7d 16 8b ?? 08 03 ?? fc 0f be ?? 83 ?? ?? 8b ?? ?? 03}  //weight: 4, accuracy: Low
        $x_1_2 = {ff f1 50 30 b5 98 cf 11 bb}  //weight: 1, accuracy: High
        $x_1_3 = "mfeed.php?txt=1&affiliate=" ascii //weight: 1
        $x_1_4 = "&ip_address=" ascii //weight: 1
        $x_1_5 = "&rid=0&st=typein&ref=" ascii //weight: 1
        $x_1_6 = "k.txt" ascii //weight: 1
        $x_1_7 = "/download.php" ascii //weight: 1
        $x_1_8 = "/buy.php" ascii //weight: 1
        $x_1_9 = {67 6f 6f 67 6c 65 2e 00}  //weight: 1, accuracy: High
        $x_1_10 = {2f 70 72 65 66 65 72 65 6e 63 65 73 [0-8] 2f 61 64 76 61 6e 63 65 64 5f 73 65 61 72 63 68 [0-8] 26 71 3d [0-5] 3f 71 3d}  //weight: 1, accuracy: Low
        $x_1_11 = {73 00 00 00 76 00 00 00 2e 65 00 00 78 00 00 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_PH_2147802634_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.PH"
        threat_id = "2147802634"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 06 10 00 00 56 ff 75 0c ff d7 8b 45 18 ff 75 10 66 c7 45 d0 02 00 89 45 d4 ff 15 ?? ?? ?? ?? 66 89 45 d2 8d 45 d0 6a 10 50 ff 75 0c ff 15 ?? ?? ?? ?? 83 f8 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 b8 60 ea 00 00 6a ff 50 50 8d 45 e4 6a 00 50 0f b7 85 6c ff ff ff 50 8d 45 c0 50 8d 45 b0 50 e8 ?? ?? ?? ?? 83 c4 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_OE_2147802635_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.OE"
        threat_id = "2147802635"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 11 80 e2 0f 32 c2 88 45 f1 33 c0 8a 45 f3 8b 55 fc 8a 04 02 24 f0 24 f0 8a 55 f1 02 c2 33 d2 8a 55 f3 8b 4d f4 88 04 11}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 c2 08 8b 55 ?? 8d 14 92 8b 4d ?? 3b 44 d1 10 73}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 50 30 8b 55 f4 89 42 ?? a1 ?? ?? ?? ?? 50 8b 45 c8 50 8b 45 f4 ff 50 30 8b 55 f4 89 42 3c}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b7 40 06 48 85 c0 0f 82 ?? ?? ?? ?? 40 89 45 ec c7 45 f0 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Renos_DZ_2147803142_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.DZ"
        threat_id = "2147803142"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 f1 b4 88 0c}  //weight: 1, accuracy: High
        $x_1_2 = {c6 00 0f c6 40 01 3f 88 58 02}  //weight: 1, accuracy: High
        $x_1_3 = {56 ff d3 6a 0d 56 8b f8}  //weight: 1, accuracy: High
        $x_1_4 = {68 e0 01 00 00 68 58 02 00 00 [0-16] 6a 0a}  //weight: 1, accuracy: Low
        $x_1_5 = {48 41 5f 25 30 38 78 00}  //weight: 1, accuracy: High
        $x_1_6 = {40 3d 00 01 00 00 ?? (f1|f4)}  //weight: 1, accuracy: Low
        $x_1_7 = {83 c6 07 83 ff 0a}  //weight: 1, accuracy: High
        $x_1_8 = {43 6f 67 6e 61 63 00}  //weight: 1, accuracy: High
        $x_1_9 = {6a 0c 50 68 00 14 2d 00 03 00 8d 45 (e0|e4)}  //weight: 1, accuracy: Low
        $x_1_10 = {83 c2 01 89 95 fc fe ff ff 81 bd fc fe ff ff 00 01 00 00 73 15}  //weight: 1, accuracy: High
        $x_1_11 = {88 04 3e 46 eb 03 00 83 f0}  //weight: 1, accuracy: Low
        $x_1_12 = {ff d0 61 ff 85 06 00 8b 85}  //weight: 1, accuracy: Low
        $x_1_13 = {ff 45 f4 8b 73 04 83 c3 04 89 07 83 c7 04 ff 45 fc 85 f6 75 ?? 83 45 f8 04 ff 45 fc 81 7d f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Renos_KJ_2147803145_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.KJ"
        threat_id = "2147803145"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 14 2d 00 03 05 06 01 ff 75 ?? ff 74 24 ?? 56 (ff 15 ?? ?? ?? ??|ff d0) 85 c0 (0f 84|74)}  //weight: 1, accuracy: Low
        $x_1_2 = {44 6c 6c 44 65 66 69 6e 65 00 44 6c 6c 52 65 67}  //weight: 1, accuracy: High
        $x_1_3 = {40 3d 00 01 00 00 ?? (f1|f4)}  //weight: 1, accuracy: Low
        $x_1_4 = {10 68 ff ff ?? ?? 68 ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_FQ_2147803148_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.FQ"
        threat_id = "2147803148"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b f8 8b f1 2b f9 8a 0e 80 f1 ?? 88 0c 37 74 ?? [0-3] 46 [0-3] 75}  //weight: 3, accuracy: Low
        $x_2_2 = {b9 0a 00 00 00 b8 68 58 4d 56 66 ba 58 56 ed 81 fb 68 58 4d 56 0f 94 c0 0f b6 c0}  //weight: 2, accuracy: High
        $x_2_3 = {33 c0 50 0f 01 4c 24 fe 58 c3}  //weight: 2, accuracy: High
        $x_2_4 = {81 fe 00 00 00 d0 (a3|a2) ?? ?? ?? 00 [0-6] 77 08 81 fe 00 00 00 80 73}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_AY_2147803149_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.AY"
        threat_id = "2147803149"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b f8 8b f1 2b f9 8a 0e 80 f1 ?? 88 0c 37 74 ?? [0-3] 46 [0-3] 75}  //weight: 2, accuracy: Low
        $x_2_2 = {b9 0a 00 00 00 b8 68 58 4d 56 66 ba 58 56 ed 81 fb 68 58 4d 56 0f 94 c0 0f b6 c0 89 85 8c fe ff ff eb}  //weight: 2, accuracy: High
        $x_2_3 = {6a 00 6a 03 68 00 00 00 80 8d 95 98 fe ff ff b9 ?? ?? ?? ?? e8 ?? ?? ?? 00 50 ff 15 ?? ?? ?? ?? 89 85 90 fe ff ff 83 f8 ff 75 03 cc eb}  //weight: 2, accuracy: Low
        $x_1_4 = "HA_%08x" ascii //weight: 1
        $x_1_5 = "\\*.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_HB_2147803248_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.HB"
        threat_id = "2147803248"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Critical System Warning! Your system is probably infected with a version of Spyware.IEPass.thief" wide //weight: 1
        $x_1_2 = "scanner.rapidantivirus.com" wide //weight: 1
        $x_1_3 = "Attn! Critical System Warning" wide //weight: 1
        $x_1_4 = "?advid=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Renos_GL_2147803310_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.GL"
        threat_id = "2147803310"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3b 45 f4 7d 19 8b 4d 08 03 4d f8 0f be 11 81 f2 ?? ?? 00 00 8b 45 fc 03 45 f8 88 10 eb d6}  //weight: 2, accuracy: Low
        $x_1_2 = "download.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_EI_2147803411_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.EI"
        threat_id = "2147803411"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 54 24 30 6a 0c 52 68 00 14 2d 00}  //weight: 3, accuracy: High
        $x_3_2 = {75 0c 43 81 c6 00 02 00 00 83 fb ?? 7c 9e}  //weight: 3, accuracy: Low
        $x_2_3 = {eb 0c 3c 2e 75 08 8a 44 24 ?? 84 c0 75 10 4e 85 f6 7f 8a}  //weight: 2, accuracy: Low
        $x_2_4 = "uid=%s&os=%s" ascii //weight: 2
        $x_2_5 = "id=%lu&adv=%lu&uid=%s" ascii //weight: 2
        $x_1_6 = "\\\\.\\PhysicalDrive%d" ascii //weight: 1
        $x_1_7 = {77 67 65 74 20 33 2e 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_IS_2147803421_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.IS"
        threat_id = "2147803421"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Warning your computer has virus !!" ascii //weight: 1
        $x_1_2 = "(window.self == window.top)" ascii //weight: 1
        $x_1_3 = "background-color:red" ascii //weight: 1
        $x_1_4 = {2e 64 6c 6c 00 49 6e 73 74 61 6c 6c 00 55 6e 69 6e 73 74 61 6c 6c 00 57 53 50 53 74 61 72 74 75 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_HS_2147803592_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.HS"
        threat_id = "2147803592"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 75 0c 8b 45 08 8a 04 02 8a 11 02 01 00 45 fe}  //weight: 1, accuracy: High
        $x_1_2 = {64 8b 1d 30 00 00 00 8a 43 02 0f b6 d8 89 (9d|5d)}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 c0 83 c0 03 24 fc e8 04 00 8a 06 (04|2c)}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 45 f4 8b 73 04 83 c3 04 89 07 83 c7 04 ff 45 fc 85 f6 75 ?? 83 45 f8 04 ff 45 fc 81 7d f8}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 0c 50 68 00 14 2d 00 04 00 [0-1] 8d (45|44 24)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Renos_FJ_2147803628_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.FJ"
        threat_id = "2147803628"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "Vsego URLov" ascii //weight: 3
        $x_3_2 = "/s/exx.php" ascii //weight: 3
        $x_3_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 3
        $x_1_4 = "clicker50Timer" ascii //weight: 1
        $x_1_5 = "Linkov boshe net GoTo wait" ascii //weight: 1
        $x_1_6 = "REMAKED!" ascii //weight: 1
        $x_1_7 = {4c 65 6e 67 74 68 00 00 00 01 00 00 6c 69 6e 6b 73 00 00 00 00 01 00 00 44 6f 63 75 6d 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {4c 69 6e 65 73 2e 53 74 72 69 6e 67 73 01 06 ?? 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_JO_2147803723_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.JO"
        threat_id = "2147803723"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 44 7e 01 eb [0-32] 8d 34 b5 04 00 00 00 6a 4c 56}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 75 0c 8b 45 08 [0-32] 8a 04 02 02 06 00 45 fe [0-32] 8a 0e 0f b6 45 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_PB_2147803737_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.PB"
        threat_id = "2147803737"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 74 10 ff 2b [0-8] a1 ?? ?? ?? ?? 8b 55 f8 8a 44 10 ff 8b 55 fc 8b 4d f4 88 04 0a ff 45 f4 81 7d f8 ?? ?? ?? ?? 0f 86 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {30 4c 10 ff [0-2] a1 ?? ?? ?? ?? 8b 55 f8 8a 44 10 ff 8b 55 fc 8b 4d f4 88 04 0a ff 45 f4 81 7d f8 ?? ?? ?? ?? 0f 86 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Renos_A_2147803769_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!A"
        threat_id = "2147803769"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "GET /trial.php?rest=%u&ver=%u&a=00000129 HTTP/1.0" ascii //weight: 5
        $x_5_2 = "GET /download.php?&advid=00000357&u=%u&p=%u HTTP/1.0" ascii //weight: 5
        $x_5_3 = "C:\\winstall.exe" ascii //weight: 5
        $x_5_4 = "C:\\Windows\\xpupdate.exe" ascii //weight: 5
        $x_3_5 = "C:\\Program Files\\BraveSentry\\BraveSentry.exe" ascii //weight: 3
        $x_5_6 = "Windows has detected spyware infection!" ascii //weight: 5
        $x_5_7 = "Windows Security Center has detected spyware/adware infection!" ascii //weight: 5
        $x_5_8 = "69.50.175.178" ascii //weight: 5
        $x_5_9 = "69.50.175.181" ascii //weight: 5
        $x_3_10 = "Host: hyyd" ascii //weight: 3
        $x_3_11 = "Host: download.bravesentry.com" ascii //weight: 3
        $x_2_12 = "Your computer is infected!" ascii //weight: 2
        $x_2_13 = "Your computer is in Danger!" ascii //weight: 2
        $x_1_14 = "Click here to protect your computer from spyware!" ascii //weight: 1
        $x_1_15 = "It is strongly recommended to use special antispyware tools to prevent data loss." ascii //weight: 1
        $x_1_16 = "Click here to install the latest protection tools!" ascii //weight: 1
        $x_1_17 = "Your c" ascii //weight: 1
        $x_1_18 = "ompute" ascii //weight: 1
        $x_1_19 = "r is infe" ascii //weight: 1
        $x_1_20 = "cted!" ascii //weight: 1
        $x_1_21 = "Windows has detec" ascii //weight: 1
        $x_1_22 = "ted spyw" ascii //weight: 1
        $x_1_23 = "are inf" ascii //weight: 1
        $x_1_24 = "ection!" ascii //weight: 1
        $x_1_25 = "It is recom" ascii //weight: 1
        $x_1_26 = "mende" ascii //weight: 1
        $x_1_27 = "d to use sp" ascii //weight: 1
        $x_1_28 = "ecial anti" ascii //weight: 1
        $x_1_29 = "spyware too" ascii //weight: 1
        $x_1_30 = "ls to prev" ascii //weight: 1
        $x_1_31 = "ent data l" ascii //weight: 1
        $x_1_32 = "oss. Wind" ascii //weight: 1
        $x_1_33 = "ows will now" ascii //weight: 1
        $x_1_34 = " download an" ascii //weight: 1
        $x_1_35 = "d install t" ascii //weight: 1
        $x_1_36 = "he most up-t" ascii //weight: 1
        $x_1_37 = "o-date anti" ascii //weight: 1
        $x_1_38 = "are for" ascii //weight: 1
        $x_1_39 = "Click h" ascii //weight: 1
        $x_1_40 = "ere to protect yo" ascii //weight: 1
        $x_1_41 = "ur comput" ascii //weight: 1
        $x_1_42 = "er from spyw" ascii //weight: 1
        $x_1_43 = "Sheri" ascii //weight: 1
        $x_1_44 = "eriff" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((20 of ($x_1_*))) or
            ((1 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_3_*) and 17 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_3_*) and 14 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_3_*) and 11 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 15 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_B_2147803788_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!B"
        threat_id = "2147803788"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "System Alert!" ascii //weight: 3
        $x_3_2 = "qVL]JV]Lj]Y\\~QT]" ascii //weight: 3
        $x_2_3 = "SpyLocked" ascii //weight: 2
        $x_3_4 = "http://www.spylocked.com/?" ascii //weight: 3
        $x_3_5 = "http://keratomir.biz/get.php?partner=" ascii //weight: 3
        $x_2_6 = "DisplayIcon" ascii //weight: 2
        $x_2_7 = "InternetOpenA" ascii //weight: 2
        $x_2_8 = "InternetOpenUrl" ascii //weight: 2
        $x_3_9 = "System has detected a number of active spyware applications that may impact the performance of your computer." ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_BAG_2147803814_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.BAG"
        threat_id = "2147803814"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Your computer is infected! It is recommended to start spyware cleaner tool." ascii //weight: 10
        $x_10_2 = "Warning! Security report" ascii //weight: 10
        $x_10_3 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_4 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_5 = "InternetOpenUrlA" ascii //weight: 10
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop" ascii //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" ascii //weight: 1
        $x_1_9 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii //weight: 1
        $x_1_10 = "http://downloadfilesldr.com/index5.php?adv=141" ascii //weight: 1
        $x_1_11 = "http://downloadfilesldr.com/index4.php?adv=141" ascii //weight: 1
        $x_1_12 = "http://downloadfilesldr.com/index3.php?adv=141" ascii //weight: 1
        $x_1_13 = "http://downloadfilesldr.com/index2.php?adv=141" ascii //weight: 1
        $x_1_14 = "http://downloadfilesldr.com/allfile.jpg" ascii //weight: 1
        $x_1_15 = "http://spywaresoftstop.com/load.php?adv=141" ascii //weight: 1
        $x_1_16 = "http://spywaresoftstop.com/wfdfdghfdghj.htm" ascii //weight: 1
        $x_1_17 = "http://spywaresoftstop.com/download/141/setup.exe" ascii //weight: 1
        $x_1_18 = "C:\\Program Files\\SpywareSoftStop\\SpywareSoftStop.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_AU_2147803841_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.AU"
        threat_id = "2147803841"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Micr%sntVer%s" ascii //weight: 2
        $x_2_2 = {69 53 53 44 5f 43 4d 00}  //weight: 2, accuracy: High
        $x_1_3 = {26 76 65 72 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 64 76 69 00}  //weight: 1, accuracy: High
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_3_6 = {81 fe 78 21 00 00 7e 0a c6 84 34 ?? ?? ff ff 68 eb 05 c6 44 34 08 63 ff d7 81 fe 97 23 00 00 7d 03 46 eb dc}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_D_2147803843_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!D"
        threat_id = "2147803843"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 6c 33 32 83 10 00 [0-5] 6b 65 72 6e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-8] 54 ff 15 ?? ?? ?? ?? 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_F_2147803845_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!F"
        threat_id = "2147803845"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Are you sure you want to uninstall Windows Safety Alert from your computer?" ascii //weight: 1
        $x_1_2 = "Please wait while Windows Safety Alert is being uninstalled. Close all applications." ascii //weight: 1
        $x_1_3 = "This program install on your system antispayware software." ascii //weight: 1
        $x_1_4 = "carolus" ascii //weight: 1
        $x_1_5 = "/c del %s >> NULL" ascii //weight: 1
        $x_1_6 = "xyxuic.dll" ascii //weight: 1
        $x_1_7 = "pkgvyg.dll" ascii //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Windows Safety Alert" ascii //weight: 1
        $x_1_9 = "rundll32.exe %s,windows" ascii //weight: 1
        $x_1_10 = "SYSRES" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Renos_HL_2147803852_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.HL"
        threat_id = "2147803852"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 24 c7 34 45 38 44 39 45 42 46 32 32 43 2d [0-5] 34 32 42 44 2d 41 38 43 42 2d 37 45 35 39 43 [0-2] 43 30 38 42 41 2f 23}  //weight: 1, accuracy: Low
        $x_1_2 = {41 6c 77 61 79 73 [0-2] 75 64 79 [0-16] 72 52 34 [0-2] 6e 65 72 [0-48] 4c 54 45 52 4e ce 55 52 4c}  //weight: 1, accuracy: Low
        $x_1_3 = {74 70 3a 2f 2f 64 6c 2e 25 73 2f 67 65 74 2f 3f 70 69 6e 3d 0b 26 4b 1e 12 ee 6c 6e 64}  //weight: 1, accuracy: High
        $x_1_4 = "/scan." ascii //weight: 1
        $x_1_5 = "PARTNERID" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_HL_2147803852_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.HL"
        threat_id = "2147803852"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DL_DOMAIN" ascii //weight: 1
        $x_1_2 = "SCAN_IMG" ascii //weight: 1
        $x_1_3 = "ER_STAT_DOMAIN2" ascii //weight: 1
        $x_1_4 = "PRESALE_REQUEST_DOMAIN" ascii //weight: 1
        $x_1_5 = "PARTNERID" ascii //weight: 1
        $x_1_6 = "<PROGRAMFILES>\\" ascii //weight: 1
        $x_1_7 = "\\Drivers\\Video\\Options\\" ascii //weight: 1
        $x_1_8 = "4E8D9EBF-122C-42BD-A8CB-7E59C9CC08BA" ascii //weight: 1
        $x_1_9 = {5f 61 64 64 6f 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_10 = {79 20 66 6f 72 20 72 75 6e 00}  //weight: 1, accuracy: High
        $x_1_11 = "func=installrun&id=%s&landing=%s" ascii //weight: 1
        $x_1_12 = "&lang=%s&sub=%s&notstat=1" ascii //weight: 1
        $x_1_13 = "func=reserveddomains" ascii //weight: 1
        $x_1_14 = {68 74 74 70 3a 2f 2f 64 6c 2e 25 73 2f 67 65 74 2f 3f 70 69 6e 3d 25 73 26 6c 6e 64 3d 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule TrojanDownloader_Win32_Renos_J_2147803857_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!J"
        threat_id = "2147803857"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "63"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ShellExecuteA" ascii //weight: 10
        $x_10_2 = "SeShutdownPrivilege" ascii //weight: 10
        $x_10_3 = "WinExec" ascii //weight: 10
        $x_10_4 = "Windows Safety Alert" ascii //weight: 10
        $x_10_5 = "ShellServiceObjectDelayLoad" ascii //weight: 10
        $x_10_6 = "rundll32.exe %s,windows" ascii //weight: 10
        $x_1_7 = "This program install on your system antivirus software." ascii //weight: 1
        $x_1_8 = "You need to reboot your computer to finalize uninstallation. Reboot now?" ascii //weight: 1
        $x_1_9 = "Please wait while Safety Alerter 2006 is being uninstalled. Close all applications." ascii //weight: 1
        $x_1_10 = "Are you sure you want to uninstall Windows Safety Alert from your computer?" ascii //weight: 1
        $x_1_11 = "You need to reboot your computer prior to uninstallation. Reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_K_2147803859_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!K"
        threat_id = "2147803859"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "StartServiceA" ascii //weight: 10
        $x_10_2 = "CreateProcessA" ascii //weight: 10
        $x_10_3 = "AccessibleObjectFromWindow" ascii //weight: 10
        $x_10_4 = "InternetOpenA" ascii //weight: 10
        $x_1_5 = "winavxx.exe" ascii //weight: 1
        $x_1_6 = "{ABCDECF0-4B15-11D1-ABED-709549C10000}" ascii //weight: 1
        $x_1_7 = "IEHlprObj.IEHlprObj" ascii //weight: 1
        $x_1_8 = "'Browser Helper Objects'" ascii //weight: 1
        $x_1_9 = "regsvr32 /s vtr.dll" ascii //weight: 1
        $x_1_10 = "systems.txt" ascii //weight: 1
        $x_1_11 = "IEHelper.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_KJ_2147803863_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!KJ"
        threat_id = "2147803863"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Microsoft\\Active Setup\\Installed Components" wide //weight: 10
        $x_10_2 = "{Y479C6D0-OTRW-U5GH-S1EE-E0AC10B4E666}" wide //weight: 10
        $x_10_3 = "{F146C9B1-VMVQ-A9RC-NUFL-D0BA00B4E999}" wide //weight: 10
        $x_10_4 = "main.bin" wide //weight: 10
        $x_10_5 = "VirusDataBaseParser" ascii //weight: 10
        $x_10_6 = "clsSockInet" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_AA_2147803864_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!AA"
        threat_id = "2147803864"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "@*\\AD:\\Master\\ADWARA_NEW\\codec\\Codec.vbp" wide //weight: 2
        $x_1_2 = "Codec.exe" wide //weight: 1
        $x_1_3 = "DxCodec" ascii //weight: 1
        $x_1_4 = "LICENSE AGREEMENT" ascii //weight: 1
        $x_1_5 = "link:http://dxcodec.com/uninstall/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_FZ_2147803883_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.FZ"
        threat_id = "2147803883"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 51 10 33 c0 89 02 89 42 04 c7 01 01 23 45 67 c7 41 04 89 ab cd ef c7 41 08 fe dc ba 98 c7 41 0c 76 54 32 10}  //weight: 1, accuracy: High
        $x_1_2 = {3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2d 62 61 73 65 2e 63 6f 6d 2f [0-16] 2f [0-16] 2e 70 68 70 3f 64 61 74 61 3d}  //weight: 1, accuracy: Low
        $x_1_3 = "SnmpUtilOidCpy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_IT_2147803902_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.IT"
        threat_id = "2147803902"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 02 66 2b c0 c1 c2 19 b9 08 ef bf ff f7 d1 e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b 39 c1 f2 15 66 83 c1 33 83 c0 01 c1 c6 09 8b 08 f7 d2 29 f9 75 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_IT_2147803902_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.IT"
        threat_id = "2147803902"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 04 3e 46 eb 05 00 35 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 ff ff 0d ba ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_U_2147803919_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!U"
        threat_id = "2147803919"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "70"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "Virus Attack!!! The your system on computer is damaged." ascii //weight: 50
        $x_5_2 = {75 8b ec 81 c4 00 fe ff ff 71 76 77 68 ff 00 00 00 8d ?? 01 ff ff ff ?? e8 ?? ?? ?? ?? 8d 85 02 fe ff ff 70 6a 00 68 ?? ?? ?? ?? 8d 85 01 ff ff ff 70 e8 ?? ?? ?? ?? 8d 85 02 fe ff ff 70 e8 ?? ?? ?? ?? 8d 85 02 fe ff ff 70 ff 15 ?? ?? ?? ?? 83 c4 04 b9 03 00 00 00 2b c1 8d bd 02 fe ff ff}  //weight: 5, accuracy: Low
        $x_5_3 = {8b ec 83 c4 f8 6a 01 6a 00 ff 75 08 8d 05 [0-4] 70 8d 05 [0-4] 70 6a 00 ff 15 [0-4] b8 01 00 00 00 c9}  //weight: 5, accuracy: Low
        $x_5_4 = {75 8b ec 81 c4 18 fe ff ff [0-3] e8 ?? ?? ?? ?? 83 f8 00 0f 85 ?? 00 00 00}  //weight: 5, accuracy: Low
        $x_5_5 = {6a 06 6a 00 6a 00 6a 00 6a 00 6a ff ff 75 08 e8}  //weight: 5, accuracy: High
        $x_5_6 = {75 1e 6a 64 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 01 00 00 00 eb 1c 6a 66 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 68 ?? ?? ?? ?? 6a 01 e8 ?? ?? ?? ?? c9 c2 10 00}  //weight: 5, accuracy: Low
        $x_1_7 = "Shell_NotifyIconA" ascii //weight: 1
        $x_1_8 = {61 6c 6c 65 72 74 00}  //weight: 1, accuracy: High
        $x_1_9 = "explorer.exe" ascii //weight: 1
        $x_1_10 = "software\\microsoft\\windows\\currentversion\\uninstall" ascii //weight: 1
        $x_1_11 = "shellexecutea" ascii //weight: 1
        $x_1_12 = "qvl]jv]lj]y\\~qt]" ascii //weight: 1
        $x_1_13 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_50_*) and 4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_T_2147803920_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!T"
        threat_id = "2147803920"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "425"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "You need to reboot your computer to finalize uninstallation." ascii //weight: 100
        $x_100_2 = "You need to reboot your computer prior to uninstallation." ascii //weight: 100
        $x_100_3 = " Reboot now?" ascii //weight: 100
        $x_100_4 = "This program install on your system antivirus software." ascii //weight: 100
        $x_100_5 = "Are you sure you want to uninstall Safety Alerter" ascii //weight: 100
        $x_100_6 = "from your computer?" ascii //weight: 100
        $x_100_7 = "Download new version software for the virus protection." ascii //weight: 100
        $x_10_8 = "shellexecutea" ascii //weight: 10
        $x_10_9 = "rundll32.exe %s,windows" ascii //weight: 10
        $x_10_10 = "Windows Safety Alert" ascii //weight: 10
        $x_10_11 = "winexec" ascii //weight: 10
        $x_10_12 = "SeShutdownPrivilege" ascii //weight: 10
        $x_1_13 = "disenfranchising" ascii //weight: 1
        $x_1_14 = "{e2b8cea1-c8a7-48e2-b2fd-89ae5c608fb8}" ascii //weight: 1
        $x_1_15 = "software\\microsoft\\windows\\currentversion\\explorer\\sharedtaskscheduler" ascii //weight: 1
        $x_1_16 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii //weight: 1
        $x_1_17 = "SoftwareMicrosoftWindowsCurrentVersionShellServiceObjectDelayLoad" ascii //weight: 1
        $x_1_18 = "%s /del" ascii //weight: 1
        $x_1_19 = "/c del %s   >>   NULL" ascii //weight: 1
        $x_1_20 = "sysres" ascii //weight: 1
        $x_1_21 = "UninstallString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 2 of ($x_10_*) and 5 of ($x_1_*))) or
            ((4 of ($x_100_*) and 3 of ($x_10_*))) or
            ((5 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_CI_2147803930_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.CI"
        threat_id = "2147803930"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "C:\\Program Files\\OnlineGuard\\OnlineGuard.exe" ascii //weight: 10
        $x_10_2 = "Host: download.Online-Guard.net" ascii //weight: 10
        $x_1_3 = {47 45 54 20 2f 6d 68 61 62 68 66 64 62 2e 70 68 70 3f 26 61 64 76 69 64 3d 30 30 30 30 ?? ?? ?? ?? 26 75 3d 30 26 70 3d 31 32 33 37 30 32 30 26 6c 61 6e 67 3d 5f 5f 5f 5f 5f 5f 5f 5f 26 76 73 3d 30 26 59 5a 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 20 48 54 54 50 2f 31 2e 30}  //weight: 1, accuracy: Low
        $x_1_4 = {47 45 54 20 2f 6d 68 61 62 68 66 64 62 2e 70 68 70 3f 26 61 64 76 69 64 3d 30 30 30 30 ?? ?? ?? ?? 26 75 3d 25 75 26 70 3d 25 75 26 6c 61 6e 67 3d 5f 5f 5f 5f 5f 5f 5f 5f 26 76 73 3d 25 75 26 25 73 20 48 54 54 50 2f 31 2e 30}  //weight: 1, accuracy: Low
        $x_1_5 = {47 45 54 20 68 74 74 70 3a 2f 2f 25 73 2f 70 6f 69 65 68 72 67 62 2e 70 68 70 3f 26 61 64 76 69 64 3d 30 30 30 30 ?? ?? ?? ?? 26 75 3d 25 75 26 70 3d 25 75 26 6c 61 6e 67 3d 5f 5f 5f 5f 5f 5f 5f 5f 26 76 73 3d 25 75 26 25 73 20 48 54 54 50 2f 31 2e 30}  //weight: 1, accuracy: Low
        $x_1_6 = "Windows update loader" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_8 = "NoHTMLWallPaper" ascii //weight: 1
        $x_1_9 = "NoChangingWallpaper" ascii //weight: 1
        $x_1_10 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop" ascii //weight: 1
        $x_1_11 = "NoDesktop" ascii //weight: 1
        $x_1_12 = "ClassicShell" ascii //weight: 1
        $x_1_13 = "NoActiveDesktop" ascii //weight: 1
        $x_1_14 = "ForceActiveDesktopOn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_CR_2147803941_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.CR"
        threat_id = "2147803941"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/newuser.php?saff=" wide //weight: 2
        $x_2_2 = "TOP RATED SPYWARE REMOVERS" wide //weight: 2
        $x_2_3 = "Somebody's trying to infect your PC" ascii //weight: 2
        $x_2_4 = "spyware!#CR#Help" ascii //weight: 2
        $x_2_5 = "\\bb_soft\\" wide //weight: 2
        $x_1_6 = "/?aid=" wide //weight: 1
        $x_1_7 = {66 72 6d 4e 4f 44 00}  //weight: 1, accuracy: High
        $x_1_8 = {66 72 6d 57 53 43 00}  //weight: 1, accuracy: High
        $x_1_9 = "\\winfrun32.bin" wide //weight: 1
        $x_1_10 = "DisableTaskMgr" wide //weight: 1
        $x_1_11 = "#portal_url" wide //weight: 1
        $x_1_12 = "about:security" wide //weight: 1
        $x_1_13 = "@_soft\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_CO_2147803946_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.CO"
        threat_id = "2147803946"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 41 6a 02 6a fc ff 75 fc ff 15 ?? ?? ?? 10 83 c4 0c ff 75 fc 6a 01 6a 04 8d 45 f8 50 ff 15 ?? ?? ?? 10 83 c4 10 e8 ?? ?? ff ff 3b 45 f8 75 07 c7 45 f4 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 02 00 00 80 e8 ?? ?? 00 00 03 45 0c 83 c0 02 83 e8 02 80 3e 00 90 90 74 08 90 90 90 30 06 46 eb f1 68}  //weight: 1, accuracy: Low
        $x_1_3 = {61 61 62 00 61 61 6c 00 61 6c 6c 65 72 74 32 00 66 67 6c 6c 65 72 74 00 71 6f 61 64 00 77 69 6e 64 6f 77 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Renos_CO_2147803946_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.CO"
        threat_id = "2147803946"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 08 80 3e 00 74 05 30 06 46 eb f6 c9 c2 08 00}  //weight: 1, accuracy: High
        $x_2_2 = {8b 75 08 90 90 80 3e 00 90 90 74 05 30 06 46 eb f2 c9 c2 08 00}  //weight: 2, accuracy: High
        $x_2_3 = {8b 75 08 90 90 90 90 90 80 3e 00 90 90 74 05 30 06 46 eb f2}  //weight: 2, accuracy: High
        $x_1_4 = {83 f8 02 75 05 03 45 0c eb 24 83 f8 03 75 0a 33 c0 8b 45 0c 83 c0 02 eb 15}  //weight: 1, accuracy: High
        $x_1_5 = {83 f8 02 75 05 03 45 0c eb 15 83 f8 04 75 10 33 c0 8b 45 0c 83 c0 02 eb 06}  //weight: 1, accuracy: High
        $x_1_6 = {83 f8 02 75 08 90 90 90 03 45 0c eb 24 83 f8 03}  //weight: 1, accuracy: High
        $x_2_7 = {03 45 0c eb 2c 83 f8 03 75 0a 33 c0 8b 45 0c 83 c0 02 eb 1d 09 00 [0-3] 83 f8 02 75}  //weight: 2, accuracy: Low
        $x_1_8 = {88 04 3a 80 34 3a ?? 80 2c 3a ?? 42 e2 ?? 68 04 01 00 00}  //weight: 1, accuracy: Low
        $x_2_9 = {88 04 3a 90 90 80 34 3a 2f 80 2c 3a 0a}  //weight: 2, accuracy: High
        $x_2_10 = {80 34 3a 2f 90 90 80 2c 3a 0a}  //weight: 2, accuracy: High
        $x_1_11 = {83 c0 02 83 e8 02 80 3e 00 74 05 30 06 46 eb f6}  //weight: 1, accuracy: High
        $x_1_12 = {eb 1c 6a 66 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? c7 05}  //weight: 1, accuracy: Low
        $x_1_13 = {61 61 62 00 61 61 6c 00 61 6c 6c 65 72 74 32 00 66 67 6c 6c 65 72 74 00 71 6f 61 64 00 77 69 6e 64 6f 77 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_AY_2147803947_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!AY"
        threat_id = "2147803947"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d f8 34 7d 22 8b 55 f8 52 68 ?? ?? ?? ?? e8 ?? ?? ff ff 83 c4 08 8b 45 fc 50 ff 15 ?? ?? ?? ?? 32 c0 e9 ?? ?? 00 00 8b 4d f8 51 68 ?? ?? ?? ?? e8 ?? ?? ff ff 83 c4 08 83 7d fc ff 0f 84 ?? ?? 00 00 6a 00 6a 00 6a 0b}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 45 e8 c1 f8 08 88 45 e6 0f b7 4d e8 81 e1 ff 00 00 00 88 4d e7 0f b6 55 e7 52 0f b6 45 e6 50 68 ?? ?? ?? ?? e8 ?? ?? ff ff 83 c4 0c 0f b6 4d e6 85 c9 0f 84 ?? ?? 00 00 6a 00 8b 55 fc 52 ff 15 ?? ?? ?? ?? 0f b7 4d f0 2b c1 83 e8 02 8b 55 10 89 02}  //weight: 1, accuracy: Low
        $x_1_3 = {73 1c 8b 45 d8 0f b6 08 0f b6 55 e7 33 ca 8b 45 d8 88 08 8b 4d d8 83 c1 01 89 4d d8 eb d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Renos_BAM_2147803948_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.BAM"
        threat_id = "2147803948"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 61 64 43 72 79 70 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {4b 4f 4c 48 54 54 50 44 6f 77 6e 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {54 6c 48 65 6c 70 33 32 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 50 47 55 6e 5a 49 50 00}  //weight: 1, accuracy: High
        $x_1_5 = {4d 79 41 55 74 69 6c 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {41 64 77 61 72 65 55 74 69 6c 73 00}  //weight: 1, accuracy: High
        $x_3_7 = {a1 b8 92 71 8c ef 11 de e1 78 17 73 cb 15 80 a8 67 52 60 a7 65 71 97 2a}  //weight: 3, accuracy: High
        $x_3_8 = {f3 50 d2 b7 eb 7c 0a eb c3 66 3d f6 50 80 62 85 78 d6 20 e1 0d c1 19 79 16 20 b6 16 8e ef 6d dc}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_BAM_2147803948_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.BAM"
        threat_id = "2147803948"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ws\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "&affid=" ascii //weight: 1
        $x_1_3 = "install/ws.zip" wide //weight: 1
        $x_1_4 = "winwebsecurity.com" ascii //weight: 1
        $x_1_5 = "2. Checking for the latest components..." wide //weight: 1
        $x_1_6 = "3. Downloading the latest components..." wide //weight: 1
        $x_1_7 = {41 00 44 00 5f 00 49 00 4c 00 06 00 43 00 4f 00 4e 00 46 00 49 00 47 00}  //weight: 1, accuracy: High
        $x_2_8 = "anti viruses chech!" ascii //weight: 2
        $x_2_9 = {81 3e 50 4b 01 02 74 0a b8 f6 ff ff ff e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_IL_2147803950_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.IL"
        threat_id = "2147803950"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "/scan/download.php?type=%s&said=%s&ver=%s" ascii //weight: 2
        $x_2_2 = "/pbpro/stats/cnt.php?type=%s&said=%s&ver=%s" ascii //weight: 2
        $x_2_3 = "WizardExtention" ascii //weight: 2
        $x_1_4 = "atiwizard.exe" ascii //weight: 1
        $x_1_5 = "iewizard.dll" ascii //weight: 1
        $x_1_6 = "Mozilla 4.0 (StatBot)" ascii //weight: 1
        $x_1_7 = "l_install" ascii //weight: 1
        $x_2_8 = {ff d0 8b 10 6a 01 8b c8 8b 02 55 ff d0}  //weight: 2, accuracy: High
        $x_2_9 = {6a 04 52 56 ff 15 ?? ?? ?? ?? 56 ff d3 8b 44 24 1c 50 ff d3 8d 45 f0 c6 44 24 38 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_Z_2147803956_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!Z"
        threat_id = "2147803956"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3003"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = "Your computer might be at risk" ascii //weight: 1000
        $x_1_2 = {53 70 79 77 61 72 65 [0-255] 44 65 74 65 63 74 65 64}  //weight: 1, accuracy: Low
        $x_1_3 = {56 69 72 75 73 [0-255] 44 65 74 65 63 74 65 64}  //weight: 1, accuracy: Low
        $x_1000_4 = "Click this balloon to fix this problem" ascii //weight: 1000
        $x_1000_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1000
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
        $x_1_7 = "WinExec" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_9 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1000_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_BAI_2147803957_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.BAI"
        threat_id = "2147803957"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {ba 7f 96 98 00 eb 0a 46 56 83 c6 10 58 48 8b f0 4a 0b d2 75 f2 1a 00 55 8b ec 83 c4 ?? 80 3d ?? ?? 00 10 00 0f 85 3a 01 00 00 c6 05 ?? ?? 00 10 01}  //weight: 6, accuracy: Low
        $x_4_2 = {81 c4 18 fe ff ff 90 90 90 83 3d ?? ?? 00 10 48 75 11 e8 ?? ?? ff ff c7 05 ?? ?? 00 10 00 00 00 00 eb 06}  //weight: 4, accuracy: Low
        $x_1_3 = "militaryass.com/" ascii //weight: 1
        $x_1_4 = "T h e computer has been crushed!!" ascii //weight: 1
        $x_1_5 = {25 73 3f 70 61 72 74 6e 65 72 3d 25 73 07 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_6 = {25 73 2f 73 79 6e 63 2e 70 68 70 07 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_5_7 = {68 7f 96 98 00 58 eb 0a 46 56 83 c6 10 5a 4a 8b f0 48 0b d2 75 f2 6a 38 68 ?? ?? 40 00 e8 ?? fe ff ff 6a 39 68 ?? ?? 40 00 e8 ?? fe ff ff}  //weight: 5, accuracy: Low
        $x_2_8 = "install GigaAntiVirus" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_BAK_2147803958_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.BAK"
        threat_id = "2147803958"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2002"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = {53 70 79 47 75 61 72 64 50 72 6f [0-16] 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}  //weight: 1000, accuracy: Low
        $x_1000_2 = "Settings\\User Agent\\Post Platform" ascii //weight: 1000
        $x_1_3 = "Windows Security Center has detected a Spyware infection!" ascii //weight: 1
        $x_1_4 = "Install anti-spyware to prevent data loss!" ascii //weight: 1
        $x_1_5 = "Click here to install latest antispyware tool." ascii //weight: 1
        $x_1_6 = "AD031" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1000_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_BAO_2147803959_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.BAO"
        threat_id = "2147803959"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 6c 75 73 2d 61 6e 74 69 76 69 72 75 73 2e 63 6f 6d 2f 08 0a 0f 0b 19 11 1c 19 14 74 65 72 6d 73 2e 68 74 6d 6c 63 62 2f 69 6e 73 74 61 6c 6c 73 2e 70 68 70 63 62 2f 72 65 61 6c 2e 70 68 70 69 6e 73 74 61 6c 6c 2f 41 6e 74 69 76 69 72 75 73 50 6c 75 73 2e 65 78 65 69 6e 73 74 61 6c 6c 2f 61 76 70 68 6c 2e 64 6c 6c 69 6e 73 74 61 6c 6c 2f 49 6e 74 65 72 6e 65 74 45 78 70 6c 6f 72 65 72 2e 64 6c 6c 69 6e 73 74 61 6c 6c 2f 41 6e 74 69 76 69 72 75 73 50 6c 75 73 2e 67 72 6e 69 6e 73 74 61 6c 6c 2f 61 64 64 2f 66 69 6c 65 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_4_2 = "\\Antivirus Plus\\Antivirus" ascii //weight: 4
        $x_4_3 = "Internet Explorer\\Quick Launch\\Antivirus Plus" ascii //weight: 4
        $x_1_4 = {5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3a 2a 3a 45 6e 61 62 6c 65 64 3a 69 6e 73 74 61 6c 6c 65 72}  //weight: 1, accuracy: Low
        $x_1_5 = "Please, check your Internet connection!" ascii //weight: 1
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
        $x_1_7 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_AZ_2147803966_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!AZ"
        threat_id = "2147803966"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%d.%d.%ls.chr.santa-inbox.com" ascii //weight: 2
        $x_1_2 = "Bluescreen Screen Saver" wide //weight: 1
        $x_1_3 = "gofuckyourself.com" ascii //weight: 1
        $x_1_4 = "tibsystems." ascii //weight: 1
        $x_1_5 = "%s/images/%d/%s/%s.gif" wide //weight: 1
        $x_1_6 = ".php?id=%" wide //weight: 1
        $x_1_7 = "avxp08.net" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_EJ_2147803967_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.EJ"
        threat_id = "2147803967"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 1e 2b ca 80 f3 ?? 66 89 0d ?? ?? ?? ?? 66 49 66 89 0d ?? ?? ?? ?? 88 1c 37}  //weight: 4, accuracy: Low
        $x_2_2 = {0f 95 c0 a2 ?? ?? ?? 00 33 c0 66 39 1d ?? ?? ?? 00 0f 95 c0 a2 ?? ?? ?? 00 eb 17 cc eb}  //weight: 2, accuracy: Low
        $x_2_3 = {33 c0 50 0f 01 4c 24 fe 58 c3}  //weight: 2, accuracy: High
        $x_4_4 = {80 0d d8 bb 40 00 ff 3d 00 00 00 d0 77 07 3d 00 00 00 80 73 06 ff d6 2b c5 eb dc}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_EN_2147803968_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.EN"
        threat_id = "2147803968"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b f0 2b f2 8d 9b 00 00 00 00 8a 0a 80 f1 ?? 88 0c 16 74 08 8a 4a 01 42 84 c9 75 ee}  //weight: 3, accuracy: Low
        $x_2_2 = {75 1a 83 c3 07 83 ee 07 83 c7 07 83 fb 46 72 c2}  //weight: 2, accuracy: High
        $x_2_3 = {33 c0 50 0f 01 4c 24 fe 58 c3}  //weight: 2, accuracy: High
        $x_1_4 = {c7 46 0c 76 54 32 10}  //weight: 1, accuracy: High
        $x_1_5 = {c7 06 01 23 45 67 0f bf ?? ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_FG_2147803969_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.FG"
        threat_id = "2147803969"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 68 58 4d 56 66 ba 58 56 ed 81 fb 68 58 4d 56 0f 94 c0 0f b6 c0}  //weight: 1, accuracy: High
        $x_1_2 = {b8 4f 00 00 00 cd 41 66 3d 86 f3 0f 94 c0 0f b6 c0}  //weight: 1, accuracy: High
        $x_1_3 = {33 c0 50 0f 01 4c 24 fe 58 c3}  //weight: 1, accuracy: High
        $x_2_4 = {6a 0c 8d 45 d8 50 68 00 14 2d 00 ff 75 e8 ff 15 ?? ?? 40 00}  //weight: 2, accuracy: Low
        $x_2_5 = {83 c7 07 83 c6 07 83 ff 46 (72|0f 82) 12 00 [0-3] 83 c4 18 85 c0 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_FL_2147803970_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.FL"
        threat_id = "2147803970"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 58 4d 56 c7 85 ?? ?? ff ff 58 56 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 4f 00 00 00 cd 41 66 3d 86 f3 0f 94 c0}  //weight: 1, accuracy: High
        $x_1_3 = {33 c0 50 0f 01 4c 24 fe 58 c3}  //weight: 1, accuracy: High
        $x_1_4 = {77 0a 81 7c 24 ?? 00 00 00 80 73}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 00 00 00 d0 [0-10] 77 07 3d 00 00 00 80 73 06}  //weight: 1, accuracy: Low
        $x_2_6 = {6a 0c 50 68 00 14 2d 00 ff 75 ?? ff 15 ?? ?? 40 00}  //weight: 2, accuracy: Low
        $x_2_7 = {85 c0 75 57 83 c6 07 81 fe ?? ?? 40 00 0f ?? ?? ff ff ff}  //weight: 2, accuracy: Low
        $x_2_8 = {8a 8c 05 d0 fd ff ff 81 f1 ?? ?? ?? ?? 88 0c 30 40 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_FS_2147803971_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.FS"
        threat_id = "2147803971"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 09 8b 45 ?? 83 c0 01 89 45 ?? 8b 4d ?? 3b 4d ?? 7d 18 8b 55 ?? 03 55 ?? 0f be 02 35 ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 88 01 eb d7}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 09 8a 55 9c 80 c2 01 88 55 9c 68 ?? ?? 01 10 e8 ?? ?? 00 00 83 c4 04 89 45 fc}  //weight: 1, accuracy: Low
        $x_1_3 = {72 62 00 00 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Renos_HP_2147803972_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.HP"
        threat_id = "2147803972"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "T h e computer has been crushed!!" ascii //weight: 1
        $x_1_2 = {25 73 3f 70 61 72 74 6e 65 72 3d 25 73 07 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {25 73 2f 73 79 6e 63 2e 70 68 70 07 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_2_4 = {61 61 62 00 61 61 6c 00 61 6c 6c 65 72 74 32 00 66 67 6c 6c 65 72 74 00 71 6f 61 64 00 77 69 6e 64 6f 77 73 00}  //weight: 2, accuracy: High
        $x_1_5 = "blowjob." ascii //weight: 1
        $x_3_6 = {ba 7f 96 98 00 eb 0a 46 56 83 c6 10 58 48 8b f0 4a 0b d2 75 f2 14 00 80 3d ?? ?? 00 10 00 0f ?? ?? 01 00 00 c6 05 ?? ?? 00 10 01}  //weight: 3, accuracy: Low
        $x_2_7 = {68 7f 96 98 00 58 eb 0a 46 56 83 c6 10 5a 4a 8b f0 48 0b d2 75 f2 6a 38 68 ?? ?? 40 00 e8 ?? fe ff ff 6a 39 68 ?? ?? 40 00 e8 ?? fe ff ff}  //weight: 2, accuracy: Low
        $x_1_8 = {5c 49 6e 50 72 6f 63 53 65 72 76 65 72 33 32 00 32 32 35 34 54 68 69 73 20 28 29 20 70 72 6f 67 72 61 6d 20 73 65 74 75 70 [0-10] 41 6e 74 69 56 69 72 75 73 2e 00}  //weight: 1, accuracy: Low
        $x_2_9 = {80 34 3a 31 [0-5] 80 2c 3a 0b 42 e2 e2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_IJ_2147803973_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.IJ"
        threat_id = "2147803973"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 0c 50 68 00 14 2d 00 ff 75 ?? ff 15 ?? ?? 40 00}  //weight: 2, accuracy: Low
        $x_2_2 = {c1 e8 1a c1 e6 06 8a 80 ?? ?? 40 00 34 a0}  //weight: 2, accuracy: Low
        $x_2_3 = {8a 06 04 60 0f b6 c0 83 c0 03}  //weight: 2, accuracy: High
        $x_1_4 = {77 07 3d 00 00 00 80 73}  //weight: 1, accuracy: High
        $x_1_5 = {68 58 4d 56 c7 85 ?? ?? ff ff 58 56 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_JA_2147803974_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.JA"
        threat_id = "2147803974"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 83 c7 04 83 fb 0a 72}  //weight: 2, accuracy: High
        $x_2_2 = {83 f9 05 7d 13 8a 94 0d ?? ?? ff ff 81 f2 ?? 00 00 00 88 14 01 41 eb e2}  //weight: 2, accuracy: Low
        $x_2_3 = {6a 0c 50 68 00 14 2d 00 ff 75 ?? ff 15 ?? ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_4 = {0f be 09 83 f1 ?? 83 f9 42 0f 84 ?? ?? 00 00 83 f9 4f 74 0b 83 f9 55 0f 84 ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_1_5 = {8a 5a 03 80 fb 3d 0f 85 8a 00 00 00 8a 42 02 3a c3 75 38}  //weight: 1, accuracy: High
        $x_1_6 = {77 07 3d 00 00 00 80 73}  //weight: 1, accuracy: High
        $x_1_7 = {68 58 4d 56 c7 85 ?? ?? ff ff 58 56 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_DC_2147803982_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.DC"
        threat_id = "2147803982"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d7 8a 4c 24 10 8d 44 24 10 84 c9 74 [0-4] 80 f1 ?? 88 08 8a 48 01 40 84 c9 75 f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_DD_2147803985_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.DD"
        threat_id = "2147803985"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 1f 56 8b f0 8d 55 0c 83 c2 04 8b 0a 85 c9 7c 06 32 4d 08 88 0e 46 ff 4d 0c 83 7d 0c 00 7f e8 5e}  //weight: 1, accuracy: High
        $x_1_2 = {74 1a 8b 45 0c 8b 00 33 ff 39 1e 76 0b 8a 4d fe 30 08 40 47 3b 3e 72 f5}  //weight: 1, accuracy: High
        $x_2_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 6f 66 74 77 61 72 65 20 4e 6f 74 69 66 69 65 72 00}  //weight: 2, accuracy: High
        $x_1_4 = {49 6e 73 74 61 6c 6c 61 74 69 6f 6e 49 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_DE_2147803988_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.DE"
        threat_id = "2147803988"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 5d f4 53 eb 3d 83 7d ec 01 75 16 68 ?? ?? ?? ?? 8d 85 e8 fe ff ff 50 ff 15 ?? ?? ?? ?? 85 c0 74 32 ff 45 f4}  //weight: 3, accuracy: Low
        $x_2_2 = {8b f0 6a 11 c1 e6 02 ff b6 ?? ?? ?? ?? ff b6 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 83 f8 01 75 19 6a 05}  //weight: 2, accuracy: Low
        $x_1_3 = {73 70 79 77 61 72 65 77 61 72 6e 69 6e 67 2e 6d 68 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 70 79 77 61 72 65 77 61 72 6e 69 6e 67 32 2e 6d 68 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_DY_2147803990_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.DY"
        threat_id = "2147803990"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 8c a4 01 00 00 55 56 57 8d 7c 24 38}  //weight: 1, accuracy: High
        $x_1_2 = {74 2f 6a 02 6a 00 6a fc 56 ff 15 ?? ?? ?? ?? 83 f8 ff 74 1d}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 6d 73 78 6d 6c 37 31 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Renos_EE_2147803991_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.EE"
        threat_id = "2147803991"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ca 68 14 10 00 00 50 51 53 ff 15 ?? ?? ?? ?? 83 f8 06 75 ?? 8d ?? 20}  //weight: 1, accuracy: Low
        $x_1_2 = {68 98 04 02 00 8b ?? 08 06 00 6a 1c 8d ?? 9c}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 85 31 02 00 00 53 56 57 6a 01 8d 44 24 24 6a 20 50 6a 00}  //weight: 1, accuracy: High
        $x_1_4 = {77 69 6e 61 6c 65 72 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {2d fb 02 25 b6 06 ba 25}  //weight: 1, accuracy: High
        $x_1_6 = {2d de 24 04 80 6c d0 49}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Renos_EF_2147803992_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.EF"
        threat_id = "2147803992"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 f1 a3 88 0c}  //weight: 2, accuracy: High
        $x_2_2 = {3f 3e 8c 8d 01 00}  //weight: 2, accuracy: High
        $x_2_3 = {43 01 51 1b 63 97 e3 95 67 00}  //weight: 2, accuracy: High
        $x_1_4 = {8d 45 e4 6a 0c 50 68 00 14 2d 00}  //weight: 1, accuracy: High
        $x_1_5 = {85 c0 74 6f 83 7d ec 04 75 69 a0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_IE_2147803997_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.IE"
        threat_id = "2147803997"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 45 f4 8d 7d f1 8d 35 ?? ?? ?? ?? b9 03 00 00 00 f3 a4 83 65 fc 00 31 db eb 3d}  //weight: 2, accuracy: Low
        $x_1_2 = "wndutl32.dll" ascii //weight: 1
        $x_1_3 = "config.cfg" ascii //weight: 1
        $x_1_4 = "WALLP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_JV_2147804003_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.JV"
        threat_id = "2147804003"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 14 2d 00 03 00 6a (0c|90) 04 01 03 50 2d 57 18}  //weight: 1, accuracy: Low
        $x_1_2 = {40 3d 00 01 00 00 ?? (f1|f4)}  //weight: 1, accuracy: Low
        $x_1_3 = {66 81 3e 8b ff 75 2e 80 3f 90 75 29}  //weight: 1, accuracy: High
        $x_1_4 = {c6 04 03 b8 43 89 14 03 83 c3 04 8d 51 04 c6 04 03 ff 43 c6 04 03 d0}  //weight: 1, accuracy: High
        $x_1_5 = {44 6c 6c 44 65 66 69 6e 65 00 44 6c 6c 52 65 67}  //weight: 1, accuracy: High
        $x_1_6 = "</url></config>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Renos_IO_2147804028_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.IO"
        threat_id = "2147804028"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 00 00 00 68 74 74 70 3a 2f 2f 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 59 33 c0 8d bd ?? ?? ff ff f3 ab 66 ab aa}  //weight: 1, accuracy: Low
        $x_1_3 = {59 0f b6 c0 83 c0 03 59 24 fc e8}  //weight: 1, accuracy: High
        $x_1_4 = {64 a1 30 00 00 00 8a 40 02 0f b6 c0 89 85}  //weight: 1, accuracy: High
        $x_1_5 = {88 04 3e 46 eb 03 00 83 f0}  //weight: 1, accuracy: Low
        $x_1_6 = {0f b6 c0 83 c0 03 24 fc e8 04 00 8a 06 (04|2c)}  //weight: 1, accuracy: Low
        $x_1_7 = {8a 04 3e 34 ?? 88 07 47 4b 75}  //weight: 1, accuracy: Low
        $x_1_8 = {68 e0 01 00 00 68 58 02 00 00 [0-16] 6a 0a}  //weight: 1, accuracy: Low
        $x_1_9 = {74 05 83 f8 02 75 ?? 6a 0f 68 03 04 00 00}  //weight: 1, accuracy: Low
        $x_1_10 = {6a 04 50 56 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 83 7d ?? 04 75}  //weight: 1, accuracy: Low
        $x_1_11 = {8a 0e 80 f1 ?? 88 0c 37 74 06 46 80 3e 00 75 f0}  //weight: 1, accuracy: Low
        $x_1_12 = {6a 04 50 e8 ?? ?? ?? ?? 59 59 8b 7d ?? 83 65 ?? 00 83 ff 04 0f 86}  //weight: 1, accuracy: Low
        $x_1_13 = {3b de 74 12 83 fb 68 74 0d 83 fb 65 74 08 81 fb fc 00 00 00 75 04}  //weight: 1, accuracy: High
        $x_1_14 = {83 c7 04 83 7d f0 0a [0-4] 0f 82}  //weight: 1, accuracy: Low
        $x_1_15 = {81 ff 00 00 00 d0 a2 ?? ?? ?? ?? 77 08 81 ff 00 00 00 80 73 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_16 = {ff 45 f4 8b 73 04 83 c3 04 89 07 83 c7 04 ff 45 fc 85 f6 75 ?? 83 45 f8 04 ff 45 fc 81 7d f8}  //weight: 1, accuracy: Low
        $x_1_17 = {2b ca 83 f9 33 0f 84 ?? ?? ?? ?? 83 f9 42 0f 84 ?? ?? ?? ?? 83 f9 4d 0f 85}  //weight: 1, accuracy: Low
        $x_1_18 = "E24211B3-A78A-C6A9-D317-70979ACE5058" ascii //weight: 1
        $x_1_19 = {83 f1 59 83 f9 62 0f 84 ?? ?? ?? ?? 83 f9 75 0f 84 ?? ?? ?? ?? 83 f9 78 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Renos_IR_2147804029_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.IR"
        threat_id = "2147804029"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 08 20 00 00 50 8d 85 ?? ?? ff ff 50 8b 85 ?? ?? ff ff 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {81 f8 0d f0 ad de 0f 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_JF_2147804030_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.JF"
        threat_id = "2147804030"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 00 3c 21 0f 84 ?? ?? 00 00 3c 2c 74 0a 3c 3b 0f 84}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 09 80 f9 21 0f 84 ?? ?? 00 00 80 f9 2c 74 0b 80 f9 3b 0f 84}  //weight: 2, accuracy: Low
        $x_1_3 = {6a 04 50 56 89 5d ?? 89 5d ?? ff 15 ?? ?? ?? ?? 85 c0 74 ?? 83 7d ?? 04 75}  //weight: 1, accuracy: Low
        $x_1_4 = {88 04 0a 74 06 41 80 39 00 75 f1 04 00 8a 01 34}  //weight: 1, accuracy: Low
        $x_1_5 = {2c 21 3b 00 fe 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {91 e7 bf 92 00}  //weight: 1, accuracy: High
        $x_1_7 = {ff 45 f4 8b 73 04 83 c3 04 89 07 83 c7 04 ff 45 fc 85 f6 75 ?? 83 45 f8 04 ff 45 fc 81 7d f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_KA_2147804031_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.KA"
        threat_id = "2147804031"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d7 99 b9 19 00 00 00 f7 f9 8b 8c 24 ?? ?? 00 00 8b c5 83 c2 08 2b c2 8d 34 18 89 0e ff d7 99 b9 ff 00 00 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {50 68 82 00 00 00 53 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {25 ff 00 00 00 8a 4c 04 ?? 8a 04 2a 32 c8 33 c0 88 4d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_KN_2147804032_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.KN"
        threat_id = "2147804032"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<url get=\"on\" crypt=\"on\"><![CDATA[http://" ascii //weight: 1
        $x_1_2 = "<url post=\"on\" crypt=\"on\"><![CDATA[http://" ascii //weight: 1
        $x_1_3 = "SSHNAS" ascii //weight: 1
        $x_1_4 = "rundll32.exe C:\\Windows\\iexplore.exe,AttachConsoleA" ascii //weight: 1
        $x_1_5 = {4c 6f 73 41 6c 61 6d 6f 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Renos_LE_2147804033_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.LE"
        threat_id = "2147804033"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3c 63 6f 6e 66 69 67 3e 3c 75 72 6c 3e 68 74 74 70 3a 2f 2f ?? ?? ?? ?? [0-32] 2f 72 65 73 6f 6c 75 74 69 6f 6e 2e 70 68 70 3c 2f 75 72 6c 3e}  //weight: 2, accuracy: Low
        $x_2_2 = {3c 67 65 74 68 69 74 3e 3c 75 72 6c 3e 68 74 74 70 3a 2f 2f ?? ?? ?? ?? [0-32] 2f 62 6f 72 64 65 72 73 2e 70 68 70 3c 2f 75 72 6c 3e}  //weight: 2, accuracy: Low
        $x_1_3 = "<url crypt=\"on\">http://" ascii //weight: 1
        $x_2_4 = {3c 63 6f 6e 66 69 67 3e 3c 75 72 6c 20 70 6f 73 74 3d 22 6f 6e 22 3e 68 74 74 70 3a 2f 2f ?? ?? ?? ?? [0-32] 2f 61 64 5f 74 79 70 65 2e 70 68 70 3c 2f 75 72 6c 3e}  //weight: 2, accuracy: Low
        $x_1_5 = "<url crypt=\"on\" post=\"on\">http://" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_NL_2147804034_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.NL"
        threat_id = "2147804034"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "]]></report>" ascii //weight: 2
        $x_2_2 = "/upd/check.php?" ascii //weight: 2
        $x_3_3 = ".php?ver=%VER%&cver=%CVER" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_OD_2147804035_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.OD"
        threat_id = "2147804035"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 3c 8b 74 ?? eb 3c 55 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 00 20 db 3c 8b 5b 74 ?? eb 3c 55 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Renos_IX_2147804040_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.IX"
        threat_id = "2147804040"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "E24211B3-A78A-C6A9-D317-70979ACE5058" ascii //weight: 1
        $x_1_2 = "HA_%08x" ascii //weight: 1
        $x_1_3 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_4 = "wininet.dll::HttpOpenRequestA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_IX_2147804040_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.IX"
        threat_id = "2147804040"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 85 08 ff ff ff 0f b6 85 64 fc ff ff 0f b7 85 a4 fd ff ff 0f b7 85 54 fe ff ff 0f b6 85 90 fe ff ff e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_CX_2147804046_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!CX"
        threat_id = "2147804046"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ax=0/ed=0/ex=0/" ascii //weight: 1
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "your computer may be infected" ascii //weight: 1
        $x_1_4 = {53 65 63 75 72 69 74 79 20 77 61 72 6e 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_5 = "Click here to learn more." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_ET_2147804054_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.ET"
        threat_id = "2147804054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Installing Spyware Soft Stop" ascii //weight: 1
        $x_1_2 = "http://localhost/sss_/downloads/install.exe" ascii //weight: 1
        $x_1_3 = "Program Files\\Spyware Soft Stop\\Spyware Soft Stop.exe" ascii //weight: 1
        $x_1_4 = "Warning!" ascii //weight: 1
        $x_1_5 = "Your computer is probably infected. Microsoft Corporation recommends  to check your computer on the spyware present`s. Click here to download updates" ascii //weight: 1
        $x_1_6 = "notifysb.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Renos_FF_2147804068_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.FF"
        threat_id = "2147804068"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 68 00 14 2d 00 ff ?? ?? ff 15 ?? ?? 40 00 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c1 03 eb 4b 83 c1 04 eb 46 83 c1 05 eb 41 83 c1 06 eb 3c 83 c1 07 eb 37 83 c1 08 eb 32}  //weight: 1, accuracy: High
        $x_1_3 = {64 a1 30 00 00 00 8a 40 02 0f b6 c0 89 45 dc}  //weight: 1, accuracy: High
        $x_1_4 = {64 a1 20 00 00 00 89 45 dc eb 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_G_2147804069_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!G"
        threat_id = "2147804069"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 80 ee 36 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 30 46 81 fe 00 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 ff 00 00 00 8a 4c 04 18 8d 44 04 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_BE_2147804086_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!BE"
        threat_id = "2147804086"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 18 88 11 8a ca 02 08 0f b6 c1 8a 84 05 ?? ?? ff ff 32 04 37 88 06 46 ff 4d 08 75 b0}  //weight: 1, accuracy: Low
        $x_1_2 = {74 14 8d 45 ?? 50 e8 ?? ?? 00 00 59 89 7d ?? 59 c6 45 ?? 03 eb 19}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_JB_2147804088_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.JB"
        threat_id = "2147804088"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 75 0c 8b 45 08 [0-32] 8a 04 02 02 06 00 45 fe [0-32] 8a 0e 0f b6 45 fe}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 c0 8a 84 05 fc fe ff ff 32 04 19 88 03}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 14 2d 00 03 00 6a 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_L_2147804101_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.L"
        threat_id = "2147804101"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 70 72 6f 64 75 63 74 25 00 00 00 ff ff ff ff 08 00 00 00 25 75 70 64 61 74 65 25 00 00 00 00 ff ff ff ff 05 00 00 00 25 61 66 66 25 00 00 00 ff ff ff ff 04 00 00 00 25 6f 73 25 00}  //weight: 2, accuracy: High
        $x_1_2 = "jcl.svn.sourceforge.net/svnroot/jcl" ascii //weight: 1
        $x_2_3 = {43 6f 6e 74 69 6e 75 65 00 00 00 00 42 49 54 42 54 4e 31 5f 42 49 54 4d 41 50 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_Y_2147804102_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.Y"
        threat_id = "2147804102"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 4f 00 00 00 cd 41 66 3d 86 f3 0f 94 c0 0f b6 c0}  //weight: 10, accuracy: High
        $x_10_2 = {53 6e 6d 70 55 74 69 6c 4f 69 64 43 70 79 00}  //weight: 10, accuracy: High
        $x_5_3 = {bf 00 01 00 00 88 84 05 fc fe ff ff 40 3b c7 72 f4}  //weight: 5, accuracy: High
        $x_5_4 = {0f b6 c0 8a 84 05 fc fe ff ff 32 04 19 88 03}  //weight: 5, accuracy: High
        $x_1_5 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 00 43 72 66 31 55 7a 48 37 70 79 00}  //weight: 1, accuracy: High
        $x_1_6 = {68 a0 bb 0d 00 ff d6 e8 ?? ?? ff ff 85 c0 75 f0 e8 ?? ?? ff ff eb e9}  //weight: 1, accuracy: Low
        $x_1_7 = {81 cb ff ff 99 a8 80 f1 98 89 1d ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 81 cb ff ff 2d e2}  //weight: 1, accuracy: Low
        $x_1_8 = {6a 0c 50 68 00 14 2d 00 04 00 [0-1] 8d (45|44 24)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_FI_2147804105_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.FI"
        threat_id = "2147804105"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 8b f1 2b f9 8a 0e 80 f1 ?? 88 0c 37 74 ?? [0-3] 46 [0-3] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 68 58 4d 56 66 ba 58 56 ed 81 fb 68 58 4d 56 0f 94 c0}  //weight: 1, accuracy: High
        $x_1_3 = "Crf1UzH7py" ascii //weight: 1
        $x_1_4 = {53 6e 6d 70 55 74 69 6c 4f 69 64 43 70 79 00}  //weight: 1, accuracy: High
        $x_1_5 = {75 75 07 75 7a 60 6a 6c 29 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Renos_HA_2147804106_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.HA"
        threat_id = "2147804106"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Critical System Warning! Your system is probably infected with a version of Spyware.IEPass.thief" ascii //weight: 1
        $x_1_2 = "scanner.rapidantivirus.com" ascii //weight: 1
        $x_1_3 = {69 53 53 44 5f 43 4d 00}  //weight: 1, accuracy: High
        $x_1_4 = "Micr%sntVer%s" ascii //weight: 1
        $x_1_5 = "Attn! Critical System Warning" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Renos_HC_2147804107_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.HC"
        threat_id = "2147804107"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 51 10 33 c0 89 02 89 42 04 c7 01 01 23 45 67 c7 41 04 89 ab cd ef c7 41 08 fe dc ba 98 c7 41 0c 76 54 32 10}  //weight: 10, accuracy: High
        $x_10_2 = {bb 00 00 00 00 b8 01 00 00 00 0f 3f 07 0b}  //weight: 10, accuracy: High
        $x_10_3 = {68 00 14 2d 00 07 00 [0-1] 8d (45|44 24) ?? 6a 0c}  //weight: 10, accuracy: Low
        $x_1_4 = {77 67 65 74 20 33 2e 30 00}  //weight: 1, accuracy: High
        $x_1_5 = {3e 20 6e 75 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {78 78 78 25 6c 75 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_AW_2147804109_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.AW"
        threat_id = "2147804109"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hi, botnet Jack here" ascii //weight: 1
        $x_1_2 = {72 69 6f 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e 00 57 4c 45 76 65 6e 74 53 74 61 72 74 53 68 65 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_AW_2147804109_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.AW"
        threat_id = "2147804109"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d fc 02 7e 23 8b 45 fc 83 e8 02 83 e0 01 85 c0 75 16 8b 45 fc 8b 4d 08 01 c1 8b 45 fc 8b 55 08 01 c2 b0 ?? 02 02 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = "hi, botnet Jack here" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_EH_2147804110_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.EH"
        threat_id = "2147804110"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 07 bb fe 00 00 00 eb 04 85 db 7e 15 8d 4c 24 0c 51 e8 ?? ?? ff ff 8b 44 24 10 83 c4 04 3b c3 7c eb}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d6 81 f2 39 30 00 00 52 68}  //weight: 1, accuracy: High
        $x_1_3 = {68 10 27 00 00 ?? ?? ?? ?? ?? 6a 0c ?? 68 00 14 2d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_AI_2147804112_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!AI"
        threat_id = "2147804112"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 1c 8a 44 3e 01 32 04 3e 8b 4c 24 14 88 04 0b 43 46 57 46 e8 ?? ?? ?? 00 3b f0 59 72 e4 8b 44 24 14 5f 5e c6 04 03 00 5b c3}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 6b 50 c7 45 d4 03 00 00 00 c7 45 d8 ?? ?? 00 10 89 7d dc 89 7d e0 89 45 e4 ff d6 68 00 7f 00 00 57 89 45 e8 ff 15 ?? ?? 00 10 6a 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {7b 4f 55 54 50 55 54 5f 4e 41 4d 45 7d 2e 64 6c 6c 00 69 6e 73 74 61 6c 6c 69 6e 67 00 6c 6f 61 64 69 6e 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Renos_AJ_2147804113_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!AJ"
        threat_id = "2147804113"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 9c 00 00 00 50 66 89 54 24 30 c7 44 24 78 80 02 00 00 c7 44 24 7c e0 01 00 00 c7 44 24 34 00 00 18 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {84 c9 74 0d 80 f1 ?? 88 08 8a 48 01 40 84 c9 75 f3}  //weight: 1, accuracy: Low
        $x_1_3 = {7b 37 38 42 35 37 38 44 37 2d 42 43 45 31 2d 34 64 38 33 2d 39 43 44 34 2d 31 39 35 42 43 33 34 44 38 43 42 33 7d 00}  //weight: 1, accuracy: High
        $x_1_4 = {2a 2a 2a 20 53 54 4f 50 3a 20 30 78 30 30 30 30 30 30 38 45 20 28 30 78 43 30 30 00 30 30 30 30 35 2c 30 58 38 30 35 36 45 42 41 34 2c 30 78 46 37 44 44 33 39 39 43 2c 30 78 30 30 30 30 30 30 30 30 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_AK_2147804114_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!AK"
        threat_id = "2147804114"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 11 8b 45 f8 0f be 08 8b 55 fc c1 e2 04 8b 45 08 8b 54 10 08 c1 ea 08 0f be c2 33 c8 8b 55 f8 88 0a 8b 45 f8 0f be 08 85 c9 75 60}  //weight: 1, accuracy: High
        $x_1_2 = {8b 48 3c 8b 55 08 8d 44 0a 18 89 45 f8 8b 4d f8 8b 55 08 03 51 60 89 55 f4 8b 45 0c c1 e8 10 25 ff ff 00 00 25 ff ff 00 00 85 c0 75 14}  //weight: 1, accuracy: High
        $x_2_3 = {25 ff 03 00 00 89 45 d8 83 7d d8 07 74 2c 83 7d d8 0a 74 14 83 7d d8 0c 74 56 83 7d d8 10 74 3e 83 7d d8 15 74 26}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_DG_2147804115_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.DG"
        threat_id = "2147804115"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 45 fc 00 00 00 00 eb 09 8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d f8 7d 18 8b 55 08 03 55 fc 0f be 02 35 ?? 00 00 00 8b 4d 0c 03 4d fc 88 01 eb d7}  //weight: 2, accuracy: Low
        $x_2_2 = {83 f8 06 0f 85 ?? ?? 00 00 68 ?? ?? ?? ?? e8 ?? ?? 00 00 83 c4 04 89 (45|85) 1f 00 6a 00 ff 15 ?? ?? 00 10}  //weight: 2, accuracy: Low
        $x_1_3 = "verifiedpaymentsolutionsonline" ascii //weight: 1
        $x_1_4 = "?sku_name=" ascii //weight: 1
        $x_1_5 = "mfeed.php?txt=1&affiliate=" ascii //weight: 1
        $x_1_6 = "rid=0&st=typein&ref=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_DM_2147804116_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.DM"
        threat_id = "2147804116"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 65 67 41 58 34 2e 62 61 74 00}  //weight: 5, accuracy: High
        $x_5_2 = {72 65 67 41 52 34 2e 72 65 67 00}  //weight: 5, accuracy: High
        $x_5_3 = {73 65 6c 66 64 65 6c 34 2e 62 61 74 00}  //weight: 5, accuracy: High
        $x_2_4 = "MinutesToUninstall" wide //weight: 2
        $x_2_5 = "SleepSeconds" wide //weight: 2
        $x_2_6 = {4f 00 70 00 65 00 6e 00 49 00 45 00 4d 00 69 00 6e 00 75 00 74 00 65 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_2_7 = {52 00 65 00 62 00 6f 00 6f 00 74 00 4d 00 69 00 6e 00 4d 00 69 00 6e 00 75 00 74 00 65 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_2_8 = {52 00 65 00 62 00 6f 00 6f 00 74 00 4d 00 61 00 78 00 4d 00 69 00 6e 00 75 00 74 00 65 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_10_9 = "*** STOP: 0x0000008E (0xC0000005,0X8056EBA4,0xF7DD399C,0x00000000)" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_DN_2147804117_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.DN"
        threat_id = "2147804117"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 65 67 41 52 32 2e 72 65 67 00}  //weight: 5, accuracy: High
        $x_5_2 = {72 65 67 41 32 2e 62 61 74 00}  //weight: 5, accuracy: High
        $x_2_3 = {4f 00 70 00 65 00 6e 00 49 00 45 00 4d 00 69 00 6e 00 75 00 74 00 65 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_2_4 = "MinutesToUninstall" wide //weight: 2
        $x_2_5 = "SleepSeconds" wide //weight: 2
        $x_2_6 = {53 00 68 00 6f 00 77 00 42 00 61 00 6c 00 6c 00 6f 00 6f 00 6e 00 4d 00 69 00 6e 00 75 00 74 00 65 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_2_7 = {53 00 68 00 6f 00 77 00 4d 00 73 00 67 00 42 00 6f 00 78 00 4d 00 69 00 6e 00 75 00 74 00 65 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_2_8 = "URL_IE" wide //weight: 2
        $x_2_9 = "URL_Balloon" wide //weight: 2
        $x_2_10 = "URL_MsgBox" wide //weight: 2
        $x_10_11 = {59 4f 55 52 20 20 43 4f 4d 50 55 54 45 52 20 20 49 53 20 20 49 4e 46 45 43 54 45 44 20 20 57 49 54 48 20 20 53 50 59 57 41 52 45 21 00}  //weight: 10, accuracy: High
        $x_10_12 = {41 52 45 20 20 53 54 49 4c 4c 20 20 54 48 45 52 45 20 20 61 6e 64 20 20 63 6f 75 6c 64 20 20 62 72 6f 6b 65 20 20 79 6f 75 72 20 20 6c 69 66 65 21 00}  //weight: 10, accuracy: High
        $x_10_13 = {52 45 4d 4f 56 45 20 20 41 4c 4c 20 20 53 50 59 57 41 52 45 20 20 46 52 4f 4d 20 20 59 4f 55 52 20 20 50 43 21 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 8 of ($x_2_*))) or
            ((1 of ($x_10_*) and 8 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_DO_2147804118_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.DO"
        threat_id = "2147804118"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 65 67 41 52 31 2e 72 65 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 65 67 41 58 31 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 65 6c 66 64 65 6c 31 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_2_4 = "URL_once" ascii //weight: 2
        $x_2_5 = "MinutesToUninstall" ascii //weight: 2
        $x_2_6 = "SleepSeconds" ascii //weight: 2
        $x_2_7 = "ValueName_" ascii //weight: 2
        $x_2_8 = "CheckValue_" ascii //weight: 2
        $x_2_9 = "ValueType_" ascii //weight: 2
        $x_2_10 = "ValueData_" ascii //weight: 2
        $x_5_11 = "%domen%" wide //weight: 5
        $x_5_12 = "%affid%" wide //weight: 5
        $x_5_13 = "%workmin%" wide //weight: 5
        $x_5_14 = "3BCF8450-D134-427E-AE9C-2A42CE8215CC" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 7 of ($x_2_*))) or
            ((4 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_5_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_DP_2147804119_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.DP"
        threat_id = "2147804119"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 65 67 41 52 33 2e 72 65 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 65 67 41 58 33 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 65 6c 66 64 65 6c 33 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_2_4 = "MinutesToUninstall" ascii //weight: 2
        $x_2_5 = "SleepSeconds" ascii //weight: 2
        $x_2_6 = {4f 70 65 6e 49 45 4d 69 6e 75 74 65 73 00}  //weight: 2, accuracy: High
        $x_2_7 = {42 61 6c 6c 6f 6f 6e 54 69 74 6c 65 00}  //weight: 2, accuracy: High
        $x_2_8 = {53 68 6f 77 42 61 6c 6c 6f 6f 6e 4d 69 6e 75 74 65 73 00}  //weight: 2, accuracy: High
        $x_2_9 = "URL_IE" ascii //weight: 2
        $x_2_10 = "URL_Balloon" ascii //weight: 2
        $x_2_11 = "BalloonText" ascii //weight: 2
        $x_5_12 = "%domen%" wide //weight: 5
        $x_5_13 = "%affid%" wide //weight: 5
        $x_5_14 = "%workmin%" wide //weight: 5
        $x_5_15 = "09E23F2C-ED1E-43FC-9AA1-1332162A35AE" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 8 of ($x_2_*))) or
            ((3 of ($x_5_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 6 of ($x_2_*))) or
            ((4 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_5_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_BD_2147804120_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.gen!BD"
        threat_id = "2147804120"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 e0 4f 00 00 00 c7 45 e4 86 f3 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 e0 cd 41 66 3b 45 e4 0f 94 c0 0f b6 c0 89 45 dc}  //weight: 1, accuracy: High
        $x_1_3 = {c7 85 80 fd ff ff 68 58 4d 56 c7 85 7c fd ff ff 58 56 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b 85 80 fd ff ff 66 8b 95 7c fd ff ff ed 3b 9d 80 fd ff ff 0f 94 c0 0f b6 c0}  //weight: 1, accuracy: High
        $x_2_5 = {81 f2 bd 00 00 00 88 14 01 41 eb}  //weight: 2, accuracy: High
        $x_2_6 = {83 f0 62 88 04 3e 46 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_IQ_2147804123_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.IQ"
        threat_id = "2147804123"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 6a 19 59 f7 f1 8b [0-3] 02 d3 80 c2 61 88 14 18 43 83 fb 03 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {63 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 46 41 42 5c d0 a0 d0 b0 d0 b1 d0 be d1 87 d0 b8 d0 b9 20 d1 81 d1 82 d0 be d0 bb 5c 4c 4c 4c 5c 52 65 6c 65 61 73 65 5c 31 2e 70 64 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_JK_2147804124_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.JK"
        threat_id = "2147804124"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 05 00 00 00 83 bd ?? ?? ?? ?? 02 75 ?? 83 bd ?? ?? ?? ?? 06 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 03 6a 00 6a 00 6a 00 6a 00 6a ff 8b 45 b8 50 e8}  //weight: 1, accuracy: High
        $x_1_3 = {4a 00 a8 03 00 00 07 00 e8 01 04 34 18 00 0a 20}  //weight: 1, accuracy: High
        $x_1_4 = {74 7f c7 45 fc 04 00 00 00 6a 41 8d 4d ?? 51 ff 15 ?? ?? ?? ?? 6a 56 8d 55 ?? 52 ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 45 fc 1d 00 00 00 6a 53 8d 4d b4 51 ff 15 ?? ?? ?? ?? 6a 79 8d 55 a4 52 ff 15 ?? ?? ?? ?? 6a 73 8d 45 84 50 ff 15 ?? ?? ?? ?? 6a 74}  //weight: 1, accuracy: Low
        $x_1_6 = {6a 56 ff 15 ?? ?? ?? ?? 8b d0 8d 8d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 8d 8d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 6a 69 ff 15 ?? ?? ?? ?? 8b d0 8d 8d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 8d 8d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 6a 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Renos_JT_2147804125_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.JT"
        threat_id = "2147804125"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 04 19 88 03}  //weight: 1, accuracy: High
        $x_1_2 = {0f 01 4c 24}  //weight: 1, accuracy: High
        $x_1_3 = "hXMV" ascii //weight: 1
        $x_1_4 = {0f b6 c0 83 c0 ?? 24}  //weight: 1, accuracy: Low
        $x_1_5 = {77 67 65 74 20 33 2e 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Renos_LU_2147804127_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.LU"
        threat_id = "2147804127"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 72 6f 67 72 61 6d 46 69 6c 65 73 44 69 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 6f 6d 6d 6f 6e 46 69 6c 65 73 44 69 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 61 46 75 64 67 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 65 74 75 70 2d 32 2e 31 31 2d 65 6e 67 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {75 70 64 61 74 65 2d 32 2e 31 31 2d 65 6e 67 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_LM_2147804133_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.LM"
        threat_id = "2147804133"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5c 6c 6d 73 2e 65 78 65 00 68 74 74 70 3a 2f 2f 6c 6f 77 64 65 63 6b 2e 6e 65 74 2f 6b 74 32 73 69 2f 64 72 6d 6c 73 68 2e 65 78 65}  //weight: 5, accuracy: High
        $x_1_2 = {5c 53 65 61 72 63 68 48 6f 73 74 50 72 6f 74 6f 63 6f 6c 2e 65 78 65 00 68 74 74 70 3a 2f 2f 6c 6f 77 64 65 63 6b 2e 6e 65 74 2f 6b 74 32 73 69 2f 69 63 6e 73 79 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 74 61 73 6b 65 6e 67 63 2e 65 78 65 00 68 74 74 70 3a 2f 2f 6c 6f 77 64 65 63 6b 2e 6e 65 74 2f 6b 74 32 73 69 2f 32 65 66 69 6e 79 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 63 72 73 73 63 2e 65 78 65 00 68 74 74 70 3a 2f 2f 6c 6f 77 64 65 63 6b 2e 6e 65 74 2f 6b 74 32 73 69 2f 63 32 73 79 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_EG_2147804134_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.EG"
        threat_id = "2147804134"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 07 be fe 00 00 00 eb 04 85 f6 7e 15 8d 44 24 08 50 e8 ?? ?? ff ff 8b 44 24 0c 83 c4 04 3b c6 7c eb}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d6 81 f2 39 30 00 00 52 68}  //weight: 1, accuracy: High
        $x_1_3 = {68 10 27 00 00 ?? ?? ?? ?? ?? 6a 0c ?? 68 00 14 2d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_FO_2147804135_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.FO"
        threat_id = "2147804135"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 18 8b f8 8b f1 2b f9 8a 0e 80 f1 ?? 88 0c 37 74 08 8a 4e 01 46 84 c9 75 ee}  //weight: 2, accuracy: Low
        $x_1_2 = {35 23 01 ef cd 50 ff 15 ?? ?? ?? ?? 0f be 0d}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d7 8b e8 ff d7 2b c5 3d 35 05 00 00 0f 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_DV_2147804136_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.DV"
        threat_id = "2147804136"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c7 45 fc 14 00 00 00 8b 45 0c ff 30 8d 45 ac 50 e8 ?? ?? ?? ff 50 6a 01 6a 0c ff 75 c4 e8}  //weight: 3, accuracy: Low
        $x_1_2 = {67 65 74 66 6e 33 32 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 65 74 41 64 76 49 44 00}  //weight: 1, accuracy: High
        $x_1_4 = {47 65 74 44 6f 6d 65 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {52 65 70 6c 61 63 65 5f 75 72 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {50 00 41 00 5a 00 55 00 5a 00 55 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {77 00 65 00 72 00 74 00 79 00 75 00 2e 00 73 00 6c 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {75 00 65 00 73 00 69 00 75 00 71 00 63 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_FW_2147804137_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.FW"
        threat_id = "2147804137"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 56 6a fc 0f 95 c1 57 88 0d ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {35 23 01 ef cd 50 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {85 c0 74 19 8b 45 fc c7 05 ?? ?? ?? ?? 00 00 0e d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_GC_2147804138_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.GC"
        threat_id = "2147804138"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 83 38 7b 75 0e}  //weight: 1, accuracy: High
        $x_1_2 = {c6 47 03 3d 80 f1 a5}  //weight: 1, accuracy: High
        $x_1_3 = {35 a5 00 00 00 3d 69 ff ff ff 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_AC_2147804143_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.AC"
        threat_id = "2147804143"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 c8 97 04 00 68 2c 05 00 00 ff 75 08 e8}  //weight: 2, accuracy: High
        $x_2_2 = {00 68 74 74 70 3a 2f 2f 25 73 2f 3f 61 69 64 3d 25 73 00 68 74 74 70 3a 2f 2f 25 73 2f 73 79 6e 63 2e 70 68 70 00}  //weight: 2, accuracy: High
        $x_1_3 = {00 61 6c 6c 65 72 74 32 00 66 67 6c 6c 65 72 74 00 71 6f 61 64 00 77 69 6e 64 6f 77 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 54 68 65 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 62 65 65 6e 20 0a 00 65 64 21 21 00}  //weight: 1, accuracy: Low
        $x_1_5 = {00 68 74 74 70 3a 2f 2f 25 73 3f 70 61 72 74 6e 65 72 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {36 36 62 6c 6f 77 6a 6f 62 2e 5f 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_AT_2147804144_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.AT"
        threat_id = "2147804144"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " This () program install " ascii //weight: 1
        $x_1_2 = {00 59 6f 75 20 63 61 6e 20 64 6f 77 6e 6c 6f 61 64 20 6e 65 77 20 76 65 72 73 69 6f 6e 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 75 08 80 3e 00 74 05 30 06 46 eb f6 c9 c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_IF_2147804145_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.IF"
        threat_id = "2147804145"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 a0 bb 0d 00 6a 00 6a 00 a3 ?? ?? ?? ?? ff d6 68 ?? ?? 00 10 68 e8 03 00 00 6a 00 6a 00 ff d6 68 ?? ?? 00 10 68 e0 93 04 00 6a 00 6a 00 ff d6 68 ?? ?? 00 10 68 00 f9 15 00}  //weight: 5, accuracy: Low
        $x_1_2 = "disturb you even when youre not surfing the Internet." ascii //weight: 1
        $x_1_3 = "Spyware can not be removed by antivirus software and firewalls" ascii //weight: 1
        $x_1_4 = "the computer is in risk of being contaminated with malicious" ascii //weight: 1
        $x_1_5 = "vulnerable to be interfered by people who wants to steal your private" ascii //weight: 1
        $x_1_6 = "high probability that your is infected with malicious spyw" ascii //weight: 1
        $x_1_7 = {5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 [0-4] 20 22 [0-4] 22 2c 20 73 74 61 72 74}  //weight: 1, accuracy: Low
        $x_1_8 = "pmutex_%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Renos_HK_2147804169_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.HK"
        threat_id = "2147804169"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 f0 8b 45 fc 66 ff 0d ?? ?? ?? ?? 8b 34 85 ?? ?? ?? ?? 8d 1c 85 ?? ?? ?? ?? 85 f6 74 ?? 8b 4d f8 8d 3c 8d ?? ?? ?? ?? 8a 06 04 ?? (25 ff 00|0f) 83 c0 ?? 24 ?? e8 ?? ?? ?? ?? 8b cc 8b d6 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "?assign@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@ID@Z" ascii //weight: 1
        $x_1_3 = "GetProcAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_KL_2147804174_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.KL"
        threat_id = "2147804174"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c4 56 50 e8 ?? ?? 00 00 8b 35 ?? ?? ?? ?? 59 59 50 ff 75 fc ff d6 89 45 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {81 7d 0c 2c 01 00 00 0f 8c ?? ?? 00 00 81 7d 0c 8f 01 00 00 0f 8f ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 14 2d 00 ff 74 24 ?? ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_PL_2147804176_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.PL"
        threat_id = "2147804176"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {19 5e 42 2a 04 00 4c 01 02 01 01 06 07 00}  //weight: 1, accuracy: Low
        $x_1_2 = {74 07 ff 54 24 1c c2 08 00 8b 45 08 50 8b 45 f4 50 8b 45 f8 50 8b 45 fc 50 [0-2] e8 ?? ?? ?? ?? 89 45 f0 8b 45 f0 8b e5 5d c2 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_JU_2147804182_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.JU"
        threat_id = "2147804182"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f be 05 ?? ?? ?? ?? 66 0f af 05 ?? ?? ?? ?? 66 a3 ?? ?? ?? ?? 33 c0 39 44 24 04 75 ?? 39 05}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 85 b8 d3 ff ff 56 50 8d 45 b8 6a 18 50 68 00 14 2d 00 ff 75 e8 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 d4 4c 1d 00 00 01 05 ?? ?? ?? ?? 8d 45 d4 50 6a 02 56 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_MC_2147804185_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.MC"
        threat_id = "2147804185"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d ff ff 7b 31 a3 ?? ?? ?? ?? c7 45 ?? 0a 00 00 00 c6 85 ?? ?? ff ff 2d c6 85 ?? ?? ff ff 2d c6 85 ?? ?? ff ff 5f c6 85 ?? ?? ff ff 2d c6 85 ?? ?? ff ff 22 c6 85 ?? ?? ff ff 38 c6 85 ?? ?? ff ff 32 c6 85 ?? ?? ff ff 34 c6 85 ?? ?? ff ff 71}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f8 ff 0f 85 ?? ?? ?? ?? 53 56 6a 03 53 6a 03 57 8d 85 ?? ?? ff ff 50 8d 85 ?? ?? ff ff 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_MO_2147804186_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.MO"
        threat_id = "2147804186"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 4d 0c 6a 04 51 6a 04 53 50 ff b6 a0 00 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {53 68 00 00 08 84 56 53 50 ff 75 e8 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {8d 8d 50 ff ff ff 51 53 ff 75 cc 50 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {53 6f 66 74 77 61 72 65 5c 4a 44 4b 35 53 57 46 4d 5a 59 00}  //weight: 1, accuracy: High
        $x_1_5 = {67 6f 6f 67 6c 65 2e 63 6f 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Renos_MD_2147804200_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Renos.MD"
        threat_id = "2147804200"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "x9c87vcx987v98cx7v.php?ini=" ascii //weight: 2
        $x_1_2 = "php?ini=v22MmTDh" ascii //weight: 1
        $x_1_3 = "POST /x9c87vcx" ascii //weight: 1
        $x_1_4 = "User-Agent: Mozilla/6.0 (Windows; wget 3.0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

