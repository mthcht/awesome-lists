rule PWS_Win32_Hupigon_2147489243_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Hupigon"
        threat_id = "2147489243"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SetCNkeyhook" ascii //weight: 2
        $x_1_2 = "getkey.dll" ascii //weight: 1
        $x_1_3 = {0b 5b 42 61 63 6b 73 70 61 63 65 5d}  //weight: 1, accuracy: High
        $x_1_4 = "CTRL_ALT_DEL_GETKEY" ascii //weight: 1
        $x_1_5 = {57 69 6e 73 74 61 30 00}  //weight: 1, accuracy: High
        $x_1_6 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_7 = "ImmGetCompositionStringA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Hupigon_AAA_2147595514_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Hupigon.AAA"
        threat_id = "2147595514"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "900"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {5b 8b e5 5d c3 00 [0-2] 6e 6f 00 00 43 68 65 63 6b 5f 41 73 73 6f 63 69 61 74 69 6f 6e 73 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 00 00 30 00 00 00 43 6f 6d 70 6c 65 74 65 64 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 57 69 7a 61 72 64 00 00 00 ff ff ff ff 01 00 00 00 22 00 00 00 ff ff ff ff 0d 00 00 00 22 20 61 62 6f 75 74 3a 62 6c 61 6e 6b 00 00 00 53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 00 00 00}  //weight: 100, accuracy: Low
        $x_100_2 = {c3 00 00 53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00}  //weight: 100, accuracy: High
        $x_100_3 = {ff ff ff ff 0a 00 00 00 69 66 20 65 78 69 73 74 20 22 00 00 ff ff ff ff 09 00 00 00 20 67 6f 74 6f 20 74 72 79 00 00 00 ff ff ff ff 06 00 00 00 64 65 6c 20 25 30 00 00 ff ff ff ff 04 00 00 00 65 78 69 74 00 00 00 00}  //weight: 100, accuracy: High
        $x_100_4 = {ff ff ff ff 0a 00 00 00 69 66 20 65 78 69 73 74 20 22 00 00 ff ff ff ff 09 00 00 00 20 67 6f 74 6f 20 74 72 79 00 00 00 d0 c2 b0 e6 b1 be bb b9 d2 aa d6 c6 d7 f7 d6 d0 2e 00 00 00 ff ff ff ff 06 00 00 00 64 65 6c 20 25 30 00 00 ff ff ff ff 04 00 00 00 65 78 69 74 00 00 00 00}  //weight: 100, accuracy: High
        $x_100_5 = {ff ff ff ff 2e 00 00 00 3a 5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65}  //weight: 100, accuracy: High
        $x_100_6 = {4e 6f 52 65 61 6c 4d 6f 64 65 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 57 69 6e 4f 6c 64 41 70 70 00 00 00 00}  //weight: 100, accuracy: High
        $x_100_7 = {ff ff ff ff 04 00 00 00 3a 74 72 79 00 00 00 00}  //weight: 100, accuracy: High
        $x_100_8 = {ff ff ff ff 05 00 00 00 64 65 6c 20 22 00 00 00 ff ff ff ff 01 00 00 00 22 00 00 00}  //weight: 100, accuracy: High
        $x_100_9 = {ff ff ff ff 08 00 00 00 32 30 30 35 30 31 30 31 00 00 00 00}  //weight: 100, accuracy: High
        $x_100_10 = {61 64 76 61 70 69 33 32 2e 64 6c 6c 00 00 00 00 51 75 65 72 79 53 65 72 76 69 63 65 43 6f 6e 66 69 67 32 41 00 00 00 00 51 75 65 72 79 53 65 72 76 69 63 65 43 6f 6e 66 69 67 32 57 00 00 00 00 43 68 61 6e 67 65 53 65 72 76 69 63 65 43 6f 6e 66 69 67 32 41 00 00 00 43 68 61 6e 67 65 53 65 72 76 69 63 65 43 6f 6e 66 69 67 32}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule PWS_Win32_Hupigon_ADF_2147596360_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Hupigon.ADF"
        threat_id = "2147596360"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 55 52 57 50 51 56 9c 54 68 00 00 00 00 8b 74 24 2c 89 e5 81 ec c0 00 00 00 89}  //weight: 1, accuracy: High
        $x_1_2 = "Shell_NotifyIconA" ascii //weight: 1
        $x_1_3 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_1_5 = "SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "DELME.BAT" ascii //weight: 1
        $x_1_7 = "if exist \"" ascii //weight: 1
        $x_1_8 = "goto try" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Hupigon_CA_2147596463_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Hupigon.CA"
        threat_id = "2147596463"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "QODNVD.com.cn_MUTEX" ascii //weight: 3
        $x_1_2 = "uninstal.bat" ascii //weight: 1
        $x_1_3 = "if exist \"" ascii //weight: 1
        $x_1_4 = "goto try" ascii //weight: 1
        $x_1_5 = "del %0" ascii //weight: 1
        $x_1_6 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
        $x_1_7 = "software\\microsoft\\windows\\currentversion\\policies\\winoldapp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Hupigon_CB_2147596920_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Hupigon.CB"
        threat_id = "2147596920"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "if exist \"" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "HACKER.com.cn" ascii //weight: 1
        $x_1_4 = "NoRealMode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Hupigon_F_2147609476_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Hupigon.gen!F"
        threat_id = "2147609476"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1458"
        strings_accuracy = "High"
    strings:
        $x_1000_1 = "bei_zhu" ascii //weight: 1000
        $x_100_2 = {ff ff ff ff 2e 00 00 00 3a 5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65}  //weight: 100, accuracy: High
        $x_100_3 = {ff ff ff ff 04 00 00 00 3a 74 72 79 00 00 00 00}  //weight: 100, accuracy: High
        $x_100_4 = {ff ff ff ff 05 00 00 00 64 65 6c 20 22 00 00 00 ff ff ff ff 01 00 00 00 22 00 00 00}  //weight: 100, accuracy: High
        $x_100_5 = {ff ff ff ff 0a 00 00 00 69 66 20 65 78 69 73 74 20 22 00 00 ff ff ff ff 09 00 00 00 20 67 6f 74 6f 20 74 72 79 00 00 00 ff ff ff ff 06 00 00 00 64 65 6c 20 25 30 00 00 ff ff ff ff 04 00 00 00 65 78 69 74 00 00 00 00}  //weight: 100, accuracy: High
        $x_100_6 = {61 64 76 61 70 69 33 32 2e 64 6c 6c 00 00 00 00 71 75 65 72 79 73 65 72 76 69 63 65 63 6f 6e 66 69 67 32 61 00 00 00 00 71 75 65 72 79 73 65 72 76 69 63 65 63 6f 6e 66 69 67 32 77 00 00 00 00 63 68 61 6e 67 65 73 65 72 76 69 63 65 63 6f 6e 66 69 67 32 61 00 00 00 63 68 61 6e 67 65 73 65 72 76 69 63 65 63 6f 6e 66 69 67 32}  //weight: 100, accuracy: High
        $x_100_7 = {73 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c 6a 01 e8 e2 ff ff ff}  //weight: 100, accuracy: High
        $x_100_8 = "RAV2_03LSLFJEIUBV" ascii //weight: 100
        $x_10_9 = "unhookwindowshookex" ascii //weight: 10
        $x_10_10 = "immgetcompositionstringa" ascii //weight: 10
        $x_10_11 = "callnexthookex" ascii //weight: 10
        $x_10_12 = "WriteProcessMemory" ascii //weight: 10
        $x_10_13 = "getkeyboardtype" ascii //weight: 10
        $x_10_14 = "20050101" ascii //weight: 10
        $x_10_15 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 73 65 74 75 70 00}  //weight: 10, accuracy: High
        $x_1_16 = {c7 03 30 00 00 00 c7 63 04 02 00 00 00 c7 63 08 03 00 00 00 33 c0 89 63 0c 33 c0 89 63 10 33 c0 89 63 14 33 c0 89 63 18 68}  //weight: 1, accuracy: High
        $x_1_17 = {07 00 42 00 42 00 41 00 42 00 4f 00 52 00 54 00}  //weight: 1, accuracy: High
        $x_1_18 = {05 00 42 00 42 00 41 00 4c 00 4c 00}  //weight: 1, accuracy: High
        $x_1_19 = {08 00 42 00 42 00 43 00 41 00 4e 00 43 00 45 00 4c 00}  //weight: 1, accuracy: High
        $x_1_20 = {07 00 42 00 42 00 43 00 4c 00 4f 00 53 00 45 00}  //weight: 1, accuracy: High
        $x_1_21 = {0c 00 50 00 52 00 45 00 56 00 49 00 45 00 57 00 47 00 4c 00 59 00 50 00 48 00}  //weight: 1, accuracy: High
        $x_1_22 = {06 00 48 00 41 00 43 00 4b 00 45 00 52 00}  //weight: 1, accuracy: High
        $x_1_23 = {0d 00 54 00 4d 00 41 00 49 00 4e 00 46 00 4f 00 52 00 4d 00 56 00 45 00 52 00 32 00}  //weight: 1, accuracy: High
        $x_1_24 = {08 00 4d 00 41 00 49 00 4e 00 49 00 43 00 4f 00 4e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1000_*) and 4 of ($x_100_*) and 5 of ($x_10_*) and 8 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 4 of ($x_100_*) and 6 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 5 of ($x_100_*))) or
            (all of ($x*))
        )
}

