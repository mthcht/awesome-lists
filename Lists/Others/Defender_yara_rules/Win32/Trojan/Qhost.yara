rule Trojan_Win32_Qhost_R_2147582937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.R"
        threat_id = "2147582937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 00 73 00 6d 00 72 00 74 00 6b 00 6e 00 [0-2] 5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 20 00 61 00 64 00 64 00 20 00 48 00 4b 00 4c 00 4d 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 [0-2] 20 00 2f 00 76 00 20 00 [0-2] 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 [0-2] 20 00 2f 00 64 00}  //weight: 10, accuracy: Low
        $x_10_2 = {40 00 2a 00 5c 00 41 00 44 00 3a 00 5c 00 63 00 61 00 6c 00 69 00 73 00 5c 00 73 00 6f 00 6d 00 75 00 72 00 74 00 6b 00 61 00 6e 00 5c 00 [0-64] 2e 00 76 00 62 00 70 00}  //weight: 10, accuracy: Low
        $x_5_3 = "smrtknsetupper" ascii //weight: 5
        $x_5_4 = "somurtkan_islem" ascii //weight: 5
        $x_1_5 = "\\drivers\\etc" wide //weight: 1
        $x_1_6 = {5c 00 73 00 6d 00 72 00 74 00 6b 00 6e 00 [0-2] 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_7 = {5c 00 73 00 6d 00 72 00 74 00 6b 00 6e 00 [0-2] 5c 00 67 00 65 00 62 00 65 00 72 00 69 00 70 00 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_8 = "notepad.exe c:\\sys.flat\\Dokuman.txt" wide //weight: 1
        $x_1_9 = "cmd /C copy c:\\sys.flat\\svchost.exe" wide //weight: 1
        $x_1_10 = "cmd /C copy c:\\sys.flat\\geberip.txt" wide //weight: 1
        $x_1_11 = "cmd /C copy c:\\sys.flat\\reg.exe" wide //weight: 1
        $x_1_12 = "lppathname.biz" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qhost_A_2147600494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.gen!A"
        threat_id = "2147600494"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 05 80 3e e9 75 1f 8b 46 01 3a 85 b0 0c 00 00 75 0e b0 00 0f c8 83 e8 05 03 c7 2b c6 89 46 01 83 c6 04 83 e9 04 46 49 83 f9 00 77 d0 eb 28 99 df 54 bc 77 f6 1c bc 77 31 3c bc 77 00 00 00 00 0a 31 32 37 2e 30 2e 30 2e 31 09 64 68 63 70 2e 76 6e 63 73 76 72 2e 63 6f 6d 00 00 0a 31 32 37}  //weight: 1, accuracy: High
        $x_1_2 = {0a 31 32 37 2e 30 2e 30 2e 31 09 64 68 63 70 2e 76 6e 63 73 76 72 2e 63 6f 6d 00 00 0a 31 32 37 2e 30 2e 30 2e 31 09 6d 76 6c 30 61 6e 37 2e 63 6f 6d 00 00 0a 31 32 37 2e 30 2e 30 2e 31 09 64 65 70 2e 6d 76 6c 30 61 6e 37 2e 63 6f 6d 00 00 0a 31 32 37 2e 30 2e 30 2e 31 09 6e 74 6b 72 6e 6c 70 61 2e 69 6e 66 6f 00 00 00 00 0a 31 32 37 2e 30 2e 30 2e 31 09 70 72 6f 78 69 6d 2e 6e 74 6b 72 6e 6c 70 61 2e 69 6e 66 6f 00 0a 31 32 37 2e 30 2e 30 2e 31 09 69 72 63 67 61 6c 61 78 79 2e 70 6c 00 0a 31 32 37 2e 30 2e 30 2e 31 09 70 72 6f 78 69 6d 61 2e 69 72 63 67 61 6c 61 78 79 2e 70 6c 00 0a 31 32 37 2e 30 2e 30 2e 31 09 70 72 6f 78 69 6d 2e 69 72 63 67 61}  //weight: 1, accuracy: High
        $x_1_3 = {2d 6c 61 62 73 2e 63 6f 6d 00 00 00 0a 31 32 37 2e 30 2e 30 2e 31 09 64 6e 6c 2d 65 75 31 2e 6b 61 73 70 65 72 73 6b 79 2d 6c 61 62 73 2e 63 6f 6d 00 00 00 0a 31 32 37 2e 30 2e 30 2e 31 09 64 6e 6c 2d 75 73 31 30 2e 6b 61 73 70 65 72 73 6b 79 2d 6c 61 62 73 2e 63 6f 6d 00 00 0a 31 32 37 2e 30 2e 30 2e 31 09 64 6e 6c 2d 75 73 39 2e 6b}  //weight: 1, accuracy: High
        $x_1_4 = {2e 31 09 75 70 64 61 74 65 37 2e 6a 69 61 6e 67 6d 69 6e 2e 63 6f 6d 00 0a 31 32 37 2e 30 2e 30 2e 31 09 75 70 64 61 74 65 2e 72 69 73 69 6e 67 2e 63 6f 6d 2e 63 6e 00 0a 31 32 37 2e 30 2e 30 2e 31 09 72 65 67 2e 72 69 73 69 6e 67 2e 63 6f 6d 2e 63 6e 00 00 00 00 0a 31 32 37 2e 30 2e 30 2e 31 09 6b 76 75 70 2e 6a 69 61 6e 67 6d 69 6e 2e 63 6f 6d 00 00 00 00 0a 31 32 37 2e 30 2e 30 2e 31 09 73 63 61 6e 2e 6b 69 6e 67 73 6f 66 74 2e 63 6f 6d 00 00 00 00 0a 31 32 37 2e 30 2e 30 2e 31 09 75 70 2e 72 69 73 69 6e 67 2e 63 6f 6d 2e 63 6e 00 0a 31 32 37 2e 30 2e 30 2e 31 09 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Qhost_IW_2147602351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.IW"
        threat_id = "2147602351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 56 57 89 65 e8 c7 45 ec ?? ?? 40 00 c7 45 f0 00 00 00 00 c7 45 f4 00 00 00 00 c7 45 fc 01 00 00 00 c7 45 fc 02 00 00 00 6a ff ff 15 40 10 40 00 c7 45 fc 03 00 00 00 ff 15 3c 10 40 00 89 45 c4 c7 45 bc 08 00 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {00 00 43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00 00 00}  //weight: 10, accuracy: High
        $x_10_3 = {5c 00 77 00 69 00 6e 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00 00 00 06 00 00 00 74 00 6d 00 70 00 00 00 16 00 00 00 5c 00 77 00 69 00 6e 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 00 00}  //weight: 10, accuracy: High
        $x_1_4 = "banamex.com" wide //weight: 1
        $x_1_5 = "banesco.com" wide //weight: 1
        $x_1_6 = "banesconline.com" wide //weight: 1
        $x_1_7 = "bancocontinental.com" wide //weight: 1
        $x_1_8 = "viabcp.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qhost_JA_2147605107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.JA"
        threat_id = "2147605107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 65 63 68 6f 20 6f 66 66 0d 0a 65 63 68 6f 20 [0-80] 3e 3e 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73}  //weight: 1, accuracy: Low
        $x_1_2 = "start http://" ascii //weight: 1
        $x_1_3 = {64 65 6c 20 22 00 5c 00 22 00 6f 70 65 6e 00 65 63 68 6f 20 3e 20 22}  //weight: 1, accuracy: High
        $x_1_4 = ".bat" ascii //weight: 1
        $x_1_5 = "ShellExecuteExA" ascii //weight: 1
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
        $x_1_7 = "CreatePipe" ascii //weight: 1
        $x_1_8 = "DeleteFileA" ascii //weight: 1
        $x_1_9 = "CreateProcessA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_CB_2147608978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.CB"
        threat_id = "2147608978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo 67.223.232.110 viabcp.com >> %windir%\\system32\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_2 = "start http://www.postales.com/buenos-deseos/animo/trampolin-al-cielo.htm" ascii //weight: 1
        $x_1_3 = "batchfile.bat" ascii //weight: 1
        $x_1_4 = "ShellExecuteExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_AM_2147612702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.AM"
        threat_id = "2147612702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 50 4e 50 23 44 6e 73 55 70 64 61 74 65 21 00 50 4e 50 23 44 41 54 41 00 00 00 00 44 41 54 41 42 41 53 45 00 00 00 00 5c 68 6f 73 74 73 00 00 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 00 00 00 5f 21 41 6e 74 69 57 65 62 54 21 5f}  //weight: 1, accuracy: High
        $x_1_2 = {55 70 64 61 74 65 2e 64 6c 6c 00 4d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_3 = {44 6e 73 46 6c 75 73 68 52 65 73 6f 6c 76 65 72 43 61 63 68 65 00 44 4e 53 41 50 49 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_BB_2147616545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.BB"
        threat_id = "2147616545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "C:\\WINDOWS\\system32\\drivers\\etc\\hosts" ascii //weight: 2
        $x_2_2 = {64 61 74 61 5c [0-8] 2e 64 6c 6c [0-4] 63 72 6f 73 73 66 69 72 65 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_1_3 = "\\d3d9.dll" ascii //weight: 1
        $x_1_4 = "\\d3dx9_37.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qhost_AQ_2147619226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.AQ"
        threat_id = "2147619226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://%s/go.php?gcode=%s" ascii //weight: 10
        $x_10_2 = "act.auto-codec.com" ascii //weight: 10
        $x_1_3 = "shoprinnai.com" ascii //weight: 1
        $x_1_4 = "ktcashmall.com" ascii //weight: 1
        $x_1_5 = "emart.co.kr" ascii //weight: 1
        $x_1_6 = "howmail.net" ascii //weight: 1
        $x_1_7 = "baidu.com" ascii //weight: 1
        $x_1_8 = "xpornosite.com" ascii //weight: 1
        $x_1_9 = "xxxparasite.com" ascii //weight: 1
        $x_1_10 = "sexytour.net" ascii //weight: 1
        $x_1_11 = "sexy4u.co.kr" ascii //weight: 1
        $x_1_12 = "pornotown.net" ascii //weight: 1
        $x_1_13 = "husler.co.kr" ascii //weight: 1
        $x_1_14 = "naver.com" ascii //weight: 1
        $x_1_15 = "yahoo.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qhost_AR_2147619323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.AR"
        threat_id = "2147619323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "127.0.0.1  viabcp.com" ascii //weight: 1
        $x_1_2 = "127.0.0.1  www.viabcp.com" ascii //weight: 1
        $x_1_3 = "127.0.0.1  scotiabank.com.pe" ascii //weight: 1
        $x_1_4 = "127.0.0.1  www.scotiabank.com.pe" ascii //weight: 1
        $x_1_5 = "127.0.0.1  bbvabancocontinental.com" ascii //weight: 1
        $x_1_6 = "127.0.0.1  www.bbvabancocontinental.com" ascii //weight: 1
        $x_1_7 = "iXato\\PharOlniNe\\Proyecto1.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_AV_2147622778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.AV"
        threat_id = "2147622778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 00 64 00 6f 00 62 00 65 00 6e 00 6f 00 75 00 00 00 04 00 2e 00 76 00 62 00 73 00}  //weight: 1, accuracy: High
        $x_1_2 = "strFileName = fso.GetSpecialFolder(0).Path & \"\\system32\\drivers\\etc\\hosts\"" ascii //weight: 1
        $x_1_3 = {53 65 74 20 4f 62 6a 46 69 6c 65 20 3d 20 6f 62 6a 46 53 4f 2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 73 74 72 46 69 6c 65 4e 61 6d 65 2c 20 32 29 20 0d 0a 6f 62 6a 46 69 6c 65 2e 57 72 69 74 65 4c 69 6e 65 20 22 32 30 32 2e 36 38 2e 32 32 35 2e 32 32 30 20 20 20 20 20 70 61 79 70 61 6c 2e 63 6f 6d 22}  //weight: 1, accuracy: High
        $x_1_4 = "objFile.WriteLine \"116.37.147.205     chase.com\"" ascii //weight: 1
        $x_1_5 = "strFileURL = \"http://116.37.147.205/hit.php\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_AW_2147622982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.AW"
        threat_id = "2147622982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 65 6c 20 25 77 69 6e 64 69 72 25 5c 68 6f 73 74 73 0d 0a 65 63 68 6f 20 31 38 39 2e 32 30 31 2e 36 35 2e 36 35 20 77 77 77 2e 62 61 6e 63 6f 6d 65 72 2e 63 6f 6d 2e 6d 78 20 3e 3e 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73}  //weight: 1, accuracy: High
        $x_1_2 = "del %windir%\\system32\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_3 = {61 74 74 72 69 62 20 2b 73 20 2b 68 20 2b 72 20 25 77 69 6e 64 69 72 25 5c 68 6f 73 74 73 0d 0a 69 70 63 6f 6e 66 69 67 20 2f 66 6c 75 73 68 64 6e 73}  //weight: 1, accuracy: High
        $x_1_4 = "echo 189.201.65.65 http://bbva.com >> %windir%\\system32\\drivers\\etc\\hosts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_AY_2147624627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.AY"
        threat_id = "2147624627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {47 65 74 54 65 6d 70 50 61 74 68 41 00}  //weight: 10, accuracy: High
        $x_1_2 = {6d 61 69 6c 2e 72 75 [0-2] 3e 3e [0-2] 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 30 00 [0-36] 65 63 68 6f}  //weight: 1, accuracy: Low
        $x_1_3 = {72 61 6d 62 6c 65 72 2e 72 75 [0-2] 3e 3e [0-2] 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 30 00 [0-36] 65 63 68 6f}  //weight: 1, accuracy: Low
        $x_1_4 = {79 61 6e 64 65 78 2e 72 75 [0-2] 3e 3e [0-2] 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 30 00 [0-36] 65 63 68 6f}  //weight: 1, accuracy: Low
        $x_1_5 = {76 6b 6f 6e 74 61 6b 74 65 2e 72 75 [0-2] 3e 3e [0-2] 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 30 00 [0-36] 65 63 68 6f}  //weight: 1, accuracy: Low
        $x_1_6 = {6f 64 6e 6f 6b 6c 61 73 [0-1] 6e 69 6b 69 2e 72 75 [0-2] 3e 3e [0-2] 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 30 00 [0-36] 65 63 68 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qhost_AZ_2147624785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.AZ"
        threat_id = "2147624785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "del killme.bat" wide //weight: 10
        $x_10_2 = "59.34.197.239/theopen.asp" wide //weight: 10
        $x_5_3 = "system32\\drivers\\etc\\hosts" wide //weight: 5
        $x_1_4 = {32 00 30 00 33 00 2e 00 31 00 37 00 31 00 2e 00 32 00 33 00 36 00 2e 00 32 00 31 00 35 00 [0-16] 77 00 77 00 77 00 2e 00 77 00 6f 00 77 00 63 00 68 00 69 00 6e 00 61 00 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_5 = {32 00 30 00 33 00 2e 00 31 00 37 00 31 00 2e 00 32 00 33 00 36 00 2e 00 32 00 31 00 35 00 [0-16] 77 00 77 00 77 00 2e 00 7a 00 74 00 67 00 61 00 6d 00 65 00 2e 00 63 00 6f 00 6d 00 2e 00 63 00 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qhost_BC_2147624856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.BC"
        threat_id = "2147624856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo 216.195.62.199 vkontakte.ru >> %windir%\\system32\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_2 = "echo ren %%windir%%\\system32\\drivers\\etc\\hosts1 hosts >> %windir%\\windstart.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_CC_2147628743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.CC"
        threat_id = "2147628743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d0 80 c2 0e 30 94 0d ?? ?? ?? ?? 83 f8 03 7e 04 33 c0 eb 03 83 c0 01 83 c1 01 81 f9 ?? ?? ?? ?? 7c dd}  //weight: 1, accuracy: Low
        $x_1_2 = {64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_BT_2147629457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.BT"
        threat_id = "2147629457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 6b 6f 6e 74 61 6b 74 65 2e 72 75 20 3e 3e 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 0d 0a 65 63 68 6f 20 03 00 2e 03 00 2e 03 00 2e 03 00 20 77 77 76 6b (2e 63|6f 6e 74 61 6b 74 65 2e) 20 3e 3e 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_CF_2147631728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.CF"
        threat_id = "2147631728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 72 69 76 65 72 73 2f 65 74 63 2f 68 6f 73 74 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {31 37 33 2e 32 31 32 2e 32 30 37 2e 32 31 36 20 20 20 20 76 6b 6f 6e 74 61 6b 74 65 2e 72 75 00}  //weight: 1, accuracy: High
        $x_1_3 = {64 65 6c 65 74 65 2e 62 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_CI_2147632778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.CI"
        threat_id = "2147632778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 00 [0-3] 03 00 2e 03 00 2e 03 00 2e 03 00 20 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 0d 0a 01 2e 02 2e 03 2e 04 20 77 77 77 2e 67 6f 6f 67 6c 65 2e}  //weight: 1, accuracy: Low
        $x_1_2 = {20 73 65 61 72 63 68 2e 79 61 68 6f 6f 2e 63 6f 6d 0d 0a 03 00 2e 03 00 2e 03 00 2e 03 00 20 75 73 2e 73 65 61 72 63 68 2e 79 61 68 6f 6f 2e 63 6f 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_CJ_2147632923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.CJ"
        threat_id = "2147632923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "127.0.0.1 www.virustotal.com" ascii //weight: 2
        $x_2_2 = "127.0.0.1 virusscan.jotti.org" ascii //weight: 2
        $x_2_3 = "127.0.0.1 forums.malwarebytes.org" ascii //weight: 2
        $x_1_4 = "DownloadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qhost_CL_2147633323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.CL"
        threat_id = "2147633323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "69.10.53.230 odnoklassniki.ru" ascii //weight: 1
        $x_1_2 = "69.10.53.230 vkontakte.ru" ascii //weight: 1
        $x_1_3 = "69.10.53.230 vk.com" ascii //weight: 1
        $x_1_4 = "echo \"%WINDIR%\\system32\\drivers\\etc\\hosts\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_CX_2147637301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.CX"
        threat_id = "2147637301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "echo start ShowSystemImage.exe >> %systemroot%\\fdsfsdfw.cmd" ascii //weight: 2
        $x_2_2 = "echo taskkill /im cmd.exe >> %systemroot%\\feeef.cmd" ascii //weight: 2
        $x_3_3 = "echo 184.82.43.206 www.odnoklassniki.ru >> %systemroot%\\system32\\drivers\\etc\\hosts" ascii //weight: 3
        $x_1_4 = "echo del /f /q *.scr >>  ~result.cmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qhost_DJ_2147639298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.DJ"
        threat_id = "2147639298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 8c 05 fc fb ff ff 8a 14 0e 88 11}  //weight: 1, accuracy: High
        $x_1_2 = {83 fa 01 74 02 75 03 80 33 01 8a 4d ?? 8a 45 ?? 24 01 3c 01 74 04}  //weight: 1, accuracy: Low
        $x_2_3 = {83 7d 08 02 0f 85 [0-5] 8b ?? 0c 8b ?? 04 [0-6] 2d 0f 85 [0-5] 6a 0f 68 ?? ?? ?? ?? b9 5b 00 00 00}  //weight: 2, accuracy: Low
        $x_1_4 = {42 3b d0 7e 94 8b 4d fc 5f 5e 33 cd 8d 85 fc fb ff ff 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qhost_DL_2147639987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.DL"
        threat_id = "2147639987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attrib +h +s \"%windir%\\system32\\drivers\\etc\\hosts\"" ascii //weight: 1
        $x_1_2 = {3e 3e 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 af 73 74 73}  //weight: 1, accuracy: High
        $x_1_3 = "echo 194.8.251.147" ascii //weight: 1
        $x_1_4 = "troy_bez_mail.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Qhost_DP_2147640616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.DP"
        threat_id = "2147640616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "% >> %windir%" ascii //weight: 3
        $x_2_2 = "attrib +%" ascii //weight: 2
        $x_2_3 = "tmp\\VKGuest.bat" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_DT_2147641802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.DT"
        threat_id = "2147641802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 32 37 2e 30 2e 30 2e 31 09 67 6f 6f 67 6c 65 2e 63 6f 6d 0d 0a 31 32 37 2e 30 2e 30 2e 31 09 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d}  //weight: 1, accuracy: High
        $x_1_2 = "%programfiles%\\AVG" ascii //weight: 1
        $x_1_3 = "ipconfig /flushdns" ascii //weight: 1
        $x_1_4 = {33 d2 f7 75 08 83 fa 09 76 05 80 c2 57 eb 03 80 c2 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_DW_2147642064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.DW"
        threat_id = "2147642064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 34 11 19 03 ca 42 3b d0 7c f2}  //weight: 2, accuracy: High
        $x_1_2 = {6c 6c 33 32 c7 45 ?? 2e 65 78 65 c7 45 ?? 20 73 65 74 c7 45 ?? 75 70 61 70}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 ee 1b c1 ?? 05 0b ?? 0f ?? c1 8a ?? 01 03 c6 42 84 c9 75 e9}  //weight: 1, accuracy: Low
        $x_1_4 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_5 = "127.0.0.1 d.360safe.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qhost_DX_2147642340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.DX"
        threat_id = "2147642340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "set golos=91.193.194.145" ascii //weight: 1
        $x_1_2 = "attrib -h -r %windir%%drapka%hos%lewro%" ascii //weight: 1
        $x_1_3 = "set drapka=\\system32\\drivers\\etc\\" ascii //weight: 1
        $x_1_4 = "echo 127.0.0.1 localhost >> %windir%%drapka%h" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_EJ_2147645373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.EJ"
        threat_id = "2147645373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "binary>>%windir%/SYS" ascii //weight: 1
        $x_1_2 = "get system_rem.exe>>%windir%/SYS" ascii //weight: 1
        $x_1_3 = "@ftp -vis:%windir%/SYS" ascii //weight: 1
        $x_1_4 = "@copy p.txt \"%windir%/system32/drivers/etc/hosts\" /Y" ascii //weight: 1
        $x_1_5 = "IF NOT EXIST \"%windir%/face.DLL\" GOTO" ascii //weight: 1
        $x_1_6 = "copy system_rem.exe \"%windir%\" /Y /B" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Qhost_EM_2147645609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.EM"
        threat_id = "2147645609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attrib +%ji% +r %windir%\\system32\\drivers\\etc\\%ji%osts" ascii //weight: 1
        $x_1_2 = {73 65 74 20 6a 69 3d 68 0d 0a 73 65 74 20 7a 69 3d 6e 0d 0a 65 63 25 6a 69 25 6f 20 39 31 2e 31 39 33 2e 31 39 34 2e 31 31 37 20 77 77 77 2e 76 6b 6f 25 7a 69 25 74 61 6b 74 65 2e 72 75 20 3e 3e 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 25 6a 69 25 6f 73 74 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_EN_2147645625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.EN"
        threat_id = "2147645625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows\\CurrentVersion\\Run\" /v \"v.exe\" /t REG_SZ /d" ascii //weight: 1
        $x_1_2 = "echo 178.63.9.124 facebook.com >> %systemroot%\\system32\\drivers\\etc\\hosts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_ET_2147647027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.ET"
        threat_id = "2147647027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {36 39 2e 31 36 33 2e 34 30 2e 31 31 31 20 20 20 77 77 77 2e 70 72 6f 76 69 6e 63 69 61 6c 2e 63 6f 6d 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {36 39 2e 31 36 33 2e 34 30 2e 31 31 31 20 20 20 68 74 74 70 3a 2f 2f 70 72 6f 76 69 6e 63 69 61 6c 2e 63 6f 6d 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_EU_2147647270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.EU"
        threat_id = "2147647270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 ee 73 74 73 [0-16] (23 20 43 6f 70 79 72 69 67|4d 79 47 75 65 73)}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 72 75 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_EY_2147647604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.EY"
        threat_id = "2147647604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 00 75 00 61 00 72 00 64 00 61 00 41 00 72 00 63 00 68 00 69 00 76 00 6f 00 [0-48] 43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Windows\\System32\\drivers\\winlogon.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_FD_2147647881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.FD"
        threat_id = "2147647881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {24 24 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 00 [0-16] fd 9a 80 5c 69 6e 65 74 63 2e 64 6c 6c 00 2f 65 6e 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = {65 78 65 00 68 74 74 70 3a 2f 2f 71 76 63 2e 63 6f 6d 2f 63 67 65 6e 2f 63 64 69 2e 6a 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_FH_2147648394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.FH"
        threat_id = "2147648394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ":\\WINDOWS\\system32\\drivers\\etc\\hosts.sys" ascii //weight: 10
        $x_2_2 = "91.220.0.38" ascii //weight: 2
        $x_1_3 = "yandex.ru" ascii //weight: 1
        $x_1_4 = "google.com" ascii //weight: 1
        $x_1_5 = "vkontakte.ru" ascii //weight: 1
        $x_1_6 = "91.223.89.101" ascii //weight: 1
        $x_1_7 = "93.73.148.17" ascii //weight: 1
        $x_1_8 = "97.253.19.9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qhost_F_2147648833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.gen!F"
        threat_id = "2147648833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 68 80 00 00 00 51 6a 00 52 50 8d 46 ?? 50 e8 ?? ?? ?? ?? 83 f8 ff 0f 84 ?? ?? ?? ?? 89 06 66 81 7e 04 b3 d7 0f 85 ?? ?? ?? ?? 66 ff 4e 04 6a 00 ff 36 e8 ?? ?? ?? ?? 40 0f 84 ?? ?? ?? ?? 2d 81 00 00 00 73 ?? 31 c0 6a 00 6a 00 50 ff 36 e8 ?? ?? ?? ?? 40 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {25 63 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 06}  //weight: 1, accuracy: High
        $x_1_3 = {63 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 2e 73 79 73 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_FL_2147649001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.FL"
        threat_id = "2147649001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 44 72 69 76 65 72 73 5c 45 74 63 5c 53 61 6e 64 62 6f 78 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = {4e 6f 74 68 69 6e 67 20 66 6f 75 6e 64 2c 20 65 78 65 63 75 74 69 6e 67 20 6d 61 6c 77 61 72 65 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = "Detected some Emulators/sandboxs, exiting..." ascii //weight: 1
        $x_1_4 = {5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 48 6f 73 74 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {74 73 6b 69 6c 6c 20 74 61 73 6b 6d 67 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_FM_2147649057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.FM"
        threat_id = "2147649057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill.exe /f /im" ascii //weight: 1
        $x_1_2 = "91.217.153.200" wide //weight: 1
        $x_1_3 = "BatLnk.lnk" wide //weight: 1
        $x_1_4 = "attrib +S +H +R" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_FR_2147649727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.FR"
        threat_id = "2147649727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".tmp\\encrypt_youtube.bat" ascii //weight: 1
        $x_1_2 = "%:\\WINDOWS\\system32\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_3 = "%://youtube.is-lost.org/nohup/total_visitas.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_FY_2147651128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.FY"
        threat_id = "2147651128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 8d 45 ?? b9 ?? ?? ?? 00 8b 55 ?? e8 ?? ?? ?? ?? 8b 45 00 e8 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 ee 73 74 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {76 6b 6f 6e 74 61 6b 74 65 2e 72 75 [0-16] ff ff ff ff ?? ?? ?? ?? [0-60] [0-48] 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_FZ_2147651219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.FZ"
        threat_id = "2147651219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "etc\\hosts" wide //weight: 10
        $x_1_2 = "yandex.ru" wide //weight: 1
        $x_1_3 = "google.com" wide //weight: 1
        $x_1_4 = "vkontakte.ru" wide //weight: 1
        $x_1_5 = "91.217.153.7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_GH_2147652122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.GH"
        threat_id = "2147652122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {63 6f 70 79 20 22 22 00 6f 53 68 65 6c 6c 4c 69 6e 6b 2e 41 72 67 75 6d 65 6e 74 73 20 3d 20 22 20 2f 63}  //weight: 2, accuracy: High
        $x_2_2 = {6f 53 68 65 6c 6c 4c 69 6e 6b 2e 49 63 6f 6e 4c 6f 63 61 74 69 6f 6e 20 3d 20 22 00 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 22 22 20 2f 59 22}  //weight: 2, accuracy: High
        $x_2_3 = "set oShellLink = WshShell.CreateShortcut(\"" ascii //weight: 2
        $x_1_4 = "Adobe Updater.lnk" ascii //weight: 1
        $x_1_5 = "filesys.DeleteFile(\"" ascii //weight: 1
        $x_1_6 = "\\checkexp.vbs\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qhost_GJ_2147652943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.GJ"
        threat_id = "2147652943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f3 a4 75 cc bb 0f 00 00 00 8d b4 24 0f 08 00 00 80 3e 40 74 4c}  //weight: 2, accuracy: High
        $x_1_2 = "system32\\drivers\\etc\\hests\",OverwriteExisting" ascii //weight: 1
        $x_1_3 = "system32\\drivers\\etc\\hosts\"\" /Y && attrib +H" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qhost_GL_2147653366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.GL"
        threat_id = "2147653366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Play_videos-iD=" ascii //weight: 1
        $x_1_2 = "bradesco.com.br" wide //weight: 1
        $x_1_3 = "bancoreal.com.br" wide //weight: 1
        $x_1_4 = "hsbc.com.br" wide //weight: 1
        $x_1_5 = "paypal.com" wide //weight: 1
        $x_1_6 = "americanexpress.com" wide //weight: 1
        $x_1_7 = "\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_8 = "69.162.64.147" wide //weight: 1
        $x_1_9 = "198.106.49.76" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_Qhost_GM_2147653639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.GM"
        threat_id = "2147653639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo 184.82.146.86 http://hotmail.com >> %windir%\\system32\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_2 = "echo 184.82.146.86 https://baneco.com.bo >> %windir%\\system32\\drivers\\etc\\hosts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_GP_2147655783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.GP"
        threat_id = "2147655783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\yeni\\Launcher.vbp" wide //weight: 5
        $x_5_2 = {5c 00 65 00 74 00 63 00 00 00 00 00 0c 00 00 00 5c 00 68 00 6f 00 73 00 74 00 73 00}  //weight: 5, accuracy: High
        $x_1_3 = "74.208.223.147 www.pvp-kenti.com" ascii //weight: 1
        $x_1_4 = "74.208.223.147 www.ko-cuce.net" ascii //weight: 1
        $x_1_5 = "74.208.223.147 www.hepgel.com" ascii //weight: 1
        $x_1_6 = "74.208.223.147 www.servertanitimi.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qhost_GR_2147656175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.GR"
        threat_id = "2147656175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "@echo off" ascii //weight: 4
        $x_4_2 = "\\drivers\\etc\\hosts" ascii //weight: 4
        $x_4_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 4
        $x_4_4 = "ping -n 1 localhost" ascii //weight: 4
        $x_4_5 = "for /l %%a in" ascii //weight: 4
        $x_1_6 = "bancoestado.cl >>" ascii //weight: 1
        $x_1_7 = "santander.cl >>" ascii //weight: 1
        $x_1_8 = "santandersantiago.cl >>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qhost_GT_2147656518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.GT"
        threat_id = "2147656518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 32 37 2e 30 2e 30 2e 31 09 77 77 77 2e 73 79 6d 61 6e 74 65 63 2e 63 6f 6d 0a 31 32 37 2e 30 2e 30 2e 31 09}  //weight: 1, accuracy: High
        $x_1_2 = {83 ec 04 89 c2 c7 44 24 10 00 00 00 00 8d 45 f8 89 44 24 0c 89 54 24 08 a1 ?? ?? ?? ?? 89 44 24 04 8b 45 fc 89 04 24 e8 ?? ?? ?? ?? 83 ec 14 a1 ?? ?? ?? ?? 89 04 24 e8 ?? ?? ?? ?? 83 ec 04 89 c2 c7 44 24 10 00 00 00 00 8d 45 f8 89 44 24 0c 89 54 24 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_HB_2147662554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.HB"
        threat_id = "2147662554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pinghux.exe" ascii //weight: 1
        $x_1_2 = "junming.exe" ascii //weight: 1
        $x_1_3 = "heshang.exe" ascii //weight: 1
        $x_1_4 = "huyoupox.exe" ascii //weight: 1
        $x_1_5 = "DETCAXZ.exe" ascii //weight: 1
        $x_1_6 = "ruyuhe851.exe" ascii //weight: 1
        $x_1_7 = "VnrYne173.exe" ascii //weight: 1
        $x_1_8 = "uMuezr352.exe" ascii //weight: 1
        $x_1_9 = "Xnuyen321.exe" ascii //weight: 1
        $x_1_10 = "TuxYwz569.exe" ascii //weight: 1
        $x_1_11 = "Cmweu1u.exe" ascii //weight: 1
        $x_1_12 = "dfe32UYD.exe" ascii //weight: 1
        $x_1_13 = "vJEHjZR.exe" ascii //weight: 1
        $x_10_14 = "drivers\\etc\\hosts" ascii //weight: 10
        $x_10_15 = "127.0.0.1       gms.ahnlab.com" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Qhost_IF_2147683607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.IF"
        threat_id = "2147683607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "c:\\users.txt" ascii //weight: 3
        $x_3_2 = "klenirken bekleyiniz..." ascii //weight: 3
        $x_3_3 = "sikesikeolm" ascii //weight: 3
        $x_3_4 = "tfen flash player y" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_PA_2147751625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.PA!MTB"
        threat_id = "2147751625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "C:\\WINDOWS\\system32\\svhchost.exe" wide //weight: 5
        $x_5_2 = "w1750996.ferozo.com/content/archivos/tarjetas/server.php" wide //weight: 5
        $x_2_3 = "El exe ya esta en su lugar" wide //weight: 2
        $x_2_4 = "No se detecto el exe" wide //weight: 2
        $x_2_5 = "listo exe en system" wide //weight: 2
        $x_2_6 = "New contenido en el server" wide //weight: 2
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_EC_2147914609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost.EC!MTB"
        threat_id = "2147914609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "z3r0_x Olucan Orjinal\\Project1.vbp" ascii //weight: 1
        $x_1_2 = "[AutoRun]" ascii //weight: 1
        $x_1_3 = "89.202.157.139" ascii //weight: 1
        $x_1_4 = "C:\\WINDOWS\\system32\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_5 = "ShowSuperHidden" ascii //weight: 1
        $x_1_6 = "UACDisableNotify" ascii //weight: 1
        $x_1_7 = "EnableLUA" ascii //weight: 1
        $x_1_8 = "DisableSR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qhost_17871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhost"
        threat_id = "17871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 43 61 70 74 69 6f 6e 06 [0-2] 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {07 43 61 70 74 69 6f 6e 06 [0-2] 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 2e 73 79 73}  //weight: 1, accuracy: Low
        $x_1_3 = {5d c3 54 61 73 6b 62 61 72 43 72 65 61 74 65 64 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

