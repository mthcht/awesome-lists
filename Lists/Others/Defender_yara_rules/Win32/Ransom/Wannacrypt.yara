rule Ransom_Win32_WannaCrypt_A_2147720966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.A!rsm"
        threat_id = "2147720966"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "7"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 61 75 6e 63 68 65 72 2e 64 6c 6c 00 50 6c 61 79 47 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 73 73 65 63 73 76 63 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WannaCrypt_A_2147720966_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.A!rsm"
        threat_id = "2147720966"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "7"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "f.wnry" ascii //weight: 1
        $x_1_2 = "%.1f BTC" ascii //weight: 1
        $x_1_3 = "@WanaDecryptor@.exe" ascii //weight: 1
        $x_1_4 = "%08X.eky" ascii //weight: 1
        $x_1_5 = "%08X.pky" ascii //weight: 1
        $x_1_6 = "%08X.res" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_WannaCrypt_A_2147720966_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.A!rsm"
        threat_id = "2147720966"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "7"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "500"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "__TREEID__PLACEHOLDER__" ascii //weight: 100
        $x_100_2 = "__USERID__PLACEHOLDER__" ascii //weight: 100
        $x_100_3 = "__TREEPATH_REPLACE__" ascii //weight: 100
        $x_100_4 = "tasksche.exe" ascii //weight: 100
        $x_100_5 = "qeriuwjhrf" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WannaCrypt_A_2147720966_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.A!rsm"
        threat_id = "2147720966"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "7"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 41 4e 41 43 52 59 21 00 00 00 00 25 00 73 00 5c 00 25 00 73 00 00 00 43 6c 6f 73 65 48 61 6e 64 6c 65 00 44 65 6c 65 74 65 46 69 6c 65 57 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 61 73 6b 73 63 68 65 2e 65 78 65 00 00 00 00 54 61 73 6b 53 74 61 72 74 00 00 00 74 2e 77 6e 72 79 00 00 69 63 61 63 6c 73 20 2e 20 2f 67 72 61 6e 74 20 45 76 65 72 79 6f 6e 65 3a 46 20 2f}  //weight: 1, accuracy: High
        $x_1_3 = {6d 73 67 2f 6d 5f 6b 6f 72 65 61 6e 2e 77 6e 72 79 0a 00 [0-112] 6d 73 67 2f 6d 5f 6c 61 74 76 69 61 6e 2e 77 6e 72 79 0a 00 20 00}  //weight: 1, accuracy: Low
        $x_1_4 = {25 30 38 58 2e 65 6b 79 00 00 00 00 25 30 38 58 2e 70 6b 79 00 00 00 00 25 30 38 58 2e 72 65 73}  //weight: 1, accuracy: High
        $x_1_5 = {74 61 73 6b 64 6c 2e 65 78 65 00 00 25 73 0a 00 66 2e 77 6e 72 79 00 00 61 74 00 00 63 6d 64 2e}  //weight: 1, accuracy: High
        $x_1_6 = {75 2e 77 6e 72 79 00 00 25 2e 31 66 20 42 54 43}  //weight: 1, accuracy: High
        $x_1_7 = {6b 67 70 74 62 65 69 6c 63 71 00 54 61 73 6b 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {4d 73 57 69 6e 5a 6f 6e 65 73 43 61 63 68 65 43 6f 75 6e 74 65 72 4d 75 74 65 78 57 00 63 6d 64 2e 65 78 65 20 2f 63 20 72 65 67 20 61 64 64 20}  //weight: 1, accuracy: High
        $x_1_9 = {5d c0 cd 6d da d7 d4 92 1e 13 82 34 6a 70 8d 8f 7c f7 04 92 55 7f f1 a2 27 b2 9e 41 ac 90 80 91 18 93 c2 b1 7b ad 2b f3 ff af db 2b 51 be 1d a3}  //weight: 1, accuracy: High
        $x_1_10 = {77 64 00 00 57 00 61 00 6e 00 61 00 43 00 72 00 79 00 70 00 74 00 30 00 72 00 00 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_WannaCrypt_2147721381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt"
        threat_id = "2147721381"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "125"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "%d.%d.%d.%d" ascii //weight: 50
        $x_50_2 = "\\\\%s\\ipc$" ascii //weight: 50
        $x_10_3 = "taskhcst.exe" ascii //weight: 10
        $x_10_4 = "lsasvs.exe" ascii //weight: 10
        $x_1_5 = "cowboy" ascii //weight: 1
        $x_1_6 = "sparky" ascii //weight: 1
        $x_1_7 = "bigdog" ascii //weight: 1
        $x_1_8 = "merlin" ascii //weight: 1
        $x_1_9 = "fucker" ascii //weight: 1
        $x_1_10 = "corvette" ascii //weight: 1
        $x_1_11 = "asshole" ascii //weight: 1
        $x_1_12 = "trustno1" ascii //weight: 1
        $x_1_13 = "fuckyou" ascii //weight: 1
        $x_1_14 = "fuckme" ascii //weight: 1
        $x_1_15 = "superman" ascii //weight: 1
        $x_1_16 = "welkome" ascii //weight: 1
        $x_1_17 = "root" ascii //weight: 1
        $x_1_18 = "letmein" ascii //weight: 1
        $x_1_19 = "dragon" ascii //weight: 1
        $x_1_20 = "passw0rd" ascii //weight: 1
        $x_1_21 = "p@ssw0rd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 1 of ($x_10_*) and 15 of ($x_1_*))) or
            ((2 of ($x_50_*) and 2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_WannaCrypt_2147721381_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt"
        threat_id = "2147721381"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "250"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "WanaCrypt0r" ascii //weight: 100
        $x_100_2 = "WANACRY!" ascii //weight: 100
        $x_10_3 = "icacls . /grant Everyone" ascii //weight: 10
        $x_10_4 = "attrib +h" ascii //weight: 10
        $x_10_5 = "cmd.exe /c" ascii //weight: 10
        $x_1_6 = ".lay6" ascii //weight: 1
        $x_1_7 = ".sqlite3" ascii //weight: 1
        $x_1_8 = ".sqlitedb" ascii //weight: 1
        $x_1_9 = ".accdb" ascii //weight: 1
        $x_1_10 = ".java" ascii //weight: 1
        $x_1_11 = ".class" ascii //weight: 1
        $x_1_12 = ".mpeg" ascii //weight: 1
        $x_1_13 = ".djvu" ascii //weight: 1
        $x_1_14 = ".tiff" ascii //weight: 1
        $x_1_15 = ".jpeg" ascii //weight: 1
        $x_1_16 = ".backup" ascii //weight: 1
        $x_1_17 = ".vmdk" ascii //weight: 1
        $x_1_18 = ".sldm" ascii //weight: 1
        $x_1_19 = ".sldx" ascii //weight: 1
        $x_1_20 = ".onetoc2" ascii //weight: 1
        $x_1_21 = ".vsdx" ascii //weight: 1
        $x_1_22 = ".potm" ascii //weight: 1
        $x_1_23 = ".potx" ascii //weight: 1
        $x_1_24 = ".ppam" ascii //weight: 1
        $x_1_25 = ".ppsx" ascii //weight: 1
        $x_1_26 = ".ppsm" ascii //weight: 1
        $x_1_27 = ".pptm" ascii //weight: 1
        $x_1_28 = ".pptx" ascii //weight: 1
        $x_1_29 = ".xltm" ascii //weight: 1
        $x_1_30 = ".xltx" ascii //weight: 1
        $x_1_31 = ".xlsb" ascii //weight: 1
        $x_1_32 = ".xlsm" ascii //weight: 1
        $x_1_33 = ".xlsx" ascii //weight: 1
        $x_1_34 = ".dotx" ascii //weight: 1
        $x_1_35 = ".dotm" ascii //weight: 1
        $x_1_36 = ".docm" ascii //weight: 1
        $x_1_37 = ".docb" ascii //weight: 1
        $x_1_38 = ".docx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 2 of ($x_10_*) and 30 of ($x_1_*))) or
            ((2 of ($x_100_*) and 3 of ($x_10_*) and 20 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_WannaCrypt_B_2147721388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.B"
        threat_id = "2147721388"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "!WannaDecryptor!" ascii //weight: 10
        $x_10_2 = "delete shadows /all /quiet" ascii //weight: 10
        $x_1_3 = ".lay6" ascii //weight: 1
        $x_1_4 = ".sqlite3" ascii //weight: 1
        $x_1_5 = ".sqlitedb" ascii //weight: 1
        $x_1_6 = ".accdb" ascii //weight: 1
        $x_1_7 = ".java" ascii //weight: 1
        $x_1_8 = ".class" ascii //weight: 1
        $x_1_9 = ".mpeg" ascii //weight: 1
        $x_1_10 = ".djvu" ascii //weight: 1
        $x_1_11 = ".tiff" ascii //weight: 1
        $x_1_12 = ".jpeg" ascii //weight: 1
        $x_1_13 = ".backup" ascii //weight: 1
        $x_1_14 = ".vmdk" ascii //weight: 1
        $x_1_15 = ".sldm" ascii //weight: 1
        $x_1_16 = ".sldx" ascii //weight: 1
        $x_1_17 = ".onetoc2" ascii //weight: 1
        $x_1_18 = ".vsdx" ascii //weight: 1
        $x_1_19 = ".potm" ascii //weight: 1
        $x_1_20 = ".potx" ascii //weight: 1
        $x_1_21 = ".ppam" ascii //weight: 1
        $x_1_22 = ".ppsx" ascii //weight: 1
        $x_1_23 = ".ppsm" ascii //weight: 1
        $x_1_24 = ".pptm" ascii //weight: 1
        $x_1_25 = ".pptx" ascii //weight: 1
        $x_1_26 = ".xltm" ascii //weight: 1
        $x_1_27 = ".xltx" ascii //weight: 1
        $x_1_28 = ".xlsb" ascii //weight: 1
        $x_1_29 = ".xlsm" ascii //weight: 1
        $x_1_30 = ".xlsx" ascii //weight: 1
        $x_1_31 = ".dotx" ascii //weight: 1
        $x_1_32 = ".dotm" ascii //weight: 1
        $x_1_33 = ".docm" ascii //weight: 1
        $x_1_34 = ".docb" ascii //weight: 1
        $x_1_35 = ".docx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 25 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_WannaCrypt_B_2147721392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.B!rsm"
        threat_id = "2147721392"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 41 4e 4e 41 43 52 59 00}  //weight: 2, accuracy: High
        $x_2_2 = "!WannaDecryptor!.exe" ascii //weight: 2
        $x_1_3 = {75 2e 77 72 79 00 00 00 25 2e 31 66 20 42 54 43}  //weight: 1, accuracy: High
        $x_1_4 = "WScript.CreateObject(\"WScript.Shell\")> c.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_WannaCrypt_B_2147721392_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.B!rsm"
        threat_id = "2147721392"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "500"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Global\\MsWinZonesCacheCounterMutexA" ascii //weight: 100
        $x_100_2 = "tasksche.exe" ascii //weight: 100
        $x_100_3 = "WNcry@2ol7" ascii //weight: 100
        $x_100_4 = "t.wnry" ascii //weight: 100
        $x_100_5 = "TaskStart" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WannaCrypt_A_2147721402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.A!!WannaCrypt.gen!A"
        threat_id = "2147721402"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        info = "WannaCrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 61 75 6e 63 68 65 72 2e 64 6c 6c 00 50 6c 61 79 47 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 73 73 65 63 73 76 63 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WannaCrypt_A_2147721402_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.A!!WannaCrypt.gen!A"
        threat_id = "2147721402"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        info = "WannaCrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 41 4e 41 43 52 59 21 00 00 00 00 25 00 73 00 5c 00 25 00 73 00 00 00 43 6c 6f 73 65 48 61 6e 64 6c 65 00 44 65 6c 65 74 65 46 69 6c 65 57 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 61 73 6b 73 63 68 65 2e 65 78 65 00 00 00 00 54 61 73 6b 53 74 61 72 74 00 00 00 74 2e 77 6e 72 79 00 00 69 63 61 63 6c 73 20 2e 20 2f 67 72 61 6e 74 20 45 76 65 72 79 6f 6e 65 3a 46 20 2f}  //weight: 1, accuracy: High
        $x_1_3 = {6d 73 67 2f 6d 5f 6b 6f 72 65 61 6e 2e 77 6e 72 79 0a 00 [0-112] 6d 73 67 2f 6d 5f 6c 61 74 76 69 61 6e 2e 77 6e 72 79 0a 00 20 00}  //weight: 1, accuracy: Low
        $x_1_4 = {25 30 38 58 2e 65 6b 79 00 00 00 00 25 30 38 58 2e 70 6b 79 00 00 00 00 25 30 38 58 2e 72 65 73}  //weight: 1, accuracy: High
        $x_1_5 = {74 61 73 6b 64 6c 2e 65 78 65 00 00 25 73 0a 00 66 2e 77 6e 72 79 00 00 61 74 00 00 63 6d 64 2e}  //weight: 1, accuracy: High
        $x_1_6 = {75 2e 77 6e 72 79 00 00 25 2e 31 66 20 42 54 43}  //weight: 1, accuracy: High
        $x_1_7 = {6b 67 70 74 62 65 69 6c 63 71 00 54 61 73 6b 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {4d 73 57 69 6e 5a 6f 6e 65 73 43 61 63 68 65 43 6f 75 6e 74 65 72 4d 75 74 65 78 57 00 63 6d 64 2e 65 78 65 20 2f 63 20 72 65 67 20 61 64 64 20}  //weight: 1, accuracy: High
        $x_1_9 = {5d c0 cd 6d da d7 d4 92 1e 13 82 34 6a 70 8d 8f 7c f7 04 92 55 7f f1 a2 27 b2 9e 41 ac 90 80 91 18 93 c2 b1 7b ad 2b f3 ff af db 2b 51 be 1d a3}  //weight: 1, accuracy: High
        $x_1_10 = {77 64 00 00 57 00 61 00 6e 00 61 00 43 00 72 00 79 00 70 00 74 00 30 00 72 00 00 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {31 c0 40 90 74 08 e8 09 00 00 00 c2 24 00 e8 a7 00 00 00 c3 e8 01 00 00 00 eb 90 5b b9 76 01 00 00 0f 32 a3 fc ff df ff 8d 43 17 31 d2 0f 30 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_WannaCrypt_D_2147721411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.D"
        threat_id = "2147721411"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 35 56 6a 01 85 ff 68 0c 03 00 00 74 0d 8b 44 24 18 50 ff 15 ?? ?? ?? ?? eb 0b}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 5f 25 73 2e 77 6e 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WannaCrypt_E_2147721412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.E"
        threat_id = "2147721412"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 19 8d 4c 24 10 51 ff d5 83 f8 04 74 0d 56 e8 ?? ?? ?? ?? 83 c4 04 6a 0a ff d7 4e 83 fe 02 7d bc}  //weight: 1, accuracy: Low
        $x_1_2 = ".WNCRYT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WannaCrypt_B_2147721434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.B!!WannaCrypt.gen!B"
        threat_id = "2147721434"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        info = "WannaCrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 41 4e 4e 41 43 52 59 00}  //weight: 2, accuracy: High
        $x_2_2 = "!WannaDecryptor!.exe" ascii //weight: 2
        $x_1_3 = {75 2e 77 72 79 00 00 00 25 2e 31 66 20 42 54 43}  //weight: 1, accuracy: High
        $x_1_4 = "WScript.CreateObject(\"WScript.Shell\")> c.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_WannaCrypt_2147721483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt!bit"
        threat_id = "2147721483"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@WanaDecryptor@.exe" ascii //weight: 1
        $x_1_2 = "your files have been encrypted" ascii //weight: 1
        $x_1_3 = "Your files will be lost" ascii //weight: 1
        $x_1_4 = "Send $300 worth of bitcoin to this address" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WannaCrypt_F_2147731094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.F!dha"
        threat_id = "2147731094"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 73 73 65 63 73 76 ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "PlayGame" ascii //weight: 1
        $x_1_3 = "launcher.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WannaCrypt_AT_2147761302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.AT!MTB"
        threat_id = "2147761302"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WANACRY!" wide //weight: 1
        $x_1_2 = "WNcry@2ol7" wide //weight: 1
        $x_1_3 = "icacls . /grant Everyone:F /T /C /Q" wide //weight: 1
        $x_1_4 = ".wnry" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WannaCrypt_DA_2147772309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.DA!MTB"
        threat_id = "2147772309"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msg/m_danish.wnry" ascii //weight: 1
        $x_1_2 = "msg/m_dutch.wnry" ascii //weight: 1
        $x_1_3 = "msg/m_filipino.wnry" ascii //weight: 1
        $x_1_4 = "msg/m_french.wnry" ascii //weight: 1
        $x_1_5 = "msg/m_german.wnry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WannaCrypt_DB_2147773122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.DB!MTB"
        threat_id = "2147773122"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WANNACRY" ascii //weight: 1
        $x_1_2 = ".wry" ascii //weight: 1
        $x_1_3 = "CryptImportKey" ascii //weight: 1
        $x_1_4 = "CryptDestroyKey" ascii //weight: 1
        $x_1_5 = "CryptDecrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WannaCrypt_SV_2147818949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.SV!MTB"
        threat_id = "2147818949"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WannaLock Ransomware" ascii //weight: 1
        $x_1_2 = "YOUR PC HAS BEEN LOCKED BY WANNALOCK RANSOMWARE!!!" ascii //weight: 1
        $x_1_3 = "PLEASE CONTACT https://message.bilibili.com/#whisper/mid490825280 TO FIX YOUR PC!!!" ascii //weight: 1
        $x_1_4 = "YOU MUST COMPLETE THIS IN ONE HOUR!!!OR YOU MUST SAY BYE BYE TO YOUR PC!!!" ascii //weight: 1
        $x_1_5 = "DONT REBOOT YOUR PC BECAUSE THIS WILL KILL YOUR PC!!!" ascii //weight: 1
        $x_1_6 = "Your Pensonal Number:" ascii //weight: 1
        $x_1_7 = "enter key below:" ascii //weight: 1
        $x_1_8 = "RIGHT KEY!!!DECRYPTING!!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WannaCrypt_CZ_2147827645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.CZ!MTB"
        threat_id = "2147827645"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mHtyDZcsrtT4/t3O+3smlSCOHOGPecD9WyHiK92g6U5yU" ascii //weight: 1
        $x_1_2 = "vgLv/4CGSWX5CdAY5bVOmiK3URqJGG6MCpTC5MB" ascii //weight: 1
        $x_1_3 = "172.16.99.5\\IPC$" wide //weight: 1
        $x_1_4 = "Rp/ovZWeh65j6G5mVS3o3Ux5cH2pfT/VZ" ascii //weight: 1
        $x_1_5 = "PlayGame" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WannaCrypt_AM_2147843597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.AM!MTB"
        threat_id = "2147843597"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 d8 1b c0 89 7c 94 10 25 44 88 00 00 05 60 40 00 00 8b c8 8b d9 c1 e9 02 f3 a5 8b cb 83 e1 03 f3 a4 8b 74 94 10 03 f0 89 74 94 10 42 83 fa 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WannaCrypt_SG_2147893950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaCrypt.SG!MTB"
        threat_id = "2147893950"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "eee.exe" ascii //weight: 1
        $x_1_2 = "CryptUnprotectMemory" ascii //weight: 1
        $x_2_3 = {6d 73 67 2f [0-15] 2e 77 6e 72 79}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

