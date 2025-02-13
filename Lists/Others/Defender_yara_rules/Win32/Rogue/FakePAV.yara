rule Rogue_Win32_FakePAV_154123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 6f 6d 70 75 74 65 72 20 73 61 66 65 74 79 0a 6c 65 76 65 6c 20 69 73}  //weight: 1, accuracy: High
        $x_1_2 = {70 65 72 66 6f 72 6d 61 6e 63 65 2c 20 63 6c 69 63 6b 20 6f 6e 0a 22 46 69 78 20 45 72 72 6f 72 73}  //weight: 1, accuracy: High
        $x_1_3 = "input type='hidden' name='subId' value=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakePAV_154123_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "is about to perform a full scan of your hard drive." ascii //weight: 1
        $x_1_2 = "\\completescan_pal" ascii //weight: 1
        $x_1_3 = "\\sold_pal" ascii //weight: 1
        $x_1_4 = "Your unique activation code:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakePAV_154123_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SelfDelete=\"1\"" ascii //weight: 2
        $x_2_2 = "7ZSfx%03x.cmd" wide //weight: 2
        $x_1_3 = "PasswordText=\"8daxzg58n9gs782\"" ascii //weight: 1
        $x_1_4 = "ExecuteFile=\"m5vmi6n606vqx6x.exe\"" ascii //weight: 1
        $x_1_5 = "PasswordText=\"0ekjohk513a4tf6\"" ascii //weight: 1
        $x_1_6 = "ExecuteFile=\"3yo4wo7q1jn6257.exe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/writelog2.php?did=" ascii //weight: 2
        $x_1_2 = "Security Essentials detected programs that may compromise your privacy or damage your computer" ascii //weight: 1
        $x_1_3 = "filelocal:/?/%TEMP%\\getkey.sys" ascii //weight: 1
        $x_1_4 = "Your unique activation code is:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_2 = "hotfix.exe" wide //weight: 1
        $x_1_3 = "Major Defense Kit" wide //weight: 1
        $x_1_4 = "AntiSpy Safeguard" wide //weight: 1
        $x_1_5 = "Peak Protection 2010" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakePAV_154123_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "The firewall module blocks network attacks and other types of online intrusion." ascii //weight: 1
        $x_1_2 = "Please remove all malware and perform the \"Cybercriminal activity test\" once again." ascii //weight: 1
        $x_1_3 = "was forced to shut down due to security reasons." ascii //weight: 1
        $x_1_4 = "This is not a valid key" ascii //weight: 1
        $x_1_5 = "Your unique activation code:" ascii //weight: 1
        $x_1_6 = "/activate.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakePAV_154123_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 69 6e 64 6f 77 73 20 41 63 74 69 76 65 20 47 75 61 72 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 6a 00 6a 00 6a 20 6a 00 6a 00 6a 00 83 7d ?? 00 74 ?? 8b 55 ?? eb ?? ba ?? ?? ?? ?? 52 6a 00 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakePAV_154123_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 00 68 00 69 00 6e 00 6b 00 50 00 6f 00 69 00 6e 00 74 00 2e 00 6c 00 6e 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 f8 8b c3 8b 08 ff 51 38 8d 45 f0 e8 ?? ?? ?? ?? ff 75 f0 68 ?? ?? ?? 00 ff 75 fc 8d 45 f4 ba 03 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakePAV_154123_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 f1 d1 e9 29 ca 76 ?? 01 d1 29 d6 66 b8 30 00 29 d6 eb ?? 66 89 04 56 4a 75}  //weight: 10, accuracy: Low
        $x_1_2 = "phishing" ascii //weight: 1
        $x_1_3 = "MoneyFlatInactiveColor" ascii //weight: 1
        $x_1_4 = "httpPayform" ascii //weight: 1
        $x_1_5 = "torrents" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakePAV_154123_9
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 f1 d1 e9 09 d2 78 1a 29 ca 76 16 29 d6 66 b8 ?? 00 29 d6 01 d1 eb ?? 66 89 04 56 4a}  //weight: 1, accuracy: Low
        $x_1_2 = "dfertter2342zc" ascii //weight: 1
        $x_1_3 = "zxczczxc" ascii //weight: 1
        $x_1_4 = "MoneyFlatInactiveColor" ascii //weight: 1
        $x_1_5 = {6d 73 63 6f 6e 66 69 67 00 6d 62 61 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakePAV_154123_10
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 57 69 6e 64 6f 77 73 20 50 72 6f 20 53 61 66 65 74 79 00 71 77 65 72 74 79 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 68 74 74 70 50 61 79 66 6f 72 6d 31 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 6a 00 6a 1a 6a 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 6a 00 6a 25 6a 00 e8 ?? ?? ?? ?? 66 c7 85 ?? ?? ?? ?? 54 00 8d 45 ?? e8 ?? ?? ?? ?? 8b c8 a1 ?? ?? ?? ?? ff 85 ?? ?? ?? ?? ba 05 00 00 00 8b 18 ff 53 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakePAV_154123_11
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0d 54 53 63 61 6e 69 6e 67 46 72 61 6d 65 09 00}  //weight: 1, accuracy: High
        $x_1_2 = "<b>Recommended:</b><br>Please click \"Remove All\" button" ascii //weight: 1
        $x_1_3 = "infected files and protect your PC" ascii //weight: 1
        $x_1_4 = {56 69 72 75 73 20 6e 61 6d 65 3a 00 53 65 63 75 72 69 74 79 20 52 69 73 6b 3a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakePAV_154123_12
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 7a 7a 2e 70 68 70 3f 00}  //weight: 2, accuracy: High
        $x_2_2 = {43 66 83 fb 5b [0-3] 0f 85 ?? ?? ?? ?? 8b 06 8b 80 ac 03 00 00 b2 01 8b 08 ff 51 64 8b 06 8b 80 ?? ?? 00 00 b2 01 8b 08 ff 51 64 68 ?? ?? ?? 00 ff 75 f4 68 ?? ?? ?? 00 ff 75 ec 68 ?? ?? ?? 00 68 ?? ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_3 = {6a 00 6a 00 8d 45 fc e8 ?? ?? ?? ?? 8d 45 fc 50 8d 4d f8 ba 03 00 00 00 b8 a8 1d 4c 00 e8 ?? ?? ?? ?? 8b 55 f8 58 e8 ?? ?? ?? ?? 8b 45 fc 50 a1 44 13 4d 00 50 6a 00 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Rogue_Win32_FakePAV_154123_13
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 69 6e 64 6f 77 73 20 53 65 63 75 72 65 20 53 75 72 66 65 72 00 63 6f 6d 66 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 65 74 65 72 72 6f 72 00 74 69 6d 65 6f 75 74 00 6e 6f 63 6f 6e 6e 65 63 74 69 6f 6e 00 63 6f 6e 6e 65 63 74 74 69 6d 65 6f 75 74 00 65 72 72 6f 72 66 6c 61 73 68 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 6a 00 6a 1a 6a 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 6a 00 6a 25 6a 00 e8 ?? ?? ?? ?? 66 c7 85 ?? ?? ?? ?? 3c 00 8d 45 ?? e8 ?? ?? ?? ?? 8b c8 ff 85 ?? ?? ?? ?? ba 05 00 00 00 8b 06 8b 18 ff 53 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakePAV_154123_14
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 02 8b 45 ?? 32 0b 88 08 66 c7 45 ?? 00 00 eb 09 00 99 f7 7d ?? 8b c2 8b 55}  //weight: 1, accuracy: Low
        $x_1_2 = "i_LMD_INSPECTOR" ascii //weight: 1
        $x_1_3 = "WebBrowser1BeforeNavigate2" ascii //weight: 1
        $x_1_4 = "phishing" ascii //weight: 1
        $x_1_5 = "your system is infected" ascii //weight: 1
        $x_1_6 = "attack" ascii //weight: 1
        $x_1_7 = "fraud" ascii //weight: 1
        $x_1_8 = "virus protection" ascii //weight: 1
        $x_1_9 = {72 75 6e 61 73 00 64 66 64 67 64 66 67 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Rogue_Win32_FakePAV_154123_15
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 57 69 6e 64 6f 77 73 20 50 72 69 6d 65 20 53 68 69 65 6c 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 00 6f 00 20 00 65 00 72 00 61 00 73 00 65 00 20 00 61 00 6c 00 6c 00 20 00 69 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 6e 00 64 00 20 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 20 00 79 00 6f 00 75 00 72 00 20 00 50 00 43 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\taskschd.msc" wide //weight: 1
        $x_1_4 = {00 50 61 79 46 6f 72 6d 00}  //weight: 1, accuracy: High
        $x_1_5 = {c7 76 5d dc c8 ca 5a 7b 9b e9 99 e1 f8 91 b4 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_FakePAV_154123_16
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 83 ce 00 00 00 a1 ?? ?? ?? ?? 50 8d 55 fc a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d fc ba ?? ?? ?? ?? a1 ?? ?? ?? ?? e8 c0 00 f7 ff 8d 55 f8 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {25 64 4b 62 00 25 32 2e 35 66 00 73 65 63 75 72 69 74 79 00 68 61 72 64 77 61 72 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 68 65 63 6b 42 6f 78 33 43 6c 69 63 6b [0-10] 52 61 64 69 6f 47 72 6f 75 70 32 43 6c 69 63 6b [0-10] 54 55 70 64 53 65 74}  //weight: 1, accuracy: Low
        $x_1_4 = {53 74 72 69 6e 67 47 72 69 64 31 44 72 61 77 43 65 6c 6c [0-10] 54 53 79 73 49 6e 66 6f 46 72 61 6d 65 [0-80] 50 72 69 76 61 63 79 00 70 72 69 76 61 63 79 00 63 6f 6e 66 69 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_FakePAV_154123_17
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 04 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 75 ?? 8d 45 fc ba 09 00 00 00 e8 ?? ?? ?? ?? 8b 55 fc 8b 83 ?? ?? 00 00 e8 ?? ?? ?? ?? 8d 4d ?? ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? b2 01}  //weight: 1, accuracy: Low
        $x_1_2 = "was launched succesfully but it was forced to shut down due to security reasons." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakePAV_154123_18
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MoneyFlatInactiveColor" ascii //weight: 1
        $x_1_2 = "i_LMD_INSPECTOR" ascii //weight: 1
        $x_1_3 = {53 63 61 6e 46 72 61 6d 65 1b 00 [0-5] 54 (53 63 61 6e 69 6e 67 46 72 61|46 72 61 6d 65 53 63 61 6e 69)}  //weight: 1, accuracy: Low
        $x_1_4 = "TFrmtor *" ascii //weight: 1
        $x_1_5 = "TAlertMail *" ascii //weight: 1
        $x_6_6 = {29 f1 d1 e9 29 ca 76 ?? 01 d1 29 d6 66 b8 30 00 29 d6 eb ?? 66 89 04 56 4a 75}  //weight: 6, accuracy: Low
        $x_6_7 = {59 29 f1 d1 e9 09 d2 78 1a 29 ca 76 16 29 d6 66 b8 30 00 29 d6 01 d1 eb 04 66 89 04 56 4a 75 f9 66 89 06 c3}  //weight: 6, accuracy: High
        $x_6_8 = {29 f1 d1 e9 09 d2 78 1a 29 ca 76 16 29 d6 66 b8 ?? 00 29 d6 01 d1 eb ?? 66 89 04 56 4a}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_6_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_19
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 f1 d1 e9 09 d2 78 1a 29 ca 76 16 29 d6 66 b8 ?? 00 29 d6 01 d1 eb ?? 66 89 04 56 4a}  //weight: 10, accuracy: Low
        $x_10_2 = {8a 0c 02 8b 45 ?? 32 0b 88 08 66 c7 45 ?? 00 00 eb 09 00 99 f7 7d ?? 8b c2 8b 55}  //weight: 10, accuracy: Low
        $x_1_3 = "phishing" ascii //weight: 1
        $x_1_4 = {73 63 61 6e 72 65 73 75 6c 74 00}  //weight: 1, accuracy: High
        $x_1_5 = "TTorrentForm" ascii //weight: 1
        $x_1_6 = {54 56 69 72 46 6f 72 6d 00}  //weight: 1, accuracy: High
        $x_1_7 = "MoneyFlatInactiveColor" ascii //weight: 1
        $x_2_8 = "httpPayform" ascii //weight: 2
        $x_1_9 = "webbrowser1beforenavigate2" ascii //weight: 1
        $x_1_10 = "TProcessManagerFrame" ascii //weight: 1
        $x_1_11 = "i_LMD_INSPECTOR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_20
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 63 61 6e 46 72 61 6d 65 1b 00 [0-5] 54 (53 63 61 6e 69 6e 67 46 72 61|46 72 61 6d 65 53 63 61 6e 69)}  //weight: 1, accuracy: Low
        $x_1_2 = {57 00 66 66 67 00 57 69 6e 64 6f 77 73 [0-21] 00 71 77 65 72 74 79 00}  //weight: 1, accuracy: Low
        $x_1_3 = {49 6e 66 65 63 74 65 64 00 4e 6f 74 20 63 6c 65 61 6e 65 64 00}  //weight: 1, accuracy: High
        $x_1_4 = "MoneyFlatInactiveColor" ascii //weight: 1
        $x_1_5 = "pi_LMD_INSPECTOR" ascii //weight: 1
        $x_2_6 = {6d 73 63 6f 6e 66 69 67 00 6d 62 61 6d 00 [0-48] 00 2e 6c 6e 6b 00}  //weight: 2, accuracy: Low
        $x_5_7 = {66 8b 04 42 66 83 c8 40 66 83 c8 20 66 0d 00 08 0f b7 c0 50 8b ?? fc 8b 10 ff 52 5c}  //weight: 5, accuracy: Low
        $x_2_8 = {ba 02 00 00 00 e8 ?? ?? ?? ?? 59 84 c9 74 0f 6a 00 8b 8d ?? ?? ff ff 51 ff 15 ?? ?? ?? ?? 66 c7 46 10 3c 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_21
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f b7 54 5a fe 33 ?? 66 89 54 58 fe 43}  //weight: 3, accuracy: Low
        $x_2_2 = "Think Point" wide //weight: 2
        $x_2_3 = {50 6a 00 6a 01 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 80 78 57 00 (75 ??|0f 85 ?? ?? ?? ??) a1 ?? ?? ?? ?? 8b 00 80 78 57 00}  //weight: 2, accuracy: Low
        $x_3_4 = "Current settings don't allow unprotected startup." wide //weight: 3
        $x_2_5 = {0e 74 68 69 6e 6b 70 6f 69 6e 74 6d 61 69 6e}  //weight: 2, accuracy: High
        $x_3_6 = {8b 38 ff 57 0c 8b 45 ?? e8 ?? ?? ?? ?? 50 6a 00 6a 01 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 80 7d eb 00 74}  //weight: 3, accuracy: Low
        $x_2_7 = {0f b7 10 33 55 f8 66 89 10 83 c0 02 4b 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_22
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 61 70 74 69 6f 6e 06 08 56 69 72 75 73 65 73 3a}  //weight: 1, accuracy: High
        $x_1_2 = "'hidden' name='projectId' value='%d'/><input type='hidden' name='partnerId'" ascii //weight: 1
        $x_1_3 = "potential personal information infiltration eliminated." ascii //weight: 1
        $x_1_4 = "Never.MUST.BE" wide //weight: 1
        $x_1_5 = "sc config WinDefend start= disabled" wide //weight: 1
        $x_1_6 = "net stop msmpsvc" wide //weight: 1
        $x_1_7 = {59 29 f1 d1 e9 09 d2 78 1a 29 ca 76 16 29 d6 66 b8 30 00 29 d6 01 d1 eb 04 66 89 04 56 4a 75 f9 66 89 06 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakePAV_154123_23
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {59 29 f1 d1 e9 09 d2 78 1a 29 ca 76 16 29 d6 66 b8 30 00 29 d6 01 d1 eb 04 66 89 04 56 4a 75 f9 66 89 06 c3}  //weight: 2, accuracy: High
        $x_1_2 = {09 70 32 70 61 6c 77 61 79 73}  //weight: 1, accuracy: High
        $x_1_3 = {00 25 64 2d 25 64 2d 25 64 5f 00 6e 65 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 6c 6e 6b 00 2f 63 20 64 65 6c 20 22 00 22 20 3e 3e 20 4e 55 4c 20}  //weight: 1, accuracy: High
        $x_1_5 = {4d 61 67 6e 69 66 69 65 72 00 42 72 61 6e 64 6d 61 75 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {68 64 77 77 69 7a 2e 63 70 6c 00 5c 53 79 73 74 65 6d 33 32 5c 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 72 65 73 75 6c 74 2e 64 62 00}  //weight: 1, accuracy: High
        $x_1_8 = "SIZE=\"+4\"><b>All-in-one Suite" ascii //weight: 1
        $x_1_9 = {14 41 6e 74 69 76 69 72 75 73 20 70 72 6f 74 65 63 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_10 = "click \"Auto Adjust\"" ascii //weight: 1
        $x_1_11 = "SIZE=\"+4\"><b>Anti-phishing protection" ascii //weight: 1
        $x_1_12 = "http://%s/?exe" ascii //weight: 1
        $x_1_13 = {49 6e 73 70 65 63 74 6f 72 00 42 72 6f 6b 65 6e 00}  //weight: 1, accuracy: High
        $x_1_14 = {72 75 6e 61 73 00 64 66 64 67 64 66 67 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_24
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 1e 43 b9 ?? 00 00 00 8b c3 99 f7 f9 89 c3 4b 33 5d ?? 43 b9 ?? 00 00 00 8b c3 99 f7 f9 89 c3 4b 83 c3 ?? 8b c3 83 e8 ?? 66 89 06 83 c6 ?? 4f 75 cd}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 8d 45 f4 50 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b 45 d8 e8 ?? ?? f6 ff eb ?? 6a 00 8d 45 f4 50 b9 ?? ?? ?? ?? ba 01 8b 45 d8 e8 ?? ?? f6 ff eb ?? 6a 00 8d 45 f4 50 b9 ?? ?? ?? ?? ba 01 8b 45 d8 e8 ?? ?? f6 ff 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 47 00 72 00 70 00 43 00 6f 00 6e 00 76 00 [0-16] 51 00 75 00 69 00 63 00 6b 00 20 00 4c 00 61 00 75 00 6e 00 63 00 68 00 [0-16] 4d 00 61 00 70 00 47 00 72 00 6f 00 75 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 [0-22] 73 00 6b 00 74 00 6f 00 70 00 [0-18] 53 00 68 00 65 00 6c 00 6c 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 73 00 [0-18] 53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 [0-18] 53 00 65 00 6e 00 64 00 54 00 6f 00}  //weight: 1, accuracy: Low
        $x_1_5 = {0b 54 46 6f 72 6d 5f 61 6c 65 72 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_FakePAV_154123_25
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 69 6e 64 6f 77 73 20 50 65 72 66 6f 72 6d 61 6e 63 65 20 41 64 76 69 73 65 72 00 73 64 66 67 68 6a 67 73 64 66 73 64 66 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 69 6e 64 6f 77 73 20 45 66 66 69 63 69 65 6e 63 79 20 41 63 63 65 6c 65 72 61 74 6f 72 00 73 64 66 67 68 6a 67 73 64 66 73 64 66 00}  //weight: 1, accuracy: High
        $x_1_3 = {57 69 6e 64 6f 77 73 20 50 72 65 6d 69 75 6d 20 47 75 61 72 64 00 78 63 76 6d 78 63 76 78 63 76 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00 5c 00 72 75 6e 61 73 00 78 63 76 78 63 76}  //weight: 1, accuracy: High
        $x_1_5 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00 74 61 73 6b 00 5c 00 72 75 6e 61 73 00 66 67 68 66 67 68 00}  //weight: 1, accuracy: High
        $x_1_6 = {57 69 6e 64 6f 77 73 20 49 6e 73 74 61 6e 74 20 53 63 61 6e 6e 65 72 00 71 77}  //weight: 1, accuracy: High
        $x_1_7 = {49 6e 66 65 63 74 65 64 00 4e 6f 74 20 63 6c 65 61 6e 65 64 00}  //weight: 1, accuracy: High
        $x_1_8 = {59 29 f1 d1 e9 09 d2 78 1a 29 ca 76 16 29 d6 66 b8 30 00 29 d6 01 d1 eb 04 66 89 04 56 4a 75 f9 66 89 06 c3}  //weight: 1, accuracy: High
        $x_1_9 = "i_LMD_INSPECTOR" ascii //weight: 1
        $x_1_10 = "MoneyFlatInactiveColor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Rogue_Win32_FakePAV_154123_26
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MoneyFlatInactiveColor" ascii //weight: 1
        $x_1_2 = "pi_LMD_INSPECTOR" ascii //weight: 1
        $x_1_3 = {00 68 74 74 70 50 61 79 66 6f 72 6d 31 00}  //weight: 1, accuracy: High
        $x_2_4 = {66 83 c8 20 66 83 c8 04 66 0d 00 08 0f b7 c0 50 8b 45 fc 8b 10 ff 52}  //weight: 2, accuracy: High
        $x_2_5 = {ba 02 00 00 00 e8 ?? ?? ?? ?? 59 84 c9 74 (0e|0f) 6a 00 8b (85|8d) ?? ?? ff ff (50|51) (ff 15|e8) ?? ?? ?? ?? 66 c7 (46 10|85 ?? ?? ff ff)}  //weight: 2, accuracy: Low
        $x_2_6 = {83 3b 00 75 07 b8 ?? ?? ?? ?? eb 02 8b 03 50 6a 00 6a 00 e8 ?? ?? ?? ?? (83 6d ?? 02 (??) 8d 45 ??|89 85 ?? ?? ff ff 8d 45 ?? 83 6d ?? ??) ba 02 00 00 00}  //weight: 2, accuracy: Low
        $x_2_7 = {3d b7 00 00 00 74 08 85 db 0f 85 ?? ?? 00 00 8b 0d ?? ?? ?? ?? 51 6a 00 e8 ?? ?? ?? ?? 8b d8 85 db 0f 84 ?? ?? 00 00 66 c7 85 ?? ?? ff ff 90 00 8d 45 ?? 8b 55 ?? e8}  //weight: 2, accuracy: Low
        $x_2_8 = {3d b7 00 00 00 0f 85 ?? ?? 00 00 8b 0d ?? ?? ?? ?? 51 6a 00 e8 ?? ?? ?? ?? 8b d8 85 db 0f 84 ?? ?? 00 00 66 c7 45 ?? ?? 00 8d 45 ?? 8b 55 ?? e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_27
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "mshta.exe \"http://%s/?0=%d&1=%d&2=%d&3=%s&4=%d&5=%d&6=%s&7=%s\"" wide //weight: 5
        $x_5_2 = {2f 00 63 00 75 00 73 00 74 00 6f 00 6d 00 67 00 61 00 74 00 65 00 2f 00 [0-16] 25 00 70 00 61 00 79 00 6d 00 65 00 6e 00 74 00 5f 00 75 00 72 00 6c 00 25 00}  //weight: 5, accuracy: Low
        $x_5_3 = "PhishFrame@@" ascii //weight: 5
        $x_5_4 = "ScanResult@@" ascii //weight: 5
        $x_5_5 = "Payform" ascii //weight: 5
        $x_5_6 = "AutoRunFrame" ascii //weight: 5
        $x_2_7 = "\\firewall.cpl" wide //weight: 2
        $x_2_8 = "defender" wide //weight: 2
        $x_2_9 = "mbam" wide //weight: 2
        $x_2_10 = "procexp" wide //weight: 2
        $x_2_11 = "regedit" wide //weight: 2
        $x_1_12 = {c7 76 5d dc c8 ca 5a 7b 9b e9 99 e1 f8 91 b4 e8}  //weight: 1, accuracy: High
        $x_1_13 = {78 da ed 9d 77 9c 5c 57 79 f7 7f e7 dc 32 bd 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_28
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 29 f1 d1 e9 09 d2 78 1a 29 ca 76 16 29 d6 66 b8 30 00 29 d6 01 d1 eb 04 66 89 04 56 4a 75 f9 66 89 06 c3}  //weight: 2, accuracy: High
        $x_2_2 = {0f b7 1f 89 75 ec 43 b9 01 00 00 00 8b c3 99 f7 f9 89 c3 4b 33 5d f8 43 b9 01 00 00 00 8b c3 99 f7 f9 89 c3 4b 4b 8d 43 01 8b 55 ec 66 89 84 55 ea fb ff ff 46 83 c7 02 81 fe 00 02 00 00 75 c0 8d 45 fc 33 d2}  //weight: 2, accuracy: High
        $x_2_3 = {ba 04 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 80 7d df 01 75 ?? b9 ?? ?? ?? ?? b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 d8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 6a 00 8d 45 f4 50}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 45 fc 85 c0 74 16 8b d0 83 ea 0a 66 83 3a 02 74 0b 8d 45 fc 8b 55 fc e8 ?? ?? ?? ?? 85 c0 74 05 83 e8 04 8b 00 48 89 45 f0 8b 5d f0 85 db 7c 34 43 33 f6 8d bd ea fb ff ff 8b 45 fc 85 c0 74 16 8b d0 83 ea 0a 66 83 3a 02 74 0b 8d 45 fc 8b 55 fc e8 ?? ?? ?? ?? 0f b7 04 70 66 89 07 46 83 c7 02 4b 75 d5}  //weight: 2, accuracy: Low
        $x_2_5 = {ff 50 1c 8d 4d f0 ba 04 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 d8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 0f b6 45 df 2c 01 72}  //weight: 2, accuracy: Low
        $x_2_6 = "PlmjoTkmjp*hjo" wide //weight: 2
        $x_2_7 = "ThinkPoint" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakePAV_154123_29
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {74 1b 6a 00 6a 00 68 64 04 00 00 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 00 e8}  //weight: 3, accuracy: Low
        $x_2_2 = {19 6a 00 6a 00 68 64 04 00 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 00 e8}  //weight: 2, accuracy: Low
        $x_2_3 = {0f b7 1e 43 b9 01 00 00 00 8b c3 99 f7 f9 89 c3 4b 33 5d f8 [0-18] 66 89 ?? 83 c6 02 4f 75}  //weight: 2, accuracy: Low
        $x_2_4 = {50 6a 00 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 00 e8}  //weight: 2, accuracy: Low
        $x_1_5 = {6a 00 6a 00 68 64 04 00 00 8d 4d}  //weight: 1, accuracy: High
        $x_2_6 = {6a 00 6a 00 68 64 04 00 00 56 e8 ?? ?? ?? ?? 6a 00 e8}  //weight: 2, accuracy: Low
        $x_2_7 = {7f 4c 04 f8 c3 80 05 1a 68 a4 02 0a 2e 38 4b 64}  //weight: 2, accuracy: High
        $x_3_8 = {e7 88 35 63 d0 6c cc 46 62 88 54 59 77 90 35 5c d0 86 e5 89 35 d6 49 9e d4 c9 9d de 09 9e c2 58}  //weight: 3, accuracy: High
        $x_3_9 = {e0 83 4e f8 cf 02 10 8c a1 0c 67 48 c3 1a da f0 86 38 cc e1 0c 15 68 37 04 d0 50 82 14 94 04 0d}  //weight: 3, accuracy: High
        $x_3_10 = {5c 86 15 fe 61 06 36 da f1 8e 78 64 e2 32 62 f0 c6 59 e4 f1 8e 6f cc c2}  //weight: 3, accuracy: High
        $x_3_11 = {2e 2e 2e 2e 2e 2e 2e 2e b9 5f fe fe 00 00 fe fe 5f b9 d5 d5 d5 d5 d5 d5 d5 d5 9a 89 70 73 73 0c}  //weight: 3, accuracy: High
        $x_3_12 = {34 3b 9e e5 d7 42 7c 4e 6f 76 dd ba fa 69 f1 2a}  //weight: 3, accuracy: High
        $x_3_13 = {aa 11 b0 b2 74 c0 03 f4 d0 3d 5d 12 b3 26 5a 8f}  //weight: 3, accuracy: High
        $x_3_14 = {87 37 0b 03 d6 c6 3f 30 10 60 e9 16 42 c0 89 00}  //weight: 3, accuracy: High
        $x_3_15 = {4c e1 c5 26 64 51 8b 90 64 40 3f c8 48 c9 4a 5a}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_30
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Your PC is under Ultimate Protection" ascii //weight: 1
        $x_1_2 = "operating system under maximum failure protection." ascii //weight: 1
        $x_1_3 = "Your system is clean and safe" ascii //weight: 1
        $x_1_4 = {59 29 f1 d1 e9 09 d2 78 1a 29 ca 76 16 29 d6 66 b8 30 00 29 d6 01 d1 eb 04 66 89 04 56 4a 75 f9 66 89 06 c3}  //weight: 1, accuracy: High
        $x_1_5 = {79 6f 75 72 20 50 43 20 69 73 20 62 65 69 6e 67 20 70 72 6f 74 65 63 74 65 64 20 62 79 20 00 20 41 6e 74 69 76 69 72 75 73 2e 00}  //weight: 1, accuracy: High
        $x_1_6 = "There's a suspicious software running on your PC." ascii //weight: 1
        $x_2_7 = "mshta.exe \"http://%s/?exe_id=%d&sub_id=%d&" ascii //weight: 2
        $x_1_8 = "Serious slowdown in system performance." ascii //weight: 1
        $x_2_9 = {74 61 73 6b 6d 67 72 00 70 72 6f 63 65 78 70 00 72 65 67 65 64 69 74 00 6d 73 73 65 63 65 73 00}  //weight: 2, accuracy: High
        $x_1_10 = {50 6a 00 68 30 00 00 02 e8 ?? ?? ?? ?? 8b f0 66 c7 45 ?? 48 00 85 f6 0f 84 ?? ?? 00 00 68 04 01 00 00 8d 85 ?? ?? ?? ff 50 56 ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_31
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 0c 02 8b 45 ?? 32 0b 88 08 66 c7 45 ?? 00 00 eb 09 00 99 f7 7d ?? 8b c2 8b 55}  //weight: 2, accuracy: Low
        $x_3_2 = {59 29 f1 d1 e9 09 d2 78 1a 29 ca 76 16 29 d6 66 b8 30 00 29 d6 01 d1 eb 04 66 89 04 56 4a 75 f9 66 89 06 c3}  //weight: 3, accuracy: High
        $x_2_3 = "FMoneyFlat" ascii //weight: 2
        $x_2_4 = "TPayFrm" ascii //weight: 2
        $x_2_5 = "TPhishFr" ascii //weight: 2
        $x_2_6 = {0d 54 53 63 61 6e 69 6e 67 46 72 61 6d 65 09 00}  //weight: 2, accuracy: High
        $x_1_7 = {09 70 32 70 61 6c 77 61 79 73}  //weight: 1, accuracy: High
        $x_1_8 = "virus protection" ascii //weight: 1
        $x_2_9 = "i_LMD_INSPECTOR" ascii //weight: 2
        $x_2_10 = "httpPayform" ascii //weight: 2
        $x_2_11 = "TSpamForm" ascii //weight: 2
        $x_2_12 = "TVirForm" ascii //weight: 2
        $x_2_13 = "@@Spam@Initialize" ascii //weight: 2
        $x_2_14 = "@@Vir@Initialize" ascii //weight: 2
        $x_2_15 = {29 f1 d1 e9 29 ca 76 ?? 01 d1 29 d6 66 b8 30 00 29 d6 eb ?? 66 89 04 56 4a 75}  //weight: 2, accuracy: Low
        $x_2_16 = {29 f1 d1 e9 09 d2 78 1a 29 ca 76 16 29 d6 66 b8 ?? 00 29 d6 01 d1 eb ?? 66 89 04 56 4a}  //weight: 2, accuracy: Low
        $x_2_17 = {6a 00 6a 00 6a 1a 6a 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 6a 00 6a 25 6a 00 e8 ?? ?? ?? ?? 66 c7 85 ?? ?? ?? ?? ?? 00 8d 45 ?? e8 ?? ?? ?? ?? 8b c8 a1 ?? ?? ?? ?? ff 85 ?? ?? ?? ?? ba 05 00 00 00 8b 18 ff 53 0c}  //weight: 2, accuracy: Low
        $x_2_18 = {54 53 43 46 52 41 4d 45 [0-18] 53 63 61 6e 46 72 61 6d 65}  //weight: 2, accuracy: Low
        $x_2_19 = "@@Autorun@Finalize" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_2_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_32
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 04 78 66 89 06 47 83 c6 02 4b 75 d5 bf 00 02 00 00 8d b5 ee fb ff ff 0f b7 1e 43 b9 01 00 00 00 8b c3 99 f7 f9 89 c3 4b 33 5d f8 66 89 1e 83 c6 02 4f 75 e3 8d 45 fc 33 d2}  //weight: 2, accuracy: High
        $x_2_2 = {ba 04 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 80 7d df 01 75 57 b9 ?? ?? ?? ?? b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 d8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 6a 00 8d 45 f4 50 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b 45 d8 e8}  //weight: 2, accuracy: Low
        $x_1_3 = {69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 47 00 72 00 70 00 43 00 6f 00 6e 00 76 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 51 00 75 00 69 00 63 00 6b 00 20 00 4c 00 61 00 75 00 6e 00 63 00 68 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4d 00 61 00 70 00 47 00 72 00 6f 00 75 00 70 00 73 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = "software of different vendors have conflict when installed" wide //weight: 1
        $x_1_6 = {76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 6f 00 66 00 20 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 6f 00 72 00 20 00 6e 00 65 00 65 00 64 00 20 00 61 00 6e 00 64 00 20 00 75 00 70 00 64 00 61 00 74 00 65 00 20 00 6f 00 72 00 20 00 61 00 64 00 64 00 2d 00 6f 00 6e 00 20 00 74 00 6f 00 20 00 66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 20 00 70 00 72 00 6f 00 70 00 65 00 72 00 6c 00 79 00 2e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_33
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {50 6a 00 68 30 00 00 02 e8 ?? ?? ?? ?? 89 ?? ?? ff ff ff 66 c7 46 10 48 00 83 bd ?? ?? ff ff 00 0f 84 ?? ?? ?? ?? 68 04 01 00 00 8d 95 ?? ?? ?? ff 52 ff b5 ?? ?? ff ff ff 95 ?? ?? ff ff 66 c7 46 10 60 00}  //weight: 3, accuracy: Low
        $x_3_2 = {c1 ef 02 33 db 89 bd ?? ?? ff ff e9 ?? ?? 00 00 8b 84 9d ?? ?? ?? ff 3b 85 ?? ?? ff ff 75 05 e9 ?? ?? 00 00 85 c0 0f 84 ?? ?? 00 00 50 6a 00 68 30 00 00 02}  //weight: 3, accuracy: Low
        $x_2_3 = {8a 14 0a 32 14 06 8b 45 ?? 88 14 08 41 3b d9 77 09 00 99 f7 7d ?? 8b c2 8b 55}  //weight: 2, accuracy: Low
        $x_2_4 = "There's a suspicious software running on your PC." ascii //weight: 2
        $x_1_5 = "Serious slowdown in system performance." ascii //weight: 1
        $x_1_6 = "Windows gets booted. More than 90% of PC issues" ascii //weight: 1
        $x_1_7 = "Auto Adjust completed." ascii //weight: 1
        $x_1_8 = "Warning! Your computer is at risk!" ascii //weight: 1
        $x_2_9 = {8a 0c 02 8b 45 ?? 32 0b 88 08 66 c7 45 ?? 00 00 eb 09 00 99 f7 7d ?? 8b c2 8b 55}  //weight: 2, accuracy: Low
        $x_2_10 = "Trojan activity detected. System data security is at risk." ascii //weight: 2
        $x_2_11 = {3d b7 00 00 00 74 08 85 ff 0f 85 ?? ?? 00 00 8b 0d ?? ?? ?? ?? 51 6a 00 e8 ?? ?? ?? ?? 8b f0 85 f6 0f 84}  //weight: 2, accuracy: Low
        $x_1_12 = {46 6c 61 73 68 20 64 6f 77 6e 6c 6f 61 64 20 65 72 72 6f 72 00}  //weight: 1, accuracy: High
        $x_1_13 = {14 4c 4d 44 53 70 65 65 64 42 75 74 74 6f 6e 31 43 6c 69 63 6b [0-24] 08 54 56 69 72 46 6f 72 6d}  //weight: 1, accuracy: Low
        $x_1_14 = {25 2a 73 20 25 64 2c 25 64 00 50 69 6e 67 [0-16] 68 74 74 70 50 61 79 66 6f 72 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_34
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\SOFTWARE\\PAV" wide //weight: 1
        $x_1_2 = "Hide details <<" wide //weight: 1
        $x_1_3 = "Scan Online" wide //weight: 1
        $x_1_4 = "cmd /C del \"" wide //weight: 1
        $x_1_5 = "cmd.exe /C del \"" wide //weight: 1
        $x_1_6 = "WarnonBadCertRecving" wide //weight: 1
        $x_1_7 = "AntiSpy Safeguard Instalation" wide //weight: 1
        $x_1_8 = "Antivirus Instalation" wide //weight: 1
        $x_5_9 = {74 24 50 6a 00 6a 01 e8 ?? ?? ?? ?? 8b d8 6a 00 53 e8 ?? ?? ?? ?? 6a ff 53 e8 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? b3 01 33 c0}  //weight: 5, accuracy: Low
        $x_4_10 = {50 6a 1a a1 ?? ?? ?? ?? 8b 00 8b 80 70 01 00 00 50 e8 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 8b 45 ?? 50 e8 ?? ?? ?? ?? 8d 45 ?? 8d 95 ?? ?? ff ff b9 05 01 00 00}  //weight: 4, accuracy: Low
        $x_4_11 = "/pipec/new.php?id=" wide //weight: 4
        $x_1_12 = {43 00 6c 00 65 00 61 00 6e 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_2_13 = "nd security for your PC!" wide //weight: 2
        $x_1_14 = "Click here to get the full version of the product" wide //weight: 1
        $x_1_15 = "ristics modul" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_35
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 56 6a 1a 56 ff d3 68 ?? ?? ?? ?? 56 56 6a 25 56 ff d3 bd 1c 01 00 00 55 56 bb ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 83 c4 0c 53}  //weight: 1, accuracy: Low
        $x_1_2 = {53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 62 00 63 00 6b 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 6a 00 6a 1a 6a 00 ff d7 68 ?? ?? ?? ?? 6a 00 6a 00 6a 25 6a 00 ff d7 68 1c 01 00 00 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c 68}  //weight: 1, accuracy: Low
        $x_1_4 = {57 57 6a 1a 57 ff d3 68 ?? ?? ?? ?? 57 57 6a 25 57 ff d3 68 1c 01 00 00 57 bb ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 83 c4 0c 53}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 00 6a 00 6a 1a 6a 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 6a 00 6a 25 6a 00 ff 15 ?? ?? ?? ?? 68 1c 01 00 00 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c c7 05 ?? ?? ?? ?? 1c 01 00 00 68}  //weight: 1, accuracy: Low
        $x_1_6 = {53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 31 00 31 00 32 00 32 00 33 00 33 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {72 00 65 00 67 00 2e 00 64 00 61 00 74 00 00 00 25 00 73 00 5c 00 25 00 73 00 00 00 25 64 25 64 25 64 00 00 77 00 2b 00 62}  //weight: 1, accuracy: High
        $x_1_8 = {53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 62 00 61 00 63 00 6b 00 31 00 32 00 33 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = "/payform/paged_form/buy.php?id=%d&sub_id=%d&install_id=%s" wide //weight: 1
        $x_1_10 = {53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 66 00 72 00 73 00 74 00 33 00 33 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {57 57 6a 1a 57 ff d6 68 ?? ?? ?? ?? 57 57 6a 25 57 ff d6 bd 1c 01 00 00 55 57 be ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 83 c4 0c 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Rogue_Win32_FakePAV_154123_36
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 6a 00 6a 1a 6a 00 ff d7 68 ?? ?? ?? ?? 6a 00 6a 00 6a 25 6a 00 ff d7 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 1c 01 00 00 6a 00 68 ?? ?? ?? ?? a3 ?? ?? ?? ?? e8}  //weight: 10, accuracy: Low
        $x_1_2 = "There's a suspicious software running on your PC." wide //weight: 1
        $x_10_3 = {75 fa 8b 46 02 3b 45 ?? 75 f2 fc ac 3c ?? 75 fb ac 3c ?? 75 02 31 c0 04 00 fd ac 3c}  //weight: 10, accuracy: Low
        $x_1_4 = {e8 0a 00 00 00 ad 35 ?? ?? ?? ?? ab e2 f2}  //weight: 1, accuracy: Low
        $x_1_5 = "Unprotected startup is unsafe for your private data!" ascii //weight: 1
        $x_1_6 = {53 00 65 00 44 00 65 00 62 00 75 00 67 00 50 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 00 00 00 00 72 00 75 00 6e 00 61 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_10_7 = {64 66 67 68 6a 6b 6c 00 53 68 65 6c 6c 33 32 2e 64 6c 6c 00}  //weight: 10, accuracy: High
        $x_1_8 = {8b 06 83 c6 04 35 ?? ?? ?? ?? 89 07 83 c7 04 e2 ef}  //weight: 1, accuracy: Low
        $x_1_9 = "Microsoft Corporation keys" wide //weight: 1
        $x_1_10 = {5c 00 72 00 65 00 73 00 75 00 6c 00 74 00 31 00 2e 00 64 00 62 00 00 00}  //weight: 1, accuracy: High
        $x_10_11 = {41 6e 74 69 76 69 72 75 73 20 43 6f 6d 70 6f 6e 65 6e 74 73 20 43 72 65 61 74 69 6f 6e 2e 2e 2e 00}  //weight: 10, accuracy: High
        $x_1_12 = {53 00 65 00 44 00 65 00 62 00 75 00 67 00 50 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 00 00 00 00 72 75 6e 61 73 00}  //weight: 1, accuracy: High
        $x_10_13 = {6a 00 6a 00 6a 1a 6a 00 ff d7 68 ?? ?? ?? ?? 6a 00 6a 00 6a 25 6a 00 ff d7 68 1c 01 00 00 6a 00 68 ?? ?? ?? ?? e8}  //weight: 10, accuracy: Low
        $x_1_14 = {5c 64 61 74 61 2e 67 66 00}  //weight: 1, accuracy: High
        $x_10_15 = {6a 39 8d 44 24 ?? 50 e8 ?? ?? ?? ?? 8b 00 55 6a 00 6a 00 68 ?? ?? ?? ?? 50 6a 00 ff 15 ?? ?? ?? ?? 83 f8 20 8d 4c 24 ?? 0f 97 c3}  //weight: 10, accuracy: Low
        $x_1_16 = {64 66 67 68 6a 6b 6c 00 53 00 68 00 65 00 6c 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00}  //weight: 1, accuracy: High
        $x_10_17 = {57 57 6a 1a 57 ff d3 68 ?? ?? ?? ?? 57 57 6a 25 57 ff d3 68 1c 01 00 00 57 bb ?? ?? ?? ?? 53 e8}  //weight: 10, accuracy: Low
        $x_1_18 = {64 66 67 68 6a 6b 6c 00 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 00}  //weight: 1, accuracy: High
        $x_10_19 = {6a 04 50 c6 45 ?? 02 e8 ?? ?? ?? ?? 8d 45 ?? 50 8d 45 ?? 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 ?? be ?? ?? ?? ?? 56 ff 15}  //weight: 10, accuracy: Low
        $x_1_20 = {2e 3f 41 56 43 61 64 77 61 72 65 41 70 70 40 40 00}  //weight: 1, accuracy: High
        $x_10_21 = {6a 39 8d 45 ?? 50 e8 ?? ?? ?? ?? (33 d2|57) 53 53 68 ?? ?? ?? ?? 8b c8 03 05 05 07 89 55 ?? 89 7d ?? c7 45 ?? ?? ?? 00 00 e8 ?? ?? ?? ?? 50 53 ff 15 ?? ?? ?? ?? 8b 4d ?? 83 f8 20 0f 97 45}  //weight: 10, accuracy: Low
        $x_10_22 = {6a 04 6a 06 ff 15 ?? ?? ?? ?? 8b ?? ?? 33 68 10 39 00 00 e8 ?? ?? ?? ?? 59 89 45}  //weight: 10, accuracy: Low
        $x_10_23 = {6a 00 6a 00 6a 1a 6a 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 6a 00 6a 25 6a 00 ff 15 ?? ?? ?? ?? 68 1c 01 00 00 6a 00 68 ?? ?? ?? ?? e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_37
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Viruses:" ascii //weight: 1
        $x_1_2 = "tst\\exe-" ascii //weight: 1
        $x_1_3 = {43 61 70 74 69 6f 6e 06 11 50 75 72 63 68 61 73 65 20 20 6c 69 63 65 6e 63 65}  //weight: 1, accuracy: High
        $x_1_4 = "/favicon.ico?0=%d&1=%d&2=%d&3=" ascii //weight: 1
        $x_1_5 = {8b d0 83 45 9c 02 8d 45 f4 e8 ?? ?? ?? ?? 83 6d 9c 02 8d 45 e4 ba 02 00 00 00 e8 ?? ?? ?? ?? 6a 08 68 ?? ?? ?? ?? ff 75 10}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 00 2d 75 6e 69 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 74 65 73 74 2e 6a 70 67 00 6b 65 72 6e 65 6c 33 32 00 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 62 75 79 00 5c 00 2e 6c 6e 6b 00 5c 00 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_9 = {66 b9 af 63 8b 16 0f bf de 81 ea ?? ?? ?? ?? 8b f8 81 f2 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_10 = "automated PC Benchmark utility" ascii //weight: 1
        $x_1_11 = {44 61 74 61 20 50 72 6f 74 65 63 74 69 6f 6e 00 48 61 72 64 20 44 69 73 6b 20 4f 70 74 69 6d 69 7a 61 74 69 6f 6e 00 4d 65 64 69 61 20}  //weight: 1, accuracy: High
        $x_1_12 = {5f 31 31 31 31 31 31 31 31 31 31 31 5f 00 65 00 00 65 00 2f 63 20 64 65 6c 20}  //weight: 1, accuracy: High
        $x_1_13 = "a 100%% computer security." ascii //weight: 1
        $x_1_14 = "'partnerId' value='%d'/><input type='hidden' name='serial' value='%s'/></form>" ascii //weight: 1
        $x_1_15 = {53 68 6f 77 20 64 65 74 61 69 6c 73 20 3e 3e 00 43 6c 65 61 6e 20 63 6f 6d 70 75 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_16 = {55 8b ec b8 ?? ?? ?? ?? c7 40 04 ?? ?? ?? ?? c7 00 ?? ?? ?? ?? c7 40 08 ?? 00 00 00 c7 40 0c ?? ?? ?? ?? c7 40 10 ?? 00 00 00 c7 40 14 ?? 00 00 00 5d c3 90 53 8b da 56 8b f0 8b 03 83 e8 11 74 0e 83 e8 05 74 09 2d 15 06 00 00 74 0e eb 17}  //weight: 1, accuracy: Low
        $x_1_17 = {57 61 72 6e 4f 6e 48 54 54 50 53 54 6f 48 54 54 50 52 65 64 69 72 65 63 74 00 00 42 75 69 6c 64 00 30 30 30 30 00}  //weight: 1, accuracy: High
        $x_1_18 = {49 6e 73 74 61 6c 6c 20 00 49 6e 73 74 61 6c 6c 20 00 25}  //weight: 1, accuracy: High
        $x_1_19 = {6d 69 63 72 6f 73 6f 66 74 00 61 70 70 6c 65 00 62 61 6e 6b 6f 66 61 6d 65 72 69 63 61 00}  //weight: 1, accuracy: High
        $x_1_20 = {25 32 2e 35 66 00 4e 6f 20 45 72 72 6f 72 73 20 46 6f 75 6e 64 00 73 65 63 75 72 69 74 79 00 68 61 72 64 77 61 72 65 00}  //weight: 1, accuracy: High
        $x_1_21 = {53 69 67 6e 61 74 75 72 65 00 43 50 55 20 46 61 75 6c 74 00 4d 65 6d 6f 72 79 20 50 61 67 65 20 46 61 75 6c 74 00 53 65 67 6d 65 6e 74 61 74 69 6f 6e 20 45 72 72 6f 72 00 44 4d 41 20 45 72 72 6f 72 00 49 6d 61 67 65 00 50 72 6f 63 65 73 73 20 49 44 00}  //weight: 1, accuracy: High
        $x_1_22 = {85 c0 74 26 6a 00 6a 00 8d 94 24 0c 01 00 00 52 8d 4c 24 0c 51 6a 00 6a 00 e8 ?? ?? ?? ?? 83 f8 20 7e 07 b8 01 00 00 00 eb 02 33 c0 81 c4 08 02 00 00 c3}  //weight: 1, accuracy: Low
        $x_1_23 = {52 65 6d 6f 76 65 00 51 75 61 72 61 6e 74 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_24 = {53 56 57 6a 00 68 00 00 00 20 6a 03 6a 00 6a 01 68 00 00 00 80 8b 45 08 50 e8 ?? ?? ?? ?? 8b f0 85 f6 75 07 33 c0 e9 ?? ?? ?? ?? 6a 00 68 02 00 00 20 6a 02 6a 00 6a 03 68 00 00 00 c0 8b 55 0c 52 e8}  //weight: 1, accuracy: Low
        $x_1_25 = {53 68 6f 77 57 69 6e 64 6f 77 00 62 75 79 00 20 20}  //weight: 1, accuracy: High
        $x_1_26 = {00 07 07 54 55 70 64 53 65 74}  //weight: 1, accuracy: High
        $x_1_27 = {62 75 79 00 20 20 53 63 61 6e 20 53 65 74 74 69 6e 67 73 00}  //weight: 1, accuracy: High
        $x_1_28 = {51 6a 00 6a 00 6a 1a 6a 00 ff d7 66 c7 45 84}  //weight: 1, accuracy: High
        $x_1_29 = {51 6a 00 6a 00 6a 1a 6a 00 ff 95 68 ff ff ff 66 c7 45 84 b4 00}  //weight: 1, accuracy: High
        $x_1_30 = {59 29 f1 d1 e9 09 d2 78 1a 29 ca 76 16 29 d6 66 b8 30 00 29 d6 01 d1 eb 04 66 89 04 56 4a 75 f9 66 89 06 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_FakePAV_154123_38
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e ab a7 44 f4 f5 7a 6c d8 80 09 16 81 6c 98 00}  //weight: 1, accuracy: High
        $x_1_2 = {09 d0 48 b7 1c 29 43 21 71 ce d4 32 51 66 66 e6}  //weight: 1, accuracy: High
        $x_1_3 = {7e 63 06 10 6f 52 73 68 63 75 4e 63 6a 76 63 74 28 63 7e 63 06 0b 55 63 67 56 69 74 72 28 63 7e}  //weight: 1, accuracy: High
        $x_1_4 = {0b 76 65 72 75 55 70 65 28 63 7e 63 06 0d 54 63 67 62 63 74 59 75 6a 28}  //weight: 1, accuracy: High
        $x_1_5 = {00 02 11 01 03 11 01 ff c4 0a 00 00 11 08 00 (c0|2d|f0) 02 (30|2d|40) 03 01}  //weight: 1, accuracy: Low
        $x_1_6 = {00 11 08 01 06 02 3a 03 01 ?? 00 02 11 01 03 11 01 ff c4}  //weight: 1, accuracy: Low
        $x_1_7 = {00 11 08 00 32 02 (30|2d|40) 03 01 ?? 00 02 11 01 03 11 01 ff c4}  //weight: 1, accuracy: Low
        $x_1_8 = {ab ab 61 6e 8c 61 6e 8c ab ab 61 6e 8c ab 15 65}  //weight: 1, accuracy: High
        $x_1_9 = {28 00 00 00 3a 02 00 00 06 01 00 00 01 00 08 00 00 00 00 00 68 49 02 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 11 08 01 31 02 2e 03 01 ?? 00 02 11 01 03 11 01 ff c4}  //weight: 1, accuracy: Low
        $x_1_11 = {28 00 00 00 a6 01 00 00 10 01 00 00 01 00 08 00 00 00 00 00 80 c2 01 00}  //weight: 1, accuracy: High
        $x_1_12 = {28 00 00 00 (30|2d|40) 02 00 00 (c0|2d|ef) 00 00 00 01 00 ?? 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_13 = {47 49 46 38 39 61 (30|2d|40) 02 (c0|2d|ef) 00 ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_14 = {47 49 46 38 39 61 (30|2d|40) 02 (2c|2d|34) 00 ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_15 = {28 00 00 00 (30|2d|40) 02 00 00 (2c|2d|34) 00 00 00 01 00 18 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_16 = {47 49 46 38 39 61 (30|2d|40) 02 (38|2d|40) 00 ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_17 = {28 00 00 00 (30|2d|40) 02 00 00 (38|2d|40) 00 00 00 01 00 08 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_18 = {0f b7 1f 89 75 ?? 43 b9 01 00 00 00 8b c3 99 f7 f9 89 c3 4b 33 5d}  //weight: 1, accuracy: Low
        $x_1_19 = "/inst_global.php?id=" wide //weight: 1
        $x_1_20 = "Essentials detected 1 potential threats" wide //weight: 1
        $x_1_21 = "To remove please install the heuristic module." wide //weight: 1
        $x_1_22 = {8b c3 83 e8 0a 66 83 38 02 74 0d 8d 45 ?? 8b 55 ?? e8 ?? ?? ?? ?? 8b d8 0f b7 04 7b 8b 55 ?? e8 ?? ?? ?? ?? 8b d0 8d 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 ?? e8 ?? ?? ?? ?? 47 4e 75}  //weight: 1, accuracy: Low
        $x_1_23 = {43 00 6c 00 65 00 61 00 6e 00 20 00 54 00 68 00 69 00 73 00 2e 00 6c 00 6e 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_24 = "/?messenger=softmarket" ascii //weight: 1
        $x_1_25 = {83 f8 01 1b c0 40 68 f4 01 00 00 e8 ?? ?? ?? ?? 8d 45 ?? e8}  //weight: 1, accuracy: Low
        $x_1_26 = {83 f8 01 1b c0 40 8d 55 ?? 33 c0 e8 ?? ?? ?? ?? ff 75 ?? 8d 55 ?? 33 c0 e8}  //weight: 1, accuracy: Low
        $x_1_27 = {89 c6 8b 45 ?? 50 (0f b6|8b 45 ??) 50 57 ff d6 8b f0 53 e8 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
        $x_2_28 = {19 43 6c 65 61 6e 20 54 68 69 73 20 2d 20 75 6e 72 65 67 69 73 74 65 72 65 64}  //weight: 2, accuracy: High
        $x_1_29 = {89 c6 8b 45 f8 50 8b 45 fc 50 57 ff d6 88 45 f7 53 e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: Low
        $x_1_30 = {83 e8 04 8b 00 8b d8 4b 8d 45 f8 8b 55 fc e8 ?? ?? ?? ?? 8b fb 85 ff 7c 40 47 33 f6 8b 5d fc 85 db 74 18 8b c3 83 e8 0a 66 83 38 02 74 0d}  //weight: 1, accuracy: Low
        $x_1_31 = {89 c6 6a 00 6a 06 ff d6 53 e8 ?? ?? ?? ?? 5e 5b c3}  //weight: 1, accuracy: Low
        $x_2_32 = {54 6a 1a a1 ?? ?? ?? ?? 8b 00 8b 80 ?? ?? 00 00 50 e8 ?? ?? ?? ?? 83 3c 24 00 74}  //weight: 2, accuracy: Low
        $n_2_33 = "Software\\LoopExpert\\TechExpert" ascii //weight: -2
        $n_2_34 = "TechExpert - LoopExpert Technologies, Inc - All rights reserved" wide //weight: -2
        $n_10_35 = ":\\POSBANK " ascii //weight: -10
        $n_10_36 = "Hideo-Maruyama" ascii //weight: -10
        $n_10_37 = ".surem.com/" wide //weight: -10
        $n_10_38 = "disinstalla ImmoPK" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_39
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 00 00 02 00 6a 01 6a 01 53 8d 54 24 ?? 52 8d 44 24 ?? 50 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 8b 08 8d 54 24 ?? 52 50 8b 41 38 ff d0}  //weight: 2, accuracy: Low
        $x_2_2 = {53 6a 01 68 01 04 00 00 56 ff 15 ?? ?? ?? ?? 33 c0 e9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 75 ?? 8b ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 6a 02 ff}  //weight: 2, accuracy: Low
        $x_1_3 = {49 00 6d 00 61 00 67 00 65 00 20 00 46 00 69 00 6c 00 65 00 20 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 20 00 4f 00 70 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 4d 00 53 00 4d 00 50 00 45 00 4e 00 47 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_2_4 = {68 00 00 02 00 56 56 53 8d 45 ?? 50 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 8b 75 ?? 8b 45 ?? 8b 08 8d 55 ?? 52 50 ff 51 38}  //weight: 2, accuracy: Low
        $x_2_5 = "%s \"%sWindows\\CurrentVersion\\%s\" /v \"MSMPENG\" /t REG_SZ /d \"%s\" /f" wide //weight: 2
        $x_2_6 = {68 00 00 02 00 6a 01 6a 01 6a 00 8d (45|4d) ?? (50|51) 8d (?? ?? ?? ?? ??|?? ??) (51|52) ff 15 ?? ?? ?? ?? 8d (45|55) ?? (50|52) 8b (45|4d) ?? 8b (08|11) 8b (45|55) ?? (50|52) 8b (41|4a) 38 ff (d0|d1)}  //weight: 2, accuracy: Low
        $x_2_7 = {6a 00 6a 01 68 01 04 00 00 8b (45|4d) ?? (50|51) ff 15 ?? ?? ?? ?? 33 c0 e9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 75 ?? 68 ?? ?? ?? ?? 6a 00 6a 02 ff 15}  //weight: 2, accuracy: Low
        $x_1_8 = {68 00 00 02 00 6a 01 6a 01 6a 00 (8d|8b) ?? ?? ?? ?? ?? ?? 03 02 04 04 6a 00 8d ?? ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8d ?? ?? ?? 8b ?? ?? 8b ?? 8b ?? ?? ?? 8b ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_9 = {5c 00 52 00 75 00 6e 00 00 00 46 00 32 00 73 00 00 00 53 00 68 00 65 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_2_10 = {68 00 00 02 00 56 56 53 53 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 8b 45 ?? 8b 08 8d 55 ?? 52 50 ff 51 38}  //weight: 2, accuracy: Low
        $x_1_11 = {57 69 6e 64 6f 77 73 20 49 6e 74 65 72 6e 65 74 20 47 75 61 72 64 00}  //weight: 1, accuracy: High
        $x_1_12 = "SC.Exe config msmpsvc start= disabled" wide //weight: 1
        $x_2_13 = {2f 00 76 00 20 00 20 00 22 00 4d 00 73 00 4d 00 70 00 65 00 4e 00 47 00 22 00 20 00 20 00 2f 00 74 00 20 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 20 00 22 00 25 00 73 00 22 00 20 00 2f 00 66 00 00 00}  //weight: 2, accuracy: High
        $x_2_14 = {68 00 00 02 00 57 57 53 53 (8d 45 ??|53) ff 15 ?? ?? ?? ?? 8b 45 ?? 8b 08 8d 55 ?? 52 50 ff 51 38}  //weight: 2, accuracy: Low
        $x_2_15 = {68 00 00 02 00 53 53 57 57 8d (54|44) 24 ?? (52|50) ff 15 ?? ?? ?? ?? 8b 44 24 ?? 8b 08 8d 54 24 ?? 52 50 8b 41 38 ff d0}  //weight: 2, accuracy: Low
        $x_2_16 = {68 00 00 02 00 6a 01 6a 01 6a 00 6a 00 03 05 05 05 8d 95 ?? ?? ?? ?? 8b 55 ?? 8b 95 ?? ?? ?? ?? 52 ff 15 ?? ?? ?? ?? 8d 45 ?? 50 8b 4d ?? 8b 11 8b 45 ?? 50 8b 4a 38 ff d1}  //weight: 2, accuracy: Low
        $x_2_17 = {68 00 00 02 00 6a 01 6a 01 55 55 56 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 8b 10 8b 52 38 8d 4c 24 ?? 51 50 ff d2}  //weight: 2, accuracy: Low
        $x_2_18 = {68 00 00 02 00 6a 01 6a 01 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8d (4d|55) ?? (51|52) 8b (55|45) ?? 8b (02|08) 8b (4d|55) ?? (51|52) 8b (50|41) 38 ff (d2|d0)}  //weight: 2, accuracy: Low
        $x_2_19 = {68 00 00 02 00 53 53 57 57 57 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 8b 10 8b 52 38 8d 4c 24 ?? 51 50 ff d2}  //weight: 2, accuracy: Low
        $x_2_20 = {68 00 00 02 00 55 55 53 53 8d 44 24 ?? 50 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 8b 08 8d 54 24 ?? 52 50 8b 41 38 ff d0}  //weight: 2, accuracy: Low
        $x_1_21 = {57 69 6e 64 6f 77 73 20 57 65 62 20 53 68 69 65 6c 64 20 00}  //weight: 1, accuracy: High
        $x_1_22 = {6a 00 68 a0 0f 00 00 6a 64 8b 45 08 50 ff 15 ?? ?? ?? ?? 6a 00 68 f4 01 00 00 6a 65 8b 4d 08 51 ff 15 ?? ?? ?? ?? 8b 55 08 52 e8}  //weight: 1, accuracy: Low
        $x_1_23 = {68 00 00 02 00 6a 01 6a 01 6a 00 6a 00 6a 00 ff 95 ?? ?? ?? ?? 8d 4d ?? 51 8b 55 ?? 8b 02 8b 4d ?? 51 8b 50 38 ff d2}  //weight: 1, accuracy: Low
        $x_2_24 = {68 00 00 02 00 57 57 53 53 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 45 ?? 8b 08 8d 55 ?? 52 50 ff 51 38}  //weight: 2, accuracy: Low
        $x_2_25 = {68 00 00 02 00 6a 01 6a 01 6a 00 6a 00 8b 8d ?? ?? ?? ?? 51 ff 95 ?? ?? ?? ?? 8d 55 ?? 52 8b 45 ?? 8b 08 8b 55 ?? 52 8b 41 38 ff d0}  //weight: 2, accuracy: Low
        $x_2_26 = {49 00 6d 00 61 00 67 00 65 00 50 00 61 00 74 00 68 00 00 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00}  //weight: 2, accuracy: High
        $x_2_27 = {53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 00 00}  //weight: 2, accuracy: High
        $x_2_28 = {83 c1 02 66 89 8d ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 18 00 00 00 c7 85 ?? ?? ?? ?? 00 00 00 00 c7 85 ?? ?? ?? ?? 40 00 00 00 8d 95 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 00 00 00 00 c7 85 ?? ?? ?? ?? 00 00 00 00 8d 85 ?? ?? ?? ?? 50 68 3f 00 0f 00 8d 8d ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 74 17 8d 55 ?? 52 8b 85 ?? ?? ?? ?? 50 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_40
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 50 00 41 00 56 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {5c 00 66 00 69 00 6c 00 72 00 [0-18] 77 00 61 00 6c 00 6c 00 2e 00 6c 00 6f 00 67 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {4c 00 6f 00 61 00 64 00 69 00 6e 00 67 00 20 00 68 00 65 00 75 00 72 00 69 00 73 00 74 00 69 00 63 00 20 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 3a 00 00 00}  //weight: 2, accuracy: High
        $x_1_4 = {22 00 20 00 67 00 6f 00 74 00 6f 00 20 00 64 00 65 00 6c 00 63 00 79 00 63 00 6c 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "defender.exe" wide //weight: 1
        $x_1_6 = "Please wait while the update modules." wide //weight: 1
        $x_1_7 = "/index_new.php?id=" wide //weight: 1
        $x_1_8 = "/inst.php?id=" wide //weight: 1
        $x_1_9 = "/preinst.php?id=" wide //weight: 1
        $x_1_10 = "Outdated viruses databases are not effective" wide //weight: 1
        $x_1_11 = {61 00 6e 00 74 00 69 00 73 00 70 00 79 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = "Required heuristics module" wide //weight: 1
        $x_3_13 = {53 8b d8 6a 1e 6a 01 68 0a 04 00 00 8b 83 a4 03 00 00 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 1e 6a 01 68 0a 04 00 00 8b 83 b4 03 00 00 e8 ?? ?? ?? ?? 50 e8}  //weight: 3, accuracy: Low
        $x_3_14 = {b8 64 00 00 00 e8 ?? ?? ?? ?? 8b d8 83 fb 32 (7d ??|0f 8d ?? ??) 6a 03 6a 14 (b9|68|a1)}  //weight: 3, accuracy: Low
        $x_3_15 = {75 1a 6a 00 8b 85 ?? ?? ff ff 50 6a 00 6a 01 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b f8 8d 95 ?? ?? ff ff 8b c6 e8 ?? ?? ?? ?? 83 f8 01 1b db 43 84 db}  //weight: 3, accuracy: Low
        $x_3_16 = {75 1a 6a 00 8b 85 ?? ?? ff ff 50 6a 00 6a 01 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b f8 83 ff 01 75 [0-32] 8b c6 e8 ?? ?? ?? ?? 83 f8 01 1b db 43 84 db}  //weight: 3, accuracy: Low
        $x_3_17 = {6a 00 8b 85 ?? ?? ff ff 50 6a 00 6a 01 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 f8 01 [0-40] 83 f8 01 1b db 43}  //weight: 3, accuracy: Low
        $x_2_18 = "Microsoft Security Essentials trying to download the setup files." wide //weight: 2
        $x_2_19 = "nd security for your PC!" wide //weight: 2
        $x_3_20 = {d1 fa 79 03 83 d2 00 [0-8] a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? 8b d0 81 ea f4 01 00 00 83 c2 4c}  //weight: 3, accuracy: Low
        $x_2_21 = {8b d0 81 ea f4 01 00 00 83 c2 4c d1 fa 79 03 83 d2 00 a1 ?? ?? ?? ?? 8b 00 e8}  //weight: 2, accuracy: Low
        $x_2_22 = {6a 00 6a 00 8b 45 f8 [0-5] 50 8b 45 fc [0-5] 50 6a 00 e8 ?? ?? ?? ?? 85 c0 75 0d 8b 45 f4 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0}  //weight: 2, accuracy: Low
        $x_2_23 = "#Microsoft Security Essentials Alert" ascii //weight: 2
        $x_1_24 = {83 e8 03 75 ?? 8d 45 ?? 8b d3 e8 ?? ?? ?? ?? 8d 45 ?? [0-32] e8 ?? ?? ?? ?? 8b 45 ?? e8}  //weight: 1, accuracy: Low
        $x_2_25 = {43 66 83 fb 5b (75 ??|0f 85 ?? ?? ?? ??) [0-8] 8b 80 ?? ?? 00 00 b2 01 8b 08 ff 51 64}  //weight: 2, accuracy: Low
        $x_2_26 = "/zz.php?" ascii //weight: 2
        $x_3_27 = {0f b7 54 5a fe 33 ?? 66 89 54 58 fe 43}  //weight: 3, accuracy: Low
        $x_2_28 = {2f 00 65 00 76 00 65 00 72 00 79 00 3a 00 4d 00 2c 00 54 00 2c 00 57 00 2c 00 54 00 68 00 2c 00 46 00 2c 00 53 00 2c 00 53 00 75 00 20 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 00 00}  //weight: 2, accuracy: High
        $x_2_29 = "/77t.php?olala=" wide //weight: 2
        $x_2_30 = {6a 00 6a 1a 8d 44 24 08 50 6a 00 e8 ?? ?? ?? ?? 85 c0 74 ?? 8b c3 8b d4 b9 05 01 00 00 e8}  //weight: 2, accuracy: Low
        $x_2_31 = {64 00 73 00 66 00 73 00 64 00 73 00 2e 00 62 00 61 00 74 00 00 00}  //weight: 2, accuracy: High
        $x_1_32 = {61 00 74 00 20 00 30 00 00 00}  //weight: 1, accuracy: High
        $x_2_33 = {b8 31 00 00 00 e8 ?? ?? ?? ?? 83 c0 0a 8d 95 ?? ?? ff ff e8 ?? ?? ?? ?? ff b5 ?? ?? ff ff 8d 45 ?? ba 08 00 00 00 e8}  //weight: 2, accuracy: Low
        $x_2_34 = {30 00 33 00 3a 00 00 00 ?? ?? ?? ?? ff ff ff ff 03 00 00 00 30 00 34 00 3a 00}  //weight: 2, accuracy: Low
        $x_2_35 = "files can't be restored (heuristic module missing)" wide //weight: 2
        $x_2_36 = {63 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 73 00 63 00 61 00 6e 00 00 00}  //weight: 2, accuracy: High
        $x_2_37 = {66 00 69 00 6c 00 65 00 73 00 20 00 69 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 00 00}  //weight: 2, accuracy: High
        $x_2_38 = "can not pass through our heuristic module" wide //weight: 2
        $x_2_39 = "\\hotfix.exe" wide //weight: 2
        $x_2_40 = "Scan Online" wide //weight: 2
        $x_2_41 = {85 c0 74 0f 6a 00 6a 00 68 64 04 00 00 50 e8 ?? ?? ?? ?? 6a 00 e8}  //weight: 2, accuracy: Low
        $x_2_42 = "Think Point" wide //weight: 2
        $x_2_43 = {50 6a 00 6a 01 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 80 78 57 00 75 ?? a1 ?? ?? ?? ?? 8b 00 80 78 57 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_41
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 6a 00 6a 1a 6a 00 (e8 ?? ?? ?? ??|ff ??) 8d 85 ?? ?? ff ff 50 8d 95 ?? ?? ff ff 52 e8}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 00 6a 01 68 05 04 00 00 50 e8 ?? ?? ?? ?? 33 c0 8b 55 ?? 64 89 15 00 00 00 00 e9 ?? ?? ?? ?? 85 c0 74 0f 6a 00 6a 01 68 02 04 00 00 50 e8}  //weight: 2, accuracy: Low
        $x_2_3 = "disablement of potentially harmful resources, fishing" ascii //weight: 2
        $x_1_4 = "is software that greatly optimizes a PC's system<br />" ascii //weight: 1
        $x_1_5 = "There is potentially harmful software installed" ascii //weight: 1
        $x_1_6 = "There are security problems in current version" ascii //weight: 1
        $x_1_7 = "@@Privacyframe@Finalize" ascii //weight: 1
        $x_1_8 = "Your software is outdated license." ascii //weight: 1
        $x_2_9 = "Potencially harmful software is detected." ascii //weight: 2
        $x_1_10 = "TPRIVACYFR" ascii //weight: 1
        $x_1_11 = "> License Manager" ascii //weight: 1
        $x_1_12 = "SECFRAME_0" ascii //weight: 1
        $x_1_13 = "harmful software have been disabled" ascii //weight: 1
        $x_1_14 = "Privacy security vulnerability" ascii //weight: 1
        $x_1_15 = "FRAMESEC_0" ascii //weight: 1
        $x_1_16 = "Microsoft#Security updates not are" wide //weight: 1
        $x_1_17 = "harmful software have been disabled." wide //weight: 1
        $x_1_18 = "Looks like porno cache" ascii //weight: 1
        $x_1_19 = "szModName : hungapp" ascii //weight: 1
        $x_1_20 = "seriuos possibility of irreversible data loss" ascii //weight: 1
        $x_1_21 = "repeat the total system security" ascii //weight: 1
        $x_1_22 = "to be able to use all the functionalities." ascii //weight: 1
        $x_1_23 = "Unprotected Privacy data" ascii //weight: 1
        $x_1_24 = "Dear User,updates succesfuly downloaded." ascii //weight: 1
        $x_2_25 = "Microsoft Security Essentials detected " ascii //weight: 2
        $x_1_26 = "sc config msmpsvc start= disabled" ascii //weight: 1
        $x_1_27 = {49 48 44 52 00 00 02 25 00 00 00 63 08 03 00 00}  //weight: 1, accuracy: High
        $x_1_28 = {00 11 08 00 63 02 25 03 01 ?? 00 02 11 01 03 11 01 ff c4}  //weight: 1, accuracy: Low
        $x_1_29 = {49 48 44 52 00 00 02 3a 00 00 00 3e 08 03 00 00}  //weight: 1, accuracy: High
        $x_1_30 = {00 11 08 00 3e 02 3a 03 01 ?? 00 02 11 01 03 11 01 ff c4}  //weight: 1, accuracy: Low
        $x_1_31 = "Best optimized performance" ascii //weight: 1
        $x_1_32 = {6b 69 6c 6c 00 64 65 66 65 6e 64 65 72}  //weight: 1, accuracy: High
        $x_2_33 = {3d b7 00 00 00 74 0d 83 3d ?? ?? ?? ?? 00 0f 85 ?? ?? 00 00 (ff 35 ?? ?? ?? ??|a1 ?? ?? ?? ??) 6a 00 e8 ?? ?? ?? ?? 85 c0 (74 ??|0f 84 ?? ?? ?? ??) 83 3d ?? ?? ?? ?? 00 74 ?? 6a 00 6a 01 68 05 04 00 00 50 e8}  //weight: 2, accuracy: Low
        $x_1_34 = "Off Realtime monitoring" ascii //weight: 1
        $x_1_35 = {11 56 69 72 75 73 65 73 20 64 65 74 65 63 74 65 64 3a}  //weight: 1, accuracy: High
        $x_1_36 = {d7 cf ae 7f 5d e8 2c eb 69 cd 7c 78 fc 7a f9 d9}  //weight: 1, accuracy: High
        $x_2_37 = {31 78 7a 63 76 78 7a 63 76 78 7a 63 76 7a 78 00}  //weight: 2, accuracy: High
        $x_1_38 = {2e 2e 5c 53 79 73 74 65 6d 33 32 5c 6d 73 78 76 63 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_2_39 = {8b c1 99 f7 7d ?? 8b c2 8b 55 ?? 8a 04 02 8a 13 32 c2 88 06 41 46 43 8b 7d ?? 3b cf 72 e2}  //weight: 2, accuracy: Low
        $x_1_40 = "Windows Troubles Remover" ascii //weight: 1
        $x_1_41 = "secure.softstore.com" ascii //weight: 1
        $x_2_42 = {8b c1 8b 75 ?? 99 f7 7d ?? 8b c2 8b 55 ?? 8a 14 0a 8a 04 06 32 d0 8b 45 ?? 88 14 08 41 3b d9 77 df}  //weight: 2, accuracy: Low
        $x_1_43 = "Searching for malware, Trojan applications, spyware" ascii //weight: 1
        $x_1_44 = {30 30 31 30 32 00 ?? 30 30 30 39 30 00 ?? 30 30 30 39 31 00 ?? 30 30 30 39 32 00 ?? ?? ?? ?? 38 30 00}  //weight: 1, accuracy: Low
        $x_1_45 = {26 31 3d 00 26 32 3d 00 26 33 3d 00 26 34 3d 00 26 35 3d 00}  //weight: 1, accuracy: High
        $x_2_46 = {c6 03 2d 43 8a 13 84 d2 75 ?? 83 fe 01 0f 85 ?? ?? ?? ?? 66 c7 85 ?? ?? ff ff 60 00 8d 45 ?? e8 ?? ?? ?? ?? 50 8d 45 ?? 83 85 ?? ?? ff ff 02}  //weight: 2, accuracy: Low
        $x_1_47 = {75 70 64 2e 65 78 65 00 [0-3] 70 72 6f 74 65 63 74 2e 64 61 74}  //weight: 1, accuracy: Low
        $x_2_48 = {8a 04 19 8b 15 ?? ?? ?? ?? 8b 4d ?? 8a 14 0a 32 c2 8b 4d ?? 8b 95 ?? ?? ff ff 88 04 11 10 00 99 f7 7d ?? 89 55 ?? 8b 4d ?? 8b 9d ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_1_49 = "_FVSFT_" ascii //weight: 1
        $x_2_50 = {8a 04 19 8b 15 ?? ?? ?? ?? 8b 8d ?? ?? ff ff 8a 14 0a 32 c2 8b 4d ?? 8b 95 ?? ?? ff ff 88 04 11 16 00 99 f7 7d ?? 89 95 ?? ?? ff ff 8b 8d ?? ?? ff ff 8b 9d ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_2_51 = {8a 14 0a 32 14 06 8b 45 ?? 88 14 08 41 3b 4d ?? 72 09 00 99 f7 7d ?? 8b c2 8b 55}  //weight: 2, accuracy: Low
        $x_2_52 = {8a 14 0a 32 14 06 8b 45 ?? 88 14 08 41 3b d9 77 09 00 99 f7 7d ?? 8b c2 8b 55}  //weight: 2, accuracy: Low
        $x_1_53 = "tst\\exe-" ascii //weight: 1
        $x_1_54 = "click on \"Fix Errors\"" ascii //weight: 1
        $x_2_55 = {8a 14 0a 8b 0d ?? ?? ?? ?? 32 14 01 8b 45 ?? 8b (8d ?? ??|4d ??) 88 14 08 66 c7 45 ?? 00 00 eb 19 00 99 f7 7d ?? 8b c2 8b 55}  //weight: 2, accuracy: Low
        $x_1_56 = "Complete system cleanup and optimization cannot be performed," ascii //weight: 1
        $x_1_57 = {0e 46 69 78 20 48 44 44 20 65 72 72 6f 72 73}  //weight: 1, accuracy: High
        $x_1_58 = {5c 00 2d 75 6e 69 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_59 = "Potentially harmful software activity has been blocked." ascii //weight: 1
        $x_1_60 = "Enable protected mode at startup" ascii //weight: 1
        $x_1_61 = "Never.MUST.BE" wide //weight: 1
        $x_1_62 = "tst\\\\exe-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePAV_154123_42
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePAV"
        threat_id = "154123"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePAV"
        severity = "129"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AntiBreach Helper" ascii //weight: 1
        $x_1_2 = {53 00 65 00 53 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 50 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 00 00 72 00 00 00 77 00 2b 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {54 00 6f 00 20 00 65 00 6c 00 69 00 6d 00 69 00 6e 00 61 00 74 00 65 00 20 00 74 00 68 00 65 00 20 00 63 00 61 00 75 00 73 00 65 00 73 00 2c 00 20 00 66 00 75 00 6c 00 6c 00 20 00 63 00 68 00 65 00 63 00 6b 00 20 00 69 00 73 00 20 00 72 00 65 00 63 00 6f 00 6d 00 6d 00 65 00 6e 00 64 00 65 00 64 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "Trojan activity detected. System data security is at risk." wide //weight: 1
        $x_1_5 = "There's a suspicious software running on your PC." wide //weight: 1
        $x_2_6 = {8d 50 02 66 8b 08 83 c0 02 66 3b ce 75 f5 2b c2 d1 f8 83 f8 04 73 10 68 ?? ?? ?? ?? 8d 4c 24 ?? e8}  //weight: 2, accuracy: Low
        $x_1_7 = "mshta.exe \"http://%s/?0=%d&1=%d&2=%d&3=%s&4=%d&5=%d&6=%S&7=%S\"" ascii //weight: 1
        $x_2_8 = {8d 34 24 ad 6b d0 01 83 ea 10 8a 02 34 ?? 4a 3c ?? 75 f7}  //weight: 2, accuracy: Low
        $x_1_9 = "%S successfully activated! Your PC is under " wide //weight: 1
        $x_1_10 = "Please click \"Auto Adjust\" button to erase all infected file" wide //weight: 1
        $x_1_11 = "Your system is clean and is being protected by %S" wide //weight: 1
        $x_1_12 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00 72 00 00 00 77 00 2b 00}  //weight: 1, accuracy: High
        $x_1_13 = {2e 3f 41 56 5a 50 61 79 66 6f 72 6d 40 40 00}  //weight: 1, accuracy: High
        $x_1_14 = {25 00 70 00 61 00 79 00 6d 00 65 00 6e 00 74 00 5f 00 75 00 72 00 6c 00 25 00 00 00 25 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 6f 00 72 00 2e 00 73 00 77 00 66 00 25 00}  //weight: 1, accuracy: High
        $x_1_15 = {2e 3f 41 56 5a 53 6f 70 61 40 40 00}  //weight: 1, accuracy: High
        $x_1_16 = {54 6f 72 72 65 6e 74 73 20 73 70 79 00}  //weight: 1, accuracy: High
        $x_1_17 = {2e 3f 41 56 5a 50 68 69 73 68 46 72 61 6d 65 40 40 00}  //weight: 1, accuracy: High
        $x_1_18 = {2e 3f 41 56 5a 46 6f 72 6d 43 41 52 44 40 40 00}  //weight: 1, accuracy: High
        $x_1_19 = "%S monitors system processes and notifies you of any unauthorized" wide //weight: 1
        $x_1_20 = {52 00 65 00 63 00 6f 00 6d 00 6d 00 65 00 6e 00 64 00 65 00 64 00 3a 00 20 00 50 00 6c 00 65 00 61 00 73 00 65 00 20 00 75 00 73 00 65 00 20 00 73 00 65 00 63 00 75 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 70 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 0a 00 66 00 6f 00 72 00 20 00 74 00 6f 00 72 00 72 00 65 00 6e 00 74 00 20 00 6c 00 69 00 6e 00 6b 00 73 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_21 = "Enable %S Firewall (recommended)" wide //weight: 1
        $x_1_22 = {5c 67 75 61 72 64 2d 25 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_23 = {5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 00 00 47 00 75 00 61 00 72 00 64 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_24 = {5c 70 72 6f 74 65 63 74 25 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_25 = "To get your protection running you need to do the first-time scanning of your PC." ascii //weight: 1
        $x_1_26 = {5c 73 61 66 65 2d 25 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_27 = {53 63 61 6e 6e 69 6e 67 2e 2e 2e 2e 2e 20 50 6c 65 61 73 65 20 77 61 69 74 00}  //weight: 1, accuracy: High
        $x_1_28 = {61 62 6f 75 74 3a 62 6c 61 6e 6b 00 50 61 79 46 6f 72 6d 00}  //weight: 1, accuracy: High
        $x_1_29 = {74 6f 20 65 72 61 73 65 20 61 6c 6c 20 69 6e 66 65 63 74 65 64 20 66 69 6c 65 73 20 61 6e 64 20 70 72 6f 74 65 63 74 20 79 6f 75 72 20 50 43 00}  //weight: 1, accuracy: High
        $x_1_30 = {53 63 61 6e 20 45 72 67 65 62 6e 69 73 73 65 3a 20 25 64 20 70 6f 74 65 6e 7a 69 65 6c 6c 65 20 42 65 64 72 6f 68 75 6e 67 65 6e 20 67 65 66 75 6e 64 65 6e 2e 00}  //weight: 1, accuracy: High
        $x_1_31 = {57 61 72 6e 75 6e 67 21 20 49 68 72 20 53 79 73 74 65 6d 20 69 73 74 20 6e 6f 63 68 20 6e 69 63 68 74 20 67 65 72 65 69 6e 69 67 74 21 00}  //weight: 1, accuracy: High
        $x_1_32 = "Phishing-Angriffen.Versuchen Sie diese" ascii //weight: 1
        $x_1_33 = {74 73 74 5c 25 64 00}  //weight: 1, accuracy: High
        $x_1_34 = "par des virus et des programmes malveillants lanc" ascii //weight: 1
        $x_1_35 = {85 c0 74 1c 39 35 ?? ?? ?? ?? 75 14 56 6a 01 68 28 04 00 00 ff 35 ?? ?? ?? ?? ff 15 0a 00 56 ff 75 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_36 = {68 00 00 03 00 6a 01 6a 01 6a 00 (6a 00|68 ?? ?? ?? ??) 6a 00 ff 15 ?? ?? ?? ?? 68 10 39 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_37 = {89 48 20 83 3d ?? ?? ?? ?? 00 74 (12|0f) 6a 00 8b (85 ?? ??|45 ??) 8b 48 20 e8 ?? ?? ?? ?? eb (22|1c) 6a 05 8b (85 ?? ??|45 ??) 8b 48 20}  //weight: 1, accuracy: Low
        $x_1_38 = {68 00 00 03 00 6a 01 6a 01 6a 00 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 8d 45 ?? 50 8b 45 ?? 8b 00 ff 75 ?? ff 50 38}  //weight: 1, accuracy: Low
        $x_1_39 = {5c 00 52 00 75 00 6e 00 00 00 50 00 72 00 53 00 66 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_40 = {5c 00 52 00 75 00 6e 00 00 00 47 00 2d 00 53 00 6f 00 66 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_41 = {31 00 32 00 33 00 31 00 32 00 33 00 2e 00 73 00 79 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_42 = {5c 00 52 00 75 00 6e 00 00 00 56 00 52 00 37 00 36 00 33 00 00 00}  //weight: 1, accuracy: High
        $x_1_43 = "ches est un composant de  Microsoft Windows qui" wide //weight: 1
        $x_1_44 = {46 00 69 00 78 00 00 00 52 00 65 00 6d 00 6f 00 76 00 65 00 00 00 00 00 00 00 00 00 49 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 00 00 00 00 4e 00 6f 00 74 00 20 00 63 00 6c 00 65 00 61 00 6e 00 65 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_45 = {68 00 00 03 00 55 55 6a 00 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 8b 10 8b 52 38 8d 4c 24 ?? 51 50 ff d2}  //weight: 1, accuracy: Low
        $x_1_46 = {85 c0 74 1d 39 3d ?? ?? ?? ?? 75 15 8b 0d ?? ?? ?? ?? 57 6a 01 68 28 04 00 00 51 ff 15 08 00 57 55 ff 15}  //weight: 1, accuracy: Low
        $x_1_47 = {6a 00 ff b5 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 74 1e 83 3d ?? ?? ?? ?? 00 75 15 6a 00 6a 01 68 28 04 00 00 ff 35 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_48 = {68 00 00 03 00 6a 01 6a 01 6a 00 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 8d ?? ?? ?? 8b ?? ?? 8b ?? 8b ?? ?? ?? 8b ?? 38 ff}  //weight: 1, accuracy: Low
        $x_1_49 = {85 c0 74 1f 83 3d ?? ?? ?? ?? 00 75 16 6a 00 6a 01 68 28 04 00 00 8b ?? ?? ?? ?? ?? ?? ff 15 0f 00 6a 00 8b ?? ?? ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_50 = {5c 00 52 00 75 00 6e 00 00 00 54 00 54 00 52 00 52 00 57 00 57 00 00 00}  //weight: 1, accuracy: High
        $x_1_51 = {46 69 78 00 52 65 6d 6f 76 65 00 00 49 6e 66 65 63 74 65 64 00 00 00 00 4e 6f 74 20 63 6c 65 61 6e 65 64 00}  //weight: 1, accuracy: High
        $x_1_52 = {68 e8 03 00 00 6a 64 68 28 04 00 00 (a1 ?? ?? ?? ??|8b ?? ?? ?? ?? ?? ??) ff 15 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? e9 ?? ?? ?? ?? 68 00 10 00 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_53 = {68 00 00 03 00 57 57 56 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 8b 45 ?? 8b 08 8d 55 ?? 52 50 ff 51 38}  //weight: 1, accuracy: Low
        $x_1_54 = {68 e8 03 00 00 6a 64 68 28 04 00 00 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 5d ?? ff 75 ?? ff 15 ?? ?? ?? ?? ff 45 ?? 39 5d ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_55 = {4e 6f 74 20 63 6c 65 61 6e 65 64 00 49 6e 66 65 63 74 65 64 00 00 00 00 52 65 6d 6f 76 65 00 00 46 69 78 00}  //weight: 1, accuracy: High
        $x_1_56 = {5c 00 64 00 65 00 73 00 6b 00 2e 00 63 00 70 00 6c 00 00 00 5c 00 64 00 69 00 73 00 6b 00 6d 00 67 00 6d 00 74 00 2e 00 6d 00 73 00 63 00 00 00 5c 00 63 00 6c 00 65 00 61 00 6e 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 00 00 5c 00 68 00 64 00 77 00 77 00 69 00 7a 00 2e 00 63 00 70 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_57 = {22 00 44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 22 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 20 00 22 00 5c 00 22 00 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4e 00 6f 00 74 00 65 00 [0-8] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_58 = {22 44 65 62 75 67 67 65 72 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 22 5c 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 4e 6f 74 65 [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_59 = {46 69 78 20 00 00 00 20 52 65 6d 6f 76 65 20 00 00 00 00 20 49 6e 66 65 63 74 65 64 20 00 00 20 4e 6f 74 20 63 6c 65 61 6e 65 64 20 00}  //weight: 1, accuracy: High
        $x_1_60 = "\\Run\" /v \"ZSFT\" /t REG_SZ /d \"%s\" /f" wide //weight: 1
        $x_1_61 = "\\Winlogon\" /v \"Shell\" /t REG_SZ /d \"%s\" /f" wide //weight: 1
        $x_1_62 = {68 00 00 02 00 6a 01 6a 01 6a 00 8d ?? ?? ?? ?? ?? ?? (6a 00|8d ?? ?? ?? ?? ?? ??) ff 15 ?? ?? ?? ?? 8d ?? ?? ?? 8b ?? ?? 8b ?? 8b ?? ?? ?? 8b ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_63 = "\\msmpeng.exe\" /v \"Debugger\" /t REG_SZ /d \"\\\"c:\\windows\\" wide //weight: 1
        $x_1_64 = "/v \"Debugger\" /t REG_SZ /d \"\\\"c:\\w.exe\\\" /z\" /f" wide //weight: 1
        $x_1_65 = {5c 00 52 00 55 00 4e 00 22 00 20 00 [0-8] 2f 00 76 00 20 00 [0-8] 22 00 [0-16] 22 00 20 00 [0-8] 2f 00 74 00 20 00 [0-8] 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 [0-8] 2f 00 64 00 20 00 [0-8] 22 00 25 00 73 00 22 00 20 00 [0-8] 2f 00 66 00}  //weight: 1, accuracy: Low
        $x_1_66 = "Windows Security Master" ascii //weight: 1
        $x_1_67 = "\\Image File Execution Options\\msmpeng.exe\" /v \"Debugger\" /t REG_SZ /d" wide //weight: 1
        $x_1_68 = {53 00 68 00 65 00 6c 00 6c 00 00 00 69 00 00 00 72 00 65 00 67 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_69 = {43 00 6f 00 6e 00 66 00 69 00 67 00 00 00 00 00 72 00 65 00 67 00 2e 00 64 00 61 00 74 00 00 00 25 00 73 00 5c 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_70 = {43 00 6f 00 6e 00 66 00 69 00 67 00 00 00 00 00 69 00 00 00 72 00 65 00 67 00 2e 00 64 00 61 00 74 00 00 00 25 00 73 00 5c 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_2_71 = "%s \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\msmpeng.exe\" /v \"%s\" /t REG_SZ /d \"" wide //weight: 2
        $x_2_72 = {5f 00 25 00 64 00 00 00 6e 00 65 00 74 00 00 00 72 00 65 00 67 00 2e 00 64 00 61 00 74 00 00 00 25 00 73 00 5c 00 25 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_2_73 = {5f 00 25 00 64 00 00 00 6e 00 65 00 74 00 00 00 69 00 00 00 72 00 65 00 67 00 2e 00 64 00 61 00 74 00 00 00 25 00 73 00 5c 00 25 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_2_74 = {49 00 6d 00 61 00 67 00 65 00 20 00 46 00 69 00 6c 00 65 00 20 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 20 00 4f 00 70 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 6d 00 73 00 6d 00 70 00 65 00 6e 00 67 00 2e 00 65 00 78 00 65 00 00 00 00 00 44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 00 00 00 00 49 00 6d 00 61 00 67 00 65 00 20 00 46 00 69 00 6c 00 65 00 20 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 20 00 4f 00 70 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 6d 00 73 00 61 00 73 00 63 00 75 00 69 00 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: High
        $x_2_75 = {49 00 6d 00 61 00 67 00 65 00 20 00 46 00 69 00 6c 00 65 00 20 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 20 00 4f 00 70 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 6d 00 73 00 6d 00 70 00 65 00 6e 00 67 00 2e 00 65 00 78 00 65 00 00 00 00 00 00 00 00 00 49 00 6d 00 61 00 67 00 65 00 20 00 46 00 69 00 6c 00 65 00 20 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 20 00 4f 00 70 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 6d 00 73 00 61 00 73 00 63 00 75 00 69 00 2e 00 65 00 78 00 65 00 00 00 00 00 44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00}  //weight: 2, accuracy: High
        $x_1_76 = {6a 00 6a 01 68 01 04 00 00 8b 55 ?? 52 ff 15 ?? ?? ?? ?? 33 c0 e9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 75 ?? 68 ?? ?? ?? ?? 6a 00 6a 02 ff 15}  //weight: 1, accuracy: Low
        $x_2_77 = {57 6a 01 68 01 04 00 00 56 ff 15 ?? ?? ?? ?? 33 c0 e9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 75 ?? 68 ?? ?? ?? ?? 57 8b 3d ?? ?? ?? ?? 6a 02 ff d7}  //weight: 2, accuracy: Low
        $x_2_78 = {25 00 73 00 20 00 22 00 25 00 73 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 25 00 73 00 22 00 20 00 2f 00 76 00 20 00 22 00 63 00 74 00 66 00 6d 00 6f 00 6e 00 22 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 20 00 22 00 25 00 73 00 22 00 20 00 2f 00 66 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

