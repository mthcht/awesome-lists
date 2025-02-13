rule Rogue_Win32_PrivacyCenter_140760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {23 5c 43 43 65 6e 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {61 70 2e 65 78 65 00 73 70 2e 65 78 65 00 73 65 74 74 69 6e 67 73 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_3 = "/newinstall/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_PrivacyCenter_140760_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 75 6e 00 ff ff ff ff 09 00 00 00 41 6e 74 69 76 69 72 75 73 00 00 00 ff ff ff ff 15 00 00 00 53 4f 46 54 57 41 52 45 5c 53 61 66 65 74 79 43 65 6e 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 75 49 45 5f 42 48 4f 2e 70 61 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_PrivacyCenter_140760_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@privacy-center.org" ascii //weight: 1
        $x_1_2 = "visiting adult sites or virus activity on your computer." ascii //weight: 1
        $x_1_3 = "Security threat!" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_5 = " Your security is under threat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_PrivacyCenter_140760_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/secure/index_new.php?id=" wide //weight: 1
        $x_1_2 = "Your computer is still in danger." wide //weight: 1
        $x_1_3 = "Do you want to continue without any changes?" wide //weight: 1
        $x_1_4 = "mailto: support@realgoldsoft.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_PrivacyCenter_140760_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {50 00 72 00 69 00 76 00 61 00 63 00 79 00 20 00 63 00 65 00 6e 00 74 00 65 00 72 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 20 00 74 00 68 00 61 00 74 00 20 00 63 00 61 00 6e 00 20 00 63 00 6f 00 70 00 79 00 20 00 69 00 74 00 73 00 65 00 6c 00 66 00 20 00 61 00 6e 00 64 00 20 00 69 00 6e 00 66 00 65 00 63 00 74 00 20 00 61 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 00 00}  //weight: 2, accuracy: High
        $x_1_3 = {4c 00 6f 00 6f 00 6b 00 73 00 20 00 6c 00 69 00 6b 00 65 00 20 00 70 00 6f 00 72 00 6e 00 20 00 63 00 61 00 63 00 68 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 00 6f 00 6f 00 6b 00 69 00 65 00 20 00 63 00 61 00 6e 00 20 00 63 00 6f 00 6e 00 74 00 61 00 69 00 6e 00 20 00 79 00 6f 00 75 00 72 00 20 00 70 00 72 00 69 00 76 00 61 00 74 00 65 00 20 00 69 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_PrivacyCenter_140760_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "(parseInt" ascii //weight: 1
        $x_1_2 = {ba 86 01 00 00 e8 ?? ?? ?? ?? 8b c3 ba 78 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 76 02 00 00 8b c3 e8 ?? ?? ?? ?? ba 5f 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Rogue_Win32_PrivacyCenter_140760_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 07 00 00 00 e8 ?? ?? ?? ?? c3 e9 ?? ?? ?? ?? eb eb 5b e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0d 00 00 00 75 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 00 00 00 53 61 66 65 74 79 20 43 65 6e 74 65 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_PrivacyCenter_140760_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 6e 73 74 61 6c 6c 61 74 69 6f 6e 00 ?? ?? ?? 00 63 68 65 63 6b 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_1_2 = {2e 65 78 65 00 64 6f 77 6e 6c 6f 61 64 00 68 74 74 70 3a}  //weight: 1, accuracy: High
        $x_1_3 = "m5soft/install" ascii //weight: 1
        $x_1_4 = "r2soft/install-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_PrivacyCenter_140760_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Applyng the lastest" ascii //weight: 1
        $x_1_2 = "fromCharCode(parseInt" ascii //weight: 1
        $x_1_3 = {b9 98 00 00 00 ba 40 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {b9 26 01 00 00 ba dd 01 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "Privacy Center" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_PrivacyCenter_140760_9
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {19 1d 1f 20 29 33 2e 2f 34 34 36 3b 35 01 01 a3 94 8f 8f 8f 8f 8f 8f 8f 93 93 8a 8e 8e 97 96 a2}  //weight: 1, accuracy: High
        $x_1_2 = {d6 dc d9 da d9 d7 dc d3 d3 df d0 d4 e9 d2 dc f8 dc e7 ff dd e7 ff db da df e2 d9 d8 79 b5 9b 93}  //weight: 1, accuracy: High
        $x_3_3 = {ba fd 00 00 00 e8 ?? ?? ?? ?? 8b c3 ba 14 00 00 00}  //weight: 3, accuracy: Low
        $x_3_4 = "the lastest" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_PrivacyCenter_140760_10
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Virus alerts" ascii //weight: 1
        $x_1_2 = "Cookieguarder1" ascii //weight: 1
        $x_1_3 = "Memorywizard1" ascii //weight: 1
        $x_1_4 = "visiting porno sites) and security" ascii //weight: 1
        $x_1_5 = "\\Privacy center\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_PrivacyCenter_140760_11
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "temp.exe -install" ascii //weight: 1
        $x_1_2 = "91.207.116.44" ascii //weight: 1
        $x_1_3 = "Tahoma" ascii //weight: 1
        $x_1_4 = {ba 8d 02 00 00 e8 ?? ?? ff ff a1 ?? ?? 40 00 ba c7 01 00 00 e8 ?? ?? ff ff a1 ?? ?? 40 00 e8 ?? ?? ff ff a1 ?? ?? 40 00 b2 01}  //weight: 1, accuracy: Low
        $x_1_5 = {08 97 c1 00 00 00 50 8b 87 35 01 00 00 29 c8 50 57 8d bf 29 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_PrivacyCenter_140760_12
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\SafetyCenter" ascii //weight: 1
        $x_1_2 = {66 75 63 6b 62 6f 6f 6b 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = "pugalka.dll" ascii //weight: 1
        $x_2_4 = "127.0.0.1/RunAntivirus\" target=\"_self" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_PrivacyCenter_140760_13
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "result from visiting porn sites" ascii //weight: 1
        $x_1_2 = "mailto: support@privacy-center.com" ascii //weight: 1
        $x_1_3 = "unsupported software licenses. View the system reports now." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_PrivacyCenter_140760_14
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Cockie" ascii //weight: 2
        $x_2_2 = "hly unrecommende" ascii //weight: 2
        $x_1_3 = "Socks bot" ascii //weight: 1
        $x_3_4 = {8b 80 20 02 00 00 8b 10 ff 52 44 8d 55 dc 06 00 8b 83 ?? ?? 00 00}  //weight: 3, accuracy: Low
        $x_1_5 = {74 26 68 01 00 02 00 6a 00 a1}  //weight: 1, accuracy: High
        $x_3_6 = {70 75 67 61 6c 6b 61 2e 64 6c 6c 00 44 6c 6c 43}  //weight: 3, accuracy: High
        $x_1_7 = "PrivacyCenter" ascii //weight: 1
        $x_1_8 = ".1/RunAntivirus" wide //weight: 1
        $x_2_9 = {83 f8 02 7e 02 b3 01 83 c7 04 4e 75 e9 84 db 74 0f 8b 45 f8 ba}  //weight: 2, accuracy: High
        $x_1_10 = {4d 61 6b 65 20 66 75 6c 6c 20 73 63 61 6e 00}  //weight: 1, accuracy: High
        $x_1_11 = "SOFTWARE\\SafetyCenter" ascii //weight: 1
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

rule Rogue_Win32_PrivacyCenter_140760_15
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\SafetyCenter" ascii //weight: 1
        $x_1_2 = "This Trojan sends email spam to your address book contacts." ascii //weight: 1
        $x_1_3 = "Make a full scan of your computer" ascii //weight: 1
        $x_1_4 = "moving tool - grants provacy to your" ascii //weight: 1
        $x_1_5 = "SpyFalcon, and thousands" ascii //weight: 1
        $x_1_6 = {5c 73 6f 75 6e 64 2e 77 61 76 [0-16] 5c 6e 65 77 2e 65 78 65 [0-16] 53 74 61 72 74 75 70}  //weight: 1, accuracy: Low
        $x_1_7 = "MG SRC=\"http://94.75." ascii //weight: 1
        $x_2_8 = {5c 75 49 45 5f 42 48 4f 2e 70 61 73 00}  //weight: 2, accuracy: High
        $x_2_9 = {70 75 67 61 6c 6b 61 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 2, accuracy: High
        $x_1_10 = {83 3e 4f 0f 8e ?? ?? ?? ?? 83 3e 65 0f 8d}  //weight: 1, accuracy: Low
        $x_1_11 = {3d e2 00 00 00 7f 54 0f 84 ?? ?? ?? ?? 83 f8 6c 7f 2b 0f 84 ?? ?? ?? ?? 83 e8 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_PrivacyCenter_140760_16
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "tings.ini" wide //weight: 1
        $x_1_3 = "If exist \"%s\" Goto 1" wide //weight: 1
        $x_1_4 = "Center did not find any antivirus software on this computer!" wide //weight: 1
        $x_1_5 = "Traces of discreditable files (for example, the history of visiting adult sites) and security exposure have been found" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_PrivacyCenter_140760_17
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "SafetyCenter software" ascii //weight: 2
        $x_2_2 = {2f 73 65 63 75 72 65 2f 69 6e 64 65 78 5f 6e 65 77 2e 70 68 70 3f 69 64 3d 00}  //weight: 2, accuracy: High
        $x_2_3 = "Our Multi-Dimensional PC Security Scanning " ascii //weight: 2
        $x_1_4 = "Main > Surfing protection" ascii //weight: 1
        $x_1_5 = {5c 53 4f 46 54 57 41 52 45 5c 53 61 66 65 74 79 43 65 6e 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {44 6f 6e 27 74 20 70 61 6e 69 63 21 0a 0d 53 61 66 65 74 79 43 65 6e 74 65 72}  //weight: 1, accuracy: High
        $x_1_7 = {4d 61 6b 65 20 66 75 6c 6c 20 73 63 61 6e 00}  //weight: 1, accuracy: High
        $x_1_8 = "Make a full scan of your computer" ascii //weight: 1
        $x_1_9 = "Main > Cookies remover" ascii //weight: 1
        $x_3_10 = {70 75 67 61 6c 6b 61 2e 64 6c 6c 00 44 6c 6c 43}  //weight: 3, accuracy: High
        $x_2_11 = {4c 69 63 65 00 00 00 00 ff ff ff ff 04 00 00 00 6e 73 65 64 00}  //weight: 2, accuracy: High
        $x_1_12 = {75 49 45 5f 42 48 4f 2e 70 61 73 00}  //weight: 1, accuracy: High
        $x_1_13 = "operation can not be executed in trial version!" ascii //weight: 1
        $x_1_14 = "Main > Registry doctor" ascii //weight: 1
        $x_2_15 = {66 3d 22 68 74 74 70 3a 2f 2f 31 (32 37 2e 30|39 32 2e 31 36 38) 2e 31 2f 53 63 61 6e 6e 65 72 22 20 74}  //weight: 2, accuracy: Low
        $x_1_16 = {63 6f 6d 70 6c 65 74 65 5f 73 63 61 6e 00}  //weight: 1, accuracy: High
        $x_1_17 = {63 6f 6f 6b 69 65 5f 66 69 6c 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_18 = {73 75 72 66 69 6e 67 5f 66 69 6c 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_19 = {61 64 75 6c 74 66 72 69 65 6e 64 66 69 6e 64 65 72 2e 63 6f 6d 00 00 00 ff ff ff ff 09 00 00 00 62 61 64 6f 6f 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_20 = "Now you have access to the latest updates from our database." ascii //weight: 1
        $x_1_21 = "This Trojan sends email spam to your address book contacts." ascii //weight: 1
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

rule Rogue_Win32_PrivacyCenter_140760_18
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "102"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {5c 50 43 00 49 6e 73 74 61 6c 6c 00 ?? ?? ?? 00 70 63 2e 65 78 65 00 61 67 65 6e 74 2e 65 78 65 00}  //weight: 100, accuracy: Low
        $x_100_2 = {5c 50 43 00 49 6e 73 74 61 6c 6c 00 ?? ?? ?? 00 ?? ?? ?? 5c 73 65 74 74 69 6e 67 73 2e 69 6e 69 00 70 63 2e 65 78 65 00 61 67 65 6e 74 2e 65 78 65 00}  //weight: 100, accuracy: Low
        $x_100_3 = {63 63 6d 61 69 6e 2e 65 78 65 00 63 63 61 67 65 6e 74 2e 65 78 65 00 ?? ?? ?? 5c 73 65 74 74 69 6e 67 73 2e 69 6e 69}  //weight: 100, accuracy: Low
        $x_100_4 = {5c 43 43 00 49 6e 73 74 61 6c 6c 00 ?? ?? ?? 00 63 63 2e 65 78 65 00 [0-2] 61 67 65 6e 74 2e 65 78 65 00}  //weight: 100, accuracy: Low
        $x_100_5 = {63 63 61 67 65 6e 74 2e 65 78 65 00 63 63 6d 61 69 6e 2e 65 78 65 00 ?? ?? ?? 5c 73 65 74 74 69 6e 67 73 2e 69 6e 69}  //weight: 100, accuracy: Low
        $x_1_6 = {5c 55 6e 69 6e 73 74 61 6c 6c 5c 50 72 69 76 61 63 79 [0-1] 43 65 6e 74 65 72}  //weight: 1, accuracy: Low
        $x_1_7 = {5c 50 72 69 76 61 63 79 [0-1] 43 65 6e 74 65 72 2e 6c 6e 6b}  //weight: 1, accuracy: Low
        $x_1_8 = "\\Uninstall\\P-Center" ascii //weight: 1
        $x_1_9 = "\\P-Center.lnk" ascii //weight: 1
        $x_1_10 = "\\Uninstall\\PCenter" ascii //weight: 1
        $x_1_11 = "\\PCenter.lnk" ascii //weight: 1
        $x_1_12 = {5c 55 6e 69 6e 73 74 61 6c 6c 5c 50 72 69 76 61 63 79 [0-1] 43 6f 6d 70 6f 6e 65 6e 74 73}  //weight: 1, accuracy: Low
        $x_1_13 = {5c 50 72 69 76 61 63 79 [0-1] 43 6f 6d 70 6f 6e 65 6e 74 73 2e 6c 6e 6b}  //weight: 1, accuracy: Low
        $x_1_14 = "\\Uninstall\\PComponents" ascii //weight: 1
        $x_1_15 = "\\PComponents.lnk" ascii //weight: 1
        $x_1_16 = {5c 55 6e 69 6e 73 74 61 6c 6c 5c 50 72 69 76 61 63 79 [0-1] 54 6f 6f 6c 73}  //weight: 1, accuracy: Low
        $x_1_17 = {5c 50 72 69 76 61 63 79 [0-1] 54 6f 6f 6c 73 2e 6c 6e 6b}  //weight: 1, accuracy: Low
        $x_1_18 = "\\Uninstall\\PTools" ascii //weight: 1
        $x_1_19 = "\\PTools.lnk" ascii //weight: 1
        $x_1_20 = {5c 55 6e 69 6e 73 74 61 6c 6c 5c 43 [0-1] 43 65 6e 74 65 72}  //weight: 1, accuracy: Low
        $x_1_21 = "\\CCenter.lnk" ascii //weight: 1
        $x_1_22 = {5c 55 6e 69 6e 73 74 61 6c 6c 5c 43 6f 6e 74 72 6f 6c [0-1] 63 65 6e 74 65 72}  //weight: 1, accuracy: Low
        $x_1_23 = {5c 43 6f 6e 74 72 6f 6c [0-1] 63 65 6e 74 65 72 2e 6c 6e 6b}  //weight: 1, accuracy: Low
        $x_1_24 = "\\C-Center.lnk" ascii //weight: 1
        $x_1_25 = {5c 55 6e 69 6e 73 74 61 6c 6c 5c 43 74 72 6c [0-1] 43 65 6e 74 65 72}  //weight: 1, accuracy: Low
        $x_1_26 = {5c 43 74 72 6c [0-1] 43 65 6e 74 65 72 2e 6c 6e 6b}  //weight: 1, accuracy: Low
        $x_1_27 = {5c 55 6e 69 6e 73 74 61 6c 6c 5c 43 6f 6e 74 72 6f 6c [0-1] 4d 61 6e 61 67 65 72}  //weight: 1, accuracy: Low
        $x_1_28 = {5c 43 6f 6e 74 72 6f 6c [0-1] 4d 61 6e 61 67 65 72 2e 6c 6e 6b}  //weight: 1, accuracy: Low
        $x_1_29 = "\\Uninstall\\PCTools" ascii //weight: 1
        $x_1_30 = "\\PCTools.lnk" ascii //weight: 1
        $x_1_31 = {5c 55 6e 69 6e 73 74 61 6c 6c 5c 43 6f 6e 74 72 6f 6c [0-1] 43 6f 6d 70 6f 6e 65 6e 74 73}  //weight: 1, accuracy: Low
        $x_1_32 = {5c 43 6f 6e 74 72 6f 6c [0-1] 43 6f 6d 70 6f 6e 65 6e 74 73 2e 6c 6e 6b}  //weight: 1, accuracy: Low
        $x_1_33 = "\\Uninstall\\CtrlComponents" ascii //weight: 1
        $x_1_34 = "\\CtrlComponents.lnk" ascii //weight: 1
        $x_1_35 = "\\Uninstall\\ControlCnt" ascii //weight: 1
        $x_1_36 = "\\ControlCnt.lnk" ascii //weight: 1
        $x_1_37 = "\\Uninstall\\ACommander" ascii //weight: 1
        $x_1_38 = "\\ACommander.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_PrivacyCenter_140760_19
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a ff 6a 1a 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 8d 45 ?? ba ?? ?? ?? ?? b9 05 01 00 00 e8}  //weight: 2, accuracy: Low
        $x_2_2 = {6a ff 6a 1a 8d 85 ?? ?? ff ff 50 6a 00 e8 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 8d 95 ?? ?? ff ff b9 05 01 00 00 e8}  //weight: 2, accuracy: Low
        $x_2_3 = {6a 00 6a 1a a1 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 46 33 c0 a3 ?? ?? ?? ?? 33 d2 b8 02 00 00 00 e8}  //weight: 2, accuracy: Low
        $x_2_4 = {61 67 65 6e 74 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_2_5 = {50 72 69 76 61 63 79 20 63 6f 6d 70 6f 6e 65 6e 74 73 00}  //weight: 2, accuracy: High
        $x_2_6 = {50 72 69 76 61 63 79 20 63 65 6e 74 65 72 00}  //weight: 2, accuracy: High
        $x_1_7 = "the history of visiting porno sites" ascii //weight: 1
        $x_1_8 = {53 75 72 66 70 72 6f 74 65 63 74 6f 72 31 43 6c 69 63 6b 00}  //weight: 1, accuracy: High
        $x_1_9 = {43 6f 6f 6b 69 65 67 75 61 72 64 65 72 31 43 6c 69 63 6b 00}  //weight: 1, accuracy: High
        $x_1_10 = {52 65 67 69 73 74 72 79 63 6c 65 61 6e 65 72 31 43 6c 69 63 6b 00}  //weight: 1, accuracy: High
        $x_1_11 = {53 79 73 74 65 6d 6d 6f 6e 69 74 6f 72 31 43 6c 69 63 6b 00}  //weight: 1, accuracy: High
        $x_1_12 = {4f 70 65 6e 58 4c 47 75 61 72 64 65 72 31 00}  //weight: 1, accuracy: High
        $x_2_13 = "--proto udp --remote 194.165.4.39 --port 1194" ascii //weight: 2
        $x_2_14 = {6b 65 79 73 00 00 00 00 ff ff ff ff 06 00 00 00 64 62 61 73 65 73 00}  //weight: 2, accuracy: High
        $x_3_15 = {62 61 73 65 00 00 00 00 ff ff ff ff 08 00 00 00 61 64 76 61 6e 63 65 64 00}  //weight: 3, accuracy: High
        $x_1_16 = {63 61 6e 20 72 65 73 75 6c 74 20 66 72 6f 6d 20 76 69 73 69 74 69 6e 67 20 (70 6f|61 64 75) 20 73 69 74 65 73}  //weight: 1, accuracy: Low
        $x_1_17 = "Sorry, live support is only aviable for licensed software customers." ascii //weight: 1
        $x_1_18 = {66 61 71 5c 67 75 69 64 65 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_19 = {41 74 74 65 6e 74 69 6f 6e 21 20 54 68 65 20 67 69 76 65 6e 20 61 63 74 69 6f 6e 20 69 73 20 [0-9] 6e 6f 74 20 72 65 63 6f 6d 6d 65 6e 64 65 64}  //weight: 1, accuracy: Low
        $x_1_20 = "Attention! This action is not recommended." ascii //weight: 1
        $x_1_21 = "License error! License manager has detected outdated software license." ascii //weight: 1
        $x_2_22 = "Necessary actions have been carried out; your system is now protected." ascii //weight: 2
        $x_1_23 = "The component has completed its work." ascii //weight: 1
        $x_1_24 = {59 6f 75 20 63 61 6e 20 63 6f 6e 74 69 6e 75 65 20 74 68 65 20 77 6f 72 6b 2e 00}  //weight: 1, accuracy: High
        $x_1_25 = "The components providing security have reported a critically low level of system protection" ascii //weight: 1
        $x_1_26 = "The Center for License Control has detected outdated or " ascii //weight: 1
        $x_1_27 = {77 61 72 6e 6c 6e 6b 30 00}  //weight: 1, accuracy: High
        $x_1_28 = "Attention! Security module has not completed removal of unsafe files." ascii //weight: 1
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

rule Rogue_Win32_PrivacyCenter_140760_20
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/PrivacyCenter"
        threat_id = "140760"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivacyCenter"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Privacy Center" wide //weight: 2
        $x_1_2 = {50 00 6f 00 72 00 6e 00 20 00 63 00 61 00 63 00 68 00 65 00 00 [0-16] 44 00 61 00 6e 00 67 00 65 00 72 00 6f 00 75 00 73 00 00 [0-16] 43 00 72 00 69 00 74 00 69 00 63 00 61 00 6c 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Computer programs that can copy itself" wide //weight: 1
        $x_1_4 = "full protection\" mode and use all it's abilities" wide //weight: 1
        $x_1_5 = "php.wen_xedni/eruces/" wide //weight: 1
        $x_1_6 = "Looks like undesirable cache" wide //weight: 1
        $x_1_7 = "Cookie is unsafe or corrupted" wide //weight: 1
        $x_1_8 = "problems! Traces of discreditable files" wide //weight: 1
        $x_1_9 = "adult sites) and security vulnerability have been found. Click" wide //weight: 1
        $x_1_10 = {65 00 78 00 65 00 2e 00 63 00 70 00 00 00 00 00 6f 00 70 00 65 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_2_11 = {64 00 65 00 74 00 72 00 6f 00 70 00 65 00 72 00 20 00 73 00 74 00 6e 00 65 00 6e 00 6f 00 70 00 6d 00 6f 00 63 00 20 00 [0-22] 6c 00 61 00 72 00 65 00 76 00 65 00 73 00}  //weight: 2, accuracy: Low
        $x_1_12 = "Cookie invade your privacy" wide //weight: 1
        $x_1_13 = {6a 00 6a 00 6a 00 53 8b d8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 6a 05 6a 00 6a 00}  //weight: 1, accuracy: Low
        $x_2_14 = {73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 2e 00 69 00 6e 00 69 00 00 00}  //weight: 2, accuracy: High
        $x_2_15 = {2e 00 73 00 67 00 6e 00 69 00 74 00 74 00 65 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_1_16 = "Undesirable data in the Internet cache" wide //weight: 1
        $x_1_17 = {50 00 72 00 69 00 76 00 61 00 63 00 79 00 20 00 63 00 6f 00 6d 00 70 00 6f 00 6e 00 65 00 6e 00 74 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_18 = "Your computer is still in danger." wide //weight: 1
        $x_1_19 = "adult sites) and security exposure have been found. Click" wide //weight: 1
        $x_1_20 = "Traces of discreditable files (for example, the history of visiting adult sites)" wide //weight: 1
        $x_1_21 = {43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 20 00 63 00 65 00 6e 00 74 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_2_22 = {73 00 67 00 6e 00 69 00 74 00 74 00 65 00 73 00 00 00 00 00 ?? ?? ?? ?? ff ff ff ff 04 00 00 00 2e 00 69 00 6e 00 69 00 00 00}  //weight: 2, accuracy: Low
        $x_1_23 = "/eruces/" wide //weight: 1
        $x_2_24 = {6e 00 69 00 61 00 6d 00 63 00 63 00 00 00}  //weight: 2, accuracy: High
        $x_2_25 = {73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 00 00 00 00 ?? ?? ?? ?? ff ff ff ff 04 00 00 00 2e 00 69 00 6e 00 69 00 00 00}  //weight: 2, accuracy: Low
        $x_1_26 = {70 00 61 00 72 00 61 00 6d 00 30 00 00 00}  //weight: 1, accuracy: High
        $x_1_27 = {43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 2d 00 43 00 65 00 6e 00 74 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_28 = "to eliminate vulnerability immediately!" wide //weight: 1
        $x_2_29 = {2f 00 72 00 32 00 68 00 69 00 74 00 2f 00 31 00 2f 00 00 00}  //weight: 2, accuracy: High
        $x_1_30 = {00 00 6e 00 69 00 61 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_2_31 = {21 00 79 00 6c 00 65 00 74 00 61 00 69 00 64 00 65 00 6d 00 6d 00 69 00 20 00 [0-2] 65 00 74 00 61 00 6e 00 69 00 6d 00 69 00 6c 00 65 00 20 00 [0-2] 6f 00 74 00 20 00 [0-2] 6e 00 6f 00 69 00 74 00 61 00 63 00 69 00 66 00 69 00 74 00 6f 00 6e 00 20 00 73 00 69 00 68 00 74 00}  //weight: 2, accuracy: Low
        $x_2_32 = {00 00 2f 00 74 00 69 00 68 00 32 00 72 00 2f 00}  //weight: 2, accuracy: High
        $x_1_33 = {00 6e 00 69 00 61 00 6d 00 00 ?? ?? ?? ?? ?? [0-80] 00 61 00 66 00 69 00 64 00 00}  //weight: 1, accuracy: Low
        $x_2_34 = "r2newinstall" wide //weight: 2
        $x_1_35 = {63 00 63 00 00 [0-22] 6d 00 61 00 69 00 6e 00 2e 00 65 00 78 00 65 00 00}  //weight: 1, accuracy: Low
        $x_1_36 = {74 00 65 00 73 00 00 [0-21] 74 00 69 00 6e 00 67 00 73 00 2e 00 69 00 6e 00 69 00 00}  //weight: 1, accuracy: Low
        $x_2_37 = "llatsniwen2r" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

