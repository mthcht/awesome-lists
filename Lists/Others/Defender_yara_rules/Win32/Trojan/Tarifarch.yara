rule Trojan_Win32_Tarifarch_E_2147680946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.E"
        threat_id = "2147680946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Borland\\Delphi\\Locales" wide //weight: 10
        $x_10_2 = "WinZip 2011" ascii //weight: 10
        $x_10_3 = "RUSSIAN_CHARSET" ascii //weight: 10
        $x_1_4 = "maxsms" ascii //weight: 1
        $x_1_5 = "price" ascii //weight: 1
        $x_1_6 = "smscount" ascii //weight: 1
        $x_1_7 = "REBILL_URL" ascii //weight: 1
        $x_1_8 = "TCountryRecordArray$" ascii //weight: 1
        $x_1_9 = "labelSmsInfoCount" ascii //weight: 1
        $x_1_10 = "labelSmsNumber" ascii //weight: 1
        $x_1_11 = "labelSmsText" ascii //weight: 1
        $x_1_12 = "confirmationCode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tarifarch_I_2147680947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.I"
        threat_id = "2147680947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "/silent /rfr=openpart /partner_new_url=http://stat.openpart.ru/newtoolbar?p=qcash" wide //weight: 2
        $x_2_2 = {26 00 61 00 75 00 78 00 3d 00 [0-40] 26 00 67 00 75 00 69 00 64 00 3d 00 24 00 5f 00 5f 00 47 00 55 00 49 00 [0-32] 26 00 73 00 69 00 67 00 3d 00 24 00 5f 00 5f 00 53 00 49 00 47 00}  //weight: 2, accuracy: Low
        $x_2_3 = {73 00 74 00 72 00 65 00 61 00 6d 00 49 00 64 00 3d 00 [0-16] 63 00 6f 00 64 00 65 00 3d 00 [0-64] 73 00 74 00 65 00 70 00 3d 00}  //weight: 2, accuracy: Low
        $x_1_4 = "/index/contact/" wide //weight: 1
        $x_1_5 = "http://helpprice.in" wide //weight: 1
        $x_1_6 = {73 00 74 00 65 00 70 00 3d 00 [0-16] 70 00 32 00 3d 00 [0-32] 70 00 33 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_7 = "/rebill/unsubscr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tarifarch_P_2147680948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.P"
        threat_id = "2147680948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {e3 ac 6f ed b3 f7 b9 fb ec bd cf 5a 17 00 92 a7 2f 97 97 06 4b 01 90 ca 13 f0 83 3c 9c e9 11 91}  //weight: 10, accuracy: High
        $x_1_2 = ".openpart.ru/newtoolbar?p=qcash" wide //weight: 1
        $x_1_3 = "/rebill/rules" wide //weight: 1
        $x_1_4 = "onKeyPrValidNumber" ascii //weight: 1
        $x_1_5 = "epCodeKeyPress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tarifarch_V_2147680949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.V"
        threat_id = "2147680949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 45 08 0f be 08 85 c9 75 05 e9 ?? ?? 00 00 6a ?? ff 15}  //weight: 4, accuracy: Low
        $x_4_2 = {c7 f8 09 00 8b 4d ?? 81 e9 00 10 00 00 89 4d}  //weight: 4, accuracy: Low
        $x_4_3 = "AVI LIST!" ascii //weight: 4
        $x_1_4 = "012830812364928218763123" ascii //weight: 1
        $x_1_5 = "usdu8888888888888656756675us7777777777777777777777777777777777777777dasd" ascii //weight: 1
        $x_1_6 = "RER656756345634" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tarifarch_X_2147680950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.X"
        threat_id = "2147680950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/search?id=" wide //weight: 1
        $x_1_2 = {00 00 2f 00 3f 00 70 00 3d 00 69 00 6e 00 64 00 65 00 78 00 2e 00 6b 00 63 00 61 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {15 62 74 6e 53 75 62 73 63 72 69 70 74 69 6f 6e 73 43 6c 69 63 6b 17 00 ?? ?? ?? ?? 10 6f 6e 4b 63 61 70 74 63 68 61 52 65 6c 6f 61 64 1b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tarifarch_Y_2147680951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.Y"
        threat_id = "2147680951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinZip 2011" ascii //weight: 1
        $x_1_2 = "/search?id=" wide //weight: 1
        $x_1_3 = "lSwitchToNormalSmsMode" ascii //weight: 1
        $x_1_4 = "onSubscriptionNumberChange" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tarifarch_T_2147680952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.T"
        threat_id = "2147680952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "p_f.php?sub_id=" ascii //weight: 20
        $x_1_2 = {4f 44 4d 34 4e 51 3d 3d 00 00 00 00 61 48 52 30 63 44 6f 76 4c 32 31 76 63 6d 56 6b 4c 6d 4a 70}  //weight: 1, accuracy: High
        $x_1_3 = {4e 7a 41 77 4f 51 3d 3d 00 00 00 00 77 50 44 73 35 65 33 6f 2f 77 3d 3d 00 00 00 00 52 6b 59 67}  //weight: 1, accuracy: High
        $x_1_4 = {4e 44 38 30 4f 51 3d 3d 00 00 00 00 5a 48 68 34 66 44 59 6a 49 32 46 6a 66 6d 6c 6f 49 6d 35 6c}  //weight: 1, accuracy: High
        $x_1_5 = {4f 7a 77 38 4e 51 3d 3d 00 00 00 00 7a 50 7a 67 36 65 48 6b 38 77 3d 3d 00 00 00 00 53 6b 6f 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tarifarch_U_2147680953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.U"
        threat_id = "2147680953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 70 6f 6f 77 69 6f 30 39 30 39 70 71 69 77 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {6f 6f 61 73 6f 6b 39 38 30 39 61 73 6f 6b 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {05 08 10 11 c0 2b 45 f4 2d 00 10 11 00 ff d0 0b c0 0f 84 9b 00 00 00 89 45 f8 8b f8 8b 75 fc 8b 0d 00 30 40 00 f3 a4 ff 35 00 30 40 00 ff 75 f8 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 08 05 ?? ?? 00 00 2d ?? 00 00 c0 83 c0 ?? 03 45 f4 89 45 fc 6a 40 68 00 30 00 00 ff 35 00 30 40 00 33 c0 50 a1 ?? ?? 40 00 05 08 10 11 c0 2b 45 f4 2d 00 10 11 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tarifarch_Q_2147680954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.Q"
        threat_id = "2147680954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "p_f.php?sub_id" ascii //weight: 1
        $x_1_2 = "kyngopranl.co.cc" ascii //weight: 1
        $x_1_3 = {69 66 68 70 66 78 6c 00 67 65 74 5f 70 65 65 72 73}  //weight: 1, accuracy: High
        $x_1_4 = "ArchiveStream" ascii //weight: 1
        $x_1_5 = "UnlockFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tarifarch_J_2147680955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.J"
        threat_id = "2147680955"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RUSSIAN_CHARSET" ascii //weight: 10
        $x_10_2 = "WinZip 2011" ascii //weight: 10
        $x_10_3 = {00 67 6e 8f 00 5b 40 53 35 4a 35 42 40 64 4d 59 40 85 70 7e 44 84 70 80 44 82 72 82 44 84 72}  //weight: 10, accuracy: High
        $x_1_4 = "labelSmsNumber" ascii //weight: 1
        $x_1_5 = "labelSmsText" ascii //weight: 1
        $x_1_6 = "labelSmsInfoCount" ascii //weight: 1
        $x_1_7 = "lSwitchToNormalSmsMode1" ascii //weight: 1
        $x_1_8 = "labelAbonentSmsInfoClick" ascii //weight: 1
        $x_1_9 = "smstariffs.ru" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tarifarch_K_2147680956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.K"
        threat_id = "2147680956"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {37 37 27 23 1d 13 24 39 6e 6f 70 71 72 72 72 72 72 72 73 74 5e 67 75 5e 24 75 68 65 74 72 72 72 72 72}  //weight: 100, accuracy: High
        $x_1_2 = "java_upd.exe" ascii //weight: 1
        $x_1_3 = "CPaymentForm" ascii //weight: 1
        $x_1_4 = "Release\\arc_2010.pdb" ascii //weight: 1
        $x_1_5 = "Release\\new_arc.pdb" ascii //weight: 1
        $x_1_6 = "Release\\arc_2005.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tarifarch_L_2147680957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.L"
        threat_id = "2147680957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "filecash.ru" wide //weight: 10
        $x_1_2 = "SMSNum" ascii //weight: 1
        $x_1_3 = "mePhoneNumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tarifarch_M_2147680958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.M"
        threat_id = "2147680958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sfix\\Release\\sfix.pdb" ascii //weight: 1
        $x_1_2 = "mhtml\\Release\\mhtml.pdb" ascii //weight: 1
        $x_1_3 = "arc\\Release\\arc.pdb" ascii //weight: 1
        $x_1_4 = "hmld1\\Release\\hmld1.pdb" ascii //weight: 1
        $x_10_5 = "/centercash.ru/" wide //weight: 10
        $x_10_6 = "/maxifiles.ru/" wide //weight: 10
        $x_10_7 = "/ccdev2.ru/" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tarifarch_N_2147680959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.N"
        threat_id = "2147680959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "stariffs.ru" ascii //weight: 100
        $x_100_2 = "stariffs.ru" wide //weight: 100
        $x_100_3 = "rufile.in" ascii //weight: 100
        $x_100_4 = "realfine.in" ascii //weight: 100
        $x_100_5 = "fastru.in" ascii //weight: 100
        $x_100_6 = {74 66 69 6c ?? 2e 72 75}  //weight: 100, accuracy: Low
        $x_100_7 = {73 6d 20 73 74 20 e0 72 69 20 66 66 73 20 2e 72 75}  //weight: 100, accuracy: High
        $x_100_8 = "lapoxol.in" ascii //weight: 100
        $x_5_9 = "TBillingInformation" ascii //weight: 5
        $x_5_10 = "btnSubscriptionCheckCode" ascii //weight: 5
        $x_5_11 = "confirmationCodeKey" ascii //weight: 5
        $x_1_12 = {14 ff a6 58 38 91 92 47 2d 64 78 37 30 6b 5e 2c 2e 6a 62 31 2e 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            ((1 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tarifarch_O_2147680960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.O"
        threat_id = "2147680960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 8c 2d c6 5c a3 b9 bd 1d 3b 83 e6 74 27 35 3d 07 a7 cb 56 19 be 18 d4 ca 9e 59 53 90 8b 14 0e}  //weight: 1, accuracy: High
        $x_1_2 = "bill/rul" wide //weight: 1
        $x_1_3 = "://helpprice.i" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Tarifarch_W_2147680961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.W"
        threat_id = "2147680961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/rebill/rule" wide //weight: 1
        $x_1_2 = "http://helpprice.in" wide //weight: 1
        $x_2_3 = {14 04 3b 04 4f 04 20 00 3f 04 3e 04 3b 04 43 04 47 04 35 04 3d 04 38 04 4f 04 20 00 34 04 6f 00 41 04 42 04 43 04 3f 04 30 04 20 00 3d 04 43 04 36 04 3d 04 3e 04 20 00 6f 00 42 04 3f 04 40 04 30 04 32 04 38 04 42 04 4c 04}  //weight: 2, accuracy: High
        $x_2_4 = {47 04 42 04 3e 04 20 00 12 04 4b 04 20 00 20 04 15 04 10 04 1b 04 2c 04 1d 04 2b 04 19 04 20 00 47 04 35 04 3b 04 3e 04 32 04 35 04 3a 04}  //weight: 2, accuracy: High
        $x_2_5 = "_new_url=http://stat" wide //weight: 2
        $x_2_6 = {00 00 15 04 10 04 1b 04 2c 04 1d 04 2b 04 19 04 20 00 47 04 35 04 3b 04 3e 04 32 04 35 04 3a 04}  //weight: 2, accuracy: High
        $x_2_7 = {34 04 3b 04 4f 04 20 00 3f 04 3e 04 34 04 42 04 32 04 35 04 40 04 36 04 34 04 35 04 3d 04 38 04 4f 04 2c 00 20 00 47 04 42 04 3e 04 20 00 12 04 4b 04 20 00 20 04 00 00}  //weight: 2, accuracy: High
        $x_2_8 = {12 04 4b 04 20 00 34 04 3e 04 3b 04 36 04 3d 04 4b 04 20 00 41 04 3e 04 33 04 3b 04 30 04 41 04 38 04 42 04 4c 04 41 04 4f 04 20 00 41 04 20 00 3f 04 40 04 30 04 32 04 38 04 3b 04 30 04 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tarifarch_Z_2147680962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.Z"
        threat_id = "2147680962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WinZip 2011" ascii //weight: 10
        $x_10_2 = "RUSSIAN_CHARSET" ascii //weight: 10
        $x_1_3 = "textPhonePrefix" ascii //weight: 1
        $x_1_4 = "pRebills" ascii //weight: 1
        $x_1_5 = "labelSmsInfoCount" ascii //weight: 1
        $x_1_6 = "labelSmsNumber" ascii //weight: 1
        $x_1_7 = "labelSmsText" ascii //weight: 1
        $x_1_8 = "confirmationCode" ascii //weight: 1
        $x_1_9 = "lSwitchToNormalSmsMode1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tarifarch_S_2147680963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.S"
        threat_id = "2147680963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovL" ascii //weight: 1
        $x_1_2 = "91810700" ascii //weight: 1
        $x_1_3 = "lSubscriptionStep3" ascii //weight: 1
        $x_1_4 = "eSubCfCodeKeyPress" ascii //weight: 1
        $x_1_5 = "doupdate" ascii //weight: 1
        $x_1_6 = "tbillinginformation" ascii //weight: 1
        $x_1_7 = "btnsubscriptioncheckcode" ascii //weight: 1
        $x_1_8 = "RUSSIAN_CHARSET" ascii //weight: 1
        $x_1_9 = "confirmationCode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tarifarch_F_2147680964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.F"
        threat_id = "2147680964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RUSSIAN_CHARSET" ascii //weight: 1
        $x_1_2 = "stariffs.ru" wide //weight: 1
        $x_1_3 = "WinZip 20" wide //weight: 1
        $x_1_4 = "/rebill/ru" wide //weight: 1
        $x_1_5 = {6d 8c 2d c6 5c a3 b9 bd 1d 3b 83 e6 74 27 35 3d 07 a7 cb 56 19 be 18 d4 ca 9e 59 53 90 8b 14 0e}  //weight: 1, accuracy: High
        $x_1_6 = {bc 01 af fe f0 19 58 fe c1 67 50 f7 c9 4e b4 ac 11 48 46 86 20 8e 82 47 96 3b 7d 4a 7f f4 2c}  //weight: 1, accuracy: High
        $x_1_7 = "/partner_new_url=http://stat.openpart.ru/newtoolbar?p=qcash" wide //weight: 1
        $x_1_8 = {26 00 67 00 75 00 69 00 64 00 3d 00 24 00 5f 00 5f 00 47 00 55 00 49 00 44 00 26 00 73 00 69 00 67 00 3d 00 24 00 5f 00 5f 00 53 00 49 00 47 00 00 00 00 00 72 00 75 00 6e 00 61 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_10_9 = {10 63 6f 6e 66 69 72 6d 61 74 69 6f 6e 43 6f 64 65 24}  //weight: 10, accuracy: High
        $x_10_10 = "eSubCfCodeKeyPress" ascii //weight: 10
        $x_10_11 = "lSubscriptionStep3" ascii //weight: 10
        $x_10_12 = "lSwitchToNormalSmsMode" ascii //weight: 10
        $x_10_13 = "btnRebillImg" ascii //weight: 10
        $x_10_14 = "lSwitchToNormalSmsModeClick" ascii //weight: 10
        $x_10_15 = "labelAbonentSmsInfoClick" ascii //weight: 10
        $x_10_16 = "lChooseDifferentSubscriptionNumberClick" ascii //weight: 10
        $x_10_17 = "onStranaIzmenena" ascii //weight: 10
        $x_10_18 = "btnSubscriptionCheckCodeImgLabel" ascii //weight: 10
        $x_10_19 = "confirmationCodeKeyPress" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tarifarch_G_2147680965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.G"
        threat_id = "2147680965"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6d 8c 2d c6 5c a3 b9 bd 1d 3b 83 e6 74 27 35 3d 07 a7 cb 56 19 be 18 d4 ca 9e 59 53 90 8b 14 0e}  //weight: 2, accuracy: High
        $x_2_2 = {26 00 67 00 75 00 69 00 64 00 3d 00 24 00 5f 00 5f 00 47 00 55 00 49 00 44 00 26 00 73 00 69 00 67 00 3d 00 24 00 5f 00 5f 00 53 00 49 00 47 00 00 00 00 00 72 00 75 00 6e 00 61 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = "/partner_new_url=http://stat.openpart.ru/newtoolbar?p=qcash" wide //weight: 2
        $x_1_4 = "/rebill/rules" wide //weight: 1
        $x_1_5 = "onKeyPressValidateNumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tarifarch_H_2147680966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.H"
        threat_id = "2147680966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 8c 2d c6 5c a3 b9 bd 1d 3b 83 e6 74 27 35 3d 07 a7 cb 56 19 be 18 d4 ca 9e 59 53 90 8b 14 0e}  //weight: 1, accuracy: High
        $x_1_2 = {34 04 3b 04 4f 04 20 00 3f 04 3e 04 34 04 42 04 32 04 35 04 40 04 36 04 34 04 35 04 3d 04 38 04 4f 04 2c 00 20 00 47 04 42 04 3e 04 20 00 12 04 4b 04 20 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {12 04 4b 04 20 00 34 04 3e 04 3b 04 36 04 3d 04 4b 04 20 00 41 04 3e 04 33 04 3b 04 30 04 41 04 38 04 42 04 4c 04 41 04 4f 04 20 00 41 04 20 00 3f 04 40 04 30 04 32 04 38 04 3b 04 30 04 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "http://helpprice.in" wide //weight: 1
        $x_1_5 = " 3339  life :); MTC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Tarifarch_AO_2147710833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarifarch.AO"
        threat_id = "2147710833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarifarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {47 04 42 04 3e 04 20 00 12 04 4b 04 20 00 20 04 15 04 10 04 1b 04 2c 04 1d 04 2b 04 19 04 20 00 47 04 35 04 3b 04 3e 04 32 04 35 04 3a 04}  //weight: 2, accuracy: High
        $x_2_2 = {6d 8c 2d c6 5c a3 b9 bd 1d 3b 83 e6 74 27 35 3d 07 a7 cb 56 19 be 18 d4 ca 9e 59 53 90 8b 14 0e}  //weight: 2, accuracy: High
        $x_1_3 = "&mtid=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

