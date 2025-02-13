rule TrojanSpy_Win32_Goldun_BX_2147803334_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Goldun.BX"
        threat_id = "2147803334"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Goldun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 72 65 64 69 72 65 63 74 5f 66 61 6b 65 2e 74 78 74 00 00 ff ff ff ff 15 00 00 00 72 65 64 69 72 65 63}  //weight: 1, accuracy: High
        $x_1_2 = {65 2d 67 6f 6c 64 2e 63 6f 6d 00 00 [0-10] 2f 61 63 63 74 2f 6c 69 2e 61 73}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff ff 0b 00 00 00 63 69 74 69 62 61 6e 6b 2e 64 65 00 ff ff ff ff 0a 00 00 00 31 32 33 34 35}  //weight: 1, accuracy: High
        $x_1_4 = "&text=------------------------------------ [HOLDER_MAIL_E-GOLD]" ascii //weight: 1
        $x_1_5 = "[IP=//*~~~~~*////*DATETIME*//]" ascii //weight: 1
        $x_1_6 = "***------------------------------------ [URL=" ascii //weight: 1
        $x_1_7 = "redirect_fake.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Goldun_BY_2147803800_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Goldun.BY"
        threat_id = "2147803800"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Goldun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5b 49 50 3d 2f 2f 2a 7e 7e 7e 7e 7e 2a 2f 2f 2f 2f 2a 44 41 54 45 54 49 4d 45 2a 2f 2f 5d 00}  //weight: 3, accuracy: High
        $x_3_2 = {5c 72 65 64 69 72 65 63 74 5f 66 61 6b 65 2e 74 78 74 00}  //weight: 3, accuracy: High
        $x_3_3 = {6c 69 2e 61 73 70 [0-16] 2f 61 63 63 74 2f 62 61 6c 61 6e 63 65 2e 61 73 70 [0-16] 2f 61 63 63 74 2f 63 6f 6e 66 69 72 6d 2e 61 73}  //weight: 3, accuracy: Low
        $x_1_4 = "https://www.e-gold.com/acct/" ascii //weight: 1
        $x_1_5 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 20 5b 55 52 4c 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = "ACTUAL_PAYMENT_OUNCES value=\"" ascii //weight: 1
        $x_1_7 = "Payee_Account=%s&Amount=%s&PAY_IN=" ascii //weight: 1
        $x_1_8 = "id=%08lX%08lX&ip=%s&title=%s&url=%s&data=" ascii //weight: 1
        $x_1_9 = "AccountID=%s&PassPhrase=%s&Amount=%s&Email=%s" ascii //weight: 1
        $x_1_10 = {26 50 41 59 4d 45 4e 54 5f 55 4e 49 54 53 3d [0-8] 26 50 41 59 4d 45 4e 54 5f 4d 45 54 41 4c 5f 49 44 3d [0-8] 26 50 41 59 45 52 5f 41 43 43 4f 55 4e 54 3d}  //weight: 1, accuracy: Low
        $x_1_11 = {69 63 71 2e 70 68 70 3f 74 65 78 74 3d 00}  //weight: 1, accuracy: High
        $x_1_12 = "gold.php?id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Goldun_BZ_2147803801_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Goldun.BZ"
        threat_id = "2147803801"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Goldun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 00 49 64 65 6e 74 69 74 69 65 73 00 50 4f 50 33 20 50 61 73 73 77 6f 72 64 32 00}  //weight: 1, accuracy: High
        $x_1_2 = {38 39 30 37 33 30 30 00 0d 0a}  //weight: 1, accuracy: High
        $x_1_3 = {0d 0a 2d 3d 3d 3b 20 41 63 63 6f 75 6e 74 0d 0a}  //weight: 1, accuracy: High
        $x_1_4 = {20 3b 20 50 72 6f 74 65 63 74 65 64 20 53 74 6f 72 61 67 65 3a 0d 0a}  //weight: 1, accuracy: High
        $x_1_5 = {25 73 20 3b 20 6d 61 69 6c 73 65 72 76 3a 20 25 73 20 3b 20 70 61 73 73 77 6f 72 64 3a 20 25 73 0d 0a}  //weight: 1, accuracy: High
        $x_1_6 = {20 3b 20 54 68 65 42 61 74 20 70 61 73 73 77 6f 72 64 73 0d 0a 00 47 45 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Goldun_CB_2147803802_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Goldun.CB"
        threat_id = "2147803802"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Goldun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "else if (document.teclado.password.value.length == 0)" ascii //weight: 1
        $x_1_2 = "banking.sparkasse-" ascii //weight: 1
        $x_1_3 = "?WG#bojdm>!ofew!#`lopsbm>!4!#ubojdm>!alwwln!=?JMSVW#wzsf>!wf{w!#mbnf>!oldjm!##lmEl`vp>!ibubp`qjsw9dvbqgbqEl`l+$oldjm$*8!#nb{ofmdwk>!13!#wbajmgf{>!2!#`obpp>!Wf{wl@lmwfmjgl!=?,WG=" ascii //weight: 1
        $x_1_4 = {65 72 77 65 69 73 75 6e 67 2e 63 67 69 00 00 00 00 67 6f 6c 64 2e 63 6f 6d 2f 61 63 63 74 2f 6c 69 2e 00}  //weight: 1, accuracy: High
        $x_1_5 = {63 65 6d 00 65 62 61 6e 6b 69 6e 74 65 72 00 00 63 6c 69 65 6e 74 5f 00 63 70 73 69 6e 74 65 72 6e 65 74 62 61 6e 6b 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Goldun_FB_2147803828_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Goldun.FB"
        threat_id = "2147803828"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Goldun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Referer: https://www.e-gold.com/acct/ai.asp?c=AS" ascii //weight: 10
        $x_10_2 = "YFHty25\\00t0p00.exe" ascii //weight: 10
        $x_10_3 = "C:\\WINDOWS\\SYSTEM32\\intel3.dll" ascii //weight: 10
        $x_5_4 = "C:\\WINDOWS\\SYSTEM32\\drivers\\etc\\hosts" ascii //weight: 5
        $x_5_5 = "SOFTWARE\\Microsoft\\Internet Account Manager\\Accounts" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Goldun_FC_2147803829_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Goldun.FC"
        threat_id = "2147803829"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Goldun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "C:\\WINDOWS\\SYSTEM32\\browsemu.dll" ascii //weight: 10
        $x_10_2 = "https://www.e-gold.com/" ascii //weight: 10
        $x_10_3 = "/acct/ai.asp?c=CO" ascii //weight: 10
        $x_10_4 = {25 54 45 4d 50 25 5c 73 65 72 76 [0-4] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_5_5 = "&WORTH_OF=Gold&Memo=&" ascii //weight: 5
        $x_5_6 = "SOFTWARE\\Microsoft\\Internet Account Manager\\Accounts" ascii //weight: 5
        $x_1_7 = "comcsi5.dll" ascii //weight: 1
        $x_1_8 = "srvswc2.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Goldun_C_2147803844_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Goldun.gen!C"
        threat_id = "2147803844"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Goldun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 63 61 73 53 65 72 76 2e 65 78 65 00 00 00 00 67 63 61 73 44 74 53 65 72 76 2e 65 78 65 00 00 47 49 41 4e 54 41 6e 74 69 53 70 79 77 61 72 65 4d 61 69 6e 2e 65 78 65 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {7a 00 00 00 26 6e 6f 77 00 00 00 00 26 6e 6e 3d 31 26 72 3d 00 00 00 00 31 2e 39 2e}  //weight: 1, accuracy: High
        $x_1_3 = {26 76 65 72 3d 00 00 00 3f 70 68 69 64 3d 00 00 25 64 00 00 69 6e 73 74 61 6c 6c 65 72 5f 74 69 6d 65}  //weight: 1, accuracy: High
        $x_1_4 = {7a 75 7a 75 00 00 00 00 65 77 75 69 79 75 77 65 79 75 00 00 52 54 5f 44 4c 4c}  //weight: 1, accuracy: High
        $x_1_5 = {70 68 69 64 00 00 00 00 53 6f 66 74 77 61 72 65 5c 57 69 6e 64 6f 77 73 00 00 00 00 63 3a 5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 4d 69 63 72 6f 73 6f 66 74 20 41 6e 74 69 53 70 79 77 61 72 65 5c 2a 2e 67 63 64}  //weight: 1, accuracy: High
        $x_1_6 = {53 65 72 76 53 74 61 74 65 00 00 00 53 6f 66 74 77 61 72 65 5c 47 49 41 4e 54 43 6f 6d 70 61 6e 79 5c 41 6e 74 69 53 70 79 77 61 72 65 00 00 00 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 00 00 00 00 6f 70 65 6e 00 00 00 00 72 65 67 73 76 72 33 32}  //weight: 1, accuracy: High
        $x_1_7 = {3b fb 74 3d 53 68 80 00 00 00 6a 02 53 6a 01 68 00 00 00 40 68 f0 11 40 00 ff 15 34 10 40 00 8b f0 83 fe ff 75 04 32 c0 eb 19}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Goldun_FO_2147803978_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Goldun.FO"
        threat_id = "2147803978"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Goldun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*barclays.co.uk*" ascii //weight: 1
        $x_1_2 = "*365online.com*" ascii //weight: 1
        $x_1_3 = "*IBLogon.jsp*" ascii //weight: 1
        $x_1_4 = "*/Logon-PinPass.asp*" ascii //weight: 1
        $x_1_5 = "POP3:%s" ascii //weight: 1
        $x_1_6 = "C:\\WINDOWS\\svhost.exe" ascii //weight: 1
        $x_2_7 = "_pass.txt" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Goldun_2147804056_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Goldun.gen!dll"
        threat_id = "2147804056"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Goldun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {74 1f 8b 4c 24 0c 81 39 77 77 77 2e 75 03 83 c1 04}  //weight: 4, accuracy: High
        $x_4_2 = {c7 42 06 62 61 6c 61 c7 42 0a 6e 63 65 2e}  //weight: 4, accuracy: High
        $x_3_3 = {8a 06 46 51 8a 4d f7 d2 c8 59 50 56 ff 45 f8 8b 75 f8 8a 06 46 8b 5d fc 39 5d f8 75 0c}  //weight: 3, accuracy: High
        $x_3_4 = {8b 54 24 0c 81 7a 02 63 63 74}  //weight: 3, accuracy: High
        $x_2_5 = {81 bd d4 fe ff ff 45 64 69 74 74 08}  //weight: 2, accuracy: High
        $x_2_6 = {0c 81 c1 00 10 00 00 c1 e9 0c 8b 7d 08 c1 ef 0c 68 00 00 06 20 6a 00 51 57 68 0d 00 01 00 ff 96}  //weight: 2, accuracy: High
        $x_3_7 = "; mailserv: %s ; password: %s" ascii //weight: 3
        $x_3_8 = {26 69 6e 66 6f 3d 00 77 77 77 2e 65 2d 67 6f 6c 64 2e 63 6f 6d}  //weight: 3, accuracy: High
        $x_3_9 = {3d 00 52 65 66 65 72 65 72 3a 20 68 74 74 70 73 3a 2f 2f 77 77 77 2e 65 2d 67 6f 6c 64 2e 63 6f 6d}  //weight: 3, accuracy: High
        $x_3_10 = "POST /%s?os=nt HTTP/1.1" ascii //weight: 3
        $x_3_11 = {2d 67 6f 6c 64 2e 63 6f 6d 2f 61 63 63 74 2f 61 69 2e 61 73 70 0d 0a 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77}  //weight: 3, accuracy: High
        $x_3_12 = {6e 00 5c 5c 2e 5c 70 69 70 65 5c 49 45 53 34}  //weight: 3, accuracy: High
        $x_2_13 = {4e 74 50 72 6f 74 65 63 74 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 5c 64 72 69 76 65 72 73 5c}  //weight: 2, accuracy: High
        $x_2_14 = "GET /%s?param=cmd" ascii //weight: 2
        $x_2_15 = {2d 6c 61 62 73 2e 63 6f 6d 00 66 74 70 2e 66 2d 73 65 63 75 72 65 2e 63 6f 6d}  //weight: 2, accuracy: High
        $x_1_16 = "=login action='balance.asp'>" ascii //weight: 1
        $x_1_17 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_18 = "ces\\SharedAccess\\Parameters\\FirewallPoli" ascii //weight: 1
        $x_1_19 = "NtWriteVirtualMemory" ascii //weight: 1
        $x_1_20 = {61 74 65 73 31 2e 6b 61 73 70 65 72 73 6b 79 2d 6c 61 62 73 2e 63 6f 6d 00 75 70 64 61 74 65 73}  //weight: 1, accuracy: High
        $x_1_21 = {64 6f 77 6e 6c 6f 61 64 2e 6d 63 61 66 65 65 2e 63 6f 6d 00 64 6f 77 6e 6c 6f 61 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((3 of ($x_3_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((5 of ($x_3_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_3_*))) or
            ((2 of ($x_4_*) and 6 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Goldun_B_2147804057_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Goldun.gen!B"
        threat_id = "2147804057"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Goldun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {42 52 4f 57 53 45 52 5f 50 52 4f 47 52 41 4d 3a 20 00 00 00 62 72 6f 77 73 65 6d 75 00 00 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 00 00 00 00 5c 00 00 00 72}  //weight: 2, accuracy: High
        $x_1_2 = "%s%x%x.tmp" ascii //weight: 1
        $x_1_3 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 45 78 41 00 49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 00 00 00 00 48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 00 00 00 00 48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 41}  //weight: 1, accuracy: High
        $x_2_4 = {43 75 73 74 6f 6d 65 72 51 75 65 73 74 69 6f 6e 00 00 00 00 65 2d 67 6f 6c 64 2e 63 6f 6d 2f 61 63 63 74 2f 63 6f 6e 74 61 63 74 75 73 2e 61 73 70 00 00 00 6c 6f 67 00 66 74 72 00 09 00 00 00 0d 0a 49 50 3a}  //weight: 2, accuracy: High
        $x_2_5 = {77 77 77 2e 65 2d 67 6f 6c 64 2e 63 6f 6d 00 00 31 32 33 34 35 36 37 38 39 30 00 00 45 52 52 4f 52 00 00 00 2f 61 63 63 74 2f 63 6f 6e 66 69 72 6d 2e 61 73 70 00 00 00 68 74 74 70 73 3a 2f 2f 77 77 77 2e 65 2d 67 6f 6c 64 2e 63 6f 6d 2f 61 63 63 74 2f 76 65 72 69 66 79 2e 61 73 70 00 00 26 42 41 63 74 69 6f 6e 3d}  //weight: 2, accuracy: High
        $x_2_6 = "https://www.e-gold.com/acct/accountinfo.asp" wide //weight: 2
        $x_1_7 = {72 3d 25 64 26 72 61 6e 64 3d 25 64 00 00 00 00 74 61 6e 73 00 00 00 00 65 67 6f 6c 64 61 63 63 00 00 00 00 26 6e 6f 77 00 00 00 00 26 6e 6e 3d 31}  //weight: 1, accuracy: High
        $x_1_8 = "bankofamerica.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Goldun_FM_2147804130_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Goldun.FM!dll"
        threat_id = "2147804130"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Goldun"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "84"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/%s/msg.php?ver=%s&extver=%s&user=%s&lang=" ascii //weight: 1
        $x_1_2 = "/%s/login.php?user=%s&lang=%s&uptime=%d_d_%dh_%dm&socks=0&ver=%s&extver=%s&win=" ascii //weight: 1
        $x_3_3 = "\\spool\\desktops.ini" ascii //weight: 3
        $x_3_4 = "\\spool\\c.ini" ascii //weight: 3
        $x_3_5 = "\\spool\\eg.ini" ascii //weight: 3
        $x_20_6 = "e-gold.com/acct/li.asp" ascii //weight: 20
        $x_30_7 = "HTTPMail Password" ascii //weight: 30
        $x_30_8 = "POP3 Password" ascii //weight: 30
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_30_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_30_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Goldun_FM_2147804130_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Goldun.FM!dll"
        threat_id = "2147804130"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Goldun"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "46"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/%s/final.php?ver=%s&user=%s&site=post" ascii //weight: 1
        $x_1_2 = "/%s/drop.php?ver=%s&site=post&user=%s%s" ascii //weight: 1
        $x_1_3 = "/%s/mail.php?ver=%s&extver=%s&user=%s&lang=%s&win" ascii //weight: 1
        $x_5_4 = "banking.postbank.de/app/ueberweisung" wide //weight: 5
        $x_5_5 = "banking.postbank.de/app/legitimation." wide //weight: 5
        $x_5_6 = "postbank.de/app/finanzstatus.init.do" wide //weight: 5
        $x_20_7 = "\\spool\\desktops.ini" ascii //weight: 20
        $x_20_8 = "URLDownloadToFileA" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

