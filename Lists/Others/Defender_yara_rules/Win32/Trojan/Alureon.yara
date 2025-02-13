rule Trojan_Win32_Alureon_B_91469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!B"
        threat_id = "91469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "PEGFSDGHXCBGTR#" ascii //weight: 3
        $x_3_2 = "KEBDHORDCZGLTA#" ascii //weight: 3
        $x_3_3 = "EEGSDHSFGJL" ascii //weight: 3
        $x_3_4 = "GHXCBGTR" ascii //weight: 3
        $x_3_5 = "ORDCZGLTA" ascii //weight: 3
        $x_3_6 = "/cnt.jpg" ascii //weight: 3
        $x_3_7 = "Content-Type: %s;%s;%x;%x;%x" ascii //weight: 3
        $x_3_8 = "User-Agent: %s" ascii //weight: 3
        $x_3_9 = "%s\\%c%c%c%c%c.%s" ascii //weight: 3
        $x_1_10 = "Explorer.exe" ascii //weight: 1
        $x_1_11 = "sidcls" ascii //weight: 1
        $x_1_12 = "clsid" ascii //weight: 1
        $x_1_13 = "Software\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 1
        $x_1_14 = "explorer.exe" ascii //weight: 1
        $x_1_15 = "http://85" ascii //weight: 1
        $x_1_16 = "Microsoft Internet Explorer" ascii //weight: 1
        $x_1_17 = "CreateEventA" ascii //weight: 1
        $x_1_18 = "SetEndOfFile" ascii //weight: 1
        $x_1_19 = "SetFilePointer" ascii //weight: 1
        $x_1_20 = "WriteFile" ascii //weight: 1
        $x_1_21 = "CreateFileA" ascii //weight: 1
        $x_1_22 = "CreateProcessA" ascii //weight: 1
        $x_1_23 = "GetSystemDirectoryA" ascii //weight: 1
        $x_1_24 = "WriteProcessMemory" ascii //weight: 1
        $x_1_25 = "VirtualProtectEx" ascii //weight: 1
        $x_1_26 = "DuplicateHandle" ascii //weight: 1
        $x_1_27 = "RemoveDirectoryA" ascii //weight: 1
        $x_1_28 = "GetTickCount" ascii //weight: 1
        $x_1_29 = "InitializeSecurityDescriptor" ascii //weight: 1
        $x_1_30 = "SetSecurityDescriptorDacl" ascii //weight: 1
        $x_1_31 = "UuidToStringA" ascii //weight: 1
        $x_1_32 = "InternetOpenA" ascii //weight: 1
        $x_1_33 = "InternetCanonicalizeUrlA" ascii //weight: 1
        $x_1_34 = "HttpOpenRequestA" ascii //weight: 1
        $x_1_35 = "HttpAddRequestHeadersA" ascii //weight: 1
        $x_1_36 = "HttpSendRequestA" ascii //weight: 1
        $x_1_37 = "InternetReadFile" ascii //weight: 1
        $x_1_38 = "InternetCloseHandle" ascii //weight: 1
        $x_1_39 = "InternetCrackUrlA" ascii //weight: 1
        $x_1_40 = "InternetConnectA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_3_*) and 29 of ($x_1_*))) or
            ((6 of ($x_3_*) and 26 of ($x_1_*))) or
            ((7 of ($x_3_*) and 23 of ($x_1_*))) or
            ((8 of ($x_3_*) and 20 of ($x_1_*))) or
            ((9 of ($x_3_*) and 17 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_113116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon"
        threat_id = "113116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 1c 00 01 00 00 e8 ?? ?? 00 00 83 c4 14 84 c0 74 30 a1 ?? ?? 40 00 85 c0 74 27 8b 3d ?? ?? 40 00 b8 ?? ?? 40 00 8b f0 8b 10 8d 44 24 0c 52 50 ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 3b 57 e8 ?? ?? 00 00 8b f0 59 59 bb ?? ?? 40 00 80 26 00 46 89 3d ?? ?? 40 00 89 35 ?? ?? 40 00 56 e8 ?? ?? ff ff 6a 2e 56 89 03}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 fc 00 01 00 00 f3 ab 66 ab aa 8d 45 fc 50 8d 85 fc fe ff ff 50 68 ?? ?? 40 00 68 ?? ?? 40 00 68 01 00 00 80 e8 ?? ?? 00 00 83 c4 14 84 c0 74 2d 83 3d ?? ?? 40 00 00 74 24 b8 ?? ?? 40 00 8b f0 ff 30}  //weight: 1, accuracy: Low
        $x_1_4 = {0f 84 88 04 00 00 d1 e9 8d 56 0c 50 a1 ?? ?? ?? ?? 51 52 53 ff 30 e8 ?? ?? ff ff 83 c4 14 85 c0 0f 95 c0 3a c3 0f 84 84 00 00 00 39 1e 75 0c c7 45 30 0f 00 00 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Alureon_D_114173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!D"
        threat_id = "114173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb b9 81 7d d4 96 00 00 00 77 06 83 7d d4 32 73 01 cc}  //weight: 1, accuracy: High
        $x_1_2 = {eb b9 81 7d d0 96 00 00 00 77 06 83 7d d0 32 73 01 cc}  //weight: 1, accuracy: High
        $x_1_3 = {9c 8f 45 fc 6a 00 6a 64 e8 00 00 00 00 58 83 c0 09 50 ff 65 e0 cc 85 c0 75 fb 64 a1 30 00 00 00 85 c0 78 5c}  //weight: 1, accuracy: High
        $x_1_4 = {9c 8f 45 fc 81 65 fc 00 01 00 00 74 01 cc 8b 55 e4 52 68 ?? ?? ?? ?? e8 ?? ?? ff ff 83 c4 08 89 45 e0 6a 00 6a 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Alureon_E_114864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!E"
        threat_id = "114864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "263"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "MD5Hash function expected!" ascii //weight: 100
        $x_100_2 = "HexDecoder function expected!" ascii //weight: 100
        $x_10_3 = "key.lky" ascii //weight: 10
        $x_10_4 = "setup3.exe" ascii //weight: 10
        $x_10_5 = "\\notepad.exe.dat" ascii //weight: 10
        $x_10_6 = "\\calc.exe.dat" ascii //weight: 10
        $x_10_7 = "Decrypt" ascii //weight: 10
        $x_10_8 = "SOFTWARE INSTALLATION: Components bundled into the software may report to Licensor" ascii //weight: 10
        $x_10_9 = "#32770" ascii //weight: 10
        $x_10_10 = "DcryptDll.dll" ascii //weight: 10
        $x_1_11 = "Nullsoft Install System" ascii //weight: 1
        $x_1_12 = "It may be possible to skip this check using the /NCRC command line switch" ascii //weight: 1
        $x_1_13 = "modern-header.bmp" ascii //weight: 1
        $x_1_14 = "startmenu.dll" ascii //weight: 1
        $x_1_15 = "lzma.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 6 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_100_*) and 7 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_F_115740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!F"
        threat_id = "115740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE INSTALLATION: Components bundled into the software may report to Licensor" ascii //weight: 2
        $x_1_2 = {63 72 63 2e 65 78 65 00 70 61 63 6b 2e 62 69 6e 00 2d 6f 2b 20 2d 70}  //weight: 1, accuracy: High
        $x_1_3 = {5c 73 65 74 75 70 20 31 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 73 65 74 75 70 20 32 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "\\crc.exe\" e" ascii //weight: 1
        $x_1_6 = {70 61 63 6b 2e 62 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_G_117858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!G"
        threat_id = "117858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 65 78 44 65 63 6f 64 65 72 00 48 65 78 45 6e 63 6f 64 65 72 00 4c 6f 61 64 53 74 72 00 4d 44 35 48 61 73 68 00}  //weight: 1, accuracy: High
        $x_1_2 = "DcryptDll.dll" ascii //weight: 1
        $x_1_3 = "notepad.exe.dat" ascii //weight: 1
        $x_1_4 = "calc.exe.dat" ascii //weight: 1
        $x_1_5 = "freebsd.exe.dat" ascii //weight: 1
        $x_1_6 = "lzma.exe" ascii //weight: 1
        $x_1_7 = "Software\\VideoPorn" ascii //weight: 1
        $x_1_8 = {6c 69 6e 75 78 00 46 46 46 00 44 65 63 72 79 70 74}  //weight: 1, accuracy: High
        $x_1_9 = "SOFTWARE INSTALLATION: Components bundled into the software may report to Licensor" ascii //weight: 1
        $x_1_10 = {cf d0 ce c3 d0 c0 cc cc cd ce c3 ce 20 ce c1 c5 d1 cf c5 d7 c5 cd c8 df 3a 20 cf f0 ee e3 f0 e0 ec ec ed ee e5 20 ee e1 e5 f1 ef e5 f7 e5 ed e8 e5 20 f1 ee e4 e5 f0 e6 e8 f2 20 ea ee ec ef ee ed e5 ed f2 fb 20 ef e5 f0 e5 e4 e0 fe f9 e8 e5}  //weight: 1, accuracy: High
        $x_1_11 = "Nullsoft Install System" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Alureon_C_121046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!C"
        threat_id = "121046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a d1 80 c2 ?? 30 14 ?? 83 c1 01 3b ?? 72 f1 c3}  //weight: 10, accuracy: Low
        $x_1_2 = "[runs_count_" ascii //weight: 1
        $x_1_3 = "[urls_to_serf_" ascii //weight: 1
        $x_1_4 = "[refs_to_change_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_C_121046_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!C"
        threat_id = "121046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "82"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "installhook" ascii //weight: 10
        $x_10_2 = "writefile" ascii //weight: 10
        $x_10_3 = "process32first" ascii //weight: 10
        $x_10_4 = "createtoolhelp32snapshot" ascii //weight: 10
        $x_10_5 = "software\\microsoft\\windows nt\\currentversion\\winlogon" ascii //weight: 10
        $x_10_6 = "software\\microsoft\\internet explorer\\typedurls" ascii //weight: 10
        $x_10_7 = "/ocget.dll" ascii //weight: 10
        $x_5_8 = "85.255." ascii //weight: 5
        $x_5_9 = "http://%s%s&id=%d&qnaes=%s" ascii //weight: 5
        $x_1_10 = "pornstarkings.com" ascii //weight: 1
        $x_1_11 = "extremebullshit.com" ascii //weight: 1
        $x_1_12 = "adultwebmasterinfo.com" ascii //weight: 1
        $x_1_13 = "adultchamber.com" ascii //weight: 1
        $x_1_14 = "pornresource.com" ascii //weight: 1
        $x_1_15 = "gofuckyourself" ascii //weight: 1
        $x_1_16 = "videoscash.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((7 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_I_122922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!I"
        threat_id = "122922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 21 8a 44 24 10 53 56 8b 74 24 10 8a 1c 31 8a d1 02 d0 32 da 88 1c 31 41 3b cf 72 ef 8b c6}  //weight: 1, accuracy: High
        $x_1_2 = {3d 00 00 00 80 73 15 68 ?? ?? 40 00 68 ?? ?? 40 00 e8 ?? ?? ff ff 85 c0 75 38 eb 2f 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Alureon_J_126104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!J"
        threat_id = "126104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {24 04 76 0f 8a d1 80 c2 ?? 30 14 01 41 3b 4c 24 04 72 f1}  //weight: 2, accuracy: Low
        $x_2_2 = {39 4c 24 08 76 14 8b 44 24 04 8a d1 03 c1 80 c2 ?? 30 10 41 3b 4c 24 08 72 ec}  //weight: 2, accuracy: Low
        $x_2_3 = {8a c8 80 c1 ?? 30 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 72 ed}  //weight: 2, accuracy: Low
        $x_2_4 = {83 2c 24 0a c6 (44 24|45) ?? b8 89 (44 24|45) ?? 66 c7 (44 24|45) ?? ff e0}  //weight: 2, accuracy: Low
        $x_1_5 = {39 28 75 d2 eb 07 8b 1c b5 ?? ?? ?? ?? 83 c7 04 81 ff ?? ?? ?? ?? 7c ab 5f}  //weight: 1, accuracy: Low
        $x_2_6 = {eb 06 8d 58 01 6a 5c 53 ff d7 85 c0 59 59 75 f2 68 ?? ?? ?? ?? 53 ff 15 ?? ?? ?? ?? 85 c0 59 59 74 07}  //weight: 2, accuracy: Low
        $x_2_7 = {5c 00 6b 00 6e 00 6f 00 77 00 6e 00 64 00 6c 00 6c 00 73 00 5c 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 2, accuracy: High
        $x_1_8 = "\\\\?\\globalroot\\systemroot\\system32\\advapi32.dll" ascii //weight: 1
        $x_1_9 = "\\\\?\\globalroot\\tdl" ascii //weight: 1
        $x_1_10 = "u=%s&i=%s&p=%s&f=%s&c=%d&d=%d" ascii //weight: 1
        $x_1_11 = "r=%s&f=%s&p=%s&u=%s&i=%s&g=%d" ascii //weight: 1
        $x_1_12 = "/dlink/hwiz.html" ascii //weight: 1
        $x_2_13 = {50 6a 40 6a 15 03 cf 51 ff d5 8b 4b 28 8b 14 31 8d 04 31}  //weight: 2, accuracy: High
        $x_2_14 = {50 8b 43 28 6a 40 6a 15 03 c7 50 ff 15 ?? ?? ?? ?? 8b 43 28 6a 05}  //weight: 2, accuracy: Low
        $x_2_15 = {8b 46 28 03 45 0c 6a 40 6a 15 50 89 75 f0 ff 15 ?? ?? ?? ?? 8b 46 28 8b 4d 0c 8d 34 38 8d 3c 08 6a 05}  //weight: 2, accuracy: Low
        $x_2_16 = {3b c6 89 45 08 74 47 6a 40 68 00 30 00 00 40 50 56 ff 15 ?? ?? ?? ?? 8b f8 3b fe 74 31}  //weight: 2, accuracy: Low
        $x_1_17 = {5f 89 48 58 8b c6 5e 5b c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_AP_126907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.AP"
        threat_id = "126907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{6BF52A52-394A-11D3-B153-00C04F79FAA6}" ascii //weight: 1
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 47 49 47 41 50 6f 72 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = "GIGAPorn Setup" ascii //weight: 1
        $x_1_4 = "inst1.exe" ascii //weight: 1
        $x_1_5 = "LICENSE AGREEMENT !" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_K_127182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!K"
        threat_id = "127182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 44 24 14 8b cd 2b f5 8a 14 0e 32 d0 88 11 41 4f 75 f5}  //weight: 2, accuracy: High
        $x_2_2 = {8b 4f 74 8b 57 08 51 52 68 ?? ?? ?? ?? e8 ?? ?? 00 00 8b e8 8b 44 24 30}  //weight: 2, accuracy: Low
        $x_2_3 = {35 55 ca 54 df 05 2b 2b 2b 2b 50}  //weight: 2, accuracy: High
        $x_2_4 = {75 12 8b 44 24 10 6a 01 56 6a 05 6a 01 50 ff 15 ?? ?? ?? ?? 6a ff 8d 4c 24 18 6a 00 51 6a 01 89 74 24 24}  //weight: 2, accuracy: Low
        $x_1_5 = {73 00 65 00 72 00 76 00 2e 00 73 00 79 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {63 00 72 00 65 00 64 00 6f 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_2_7 = {b8 50 43 52 50 3b c8 77 54 74 48 8b c1 2d 48 4c 4c 44 74 2f}  //weight: 2, accuracy: High
        $x_2_8 = {75 15 32 d2 8b cb c7 43 18 56 01 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_L_127242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!L"
        threat_id = "127242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 40 8b 4d fc 83 c1 03 89 4d fc 68 ?? ?? ?? ?? 8b 55 fc 52 e8 ?? ?? 00 00 83 c4 08 89 45 f8 83 7d f8 00}  //weight: 2, accuracy: Low
        $x_2_2 = {73 1c 8b 4d 08 03 4d f8 0f be 11 33 55 0c 88 55 f0 8b 45 f4 03 45 f8 8a 4d f0 88 08 eb d3}  //weight: 2, accuracy: High
        $x_1_3 = {3f 63 3d 00 26 6d 6b 3d 00}  //weight: 1, accuracy: High
        $x_2_4 = {66 69 72 65 73 6f 78 2e 64 6c 6c 00 3f 3f 52}  //weight: 2, accuracy: High
        $x_2_5 = {75 72 6c 2d 3e 20 25 73 0a 0a 72 65 66 20 2d 3e}  //weight: 2, accuracy: High
        $x_1_6 = "SendPostRaw" ascii //weight: 1
        $x_1_7 = "First-Click:%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_AW_127340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.AW"
        threat_id = "127340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "56"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\tdssinit.dll" ascii //weight: 2
        $x_2_2 = "tdssserf.dll" wide //weight: 2
        $x_1_3 = "[runs_count_" ascii //weight: 1
        $x_1_4 = "[urls_to_serf_" ascii //weight: 1
        $x_1_5 = "[refs_to_change_" ascii //weight: 1
        $x_2_6 = "g_plpstrUrlsToSerf" ascii //weight: 2
        $x_10_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 10, accuracy: High
        $x_10_8 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 00}  //weight: 10, accuracy: High
        $x_10_9 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 00}  //weight: 10, accuracy: High
        $x_10_10 = {4d 61 70 46 69 6c 65 41 6e 64 43 68 65 63 6b 53 75 6d 41 00}  //weight: 10, accuracy: High
        $x_10_11 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_O_131469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!O"
        threat_id = "131469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 c0 8a c8 80 c1 54 30 88 ?? ?? 00 10 40 83 f8 ?? 72 ef c3}  //weight: 3, accuracy: Low
        $x_1_2 = {00 58 3a 5c 72 65 73 79 63 6c 65 64 5c 62 6f 6f 74 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 58 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 50 4f 53 54 20 2f 63 67 69 2d 62 69 6e 2f 67 65 6e 65 72 61 74 6f 72 20 48 54 54 50 2f 31 2e 30 0d 0a}  //weight: 1, accuracy: High
        $x_1_5 = {5c 5c 3f 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 73 79 73 74 65 6d 72 6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 61 64 76 61 70 69 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 73 65 78 76 69 64 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 74 65 6d 70 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_P_132759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!P"
        threat_id = "132759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 5c 06 04 8a d0 32 1d ?? ?? 40 00 c0 e2 40 0a d0 c0 e2 17 2a da 2a d9 88 5c 06 04 40 3b c7 72 df}  //weight: 1, accuracy: Low
        $x_1_2 = {be 65 00 00 00 e8 ?? ?? 00 00 83 f8 04 75 07 be 66 00 00 00 eb 0a 83 f8 08 75 05 be 67 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_Q_132804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!Q"
        threat_id = "132804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d0 80 c2 54 30 90 ?? ?? ?? ?? 40 3b c1 72 f0}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 1a 50 c7 45 f4 ?? ?? ?? ?? c7 45 f8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 0f 85 aa 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {69 61 6d 66 61 6d 6f 75 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_R_133720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!R"
        threat_id = "133720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hDDAMh2LDT" ascii //weight: 2
        $x_1_2 = {5c 44 65 76 69 63 65 5c 4e 50 52 4f 54 5f 25 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {2d 63 53 82 63 f7 d8 1b c0}  //weight: 1, accuracy: High
        $x_1_4 = "85.255.112.36;85" ascii //weight: 1
        $x_1_5 = {8a d1 02 d0 30 14 31 83 c1 01 3b cf 72 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_S_134073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!S"
        threat_id = "134073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 4b 43 52 50 68 32 4c 44 54 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {68 4c 43 52 50 bb 32 4c 44 54}  //weight: 1, accuracy: High
        $x_1_3 = {6a 04 8d 85 fc fe ff ff 50 c6 04 37 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_BD_134715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.BD"
        threat_id = "134715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 6a 0a bf ?? ?? ?? ?? 8b f3 59 33 c0 f3 a6 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 f0 e9 ab 56 e8}  //weight: 1, accuracy: High
        $x_1_3 = {59 59 74 12 83 c6 04 83 fe 04 72 e5}  //weight: 1, accuracy: High
        $x_1_4 = "tdlmask.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Alureon_BC_136835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.BC"
        threat_id = "136835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 c0 74 02 ff e0 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8d 8d 00 fe ff ff 51 56 ff d0}  //weight: 1, accuracy: High
        $x_1_3 = ",85.255." ascii //weight: 1
        $x_1_4 = "faces\\%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_BE_136836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.BE"
        threat_id = "136836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 10 8a d1 02 54 24 08 30 14 01 41 3b 4c 24 04 72 f0}  //weight: 1, accuracy: High
        $x_1_2 = {f3 a6 74 10 8b f0 6a 0a bf ?? ?? ?? ?? 59 33 c0 f3 a6}  //weight: 1, accuracy: Low
        $x_1_3 = "tdllog.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_BF_136837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.BF"
        threat_id = "136837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET_PARAMS" ascii //weight: 1
        $x_1_2 = {5b 72 65 66 65 72 65 72 5f 65 6e 64 5d 00}  //weight: 1, accuracy: High
        $x_1_3 = {5b 6a 73 5f 69 6e 6a 65 63 74 5f 65 6e 64 5d 00}  //weight: 1, accuracy: High
        $x_1_4 = {5b 50 41 4e 45 4c 5f 53 49 47 4e 5f 43 48 45 43 4b 5d 00}  //weight: 1, accuracy: High
        $x_1_5 = "NetFilter.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Alureon_BG_136838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.BG"
        threat_id = "136838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "hDIBGh2LDT" ascii //weight: 1
        $x_1_2 = {80 38 e9 74 04 33 c0 eb 07 8b 48 01 8d 44 01 05}  //weight: 1, accuracy: High
        $x_1_3 = {59 75 15 81 c6 20 02 00 00 47 8b c6 83 3e 00 75 e4}  //weight: 1, accuracy: High
        $x_1_4 = {8a d1 02 54 24 0c 30 14 01 41 3b 4c 24 08 72 f0}  //weight: 1, accuracy: High
        $x_1_5 = "FR243532" ascii //weight: 1
        $x_1_6 = {6a 01 6a 09 68 ?? ?? ?? ?? 8b c6 e8 ?? ?? 00 00 85 c0 74 19 57}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_BH_136839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.BH"
        threat_id = "136839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 8b 43 28 6a 40 6a 15 03 c7 50 ff 15 ?? ?? ?? ?? 8b 43 28 6a 05}  //weight: 1, accuracy: Low
        $x_1_2 = "hGREVh2LDT" ascii //weight: 1
        $x_1_3 = {8b 44 24 04 8a d1 02 54 24 0c 03 c1 30 10 41 3b 4c 24 08 72 eb}  //weight: 1, accuracy: High
        $x_1_4 = {80 7c 31 01 0a 74 15 8a d1 2a 55 10 32 d0 88 14 31 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_BJ_138797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.BJ"
        threat_id = "138797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {76 10 8a d1 02 54 24 08 30 14 01 41 3b 4c 24 04 72 f0}  //weight: 2, accuracy: High
        $x_2_2 = {75 f6 8d 45 08 50 68 13 01 00 00 22 00 c6 85 ?? ?? ?? ?? e9}  //weight: 2, accuracy: Low
        $x_2_3 = "hDDAMhXKNS" ascii //weight: 2
        $x_1_4 = "js.php?u=%s" ascii //weight: 1
        $x_1_5 = "keyword = RegExp.$1;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_BK_139065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.BK"
        threat_id = "139065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e8 89 9c 24 ?? ?? ?? ?? c7 84 24 ?? ?? ?? ?? 83 2c 24 0c c6 84 24 ?? ?? ?? ?? b8}  //weight: 2, accuracy: Low
        $x_2_2 = {8a c8 80 c1 ?? 30 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 72 ed}  //weight: 2, accuracy: Low
        $x_2_3 = {ff d0 c6 45 ?? e9 89 5d ?? ff 15}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 44 24 04 8a d1 03 c1 80 c2 ?? 30 10 41 3b 4c 24 08 72 ec}  //weight: 2, accuracy: Low
        $x_2_5 = {33 d2 6a 19 59 f7 f1 80 c2 61 88 14 1e 46 3b f7 72 e3}  //weight: 2, accuracy: High
        $x_2_6 = {03 cb 23 c8 8a 8c 0d ?? ?? ?? ?? 03 d6 30 0a 46 89 75 10 3b 75 0c 72 b8}  //weight: 2, accuracy: Low
        $x_2_7 = "\\knowndlls\\dll.dll" wide //weight: 2
        $x_1_8 = "%s%s%s.tmp" ascii //weight: 1
        $x_1_9 = "%s%s.sys" ascii //weight: 1
        $x_1_10 = "\\\\?\\globalroot\\systemroot\\system32\\ole32.dll" ascii //weight: 1
        $x_1_11 = "\\\\?\\globalroot\\systemroot\\system32\\msvcrt.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_BN_139464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.BN"
        threat_id = "139464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 1d 57 8d 45 f8 50 68 00 d2 00 00 68 ?? ?? ?? ?? 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 e4 54 00 00 00 c7 45 c4 ab 00 00 00 8b 4d c4 83 c1 01 8b 45 e4 99 f7 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_BQ_140128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.BQ"
        threat_id = "140128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 43 28 6a 40 6a 25 03 c7 50 ff 15 ?? ?? ?? ?? 8b 43 28 6a 09 03 f0 03 f8 59 f3 a5 8d 45 0c 50 a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_T_140593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!T"
        threat_id = "140593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {24 04 76 0f 8a d1 80 c2 ?? 30 14 01 41 3b 4c 24 04 72 f1}  //weight: 3, accuracy: Low
        $x_2_2 = {83 c0 28 6a 05 33 db 59 8b f0 8b fa f3 a6 75 f0}  //weight: 2, accuracy: Low
        $x_2_3 = "CAEEB026-6964-4327-87CD-681FA25026F7" wide //weight: 2
        $x_1_4 = "\\\\?\\globalroot\\systemroot\\system32\\drivers\\UACd.sys" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_BT_141150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.BT"
        threat_id = "141150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {74 39 8d 44 24 04 68 04 01 00 00 50 ff 15}  //weight: 2, accuracy: High
        $x_2_2 = {66 8b 01 03 c2 8a 51 01 41 84 d2 75 e5}  //weight: 2, accuracy: High
        $x_1_3 = {3d ed 03 00 00 72 0f 77 08 81 f9 00 c0 10 d4 76 05 be 01 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_BU_141285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.BU"
        threat_id = "141285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 44 49 50 47 ?? 32 4c 44 54}  //weight: 2, accuracy: Low
        $x_2_2 = {76 0f 8a d1 80 c2 ?? 30 14 01 41 3b 4c 24 04 72 f1}  //weight: 2, accuracy: Low
        $x_1_3 = {c7 45 f0 43 d2 0e 53}  //weight: 1, accuracy: High
        $x_1_4 = {63 6c 6b 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_5 = "infobin.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_CG_143701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.CG"
        threat_id = "143701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 65 72 3d [0-2] 26 62 69 64 3d 25 73 26 61 69 64 3d 25 73 26 73 69 64 3d 25 73 26 71 3d 25 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 3f 70 3d 00 26 70 3d 00 77 77 77 2e 62 69 6e 67 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = "try{var x=document.getElementById(\"_a\");x.href=url;x.click()}catch(e){try{var x=document.getElementById(\"_f\");" ascii //weight: 1
        $x_1_4 = {00 0d 0a 58 2d 4d 6f 7a 3a 20 70 72 65 66 65 74 63 68 0d 0a 00 0d 0a 75 73 65 72 2d 61 67 65 6e 74 3a 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_W_144444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!W"
        threat_id = "144444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d1 02 d0 30 14 31 83 c1 01 3b cf 72 f2}  //weight: 1, accuracy: High
        $x_1_2 = {8d a4 24 00 00 00 00 80 34 38 ?? 83 c0 01 3b c6 72 f5}  //weight: 1, accuracy: Low
        $x_1_3 = {81 3f 53 54 53 54 75}  //weight: 1, accuracy: High
        $x_1_4 = "affid=%s&subid=%s&data=%s&id=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Alureon_CO_144686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.CO"
        threat_id = "144686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 04 8a d1 03 c1 80 c2 ?? 30 10 41 3b 4c 24 08 72 ec}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 48 3c 8d 4c 01 04 (66 81 49 12|ba 00 20 00 00 66 09)}  //weight: 1, accuracy: Low
        $x_2_3 = {c6 45 eb 23 c6 45 ec 39 c6 45 ed 35 c6 45 ee 36 c6 45 ef 1f}  //weight: 2, accuracy: High
        $x_2_4 = {3d 57 01 00 c0 75 0f}  //weight: 2, accuracy: High
        $x_1_5 = {c6 45 f0 e9 ab 56 e8}  //weight: 1, accuracy: High
        $x_2_6 = {76 15 8b 44 24 04 8a d1 02 54 24 0c 03 c1 30 10 41}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_CT_144991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.CT"
        threat_id = "144991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 45 fc 74 c6 45 fd 64 c6 45 fe 6c 33 c0 ?? 00 01 00 00 88}  //weight: 2, accuracy: Low
        $x_2_2 = {c6 45 f8 74 c6 45 f9 64 c6 45 fa 6c (39|33 c0 88 ?? ?? ?? ?? ?? ?? ?? ?? 00 01)}  //weight: 2, accuracy: Low
        $x_1_3 = {0f b7 46 06 47 83 c5 28 3b f8 72 ce}  //weight: 1, accuracy: High
        $x_2_4 = "tdlcmd" ascii //weight: 2
        $x_1_5 = {80 38 0d 75 05 c6 00 00 ff 01 8b 01 80 38 0a 74 13}  //weight: 1, accuracy: High
        $x_1_6 = {50 6a 5a 57 ff d6 8d 85}  //weight: 1, accuracy: High
        $x_1_7 = {c6 00 21 6a 7c 57 ff d6}  //weight: 1, accuracy: High
        $x_1_8 = {6a 6d 58 6a 61 66 89 45 d8 58 6a 63}  //weight: 1, accuracy: High
        $x_2_9 = {76 0f 8a d1 80 c2 ?? 30 14 01 41 3b 4c 24 04 72 f1}  //weight: 2, accuracy: Low
        $x_1_10 = {6a 6d 58 6a 61 66 89 45 ?? 58 6a 63 66 89 45 ?? 58 6a 68}  //weight: 1, accuracy: Low
        $x_1_11 = {74 6c 56 8d 45 fc 50 68 ac 01 00 00 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_CU_145029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.CU"
        threat_id = "145029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 7f 8d 45 e4 50 6a 00 6a 01 53 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 5a 53 ff d7 8d 45}  //weight: 1, accuracy: High
        $x_1_3 = "gasfky" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_CV_145030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.CV"
        threat_id = "145030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {76 0f 8a d1 80 c2 ?? 30 14 01 41 3b 4c 24 04 72 f1}  //weight: 3, accuracy: Low
        $x_3_2 = {68 44 49 42 47 ?? 32 4c 44 54}  //weight: 3, accuracy: Low
        $x_1_3 = "hDIAG" ascii //weight: 1
        $x_1_4 = "hTNCG" ascii //weight: 1
        $x_1_5 = "/adc.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_CW_145185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.CW"
        threat_id = "145185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 0f 8a d1 80 c2 ?? 30 14 01 41 3b 4c 24 04 72 f1}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 03 83 c0 28 6a 05 33 d2 59 8b f0 bf ?? ?? ?? ?? f3 a6 75 ed}  //weight: 1, accuracy: Low
        $x_1_3 = {55 41 43 64 2e 73 79 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_CX_145186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.CX"
        threat_id = "145186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a c8 80 c1 54 30 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 72 ed}  //weight: 1, accuracy: Low
        $x_1_2 = {81 38 58 4b 4e 53 74}  //weight: 1, accuracy: High
        $x_1_3 = {76 10 8a d1 02 54 24 08 30 14 01 41 3b 4c 24 04 72 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_CY_145201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.CY"
        threat_id = "145201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3b c6 89 45 08 74 47 6a 40 68 00 30 00 00 40 50 56 ff 15 ?? ?? ?? ?? 8b f8 3b fe 74 31}  //weight: 2, accuracy: Low
        $x_2_2 = {ff 74 b5 dc e8 ?? ?? ?? ?? 85 c0 59 59 74 ?? 46 83 fe 09 72}  //weight: 2, accuracy: Low
        $x_2_3 = {72 65 71 75 65 73 74 3d 69 6e 73 74 61 6c 6c 65 72 26 62 6f 74 5f 67 75 69 64 3d 25 73 26 73 74 61 67 65 3d 25 73 26 73 74 61 74 75 73 3d 25 73 00}  //weight: 2, accuracy: High
        $x_1_4 = {4c 4f 41 44 45 52 3a 20 62 6c 61 63 6b 6c 69 73 74 20 63 6f 75 6e 74 72 79 20 63 68 65 63 6b 20 46 41 49 4c 45 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_DA_145422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DA"
        threat_id = "145422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {76 35 55 89 54 24 ?? 57 8b 74 24 ?? 6a (05|06) bf ?? ?? ?? ?? 59 33 ed f3 a6 74 10 83 44 24 ?? 28}  //weight: 2, accuracy: Low
        $x_1_2 = {74 18 3c 0d 75 04 c6 06 00 46 80 3e 0a 74 18 46 8a 06 84 c0 75 ec 3b ?? 75 02 33 ?? 85 ?? 74 0d}  //weight: 1, accuracy: Low
        $x_1_3 = {64 2e 73 79 73 00 03 00 03 03 03 03 55 41 43 53 52 54 4f 49 44}  //weight: 1, accuracy: Low
        $x_1_4 = {64 00 2e 00 73 00 79 00 73 00 00 00 06 00 (4f 00 49 00|47 00 4d 00)}  //weight: 1, accuracy: Low
        $x_1_5 = {50 ff 75 08 8d 85 fc fe ff ff 50 68 ?? ?? ?? ?? 56 57 ff 15 ?? ?? ?? ?? 83 c4 18 57 ff 15 ?? ?? ?? ?? 83 f8 ff 75 ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_DB_145935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DB"
        threat_id = "145935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 0a 8b 11 8b 49 04 89 11 89 4a 04 6a 50 6a 00 50 e8}  //weight: 1, accuracy: High
        $x_1_2 = "tdl3desk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_DC_146021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DC"
        threat_id = "146021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 38 53 52 54 00}  //weight: 1, accuracy: High
        $x_1_2 = "%s%s%x.tmp" ascii //weight: 1
        $x_1_3 = "[%s] File download %s" ascii //weight: 1
        $x_1_4 = "DownloadAndExecuteSoftString(%s)" ascii //weight: 1
        $x_1_5 = "LiteLoader" ascii //weight: 1
        $x_1_6 = "TDL Start Mutex detected" ascii //weight: 1
        $x_1_7 = "MRS Loader was here..." ascii //weight: 1
        $x_1_8 = {32 32 34 3b 6e 65 77 3b 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_3_9 = {8d 54 02 18 33 c0 3b de 76 35 55 89 54 24 0c 57 8b 74 24 10 6a 05 bf ?? ?? ?? ?? 59 33 ed f3 a6 74 10 83 44 24 10 28 40 3b c3 72 e4}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_DD_146343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DD"
        threat_id = "146343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 f0 69 c6 45 f1 27 c6 45 f2 6c c6 45 f3 6c c6 45 f4 20 c6 45 f5 62 c6 45 f6 65 c6 45 f7 20 c6 45 f8 62 c6 45 f9 61 c6 45 fa 63 c6 45 fb 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_DE_146606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DE"
        threat_id = "146606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 57 c6 45 ?? 43 c6 45 ?? 63 c6 45 ?? 5a c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 6f c6 45 ?? 44 c6 45 ?? 61 c6 45 ?? 74 c6 45 ?? 61 c6 45 ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 6f 58 6a 74 66 89 45 ?? 58 6a 67}  //weight: 1, accuracy: Low
        $x_1_3 = {50 b8 a9 32 8c 7a ff d0}  //weight: 1, accuracy: High
        $x_1_4 = {8b 43 08 01 45 08 81 73 0c ?? ?? ?? ?? 8b 5b 0c 8b 46 2c 03 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Alureon_DH_147052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DH"
        threat_id = "147052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\h8srt" ascii //weight: 1
        $x_1_2 = "http://%s/?gd=%s&affid=%s&subid=%s" ascii //weight: 1
        $x_1_3 = "[PANEL_SIGN_CHECK]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_DI_147210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DI"
        threat_id = "147210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 74 24 04 ?? d8 ?? 90 ?? 6a 30 ?? d8 ?? 90 ?? 58 e9 ?? ?? 00 00 ?? ?? ?? e9 ?? ?? 00 00 83 ec 04 97 d8 ?? 90 97 33 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_DJ_147440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DJ"
        threat_id = "147440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 2f 57 ff 15 ?? ?? ?? ?? 85 c0 75 14 56 ff 15 ?? ?? ?? ?? 8d 44 30 ff 8b f0 2b f7 83 c6 01 eb 04 8b f0 2b f7 85 c0 74 ?? 6a 40 68 00 30 00 00 8d 46 01 50 6a 00 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = "Software\\h8srt" ascii //weight: 2
        $x_1_3 = ">ClickMe</a><script type=\"text/javascript\">redirect.click();</script>" ascii //weight: 1
        $x_1_4 = {73 6f 72 64 65 72 2e 64 6c 6c 00 00 57 53 50 53 74 61 72 74 75 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_DM_147646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DM"
        threat_id = "147646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {61 66 66 69 64 3d 25 73 26 73 75 62 69 64 3d 25 73 00 00 00 2f 63 72 2f 63 66 2e 70 68 70 00}  //weight: 5, accuracy: High
        $x_2_2 = {68 38 73 72 74 64 61 74 61 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_1_3 = "\\\\?\\globalroot" ascii //weight: 1
        $x_1_4 = "ThreadSpam()1111111111" ascii //weight: 1
        $x_2_5 = {8d 49 00 8a d0 80 c2 54 30 14 30 83 c0 01 3b c7 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_DN_147653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DN"
        threat_id = "147653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {76 0f 8a d0 80 c2 ?? 30 14 30 83 c0 01 3b c1 72 f1}  //weight: 2, accuracy: Low
        $x_1_2 = {76 11 8d 9b 00 00 00 00 80 34 18 ?? 83 c0 01 3b c6 72 f5}  //weight: 1, accuracy: Low
        $x_1_3 = {75 0e 83 c6 04 81 fe ?? ?? ?? ?? 72 e7}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 40 6a 01 ff d6 50 6a 00 ff d6 8b 4c 24 ?? 50 6a 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_5 = "[PANEL_SIGN_CHECK]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_DO_147951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DO"
        threat_id = "147951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 37 0f b7 48 14 83 65 fc 00 8d 54 01 18 0f b7 40 06 33 c9 66 3b c8 73 20}  //weight: 1, accuracy: High
        $x_1_2 = {7c e7 ff 75 0c 8b 55 14 8b 4d 10 8d 85 fc fe ff ff e8}  //weight: 1, accuracy: High
        $x_1_3 = {b8 00 20 00 00 66 0b 46 16 83 c6 04 0f b7 c0}  //weight: 1, accuracy: High
        $x_1_4 = "4DW4R3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_DP_147952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DP"
        threat_id = "147952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 43 43 43 4e 89 45 ?? 68 33 33 52 47}  //weight: 2, accuracy: Low
        $x_1_2 = {b8 4e 46 4d 47 e8}  //weight: 1, accuracy: High
        $x_1_3 = {b8 4f 43 49 48 e8}  //weight: 1, accuracy: High
        $x_1_4 = {b8 42 50 4d 48 e8}  //weight: 1, accuracy: High
        $x_1_5 = {7c e6 ff 75 10 8b 55 18 8b 4d 14 8d 85 fc fe ff ff}  //weight: 1, accuracy: High
        $x_1_6 = {c6 00 e9 83 e9 05 89 48 01 8d 45 f8 50 6a 05}  //weight: 1, accuracy: High
        $x_1_7 = "4DW4R3" ascii //weight: 1
        $x_1_8 = "subdel.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_DQ_148106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DQ"
        threat_id = "148106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&botid=%s&affid=%s&subid=" ascii //weight: 1
        $x_1_2 = "wspservers" ascii //weight: 1
        $x_1_3 = "tdlcmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_DV_149864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DV"
        threat_id = "149864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 74 74 70 3a 2f 2f 25 73 2f 6b 78 2e 70 68 70 00}  //weight: 2, accuracy: High
        $x_2_2 = {25 73 26 61 73 5f 61 63 63 74 3d 25 73 26 63 72 3d 25 73 00}  //weight: 2, accuracy: High
        $x_1_3 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 69 6e 44 65 66 65 6e 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {61 64 6d 69 6e 3b 3b 72 6f 6f 74 3b 41 64 6d 69 6e 3b 31 32 33 34 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 72 65 64 46 72 65 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {2e 65 78 65 3f 00}  //weight: 1, accuracy: High
        $x_1_8 = "getgrab" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_DW_152081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DW"
        threat_id = "152081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4d 08 3a c3 75 e6 3b f9 75 02 33 ff 3b fb 0f 84 ?? ?? ?? ?? 56 8d 85 ?? ?? ?? ?? 53 50 c6 45 ?? 6b}  //weight: 1, accuracy: Low
        $x_1_2 = {68 51 c6 a6 02 e8 ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_3 = "knock_%d_%x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_DY_153302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DY"
        threat_id = "153302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 45 f8 74 c6 45 f9 64 c6 45 fa 6c 39}  //weight: 2, accuracy: High
        $x_2_2 = {6a 21 6a 7c 50 89 45 ?? e8 ?? ?? ?? ?? 6a 20 6a 3b}  //weight: 2, accuracy: Low
        $x_1_3 = {0f b7 43 06 83 c2 28 ff 45 ?? 89 55 ?? 39 45}  //weight: 1, accuracy: Low
        $x_1_4 = {3c 0d 75 04 c6 06 00 46 80 3e 0a}  //weight: 1, accuracy: High
        $x_1_5 = {50 6a 5a 68 00 08 00 00 ff 15 ?? ?? ?? ?? 85 c0 75 0e be ?? ?? ?? ?? 8d bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_DX_153303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DX"
        threat_id = "153303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {eb 16 8b 16 ff 4d 0c 8d 74 16 04 3b f0 72 27 8b 55 08 03 d0 3b f2 73 1e}  //weight: 2, accuracy: High
        $x_2_2 = {8b f8 b8 00 20 00 00 66 09 47 16}  //weight: 2, accuracy: High
        $x_1_3 = {6c 64 72 31 36 00}  //weight: 1, accuracy: High
        $x_1_4 = {62 63 6b 66 67 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 72 76 00 63 6d 64 00 77 73 72 76 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_DZ_154042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.DZ"
        threat_id = "154042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 6a 02 68 00 00 00 80 56 8b 05 ?? ?? 40 00 ff d0 56 8b [0-4] 40 00 ff d0 8b [0-3] 3b c7 0f 85 ?? 00 00 00 57 ff [0-3] 57 ff [0-3] e8 ?? ?? ?? ?? e9 ?? 00 00 00 83 f8 02 0f 84 ?? 00 00 00 3b c6 0f 85 ?? 00 00 00 f7 [0-3] fe ff ff ff 0f 84 ?? 00 00 00 83 f8 03 0f 84 ?? 00 00 00 56 56 56 56 e8 ?? ?? ?? ?? 50 8b [0-4] 40 00 e9 ?? 00 00 00 6a 4d 6a 4d 6a 37 6a 2c 57 57 8b [0-4] 40 00 ff d0 85 c0 0f 84 ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_EA_154088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.EA"
        threat_id = "154088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d0 53 53 53 8b ?? ?? ?? ?? 40 00 ff d0 68 33 2b 38 6a e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? ff d0 83 f8 05 0f 84 ?? 00 00 00 83 f8 02 0f 85 ?? 00 00 00 80 7c 24 ?? 61 0f 84 ?? 00 00 00 33 c0 e9 ?? ?? 00 00 6a 40 68 00 30 00 00 68 00 38 0b 00 53 8b [0-4] 40 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_X_154093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!X"
        threat_id = "154093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 0b 01 e9 ?? ?? ?? ?? b8 43 46 00 00 66 39 85 ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? 66 83 bd ?? ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_EC_154186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.EC"
        threat_id = "154186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 c7 47 16 02 21 53 89 75 f8 89 75 fc ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8a 4e 26 02 c8 30 88 ?? ?? ?? ?? 40 83 f8 ?? 7c ef}  //weight: 1, accuracy: Low
        $x_1_3 = {68 90 01 00 00 8d 85 2c fd ff ff 50 8d 85 c0 fe ff ff 50 e8}  //weight: 1, accuracy: High
        $x_1_4 = {76 15 8b 44 24 04 8a d1 02 54 24 0c 03 c1 30 10 41}  //weight: 1, accuracy: High
        $x_1_5 = {8a c8 80 c1 66 30 8c 05 ?? ?? ?? ?? 40 3b c7 72 ef}  //weight: 1, accuracy: Low
        $x_1_6 = {c6 45 f8 e9 ab 8b 45 08 89 45 18 ff 75 18 e8}  //weight: 1, accuracy: High
        $x_1_7 = "?i=%s&a=%d&f=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_EN_158265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.EN"
        threat_id = "158265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[SCRIPT_SIGNATURE_CHECK]" ascii //weight: 1
        $x_1_2 = "[kit_hash_end]" ascii //weight: 1
        $x_1_3 = "[cmd_dll_hash_end]" ascii //weight: 1
        $x_2_4 = {8a d0 80 c2 51 30 90 ?? ?? ?? ?? 83 c0 01 3d 00 01 00 00 72 eb}  //weight: 2, accuracy: Low
        $x_2_5 = {8a c8 80 c1 51 30 88 ?? ?? ?? ?? 83 c0 01 83 f8 20 72 ed}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_EO_158266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.EO"
        threat_id = "158266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 37 13 c3 cd 8b ?? 03 ?? 85 05 00 89 ?? 08 c7}  //weight: 1, accuracy: Low
        $x_1_2 = {51 6a 05 6a 01 53 ff 15 ?? ?? ?? ?? 3b c7 74}  //weight: 1, accuracy: Low
        $x_1_3 = "ldr_dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_EP_158267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.EP"
        threat_id = "158267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 f8 21 43 65 87 c7 45 e8 2b 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff d0 c6 85 ?? ?? ?? ?? e9 c7 85}  //weight: 1, accuracy: Low
        $x_1_3 = "maxsscore" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_EQ_158268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.EQ"
        threat_id = "158268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 44 24 20 21 43 65 87 c7 44 24 1c 2b 02 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {53 6a 01 6a 0a ff d6 e8}  //weight: 1, accuracy: High
        $x_1_3 = {73 70 6f 6f 6c 73 76 2e 65 78 65 00 4c 64 72 41 64 64 52 65 66 44 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_ET_160409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.ET"
        threat_id = "160409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 0d 2f 00 00 74 23 3d 0c 2f 00 00 74 1c 3d 05 2f 00 00 74 15 3d 06 2f 00 00 74 0e 3d 07 2f 00 00 74 07 3d 14 2f 00 00 75}  //weight: 1, accuracy: High
        $x_1_2 = {8d 45 f8 50 8d 45 fc 50 68 05 00 00 20 ff 77 08 c7 45 f8 04 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 74 0d 39 75 fc 75 08 33 c0 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_AA_161295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!AA"
        threat_id = "161295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 0b 01 89 45 ?? e9 ?? ?? ?? ?? b8 43 46 00 00 66 39 85 ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? 66 83 bd ?? ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_EW_162575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.EW"
        threat_id = "162575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 46 14 8d 7c 30 18 8b 46 50 6a 40}  //weight: 1, accuracy: High
        $x_1_2 = {76 11 8b 44 24 04 03 c1 30 10 fe c2 41 3b 4c 24 08 72 ef}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 f8 74 c6 45 f9 73 c6 45 fa 74 33 c0 88 ?? ?? ?? ?? ?? ?? ?? ?? 00 01 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "xtasks.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_EZ_162731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.EZ"
        threat_id = "162731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 00 20 00 00 66 09 46 16 8d 45 ?? 50}  //weight: 1, accuracy: Low
        $x_1_2 = {74 4c 0f b7 48 14 0f b7 78 06 8d 74 01 18}  //weight: 1, accuracy: High
        $x_1_3 = {74 49 8d 45 fc 50 6a 05 6a 01 ff 75 08 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {05 22 22 22 22 50 b8 11 11 11 11 ff d0 33 c0 50 b8 33 33 33 33 ff d0}  //weight: 1, accuracy: High
        $x_1_5 = {8b 40 28 03 45 08 68 42 50 57 46}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_FA_162850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.FA"
        threat_id = "162850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&affid=%s&subid=%s&" ascii //weight: 1
        $x_1_2 = "[date_begin]" ascii //weight: 1
        $x_1_3 = "OK_INSTALL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_AC_163312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!AC"
        threat_id = "163312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 72 65 61 74 65 52 65 63 74 52 67 6e 49 6e 64 69 72 65 63 74 00 00 00 50 74 49 6e 52 65 67 69 6f 6e 00}  //weight: 2, accuracy: High
        $x_1_2 = {85 c0 0f 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? c6 45 ?? 22 c6 45 ?? 53 ff 55 ?? 68 ?? ?? ?? ?? ff 35 02 8b ?? ff 55 05 6a}  //weight: 1, accuracy: Low
        $x_1_3 = {85 c0 0f 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? c6 45 ?? 53 c6 45 ?? 22 ff 55 ?? 68 ?? ?? ?? ?? ff 35 02 8b ?? ff 55 05 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_AD_163751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.gen!AD"
        threat_id = "163751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 0b 01 89 45 ?? e9 ?? ?? ?? ?? b8 53 46 00 00 66 39 85 ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? 66 83 bd ?? ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_FE_164569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.FE"
        threat_id = "164569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 06 42 4b 46 53 66 89 4e 06 89 ?? 18}  //weight: 2, accuracy: Low
        $x_1_2 = {83 f9 2c 76 13 80 7d ?? 00 74 0d 68 67 04 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {03 c9 56 8b 70 10 03 c9 3b ce 73 0a b8 7f 00 00 c0}  //weight: 1, accuracy: High
        $x_1_4 = {62 69 64 00 (76|6d) 62 72}  //weight: 1, accuracy: Low
        $x_1_5 = {53 85 f6 75 ?? b8 ?? 00 00 c0 0f 00 c6 45 ?? 42 c6 45 ?? 4b c6 45 ?? 46 c6 45}  //weight: 1, accuracy: Low
        $x_1_6 = {30 1c 17 47 3b 7d 0c 72 94}  //weight: 1, accuracy: High
        $x_1_7 = {8b 70 18 8b 40 14 c1 e0 09 c1 ee 05 c1 e8 05 3b f0 72 0b b8 7f 00 00 c0}  //weight: 1, accuracy: High
        $x_3_8 = {52 85 c9 75 ?? b8 ?? 00 00 c0 8b e5 5d c3 c6 45 ff 03 8a 45 ff 53 83 ca ff 0f 00 c6 45 ?? 41 c6 45 ?? 4a c6 45 ?? 45 c6 45}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_FF_164570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.FF"
        threat_id = "164570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {76 0b 80 34 08 ?? 40 3b 44 24 04 72 f5}  //weight: 2, accuracy: Low
        $x_2_2 = {8a c8 80 c1 5a 30 0c 30 40 3b c5 72 f3}  //weight: 2, accuracy: High
        $x_2_3 = {8a d0 80 c2 54 30 14 30 40 3b c1 72 f3}  //weight: 2, accuracy: High
        $x_1_4 = "[PANEL_SIGN_CHECK]" ascii //weight: 1
        $x_1_5 = "GET_PARAMS" ascii //weight: 1
        $x_1_6 = "[referer_end]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_FG_164571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.FG"
        threat_id = "164571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ldr_facedll" ascii //weight: 1
        $x_1_2 = "[subject_fb_end]" ascii //weight: 1
        $x_1_3 = "[text_fb_end]" ascii //weight: 1
        $x_1_4 = "mainfb.script" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Alureon_FH_164686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.FH"
        threat_id = "164686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 62 63 6b 66 67 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {b8 4c 01 00 00 66 39 46 04 0f 85 ?? ?? ?? ?? 83 c0 bf 66 39 46 18 0f 85 ?? ?? ?? ?? 0f b7 46 14 8d 7c 30 18 8b 46 50 6a 40 68 00 30 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_FI_164918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.FI"
        threat_id = "164918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%[^.].%[^(](%[^)])" ascii //weight: 1
        $x_1_2 = "ph|%s|%s|%s|%s" ascii //weight: 1
        $x_1_3 = {39 5e 1c 75 0d ff 76 10 ff 75 08}  //weight: 1, accuracy: High
        $x_1_4 = {31 36 30 31 00 00 00 00 31 34 30 30 00 00 00 00 31 32 30 36}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_FJ_165678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.FJ"
        threat_id = "165678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c5 8b 13 8b ca c1 e1 09 be 53 46 00 00 66 89 34 39}  //weight: 2, accuracy: High
        $x_2_2 = {0f b7 40 16 c1 e8 0d 83 e0 01 75}  //weight: 2, accuracy: High
        $x_2_3 = {b9 ff df 00 00 66 21 4e 16 8d 54 24}  //weight: 2, accuracy: High
        $x_1_4 = "PurpleHaze" ascii //weight: 1
        $x_1_5 = "\\\\.\\globalroot%s\\ph" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_FK_165682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.FK"
        threat_id = "165682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 f0 e9 ab 56 e8}  //weight: 1, accuracy: High
        $x_1_2 = {3c 0d 75 04 c6 07 00 47 80 3f 0a}  //weight: 1, accuracy: High
        $x_1_3 = {74 70 80 3f 2f be ?? ?? ?? ?? 6a 01 75 0f}  //weight: 1, accuracy: Low
        $x_1_4 = "PurpleHaze" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Alureon_FL_166233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.FL"
        threat_id = "166233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {47 6c 6f 62 61 6c 5c 25 73 2d 4d 00}  //weight: 2, accuracy: High
        $x_1_2 = {47 6c 6f 62 61 6c 5c 25 73 2d 45 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 69 64 00 6d 62 72}  //weight: 1, accuracy: High
        $x_1_4 = {50 00 41 00 54 00 43 00 48 00 03 00 4d 00 42 00 52 00}  //weight: 1, accuracy: High
        $x_1_5 = {46 00 49 00 4c 00 45 00 04 00 42 00 4f 00 4f 00 54 00}  //weight: 1, accuracy: High
        $x_1_6 = {83 f9 2c 76 13 80 7d ?? 00 74 0d 68 67 04 00 00}  //weight: 1, accuracy: Low
        $x_1_7 = {6a 0c 89 45 f8 89 45 f4 8d 45 f0 50 68 00 14 2d 00 56 c7 45 f0 01 00 00 00 ff d3 83 f8 01}  //weight: 1, accuracy: High
        $x_1_8 = {53 85 f6 75 ?? b8 ?? 00 00 c0 0f 00 c6 45 ?? 42 c6 45 ?? 4b c6 45 ?? 46 c6 45}  //weight: 1, accuracy: Low
        $x_1_9 = {8b 70 18 8b 40 14 c1 e0 09 c1 ee 05 c1 e8 05 3b f0 72 0b b8 7f 00 00 c0}  //weight: 1, accuracy: High
        $x_1_10 = {59 66 83 c9 ff 66 41 66 8b 11 66 81 f2 ?? ?? 66 81 fa ?? ?? 74 0e 81 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_FO_170134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.FO"
        threat_id = "170134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 13 8b 75 10 8b c2 c1 e0 09 b9 53 46 00 00 66 89 0c 38}  //weight: 2, accuracy: High
        $x_2_2 = {0f b7 48 16 33 c0 c1 e9 0d 40 23 c8 75}  //weight: 2, accuracy: High
        $x_2_3 = {b8 ff df 00 00 66 21 47 16}  //weight: 2, accuracy: High
        $x_1_4 = "PurpleHaze" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_FP_170135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.FP"
        threat_id = "170135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 48 48 00 00 8a e8 c7 45 ec 16 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {77 73 72 76 00 00 00 00 70 73 72 76 00 00 00 00 63 73 72 76}  //weight: 1, accuracy: High
        $x_1_3 = "bpslemnq -p labgsurwkk" ascii //weight: 1
        $x_1_4 = "ver=%s&bid=%s&aid=%s&sid=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_FQ_171515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.FQ"
        threat_id = "171515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 03 45 ?? 8b 4d ?? 8a 00 85 c9 75 06 04 44 34 cc eb}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 89 04 24 68 ?? ?? ?? ?? 58 93 01 1c 24 33 c9 0b 0c 24}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 e0 63 5c 5d 5e c7 45 e4 5f 78 79 7a c7 45 e8 7b 74 75 76}  //weight: 1, accuracy: High
        $x_1_4 = {0f b6 4c 05 bc 81 e9 ?? 00 00 00 81 f1 ?? 00 00 00 88 4d ff 8a 4d ff 0f b6 c9 88 84 0d 38 ff ff ff 40 83 f8 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_FR_172412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.FR"
        threat_id = "172412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 8d 7c 00 00 66 39 06 75 06 80 7e 02 24 74}  //weight: 2, accuracy: High
        $x_2_2 = {eb 36 bb 64 86 00 00 66 3b f3 75 2a 8b b4 d0 88 00 00 00 85 f6 74 1f}  //weight: 2, accuracy: High
        $x_2_3 = {c7 45 f0 48 81 c4 d0 8b 45 f0 89 84 3e 18 02 00 00 c7 45 f4 03 00 00 c3}  //weight: 2, accuracy: High
        $x_1_4 = "subid=%d&se=%s&keyword=%s" ascii //weight: 1
        $x_1_5 = {43 6d 64 52 75 6e 45 78 65 55 72 6c 00 43 6d 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_FS_172968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.FS"
        threat_id = "172968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 59 81 e1 00 f0 ff ff 66 81 39 4d 5a}  //weight: 1, accuracy: High
        $x_1_2 = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume%u" wide //weight: 1
        $x_1_3 = {46 00 49 00 4c 00 45 00 04 00 42 00 4f 00 4f 00 54 00}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 f4 75 61 6c 41 c7 45 f8 6c 6c 6f 63 c6 45 fc 00 6a 40 68 ?? ?? 00 00 68 ?? ?? 00 00 6a 00 8d 45 f0 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Alureon_FT_174099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.FT"
        threat_id = "174099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0a 33 d2 59 f7 f1 83 fa 01 73 05 e8 ?? ?? ?? ?? 68 e8 03 00 00 ff 15 ?? ?? ?? ?? 8b 4d 08}  //weight: 1, accuracy: Low
        $x_1_2 = {83 e8 05 89 45 ?? 8b 45 14 8d 3c 1e c6 45 ?? e9 8d 75 ?? a5 a4 8b 7d fc 89 18 8b 45 10 2b c7 83 e8 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_FV_177920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.FV"
        threat_id = "177920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ec 88 00 00 00 c7 45 b2 40 00 00 00 c7 45 9a 04 00 00 00 c7 45 c6 00 30 00 00 c7 45 e6 df 28 2d 63}  //weight: 1, accuracy: High
        $x_1_2 = {81 ec 88 00 00 00 c7 45 b0 40 00 00 00 c7 45 8e 00 00 01 00 c7 85 7e ff ff ff 00 00 00 00 c7 45 e8 c3 04 2f 97}  //weight: 1, accuracy: High
        $x_1_3 = {81 ec 88 00 00 00 c7 45 f6 01 00 00 00 c7 45 be 14 00 00 00 c7 45 82 00 80 00 00 c7 45 d0 00 00 01 00 c7 45 e2 00 30 00 00 c7 45 8e 5f 27 29 d2}  //weight: 1, accuracy: High
        $x_1_4 = {81 ec 88 00 00 00 c7 45 c8 18 00 00 00 c7 45 b4 04 00 00 00 c7 45 e4 06 1c c8 16 c7 45 a2 40 00 00 00 c7 45 90 00 30 00 00 c7 45 e0 00 80 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {81 ec 8c 00 00 00 c7 45 d2 00 30 00 00 c7 85 7a ff ff ff 14 00 00 00 c7 45 90 00 00 00 00 c7 45 c2 18 00 00 00 c7 45 88 40 00 00 00 c7 45 f2 00 00 00 00 c7 45 a4 90 20 70 45}  //weight: 1, accuracy: High
        $x_1_6 = {81 ec 8c 00 00 00 c7 45 8e 04 00 00 00 c7 45 b4 00 30 00 00 c7 45 de 18 00 00 00 c7 45 a2 00 80 00 00 c7 45 ce 00 00 01 00 c7 45 ec 00 00 00 00 c7 45 ac 01 00 00 00 c7 45 c6 00 00 00 00 c7 45 92 40 00 00 00 c7 45 b0 87 57 45 0f}  //weight: 1, accuracy: High
        $x_1_7 = {81 ec 8c 00 00 00 c7 45 98 40 00 00 00 c7 45 fc 00 00 00 00 c7 45 8e c7 ce a0 78}  //weight: 1, accuracy: High
        $x_1_8 = {81 ec 8c 00 00 00 c7 45 f8 14 00 00 00 c7 45 b4 00 00 01 00 c7 45 8e 00 00 00 00 c7 45 bc 40 00 00 00 c7 45 aa 00 00 00 00 c7 45 c0 00 80 00 00 c7 85 7e ff ff ff d0 67 32 b3}  //weight: 1, accuracy: High
        $x_1_9 = {81 ec 8c 00 00 00 c7 45 da 00 00 00 00 c7 45 92 01 00 00 00 c7 45 c8 40 00 00 00 c7 45 e8 00 30 00 00 c7 45 82 14 00 00 00 c7 45 ec 00 80 00 00 c7 45 ac 04 00 00 00 c7 45 96 00 00 01 00 c7 45 fc c6 a6 09 fa}  //weight: 1, accuracy: High
        $x_1_10 = {81 ec 8c 00 00 00 c7 45 9a 00 80 00 00 c7 45 cc 01 00 00 00 c7 45 fc 40 00 00 00 c7 45 bc 04 00 00 00 c7 45 8a 00 30 00 00 c7 45 d0 52 87 f8 88}  //weight: 1, accuracy: High
        $x_1_11 = {81 ec 8c 00 00 00 c7 45 d0 00 30 00 00 c7 45 cc 18 00 00 00 c7 45 90 00 80 00 00 c7 45 80 40 00 00 00 c7 45 f8 00 00 01 00 c7 45 ec 00 00 00 00 c7 45 f4 04 00 00 00 c7 45 fc 5c 77 2c b2}  //weight: 1, accuracy: High
        $x_1_12 = {c7 45 f0 00 80 00 00 c7 45 d0 01 00 00 00 c7 45 c4 14 00 00 00 c7 45 e0 3c f2 43 b3}  //weight: 1, accuracy: High
        $x_1_13 = {c7 45 9a 18 00 00 00 c7 45 ce 04 00 00 00 c7 45 fc 00 30 00 00 c7 45 c0 00 00 00 00 c7 45 a2 bd a5 b2 8f}  //weight: 1, accuracy: High
        $x_1_14 = {81 ec 8c 00 00 00 c7 45 8a 00 00 00 00 c7 45 b2 6f 61 ee df c7 45 ea 40 00 00 00}  //weight: 1, accuracy: High
        $x_1_15 = {c7 45 b0 14 00 00 00 c7 45 96 00 30 00 00 c7 45 e4 16 71 22 9b c7 45 b8 00 80 00 00}  //weight: 1, accuracy: High
        $x_1_16 = {81 ec 8c 00 00 00 c7 45 f2 00 30 00 00 c7 45 84 18 00 00 00 c7 45 f6 1e 27 05 43}  //weight: 1, accuracy: High
        $x_1_17 = {81 ec 8c 00 00 00 c7 45 d2 99 9a f7 6d c7 45 e8 01 00 00 00 c7 45 f0 00 00 00 00 c7 45 ec 00 00 00 00 c7 45 c0 18 00 00 00}  //weight: 1, accuracy: High
        $x_1_18 = {81 ec 8c 00 00 00 c7 45 80 00 80 00 00 c7 45 e4 25 7b 0e b7 c7 45 c8 00 30 00 00}  //weight: 1, accuracy: High
        $x_1_19 = {c7 45 c8 18 00 00 00 c7 45 a8 00 00 01 00 c7 45 e4 ba 56 c2 88 c7 45 ac 40 00 00 00 c7 45 94 00 30 00 00}  //weight: 1, accuracy: High
        $x_1_20 = {c7 45 c4 00 80 00 00 c7 45 e8 00 00 00 00 c7 45 f0 00 00 00 00 c7 45 c8 6a 5b 59 22}  //weight: 1, accuracy: High
        $x_1_21 = {c7 45 aa ab 9a 73 6e c7 45 8e 01 00 00 00 c7 45 f8 04 00 00 00}  //weight: 1, accuracy: High
        $x_1_22 = {81 ec 8c 00 00 00 c7 45 e0 14 00 00 00 c7 45 c8 18 00 00 00 c7 45 90 04 00 00 00 c7 45 9e 00 30 00 00 c7 85 7a ff ff ff 85 3f 36 77}  //weight: 1, accuracy: High
        $x_1_23 = {81 ec 8c 00 00 00 c7 45 9e 04 00 00 00 c7 45 d6 00 30 00 00 c7 45 a6 00 80 00 00 c7 45 e4 25 ce 1b 64}  //weight: 1, accuracy: High
        $x_1_24 = {c7 45 a8 46 89 bb d9 c7 45 96 00 00 01 00 c7 45 fc 00 80 00 00}  //weight: 1, accuracy: High
        $x_1_25 = {c7 45 e0 14 00 00 00 c7 45 a4 04 00 00 00 c7 45 b0 00 00 00 00 c7 45 ac 3f b9 a3 62}  //weight: 1, accuracy: High
        $x_1_26 = {81 ec 8c 00 00 00 c7 85 7e ff ff ff 40 00 00 00 c7 45 aa 52 62 88 90}  //weight: 1, accuracy: High
        $x_1_27 = {81 ec 8c 00 00 00 c7 45 e2 7c 88 35 e9 c7 45 94 01 00 00 00 c7 45 9a 00 30 00 00}  //weight: 1, accuracy: High
        $x_1_28 = {81 ec 8c 00 00 00 c7 45 9a 04 00 00 00 c7 45 aa 18 00 00 00 c7 45 8a c8 a2 9b 74}  //weight: 1, accuracy: High
        $x_1_29 = {c7 45 ec 00 00 01 00 c7 45 aa 00 30 00 00 c7 45 be 61 af 96 5e}  //weight: 1, accuracy: High
        $x_1_30 = {c7 45 8a 00 30 00 00 c7 45 ae 01 00 00 00 c7 45 a2 0b 12 cf b2}  //weight: 1, accuracy: High
        $x_1_31 = {c7 45 a4 14 00 00 00 c7 45 8a 18 00 00 00 c7 45 86 5f 50 8a b7}  //weight: 1, accuracy: High
        $x_1_32 = {c7 45 8e ee 70 44 18 c7 45 8a 00 30 00 00 c7 45 e4 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_33 = {c7 45 a8 dc 11 81 3d c7 45 96 00 30 00 00 c7 45 8e 18 00 00 00}  //weight: 1, accuracy: High
        $x_1_34 = {c7 45 96 00 80 00 00 c7 45 cc 40 00 00 00 c7 45 92 d8 9b e1 1e}  //weight: 1, accuracy: High
        $x_1_35 = {81 ec 8c 00 00 00 c7 45 86 60 29 d0 1f c7 45 fc 04 00 00 00}  //weight: 1, accuracy: High
        $x_1_36 = {c7 45 d8 04 00 00 00 c7 45 c4 40 00 00 00 c7 45 bc 0c 2a f0 70}  //weight: 1, accuracy: High
        $x_1_37 = {c7 45 ac 04 00 00 00 c7 45 92 ae 59 f8 a3 c7 45 b4 18 00 00 00}  //weight: 1, accuracy: High
        $x_1_38 = {c7 45 92 a9 c0 7f f0 c7 45 a2 00 30 00 00 c7 45 aa 40 00 00 00}  //weight: 1, accuracy: High
        $x_1_39 = {81 ec 8c 00 00 00 c7 45 92 00 00 00 00 c7 45 b2 fd a7 ad 12 c7 45 fc 40 00 00 00}  //weight: 1, accuracy: High
        $x_1_40 = {c7 45 98 14 00 00 00 c7 45 9c 00 00 00 00 c7 45 b2 d0 a3 87 2f}  //weight: 1, accuracy: High
        $x_1_41 = {c7 45 88 01 00 00 00 c7 45 b2 b0 52 a2 f0 c7 45 ec 00 30 00 00}  //weight: 1, accuracy: High
        $x_1_42 = {81 ec 8c 00 00 00 c7 45 ca 18 00 00 00 c7 45 a2 18 07 26 72}  //weight: 1, accuracy: High
        $x_1_43 = {c7 45 b2 00 80 00 00 c7 45 ca 14 00 00 00 c7 45 fc 58 28 d5 16}  //weight: 1, accuracy: High
        $x_1_44 = {c7 45 f0 00 00 01 00 c7 45 f8 40 00 00 00 c7 45 8e 24 38 99 e3}  //weight: 1, accuracy: High
        $x_1_45 = {81 ec 8c 00 00 00 c7 45 8a c9 78 dc 57 c7 45 ac 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_46 = {c7 45 86 0a 4f ef 92 c7 45 de 14 00 00 00 c7 45 8a 00 00 01 00}  //weight: 1, accuracy: High
        $x_1_47 = {c7 45 f0 00 00 01 00 c7 45 ec 49 64 82 75 c7 45 d2 18 00 00 00}  //weight: 1, accuracy: High
        $x_1_48 = {c7 45 8c 18 00 00 00 c7 45 ae 00 00 00 00 c7 45 9c 01 4e 65 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Alureon_FW_183436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.FW"
        threat_id = "183436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c0 e8 04 80 e2 0f fe c8 3c 02 77 ?? 80 ea 02 80 fa 05 77 04 c6 41 fe 00 41 4e 75 ?? eb ?? (39|83 7d) 75 ?? 83 7d 20 23 72}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fe 05 72 df 85 f6 75 04 33 c0 eb 3d 8b 45 fc 2b c3 57 83 e8 05 89 45 f5 8b 45 14 8d 3c 1e c6 45 f4 e9 8d 75 f4}  //weight: 1, accuracy: High
        $x_1_3 = {75 32 83 4a 18 02 8a c8 c0 e9 06 88 4a 0d 8a c8 88 42 0c 0f b6 c0 c0 e9 03 83 e0 07 80 e1 07 43 88 4a 0e 88 42 0f 3c 05 75 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_GB_195781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.GB"
        threat_id = "195781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 53 61 66 67 3f 69 64 3d 25 73 26 61 66 66 3d 25 75 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 ec e9 8b 4d 10 2b 4d fc 83 e9 05 89 4d ed}  //weight: 1, accuracy: High
        $x_1_3 = {6a 2a 56 ff 15 ?? ?? ?? ?? 59 59 89 44 24 1c 3b c3 74 02 88 18 6a 3c}  //weight: 1, accuracy: Low
        $x_1_4 = {71 00 61 00 7a 00 78 00 73 00 77 00 5f 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Alureon_GC_196225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.GC"
        threat_id = "196225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%[^.].%[^(](%[^)])" ascii //weight: 1
        $x_1_2 = {8b 75 08 80 7e 14 00 75 ?? 8b 4e 08 8d 46 24 50 6a 00 68 3f 00 0f 00 c6 46 14 01 ff d1}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 46 04 b9 64 86 00 00 66 3b c1 75 06 8b 4a 08 29 4e 50 b9 4c 01 00 00 66 3b c1 75 06 8b 42 08 29 46 50 33 c0 6a 0a 59 8b fa f3 ab b8 ff ff 00 00 66 01 46 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_GD_196398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.GD"
        threat_id = "196398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 75 61 63 36 34 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 6a 02 53 e8 ?? ?? ?? ?? ff d6 [0-4] 3d 5a 04 00 00 74 0b ff d6 83 f8 7f 74 04}  //weight: 1, accuracy: Low
        $x_1_3 = {85 c0 74 0f 33 c0 81 7d ?? 55 05 00 00 0f 94 c0 89 45 ?? ff 75 ?? ff d6}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 04 68 00 30 00 00 68 06 01 00 00 56 ff 75 10 ff 15 ?? ?? ?? ?? 8b d8 3b de 0f 84 ?? ?? ?? ?? 8b 45 0c 8d 50 02 66 8b 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_GG_197327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.GG"
        threat_id = "197327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 70 54 57 53 e8 ?? ?? ?? ?? 0f b7 70 06 0f b7 48 14 8d 4c 01 18 85 f6 7e 5d}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 04 38 b8 b9 ff e0 00 00 66 89 4c 38 05 8b 06 8b 3d ?? ?? ?? ?? c6 00 fa ff 76 08 ff 36 e8 ?? ?? ?? ?? 59 59}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 5e 0c 8b 09 ff 76 08 03 d9 53 ff 75 ?? e8}  //weight: 1, accuracy: Low
        $x_1_4 = {49 6e 6a 65 63 74 4e 6f 72 6d 61 6c 52 6f 75 74 69 6e 65 00 49 6e 6a 65 63 74 65 64 53 68 65 6c 6c 43 6f 64 65 45 6e 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_GH_197723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.GH"
        threat_id = "197723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 3b ac 33 f8 97 2b fe 88 03 8b 85 ?? ?? ?? ?? 03 c3 49 74 09 43 42 83 fa 08 75 e4}  //weight: 1, accuracy: Low
        $x_1_2 = {74 3f 89 45 b8 83 20 00 8d 55 c0 8b c8 ff 15 ?? ?? ?? ?? fa a1 6c ae 00 10 8b 0d ?? ?? ?? ?? 89 48 04 fb}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 7c 08 fe 6a 00 57 68 08 01 00 00 68 ?? ?? ?? ?? 68 bb 20 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_GO_197898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.GO"
        threat_id = "197898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "jflsdkjf001.dat" wide //weight: 10
        $x_10_2 = {c7 45 80 6c 00 6c 00 c7 45 86 32 00 2e 00 c7 45 8a 65 00 78 00 c7 45 8e 65 00 20 00 c7 45 92 25 00 73 00}  //weight: 10, accuracy: High
        $x_1_3 = "typerttsx.com:80;typicalsx.com:80" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alureon_GQ_197899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.GQ"
        threat_id = "197899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 6f 6e 66 69 67 77 72 69 74 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 64 6f 77 6e 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 6c 6f 61 64 6d 6f 64 75 6c 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 63 6d 64 64 65 6c 61 79 00}  //weight: 1, accuracy: High
        $x_4_5 = {26 61 69 64 3d 25 73 26 69 64 3d 25 73 26 6f 73 3d 25 73 5f 25 73 00}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_GQ_197899_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.GQ"
        threat_id = "197899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\basenamedobjects\\{%08x-%04x-%04x-%04x-%04x%08x}" wide //weight: 1
        $x_1_2 = {8b 43 3c 03 c3 74 ?? 8b 88 a0 00 00 00 85 c9 74 ?? 8b 80 a4 00 00 00 03 cb 89 45 08 85 c0 74 ?? 8b 41 04 29 45 08}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d6 8b 47 3c 8b 44 38 28 6a 00 6a 01 57 03 c7 ff d0 6a ff ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {39 5d 04 75 20 8b 45 00 6a 40 68 00 30 00 00 50 6a 00 a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 44 24 ?? 85 c0 75 ?? 0f b7 46 06 47 83 c5 28 3b f8 72 cf}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 03 06 00 00 00 c7 45 ?? 02 00 00 00 c7 45 ?? 17 00 02 00 c7 45 ?? 03 00 00 00 89 45 ?? 89 75 ?? ff 15 ?? ?? ?? ?? 85 c0 75 ?? 8d 7d ?? ab ab ab ab ab 6a 04 58 66 89 ?? ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_GK_197906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.GK"
        threat_id = "197906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "235"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "jflsdkjf001.dat" wide //weight: 100
        $x_100_2 = "shimanostore.com.tw:80;sramstore.com.tw:80" ascii //weight: 100
        $x_25_3 = "85.195.91.34:8080/k/%s/%s/%s/%d/%08x/%d/" ascii //weight: 25
        $x_25_4 = {8d 85 f8 fd ff ff 83 c4 18 8d 48 02 66 8b 10 83 c0 02 66 85 d2 75 f5 2b c1 d1 f8 4e f7 de 1b f6 83 e6 fa 83 c6 08 56 03 c0 50}  //weight: 25, accuracy: High
        $x_25_5 = {66 8b 08 83 c0 02 66 85 c9 75 f5 8d bd d8 fd ff ff 2b c2 83 ef 02 66 8b 4f 02 83 c7 02 66 85 c9 75 f4 8b c8 c1 e9 02 8b f2 f3 a5}  //weight: 25, accuracy: High
        $x_10_6 = "err_srv_step0_%08x" ascii //weight: 10
        $x_10_7 = "_exe_step1_%08x_%d_%x" ascii //weight: 10
        $x_10_8 = "7f5ed85d-6828-4f92-858c-f40b0ac68138" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_25_*) and 1 of ($x_10_*))) or
            ((2 of ($x_100_*) and 2 of ($x_25_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_GJ_197909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.GJ"
        threat_id = "197909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "115"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "jflsdkjf001.dat" wide //weight: 50
        $x_60_2 = "shimanostore.com.tw:80;sramstore.com.tw:80" ascii //weight: 60
        $x_10_3 = {8b 78 0c 68 3c 20 00 00 6a 08 51 ff d3 8b f0 33 c0 3b f0 74 76 8b 4d 0c 8d 56 34 89 96 34 20 00 00 89 7e 1c}  //weight: 10, accuracy: High
        $x_5_4 = "%d.%d.%d_%d.%d_%d" ascii //weight: 5
        $x_5_5 = {66 83 7d dc 09 0f 95 c0 48 83 e0 20 83 c0 20 50 8b 85 4c ff ff ff 51}  //weight: 5, accuracy: High
        $x_10_6 = {c7 45 80 6c 00 6c 00 c7 45 86 32 00 2e 00 c7 45 8a 65 00 78 00 c7 45 8e 65 00 20 00 c7 45 92 25 00 73 00}  //weight: 10, accuracy: High
        $x_10_7 = "knock.php?log=%s|id=%s|os=%s %s|version=%u.%u.%u.%u" ascii //weight: 10
        $x_5_8 = "peercmd_%u_%u.%u.%u.%u:%u_%u=%u" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_60_*) and 1 of ($x_50_*) and 1 of ($x_5_*))) or
            ((1 of ($x_60_*) and 1 of ($x_50_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_GL_197910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.GL"
        threat_id = "197910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "jflsdkjf001.dat" wide //weight: 100
        $x_50_2 = "groundtask.com:80;sky2force.com:80;84.16.234.103:80" ascii //weight: 50
        $x_25_3 = {8d 85 f8 fd ff ff 83 c4 18 8d 48 02 66 8b 10 83 c0 02 66 85 d2 75 f5 2b c1 d1 f8 4e f7 de 1b f6 83 e6 fa 83 c6 08}  //weight: 25, accuracy: High
        $x_25_4 = {66 8b 08 83 c0 02 66 85 c9 75 f5 8d bd d8 fd ff ff 2b c2 83 ef 02 66 8b 4f 02 83 c7 02 66 85 c9 75 f4 8b c8 c1 e9 02 8b f2 f3 a5}  //weight: 25, accuracy: High
        $x_10_5 = "%s/%s/%s/%s/%s/%d/%08x" ascii //weight: 10
        $x_10_6 = "%d.%d.%d_%d.%d_%d" ascii //weight: 10
        $x_10_7 = {30 30 33 00 31 2e 37 00 68 65 6c 6c 6f}  //weight: 10, accuracy: High
        $x_10_8 = "\"%s\" 7 \"%s\" %S" wide //weight: 10
        $x_10_9 = "sx_run" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_25_*) and 5 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 5 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_25_*) and 3 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_25_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_GS_198696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.GS"
        threat_id = "198696"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[SCRIPT_SIGNATURE_CHECK]" ascii //weight: 1
        $x_1_2 = "[kit_hash_end]" ascii //weight: 1
        $x_1_3 = "[cmd_dll_hash_end]" ascii //weight: 1
        $x_2_4 = {8a d0 80 c2 51 30 90 ?? ?? ?? ?? 83 c0 01 3d 00 01 00 00 72 eb}  //weight: 2, accuracy: Low
        $x_2_5 = {8a c8 80 c1 51 30 88 ?? ?? ?? ?? 83 c0 01 83 f8 20 72 ed}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Alureon_GT_200079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.GT"
        threat_id = "200079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 3c 3c 22 00 56 89 5c 24 ?? ff 15 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 8d 84 24 ?? ?? 00 00 50 68 02 00 00 80}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 48 46 00 00 66 89 07 b8 fa 01 00 00 3b c8 77 05}  //weight: 1, accuracy: High
        $x_1_3 = {6a 01 6a 28 56 8b c7 e8 ?? ?? ?? ?? 85 c0 74 ad 33 ff 81 bd ?? ?? ff ff 78 56 34 12 74 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Alureon_AL_264901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alureon.AL!MTB"
        threat_id = "264901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 14 52 b2 ?? ?? 5a 8a 2f 52 b2 04 ?? 5a 32 e9 52 b2 04 ?? 5a 88 2f 52 b2 04 ?? 5a 47 52 b2 04 ?? 5a 4d 52 b2 04 ?? 5a 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {36 55 50 03 fe 8d 3c 38 33 c0 03 fe 8d 3c 38 68 2c ca 3a 16 03 fe 8d 3c 38 68 35 d0 15 dc 03 fe 8d 3c 38 6a 00 03 fe 8d 3c 38 68 a2 7d 80 62 6a 53 83 c4 04 54 6a 53 83 c4 04 68 30 08 01 00 6a 53 83 c4 04 6a 10 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

