rule Backdoor_Win32_Haxdoor_2147789787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Haxdoor"
        threat_id = "2147789787"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Haxdoor"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 50 3c 66 81 3c 02 50 45 75 05 a3 ?? ?? ?? 00 68 ?? ?? ?? 00 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 92 8b 04 24 68 40 01 00 00 0f 31}  //weight: 10, accuracy: Low
        $x_1_2 = "vbagz.sys" wide //weight: 1
        $x_1_3 = "gzipmod.dll" wide //weight: 1
        $x_1_4 = "\\DosDevices\\vbagz" wide //weight: 1
        $x_1_5 = "mprexe.exe" ascii //weight: 1
        $x_1_6 = "tremir.bin" ascii //weight: 1
        $x_1_7 = "\\driversLODE" ascii //weight: 1
        $x_1_8 = "NdisRegisterProtocol" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Haxdoor_2147789787_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Haxdoor"
        threat_id = "2147789787"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Haxdoor"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f 20 c3 53 a6 81 e3 ff ff fe ff}  //weight: 4, accuracy: High
        $x_4_2 = {0f 20 c3 53 81 e3 ff ff fe ff 0f 22}  //weight: 4, accuracy: High
        $x_4_3 = {0f 20 c1 51 81 e1 ff ff fe ff 0f 22 c1}  //weight: 4, accuracy: High
        $x_3_4 = {0f 20 c0 50 25 ff ff fe ff 0f 22 c0}  //weight: 3, accuracy: High
        $x_4_5 = {1c 89 47 18 8b 77 60 80 3e 0e 0f 85 ?? ?? 00 00 8b 46 0c 3d}  //weight: 4, accuracy: Low
        $x_4_6 = {0b c0 74 10 8b 08 0b c9 74 0a 80 39 b8 75 05 8b 41}  //weight: 4, accuracy: High
        $x_4_7 = {0b c0 74 0f 8b 08 0b c9 74 09 80 39 b8 75 04 8b 41}  //weight: 4, accuracy: High
        $x_3_8 = {81 3e 73 76 63 68 75 09 81 7e 04 6f 73 74 2e 74 22}  //weight: 3, accuracy: High
        $x_2_9 = {ff 74 24 04 c7 44 24 0c ff 0f 1f 00 ff 74 24 28 ff 74 24 28 ff 74 24 28}  //weight: 2, accuracy: High
        $x_2_10 = {64 a1 18 00 00 00 8b 40 20}  //weight: 2, accuracy: High
        $x_2_11 = "KeServiceDescriptorTable" ascii //weight: 2
        $x_2_12 = {03 40 01 83 c0 05 8b 40 02}  //weight: 2, accuracy: High
        $x_1_13 = "PsLookupProcessByProcessId" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Haxdoor_2147789787_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Haxdoor"
        threat_id = "2147789787"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Haxdoor"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {00 00 68 00 30 40 00 50 e8 ?? ?? 00 00 59 51 80 3d ?? ?? ?? 00 00 74 10 68}  //weight: 6, accuracy: Low
        $x_5_2 = {66 81 7c 08 fe 21 21 0f 84 ?? ?? ff ff ff}  //weight: 5, accuracy: Low
        $x_5_3 = {be 32 30 40 00 8b fe ac c0 c0 ?? aa ac [0-1] c0 [0-2] e2}  //weight: 5, accuracy: Low
        $x_4_4 = {66 81 7c 08 fe 21 21 74}  //weight: 4, accuracy: High
        $x_3_5 = {be 00 30 40 00 8b fe ac}  //weight: 3, accuracy: High
        $x_3_6 = {74 07 ba 36 36 36 00 ff e0}  //weight: 3, accuracy: High
        $x_2_7 = {40 00 ba 36 36 36 00 ff d0 61}  //weight: 2, accuracy: High
        $x_2_8 = {50 ba 4d 5a 4d 5a 52 8b d4 6a 02 52 53 e8}  //weight: 2, accuracy: High
        $x_1_9 = "[%u%u]" ascii //weight: 1
        $x_1_10 = "p2.ini" ascii //weight: 1
        $x_1_11 = "cz.dll" ascii //weight: 1
        $x_1_12 = "hz.dll" ascii //weight: 1
        $x_1_13 = "mprexe.exe" ascii //weight: 1
        $x_1_14 = "MaxWait" ascii //weight: 1
        $x_1_15 = "\\MPRServices\\TestService" ascii //weight: 1
        $x_4_16 = {81 3e 52 65 66 65 75 ?? 81 7e 04 72 65 72 3a 75}  //weight: 4, accuracy: Low
        $x_4_17 = {81 3f 65 2d 67 6f 0f 85 ?? ?? 00 00 81 7f 07 42 61 6c 61}  //weight: 4, accuracy: Low
        $x_4_18 = {50 ba 4d 5a 00 00 52 8b cc 6a 04 51 50 e8 ?? ?? ?? ?? 59 59 51 68 ?? ?? 00 00 68 04 30 40}  //weight: 4, accuracy: Low
        $x_3_19 = {ba 36 36 36 00 ff 65 08}  //weight: 3, accuracy: High
        $x_3_20 = {5a 81 fa 36 36 36 00 75 07}  //weight: 3, accuracy: High
        $x_3_21 = {81 3f 76 61 6c 75}  //weight: 3, accuracy: High
        $x_3_22 = {81 7f 09 76 61 6c 75}  //weight: 3, accuracy: High
        $x_2_23 = {55 8b ec e8 00 00 00 00 58 2d}  //weight: 2, accuracy: High
        $x_2_24 = {00 4d 65 4d 65 73 73 61 67 65 72 00}  //weight: 2, accuracy: High
        $x_2_25 = "WNetEnumCachedPasswords" ascii //weight: 2
        $x_2_26 = "WebMoney Detected!" ascii //weight: 2
        $x_2_27 = {53 75 62 6a 65 63 74 3a 20 2a 25 73 2a 27 0d 0a 00}  //weight: 2, accuracy: High
        $x_2_28 = "Software\\WebMoney" ascii //weight: 2
        $x_1_29 = "A-311" ascii //weight: 1
        $x_1_30 = "Referer: https://www.e-gold.com/" ascii //weight: 1
        $x_1_31 = "/acct/accountinfo.asp" ascii //weight: 1
        $x_1_32 = {00 42 42 4d 54 72 61 70}  //weight: 1, accuracy: High
        $x_1_33 = "application/octet-stream" ascii //weight: 1
        $x_1_34 = "vdmt16" ascii //weight: 1
        $x_1_35 = "PStoreCreateInstance" ascii //weight: 1
        $x_1_36 = "WriteProcessMemory" ascii //weight: 1
        $x_1_37 = "NtQuerySystemInformation" ascii //weight: 1
        $x_1_38 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_39 = {2e 73 79 73 00 53 79 73 74 65 6d 5c 43}  //weight: 1, accuracy: High
        $x_4_40 = {3d 4b 69 6c 6c 75 3c 6a 00 6a 04 8d 85}  //weight: 4, accuracy: High
        $x_4_41 = {3d 73 6c 6b 67 75 16 6a 00 6a 01 68}  //weight: 4, accuracy: High
        $x_4_42 = {3d 67 63 66 67 75 19 6a 00 68 1c 01}  //weight: 4, accuracy: High
        $x_4_43 = {3d 50 72 69 6f 75 4d 6a 00 6a 04 8d 85}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((12 of ($x_1_*))) or
            ((1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_2_*))) or
            ((1 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            ((1 of ($x_4_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((2 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((3 of ($x_4_*))) or
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_6_*) and 6 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Haxdoor_2147792327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Haxdoor"
        threat_id = "2147792327"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Haxdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "skyx16.dll" ascii //weight: 2
        $x_2_2 = "kirdam.dll" ascii //weight: 2
        $x_2_3 = "GET /%sbsrv.php?lang=%s&pal=%u&bay=%u&gold=%u&id=%s&param=%u&socksport=%u&httpport=%" ascii //weight: 2
        $x_2_4 = "GET /%swx.php?wxx=%s&uid=%s HTTP/1.0" ascii //weight: 2
        $x_1_5 = "WM Keeper Detected" ascii //weight: 1
        $x_2_6 = "A-311 Death welcome" ascii //weight: 2
        $x_6_7 = {00 00 68 00 30 40 00 50 e8 ?? ?? 00 00 59 51 80 3d ?? ?? ?? 00 00 74 10 68}  //weight: 6, accuracy: Low
        $x_5_8 = {66 81 7c 08 fe 21 21 0f 84 ?? ?? ff ff ff}  //weight: 5, accuracy: Low
        $x_5_9 = {be 32 30 40 00 8b fe ac c0 c0 ?? aa ac [0-1] c0 [0-2] e2}  //weight: 5, accuracy: Low
        $x_4_10 = {66 81 7c 08 fe 21 21 74}  //weight: 4, accuracy: High
        $x_3_11 = {be 00 30 40 00 8b fe ac}  //weight: 3, accuracy: High
        $x_3_12 = {74 07 ba 36 36 36 00 ff e0}  //weight: 3, accuracy: High
        $x_2_13 = {40 00 ba 36 36 36 00 ff d0 61}  //weight: 2, accuracy: High
        $x_2_14 = {50 ba 4d 5a 4d 5a 52 8b d4 6a 02 52 53 e8}  //weight: 2, accuracy: High
        $x_1_15 = "[%u%u]" ascii //weight: 1
        $x_1_16 = "p2.ini" ascii //weight: 1
        $x_1_17 = "cz.dll" ascii //weight: 1
        $x_1_18 = "hz.dll" ascii //weight: 1
        $x_1_19 = "mprexe.exe" ascii //weight: 1
        $x_1_20 = "MaxWait" ascii //weight: 1
        $x_1_21 = "\\MPRServices\\TestService" ascii //weight: 1
        $x_4_22 = {81 3e 52 65 66 65 75 ?? 81 7e 04 72 65 72 3a 75}  //weight: 4, accuracy: Low
        $x_4_23 = {81 3f 65 2d 67 6f 0f 85 ?? ?? 00 00 81 7f 07 42 61 6c 61}  //weight: 4, accuracy: Low
        $x_4_24 = {50 ba 4d 5a 00 00 52 8b cc 6a 04 51 50 e8 ?? ?? ?? ?? 59 59 51 68 ?? ?? 00 00 68 04 30 40}  //weight: 4, accuracy: Low
        $x_3_25 = {ba 36 36 36 00 ff 65 08}  //weight: 3, accuracy: High
        $x_3_26 = {5a 81 fa 36 36 36 00 75 07}  //weight: 3, accuracy: High
        $x_3_27 = {81 3f 76 61 6c 75}  //weight: 3, accuracy: High
        $x_3_28 = {81 7f 09 76 61 6c 75}  //weight: 3, accuracy: High
        $x_2_29 = {55 8b ec e8 00 00 00 00 58 2d}  //weight: 2, accuracy: High
        $x_2_30 = {00 4d 65 4d 65 73 73 61 67 65 72 00}  //weight: 2, accuracy: High
        $x_2_31 = "WNetEnumCachedPasswords" ascii //weight: 2
        $x_2_32 = "WebMoney Detected!" ascii //weight: 2
        $x_2_33 = {53 75 62 6a 65 63 74 3a 20 2a 25 73 2a 27 0d 0a 00}  //weight: 2, accuracy: High
        $x_2_34 = "Software\\WebMoney" ascii //weight: 2
        $x_1_35 = "A-311" ascii //weight: 1
        $x_1_36 = "Referer: https://www.e-gold.com/" ascii //weight: 1
        $x_1_37 = "/acct/accountinfo.asp" ascii //weight: 1
        $x_1_38 = {00 42 42 4d 54 72 61 70}  //weight: 1, accuracy: High
        $x_1_39 = "application/octet-stream" ascii //weight: 1
        $x_1_40 = "vdmt16" ascii //weight: 1
        $x_1_41 = "PStoreCreateInstance" ascii //weight: 1
        $x_1_42 = "WriteProcessMemory" ascii //weight: 1
        $x_1_43 = "NtQuerySystemInformation" ascii //weight: 1
        $x_1_44 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_45 = {2e 73 79 73 00 53 79 73 74 65 6d 5c 43}  //weight: 1, accuracy: High
        $x_4_46 = {3d 4b 69 6c 6c 75 3c 6a 00 6a 04 8d 85}  //weight: 4, accuracy: High
        $x_4_47 = {3d 73 6c 6b 67 75 16 6a 00 6a 01 68}  //weight: 4, accuracy: High
        $x_4_48 = {3d 67 63 66 67 75 19 6a 00 68 1c 01}  //weight: 4, accuracy: High
        $x_4_49 = {3d 50 72 69 6f 75 4d 6a 00 6a 04 8d 85}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((12 of ($x_1_*))) or
            ((1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_2_*))) or
            ((1 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            ((1 of ($x_4_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((2 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((3 of ($x_4_*))) or
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_6_*) and 6 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Haxdoor_A_2147792385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Haxdoor.gen!A"
        threat_id = "2147792385"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Haxdoor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 6a 15 68 ?? ?? 01 00 6a 00 ff 75 08 e8 ?? ?? 00 00 0b c0}  //weight: 2, accuracy: Low
        $x_1_2 = {b9 2a 00 00 00 f3 a4 b8 ?? ?? 01 00 50 68 ?? ?? 01 00 e8 ?? ?? 00 00 8d 0d ?? ?? 01 00 33 d2 1a 00 64 89 25 00 00 00 00 8d 1d ?? ?? 01 00 a1 ?? ?? 01 00 8b 33 8d b8 ?? ?? 01 00}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 1a 00 00 00 f3 a4 68 ?? ?? 01 00 68 ?? ?? 01 00 e8 13 00 8d 1d ?? ?? 01 00 a1 ?? ?? 01 00 8b 33 8d b8 ?? ?? 01 00}  //weight: 1, accuracy: Low
        $x_3_4 = {ba 36 36 36 00 ff d0 61 c9 17 00 8d 86 ?? ?? 40 00 50 ff 96 ?? ?? 40 00 0b c0 74 0d 03 86 ?? ?? 40 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Haxdoor_B_2147792390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Haxdoor.gen!B"
        threat_id = "2147792390"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Haxdoor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {40 ff d0 6a 00 08 00 b8 ?? ?? ?? ?? 83 c0}  //weight: 2, accuracy: Low
        $x_2_2 = {50 83 2c 24 ?? ff 0c 24 c3 05 00 b8}  //weight: 2, accuracy: Low
        $x_2_3 = {7f 0b 83 c7 04 8b 0f 0b c9 75 ee eb 44 8b d8 8d 45 08 6a 04 50 53 e8}  //weight: 2, accuracy: High
        $x_2_4 = {c6 01 e9 2b c1 83 e8 05 89 41 01}  //weight: 2, accuracy: High
        $x_2_5 = {66 3d 21 21 75 19 57 8b f9 b9 e8 03 00 00 b0 3c f2 ae 81 7f ff 3c 21 21 3e}  //weight: 2, accuracy: High
        $x_1_6 = {c7 00 5b 53 4f 4c}  //weight: 1, accuracy: High
        $x_1_7 = {c7 00 5b 43 45 52}  //weight: 1, accuracy: High
        $x_3_8 = {d1 ef 6a 18 56 e8 ?? ?? ?? ?? 83 c6 18 4f 75 f2 ff 35 ?? ?? ?? ?? 81 2c 24 ?? ?? ?? ?? c3}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Haxdoor_C_2147792393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Haxdoor.gen!C"
        threat_id = "2147792393"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Haxdoor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 6f 70 65 6e 59 5a ff e2}  //weight: 3, accuracy: High
        $x_3_2 = {51 83 04 24 04 05 00 b9}  //weight: 3, accuracy: Low
        $x_2_3 = {c0 06 03 46 e2 fa}  //weight: 2, accuracy: High
        $x_1_4 = {89 06 e3 14 8b 45 3c 8d 44 28 14 0f b7 10 8d 44 02 04 2b 48 0c 03 48 14 89 4e 04 83 c7 04 83 c6 08 eb d2}  //weight: 1, accuracy: High
        $x_1_5 = {8b 10 0b d2 74 09 80 3a b8 75 04 8b 42 01}  //weight: 1, accuracy: High
        $x_1_6 = {16 99 98 45 75 9e e0 dd}  //weight: 1, accuracy: High
        $x_1_7 = {89 53 be af 9b 4a aa e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Haxdoor_D_2147792394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Haxdoor.gen!D"
        threat_id = "2147792394"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Haxdoor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 f3 ff 35 04 10 40 00 81 2c 24 ?? ?? ?? ?? ff 24 24}  //weight: 1, accuracy: Low
        $x_1_2 = {75 f2 ff 35 04 10 40 00 81 2c 24 ?? ?? ?? ?? ff 0c 24 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Haxdoor_BA_2147792420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Haxdoor.BA"
        threat_id = "2147792420"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Haxdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "445"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "66.246.38." ascii //weight: 100
        $x_100_2 = "\\system32\\config\\SAM" ascii //weight: 100
        $x_100_3 = "TO: HAXOR" ascii //weight: 100
        $x_100_4 = "MAIL FROM:<%s>" ascii //weight: 100
        $x_10_5 = "klog.sys" ascii //weight: 10
        $x_10_6 = "outpost.exe" ascii //weight: 10
        $x_10_7 = "\\win.com" ascii //weight: 10
        $x_10_8 = "ntdetect.com" ascii //weight: 10
        $x_1_9 = "www.prodexteam.net" ascii //weight: 1
        $x_1_10 = "corpse@mailserver.ru" ascii //weight: 1
        $x_1_11 = "ExitWindowsEx" ascii //weight: 1
        $x_1_12 = "CallNextHookEx" ascii //weight: 1
        $x_1_13 = "NtQuerySystemInformation" ascii //weight: 1
        $x_1_14 = "GET /Aserver.php?id=%s&param=%u HTTP/1.1" ascii //weight: 1
        $x_1_15 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\pdx" ascii //weight: 1
        $x_1_16 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\7-zipCfg.exe" ascii //weight: 1
        $x_1_17 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\WinRar.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 4 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

