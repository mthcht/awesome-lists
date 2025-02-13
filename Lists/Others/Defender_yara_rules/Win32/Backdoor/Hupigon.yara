rule Backdoor_Win32_Hupigon_2147489240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon"
        threat_id = "2147489240"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0e 54 47 56 49 50 5f 4d 61 69 6e 46 6f 72 6d}  //weight: 2, accuracy: High
        $x_2_2 = {0d 0a 54 65 6c 6e 65 74 20 48 65 6c 70 3a 0d 0a 20 20 20 20 54 65 6c 6e 65 74 20 5b 69 70 5d 20 5b 70 6f 72 74 5d 0d 0a}  //weight: 2, accuracy: High
        $x_2_3 = {ff ff ff ff 05 00 00 00 48 47 5a 35 05}  //weight: 2, accuracy: High
        $x_2_4 = {0f 54 52 65 63 76 46 69 6c 65 54 68 72 65 61 64}  //weight: 2, accuracy: High
        $x_2_5 = {0e 54 53 65 6e 64 44 69 72 54 68 72 65 61 64}  //weight: 2, accuracy: High
        $x_1_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 65 74 75 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {0b 56 69 64 65 6f 53 6f 63 6b 65 74}  //weight: 1, accuracy: High
        $x_1_8 = {0b 46 69 6c 65 73 53 6f 63 6b 65 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_2147489242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.gen!hook"
        threat_id = "2147489242"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "hook: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fe ff 8b 55 fc 33 db 8a 5c 02 ff 83 eb 19 8d 45 f4 8b d3 e8}  //weight: 2, accuracy: High
        $x_2_2 = {fe ff 85 c0 74 04 33 c0 eb 02 b0 01 f6 d8 1b c0 85 f6 74 04 85 c0 75 84 8b c6 5f 5e 5b 5d c2 08 00 8d 40 00}  //weight: 2, accuracy: High
        $x_2_3 = "GPigeon5_Shared" ascii //weight: 2
        $x_1_4 = "EnumServicesStatusW" ascii //weight: 1
        $x_1_5 = "FindNextFileW" ascii //weight: 1
        $x_1_6 = "NtQuerySystemInformation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_A_2147555277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.A"
        threat_id = "2147555277"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IZxt1Z3@3BexRn)u:-Gj<*lgO5y5=3)" ascii //weight: 1
        $x_1_2 = "6d92aDaNAr1i" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Hupigon_H_2147565368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.H"
        threat_id = "2147565368"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 33 33 32 32 2e 6f 72 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 25 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 53 74 6f 72 6d 5c 75 70 64 61 74 65 5c 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d f8 3b 4d fc 76 2e 8b 55 f8 8a 02 88 45 f4 8b 4d f8 8b 55 fc 8a 02 88 01 8b 4d f8 83 e9 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_B_2147599234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.gen!B"
        threat_id = "2147599234"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a 00 8b 00 8b 15 ?? ?? 49 00 e8 ?? ?? fb ff a1 ?? ?? 4a 00 8b 00 e8 ?? ?? fb ff c3 8b c0 55 8b ec 8b 45 08 48 74 24 48 74 05 48 74 10 eb 5f a1 ?? ?? 4a 00 c7 40 04 07 00 00 00 eb 51 03 00 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_C_2147599235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.gen!C"
        threat_id = "2147599235"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 02 00 00 00 e8 8c f9 ff ff 84 c0 0f 84 90 01 00 00 b2 01 a1 18 98 ?? ?? e8 10 e3 ff ff 0a 00 b9 4c e9 ?? ?? b8 ?? b7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_D_2147599236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.gen!D"
        threat_id = "2147599236"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 00 8b 00 8b 15 ?? ?? 46 00 e8 ?? ?? fe ff a1 ?? ?? 47 00 8b 00 e8 ?? ?? fe ff 5d c2 04 00 [0-1] a1 ?? ?? 47 00 50 6a 00 6a 00 68 ?? ?? 46 00 6a 00 6a 00 e8 ?? ?? ?? ff 8b 15 ?? ?? 47 00 89 02 c3 [0-3] 83 c4 ?? c7 04 24 03 00 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_ZM_2147599237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.ZM"
        threat_id = "2147599237"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {e8 ea f8 ff ff 84 c0 74 21 e8 79 fd ff ff ba 16 00 75 3e 68 ?? ?? 41 00 ba ?? ?? 41 00 b9 01 00 00 00 b8 0a 00 00 00}  //weight: 7, accuracy: Low
        $x_1_2 = "C:\\RegRun.reg" ascii //weight: 1
        $x_1_3 = "ServiceDll" ascii //weight: 1
        $x_1_4 = {2e 64 6c 6c 00 00 00 54 46 4f 52 4d 32 00}  //weight: 1, accuracy: High
        $x_1_5 = {64 65 6c 20 25 30 00 00 ff}  //weight: 1, accuracy: High
        $x_1_6 = {20 67 6f 74 6f 20 74 72 79 00}  //weight: 1, accuracy: High
        $x_1_7 = "ChangeServiceConfig2A" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_ZN_2147599319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.ZN"
        threat_id = "2147599319"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Microsoft Wisin Control" wide //weight: 10
        $x_10_2 = {3c 00 0a 00 01 00 4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 57 00 69 00 73 00 69 00 6e 00 2e 00 65 00 78 00 65 00 00 00 72 00 29 00 01 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 28 00 52 00 29 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 28 00 52 00 29 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_ZO_2147600096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.ZO"
        threat_id = "2147600096"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "360safe" ascii //weight: 10
        $x_10_2 = "kaspersky" ascii //weight: 10
        $x_10_3 = "\\RunMgr.EXE" ascii //weight: 10
        $x_10_4 = "cmd.exe /c del %SystemRoot%\\Debug.exe" ascii //weight: 10
        $x_10_5 = "/c taskkill /im 360tray.exe" ascii //weight: 10
        $x_10_6 = "> nul" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_ZP_2147601130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.ZP"
        threat_id = "2147601130"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_50_1 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f0 8a 54 32 ff 80 e2 0f 32 c2}  //weight: 50, accuracy: High
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup" ascii //weight: 1
        $x_1_3 = "\"un userinit.exe" ascii //weight: 1
        $x_1_4 = "netservice.exe" ascii //weight: 1
        $x_1_5 = "sysns.dll" ascii //weight: 1
        $x_1_6 = "svchost.exe -k" ascii //weight: 1
        $x_1_7 = "plugin\\001.dll" ascii //weight: 1
        $x_1_8 = "cmd /c at 23:59 shutdown -r -t 0" ascii //weight: 1
        $x_1_9 = "kvmonxp.kxp" ascii //weight: 1
        $x_1_10 = "c:\\1.hiv" ascii //weight: 1
        $x_1_11 = "Software\\ns" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_RA_2147603273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.RA"
        threat_id = "2147603273"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_2 = "OpenSCManagerA" ascii //weight: 1
        $x_1_3 = "FinalFantasy" ascii //weight: 1
        $x_1_4 = {44 65 6c 65 74 65 6d 65 2e 62 61 74 00 00 00 00 ff ff ff ff 07 00 00 00 3a 52 65 70 65 61 74 00 ff ff ff ff 05 00 00 00 64 65 6c 20}  //weight: 1, accuracy: High
        $x_1_5 = "MainServer" ascii //weight: 1
        $x_1_6 = "SYSTEM\\CurrentControlSet\\Services\\" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_8 = "FFServer.exe" ascii //weight: 1
        $x_1_9 = "#WindowsManagementCheckRadioBoxClick*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Backdoor_Win32_Hupigon_YA_2147604956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.YA"
        threat_id = "2147604956"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4030"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s (%s, line %d)" ascii //weight: 1
        $x_1_2 = "Out of memory" ascii //weight: 1
        $x_1_3 = "Unknown compression algorithm" ascii //weight: 1
        $x_1_4 = "Range check error" ascii //weight: 1
        $x_1_5 = " [%d]" ascii //weight: 1
        $x_1_6 = "Variant is not an array" ascii //weight: 1
        $x_1_7 = "Floating point division by zero" ascii //weight: 1
        $x_2_8 = "Format '%s' invalid or incompatible with argument" ascii //weight: 2
        $x_4_9 = "Win32 Error.  Code: %d." ascii //weight: 4
        $x_2_10 = "A Win32 API function failed" ascii //weight: 2
        $x_1_11 = "TlameAsm" ascii //weight: 1
        $x_1_12 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_13 = "EWriteError" ascii //weight: 1
        $x_1_14 = "GetPropA" ascii //weight: 1
        $x_1_15 = "EListError" ascii //weight: 1
        $x_1_16 = "TWin32Resource " ascii //weight: 1
        $x_2_17 = "SetForegroundWindow" ascii //weight: 2
        $x_1_18 = "TLameLoader" ascii //weight: 1
        $x_1_19 = "IsWindowEnabled" ascii //weight: 1
        $x_2_20 = "TLamePESection" ascii //weight: 2
        $x_2_21 = "ClientToScreen" ascii //weight: 2
        $x_1_22 = "SetROP2" ascii //weight: 1
        $x_1000_23 = {00 00 00 00 a4 08 92 00 a4 08 92 00 54 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 00 c4 08 92 00 c4 08 92 00 10 00 00 00 30 00 00 00 27 00}  //weight: 1000, accuracy: High
        $x_1000_24 = {14 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 54 00 00 00 1f 00 00 00 01 00 00 00 0c 00 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 1a 00 00 00 14 f6 90 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0e 00 00 00 3c f5 90 00 ff ff ff ff 12 00 00 00 50 f2 90 00 54 09 92 00 00 00 00 00 4a 00 00 00 01 00 00 00}  //weight: 1000, accuracy: High
        $x_1000_25 = {38 00 00 00 ce f8 e8 e1 ea e0 20 ee f2 ea f0 fb f2 e8 ff 20 f4 e0 e9 eb e0 20 5b 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 5d 00 00 00 00 04 86 91 00 04 86 91 00 6c 36 00 00 00 00 00 00}  //weight: 1000, accuracy: High
        $x_1000_26 = {eb f0 5f 5e 5b 59 59 5d c2 08 00 00 ff ff ff ff 1a 00 00 00 71 77 65 72 74 79 75 69 6f 70 61 73 64 66 67 68 6a 6b 6c 7a 78 63 76 62 6e 6d 00 00 55 8b ec 81 c4 04 f0 ff ff 50 81 c4 28 ff ff ff}  //weight: 1000, accuracy: High
        $x_1000_27 = {0e 0b 54 47 55 49 5f 53 54 52 49 4e 47 0d 00 00 00 03 00 00 00 00}  //weight: 1000, accuracy: High
        $x_5_28 = "KKtiSS6" ascii //weight: 5
        $x_5_29 = "eeK\\Z" ascii //weight: 5
        $x_5_30 = "^^xfZZ\\KeeXNbb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1000_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 16 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 1 of ($x_5_*) and 5 of ($x_2_*) and 15 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 15 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 13 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 11 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 4 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 16 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 15 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 11 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_1000_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_E_2147605474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.gen!E"
        threat_id = "2147605474"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 00 8b 00 8b 15 ?? ?? 46 00 e8 ?? ?? fd ff a1 ?? ?? 47 00 8b 00 e8 ?? ?? fd ff 83 c4 ?? c3 8d 40 00 55 8b ec 8b 45 08 48 74 24 48 74 05 48 74 10 eb 5f a1 ?? ?? 47 00 c7 40 04 07 00 00 00 eb 51 03 00 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_YB_2147605723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.YB"
        threat_id = "2147605723"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4030"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s (%s, line %d)" ascii //weight: 1
        $x_1_2 = "Out of memory" ascii //weight: 1
        $x_1_3 = "Unknown compression algorithm" ascii //weight: 1
        $x_1_4 = "Range check error" ascii //weight: 1
        $x_1_5 = " [%d]" ascii //weight: 1
        $x_1_6 = "Variant is not an array" ascii //weight: 1
        $x_1_7 = "Floating point division by zero" ascii //weight: 1
        $x_2_8 = "Format '%s' invalid or incompatible with argument" ascii //weight: 2
        $x_4_9 = "Win32 Error.  Code: %d." ascii //weight: 4
        $x_2_10 = "A Win32 API function failed" ascii //weight: 2
        $x_1_11 = "TlameAsm" ascii //weight: 1
        $x_1_12 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_13 = "EWriteError" ascii //weight: 1
        $x_1_14 = "GetPropA" ascii //weight: 1
        $x_1_15 = "EListError" ascii //weight: 1
        $x_1_16 = "TWin32Resource " ascii //weight: 1
        $x_2_17 = "SetForegroundWindow" ascii //weight: 2
        $x_1_18 = "TLameLoader" ascii //weight: 1
        $x_1_19 = "IsWindowEnabled" ascii //weight: 1
        $x_2_20 = "TLamePESection" ascii //weight: 2
        $x_2_21 = "ClientToScreen" ascii //weight: 2
        $x_1_22 = "SetROP2" ascii //weight: 1
        $x_1000_23 = {00 00 00 00 a4 08 92 00 a4 08 92 00 54 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 00 c4 08 92 00 c4 08 92 00 10 00 00 00 30 00 00 00 27 00}  //weight: 1000, accuracy: High
        $x_1000_24 = {14 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 54 00 00 00 1f 00 00 00 01 00 00 00 0c 00 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 1a 00 00 00 14 f6 90 00 00 40 92 00 00 d0 01 00 76 69 72 6f 00 e0 01 00 82 01 00 00 cc 07 91 00 b0 0a 92 00 50 45 00 00 4c 01 03 00 c3 bb fe 47 00 00 00 00 00 00 00 00 e0 00 02 01}  //weight: 1000, accuracy: High
        $x_1000_25 = {eb f0 5f 5e 5b 59 59 5d c2 08 00 00 ff ff ff ff 1a 00 00 00 71 77 65 72 74 79 75 69 6f 70 61 73 64 66 67 68 6a 6b 6c 7a 78 63 76 62 6e 6d 00 00 55 8b ec 81 c4 04 f0 ff ff 50 81 c4 28 ff ff ff}  //weight: 1000, accuracy: High
        $x_1000_26 = {0e 0b 54 47 55 49 5f 53 54 52 49 4e 47 0d 00 00 00 03 00 00 00 00}  //weight: 1000, accuracy: High
        $x_5_27 = "KKtiSS6" ascii //weight: 5
        $x_5_28 = "eeK\\Z" ascii //weight: 5
        $x_5_29 = "^^xfZZ\\KeeXNbb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1000_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 16 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 1 of ($x_5_*) and 5 of ($x_2_*) and 15 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 15 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 13 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 11 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 4 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 16 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 15 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 11 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_1000_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_ZAF_2147609237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.ZAF"
        threat_id = "2147609237"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Borland\\Delphi\\RTL" ascii //weight: 5
        $x_1_2 = {00 77 69 6e 64 6e 73 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 62 65 69 7a 68 75 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 67 6f 6f 67 6c 65 63 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 4c 49 54 41 4f 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 59 65 73 6e 6f 73 65 72 76 65 72 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 2e 33 33 32 32 2e 6f 72 67 3a 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 73 65 72 6e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_9 = "rwx_bye" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_F_2147609692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.gen!F"
        threat_id = "2147609692"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a 00 8b 00 8b 15 ?? ?? 49 00 e8 ?? ?? fb ff a1 ?? ?? 4a 00 8b 00 e8 ?? ?? fb ff c3 8b c0 55 8b 45 08 8b ec 48 74 24 48 74 05 48 74 10 eb 5f a1 ?? ?? 4a 00 c7 40 04 07 00 00 00 eb 51 03 00 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_G_2147610155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.gen!G"
        threat_id = "2147610155"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 00 8b 00 e8 ?? ?? fc ff 8b 0d ?? ?? 48 00 a1 ?? ?? 48 00 8b 00 8b 15 ?? ?? 47 00 e8 ?? ?? fc ff a1 ?? ?? 48 00 8b 00 e8 ?? ?? fc ff c3 [0-1] 55 8b ec 8b 45 08 48 74 24 48 74 05 48 74 10 eb 5f a1 ?? ?? 48 00 c7 40 04 07 00 00 00 eb 51 03 00 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_H_2147610156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.gen!H"
        threat_id = "2147610156"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 e9 86 00 00 00 8b 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 74 14 8d 45 fc e8 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b c6 e8 ?? ?? ?? ?? 8b 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 74 3c 8b 45 fc e8}  //weight: 1, accuracy: Low
        $x_1_2 = {cf b5 cd b3 b2 bb c4 dc ca b9 d3 c3 20 54 65 6c}  //weight: 1, accuracy: High
        $x_2_3 = {48 00 8b 00 8b 15 ?? ?? 47 00 e8 ?? ?? fc ff a1 ?? ?? 48 00 8b 00 09 00 8b 0d ?? ?? 48 00 a1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c6 40 5b 00 a1 ?? ?? 48 00 e8 ?? ?? fc ff c3 [0-2] 55 8b ec 8b 45 08 48 74 24 48 74 05 48 74 10 eb 5f a1 ?? ?? 48 00 c7 40 04 07 00 00 00 eb 51}  //weight: 2, accuracy: Low
        $x_2_4 = {49 00 b1 fe ba ?? 00 00 00 e8 ?? ?? ?? ff a1 ?? ?? 48 00 8b 00 e8 ?? ?? fc ff c3 55 8b ec 8b 45 08 48 74 24 48 74 05 48 74 10 eb 5f a1 ?? ?? 48 00 c7 40 04 07 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_CK_2147617704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.CK"
        threat_id = "2147617704"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Passive Mode (127,0,0,1,%d,%d)" ascii //weight: 1
        $x_1_2 = "TPigeonService" ascii //weight: 1
        $x_1_3 = "[PageDown]" ascii //weight: 1
        $x_1_4 = "Pigeon_VIP_" ascii //weight: 1
        $x_1_5 = "TVideoCap" ascii //weight: 1
        $x_1_6 = "PXF2000.vicp.net:8080" ascii //weight: 1
        $x_1_7 = "Windows_rejoice" ascii //weight: 1
        $x_3_8 = {8b 45 f8 0f b6 78 04 6a 10 e8 ?? ?? ?? ff 0f bf c0 89 45 f0 6a 14 e8 ?? ?? ?? ff 0f bf c0 89 45 f4 68 90 00 00 00}  //weight: 3, accuracy: Low
        $x_1_9 = {c7 45 e0 20 00 00 00 8d 45 e0 50 e8 ?? ?? ?? ?? 8b 45 e8 c1 e8 ?? 33 d2 52 50 8d 45 dc e8 ?? ?? ?? ?? 8b 55 dc 8b c3 b9}  //weight: 1, accuracy: Low
        $x_1_10 = {88 5d fd c6 45 fe 3a c6 45 ff 00 8d 45 fd 50 e8 ?? ?? ?? ?? 8b f0 83 fe 02 75 22 06 00 0f 84 ff 00 00 00}  //weight: 1, accuracy: Low
        $x_1_11 = {40 4a 75 f9 33 c0 55 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6a 11 6a 02 6a 02 e8 03 00 c6 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_CY_2147624278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.CY"
        threat_id = "2147624278"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff ff ff 0c 00 00 00 20 67 6f 74 6f 20 52 65 70 65 61 74 [0-4] ff ff ff ff 06 00 00 00 64 65 6c 20 25 30 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 e8 50 8d 45 ea 50 68 2a 54 00 00 8d 85 ba ab ff ff 50 6a 32 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {50 6a 00 e8 ?? ?? ?? ?? 80 7b 50 00 74 23 0f b7 05 ?? ?? ?? ?? 50 6a 00 6a 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_DD_2147624685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.DD"
        threat_id = "2147624685"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 01 00 00 00 8b 45 f8 8b 08 ff 51 48 8d 55 f8 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? 33 c0 5a}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 00 e8 ?? ?? ?? ?? 80 7b 50 00 74 23 0f b7 05 ?? ?? ?? ?? 50 6a 00 6a 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_DE_2147625353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.DE"
        threat_id = "2147625353"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WaveIn-UnprepareHead" ascii //weight: 1
        $x_1_2 = "\\SexSoftW" ascii //weight: 1
        $x_1_3 = "KeyLogo:" ascii //weight: 1
        $x_1_4 = "GetDriverI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_DF_2147625471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.DF"
        threat_id = "2147625471"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 07 07 00 01 00 57 8b 45 14 8b 00 50 e8 ?? ?? ?? ?? 8d 45 f8 50 6a 04 8b 45 0c 50 8b 87 ?? 00 00 00 83 c0 08 50 8b 06 50 e8 ?? ?? ?? ?? 8b 7d 0c 8b 3f}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 6a 00 6a 00 6a 10 e8 ?? ?? ?? ?? e9 c5 00 00 00 6a 00 6a 00 6a 00 6a 5b e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_DG_2147626040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.DG"
        threat_id = "2147626040"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6d 64 30 30 31 00 00 ff ff ff ff 06 00 00 00 43 6d 64 30 30 32 00}  //weight: 1, accuracy: High
        $x_1_2 = {4b 45 52 4e 45 4c 33 32 2e 44 4c 4c 00 00 00 00 52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b f0 89 35 ?? ?? ?? ?? 85 f6 74 0e 6a 01 e8 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_DV_2147630677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.DV"
        threat_id = "2147630677"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "-infect " ascii //weight: 1
        $x_1_2 = {52 75 6e 20 69 6e 20 72 69 6e 67 30 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b e8 83 c4 04 85 ed 0f 84 ?? ?? ?? ?? 81 fd 00 00 00 80 0f 82 ?? ?? ?? ?? 81 fd ff ff ff 9f 0f 87}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_EA_2147631244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.EA"
        threat_id = "2147631244"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 65 6c 65 74 65 6d 65 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 0c 8b 04 24 50 55 ff d6 85 c0 0f 94 c3 57 e8 ?? ?? ?? ?? 8b c3}  //weight: 1, accuracy: Low
        $x_1_3 = {03 42 3c 8b 55 f8 89 02 8b 45 f8 8b 00 05 f8 00 00 00 89 06 8b 45 f8 8b 00 8b 50 38 8b 45 f8 8b 00 8b 40 54 e8 ?? ?? ?? ?? 8b 55 0c 03 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_DZ_2147634345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.DZ"
        threat_id = "2147634345"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 07 8b 45 ?? e8 ?? ?? ?? ?? 50 ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = {8a 03 3c 07 77 07 83 e0 7f}  //weight: 1, accuracy: High
        $x_1_3 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_4 = "Remote ABC" ascii //weight: 1
        $x_1_5 = "AVPSytemPid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_ED_2147634346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.ED"
        threat_id = "2147634346"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c 07 77 07 83 e0 7f 0f 03}  //weight: 1, accuracy: High
        $x_1_2 = "Device\\PhysicalMem" ascii //weight: 1
        $x_2_3 = "(WinDir)\\360.com" ascii //weight: 2
        $x_1_4 = "del %0" ascii //weight: 1
        $x_1_5 = {c9 cf cf df b7 d6 d7 e9}  //weight: 1, accuracy: High
        $x_1_6 = {c9 cf cf df d6 f7 bb fa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_BaiJin_2147635916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.gen!BaiJin"
        threat_id = "2147635916"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 c6 f8 05 00 00 80 c3 f8 81 ?? f7 05 00 00 eb 09}  //weight: 5, accuracy: Low
        $x_5_2 = {b8 01 00 00 00 68 ?? ?? 00 10 c3 8b 0d ?? ?? ?? 10 [0-1] 83 39 00 75 16}  //weight: 5, accuracy: Low
        $x_5_3 = {b8 01 00 00 00 68 ?? ?? ?? 10 c3 8b 75 08 8b 0d ?? ?? ?? 10 89 35 ?? ?? ?? 10 83 39 00 75 16}  //weight: 5, accuracy: Low
        $x_3_4 = {3d 05 01 00 00 77 51 74 31 2d 00 01 00 00 74 0c 48 74 27}  //weight: 3, accuracy: High
        $x_3_5 = {8a 16 32 d0 88 16 46 49 75 f6}  //weight: 3, accuracy: High
        $x_2_6 = {f6 c1 01 74 0b 83 e1 fe 51}  //weight: 2, accuracy: High
        $x_2_7 = {8b e8 8b 45 3c 8d 4d 0a 51}  //weight: 2, accuracy: High
        $x_1_8 = "RegisterServiceCtrlHandlerEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_EE_2147637019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.EE"
        threat_id = "2147637019"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Device\\PhysicalMemory" wide //weight: 1
        $x_1_2 = {69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 52 00 69 00 73 00 69 00 6e 00 67 00 20 00 52 00 73 00 53 00 68 00 65 00 6c 00 6c}  //weight: 1, accuracy: High
        $x_1_3 = {72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 52 00 73 00 6d 00 61 00 69 00 6e 00 2e 00 65}  //weight: 1, accuracy: High
        $x_1_4 = "info:Shell Code" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_FC_2147637023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.FC"
        threat_id = "2147637023"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d7 66 81 f2 3b 01 88 50 01}  //weight: 2, accuracy: High
        $x_2_2 = {83 ea 41 6b d2 1a}  //weight: 2, accuracy: High
        $x_2_3 = {69 c0 0b 35 00 00 05 68 60 00 00}  //weight: 2, accuracy: High
        $x_2_4 = {83 e2 01 4a 0f 94 45 ?? 83 e0 01 48 0f 94 45 ?? 83 ff 30}  //weight: 2, accuracy: Low
        $x_1_5 = {8d 04 19 48 33 d2 f7 f1 f7 e9}  //weight: 1, accuracy: High
        $x_1_6 = {8b f0 85 f6 74 0c 8b 04 24 50 55 ff d6 85 c0 0f 94 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_FF_2147637822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.FF"
        threat_id = "2147637822"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 d8 1b c0 25 ba d8 ff ff 05 46 27 00 00 c2 ?? 00}  //weight: 1, accuracy: Low
        $x_2_2 = {3d 05 10 00 00 77 ?? 74 ?? 2d 01 10 00 00 74 ?? 83 e8 03 0f 85 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_1_3 = {c9 cf cf df d6 f7 bb fa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_FI_2147637956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.FI"
        threat_id = "2147637956"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gRAYpIGEON" ascii //weight: 1
        $x_1_2 = "POsCREENcENTER" ascii //weight: 1
        $x_1_3 = "oNkEYdOWN" ascii //weight: 1
        $x_1_4 = "aUTlOGINtcpcLIENT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_FI_2147637956_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.FI"
        threat_id = "2147637956"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d6 f7 bb fa d7 d4 b6 af c9 cf cf df}  //weight: 2, accuracy: High
        $x_1_2 = "\\Device\\PhysicalMemory" ascii //weight: 1
        $x_1_3 = {83 f8 3a 0f 87 ?? ?? 00 00 ff 24 85 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_2_4 = {85 c0 0f 84 ?? ?? 00 00 c7 85 ?? ?? ff ff 07 00 01 00}  //weight: 2, accuracy: Low
        $x_1_5 = {00 42 45 49 5f 5a 48 55 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_EJ_2147638801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.EJ"
        threat_id = "2147638801"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 20 53 74 61 72 74 75 70 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {0d 0a 5b 25 30 32 64 2f 25 30 32 64 2f 25 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 5d 20 28 25 73 29 0d 0a}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 fc ff ff ff ff e8 ?? ?? ?? ?? 39 9d ?? ?? ff ff 75 ?? 3b f3 74 0f 56 53 ff 95 ?? ?? ff ff 50 ff 95 ?? ?? ff ff 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_FK_2147640854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.FK"
        threat_id = "2147640854"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6e 6d 65 6e c7 45 ?? 74 53 75 62}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 14 01 80 f2 62 88 10 40 ff 4d ?? 75 f2}  //weight: 2, accuracy: Low
        $x_2_3 = {83 f8 7f 77 18 83 f8 14 72 13}  //weight: 2, accuracy: High
        $x_1_4 = "\\syslog.dat" ascii //weight: 1
        $x_1_5 = "_kaspersky" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_FU_2147640855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.FU"
        threat_id = "2147640855"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 14 01 80 f2 62 88 10 40 ff}  //weight: 2, accuracy: High
        $x_1_2 = {83 f8 7f 77 ?? 83 f8 14 72}  //weight: 1, accuracy: Low
        $x_1_3 = "\\syslog.dat" ascii //weight: 1
        $x_1_4 = "_kaspersky" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_EU_2147642407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.EU"
        threat_id = "2147642407"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 69 72 33 38 30 34 37 32 38 31 39 33 37 33 39 33 37 00 00 6d 69 72 33 39 34 37 33 34 37 35 37 38 36 39 34 37 30 00 00 6d 69 72 33 35 37 39 38 37 36 37 35 33 36 38 32 34 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 65 53 65 6d 61 70 68 6f 72 65 00 00 00 00 53 44 44 79 6e 44 6c 6c 30 39 00 00 00 00 53 44 44 79 6e 44 6c 6c 31 31 00 00 00 00 53 44 44 79 6e 44 6c 6c 30 35 00}  //weight: 1, accuracy: High
        $x_1_3 = {ff 15 14 20 40 00 3d 36 20 00 00 72 35 8d 05 14 20 40 00 89 45 fc 68 00 10 40 00 68 88 30 40 00 68 00 30 40 00 ff 75 fc ff 15 24 20 40 00 85 c0 74 40 6a ff ff 35 08 30 40 00 ff 15 04 20 40 00 eb 30 68 78 30 40 00 8d 85 fc fe ff ff 68 68 30 40 00 50 ff 15 30 20 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_ZAI_2147642547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.ZAI"
        threat_id = "2147642547"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 94 05 00 00 23 ?? 6a 00 6a 04 50 6a ff ff (55 ??|15 ?? ?? ?? ??) 85 c0 a3}  //weight: 3, accuracy: Low
        $x_3_2 = "fUCK_AVP" ascii //weight: 3
        $x_1_3 = "MyLive" ascii //weight: 1
        $x_1_4 = "\\pbk\\rasphone.pbk" ascii //weight: 1
        $x_1_5 = "\\perfc008.dat" ascii //weight: 1
        $x_1_6 = "[%d/%d/%d %d:%d:%d]" ascii //weight: 1
        $x_1_7 = "BITSServiceMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_ZAI_2147642547_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.ZAI"
        threat_id = "2147642547"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 6d 4d 30 62 56 31 75 4b 6a 68 64 54 54 51 33 5a 58 4d 31 50 44 35 41 6e 77 3d 3d 40 33 51 4c 7a 34 50 45 43 2f 76 4d 43 76 51 50 37 2b 35 38 3d 00 48 41 48 48 48 48}  //weight: 1, accuracy: High
        $x_1_2 = "SOFTWARE\\mICRosOFT\\wINDoWs nt\\cURrENTvERsIoN\\sVcHosT" ascii //weight: 1
        $x_1_3 = "%s:\\DoCumEnts And SetTinGs\\LocalSeRVice" ascii //weight: 1
        $x_1_4 = "%s\\%d_Index.TEMP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_ZAJ_2147642548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.ZAJ"
        threat_id = "2147642548"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c b3 cc d0 f2 5c c6 f4 b6 af 5c}  //weight: 2, accuracy: High
        $x_2_2 = {00 4d 79 4c 69 76 65 00}  //weight: 2, accuracy: High
        $x_2_3 = "\\teslortnoctnerruc\\" ascii //weight: 2
        $x_1_4 = "\\server.exe" ascii //weight: 1
        $x_1_5 = "360tray.exe" ascii //weight: 1
        $x_1_6 = "36%xsvc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_ZAK_2147642549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.ZAK"
        threat_id = "2147642549"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 01 6a 47 68 ?? ?? ?? ?? 89 45 ?? ff d6 83 c4 0c 50}  //weight: 2, accuracy: Low
        $x_2_2 = "0etVolumeInformation" ascii //weight: 2
        $x_1_3 = "GT_Update" ascii //weight: 1
        $x_1_4 = "\\Gh0st %d" ascii //weight: 1
        $x_1_5 = "%s:\\Documents" ascii //weight: 1
        $x_1_6 = "ONS\\IExPLoRE.EXE\\SHelL\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_EX_2147647694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.EX"
        threat_id = "2147647694"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FTP.EXE -i -s:j&del j&echo for %%i in (*.exe) do start %%i >D.bat&echo del /f /q %0% >>D.bat&D.ba" wide //weight: 1
        $x_1_2 = "AttackScanner via Gothin" wide //weight: 1
        $x_1_3 = "\\Windows\\System','DisableCMD'" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Hupigon_FP_2147691771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.FP"
        threat_id = "2147691771"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "kvmonxp.kxp" ascii //weight: 1
        $x_1_2 = "k-meleon.exe" ascii //weight: 1
        $x_1_3 = "kwatchui.exe" ascii //weight: 1
        $x_1_4 = {ff ff ff ff 04 00 00 00 3a 74 72 79 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {ff ff ff ff 05 00 00 00 64 65 6c 20 22 00 00 00 ff ff ff ff 01 00 00 00 22 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {08 00 4d 00 41 00 49 00 4e 00 49 00 43 00 4f 00 4e 00}  //weight: 1, accuracy: High
        $x_1_7 = {7d 03 46 eb 05 be 01 00 00 00 8b 45 ?? 33 db 8a 5c 30 ff 33 5d ?? 3b fb 7c 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_ZAP_2147733097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.ZAP!bit"
        threat_id = "2147733097"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tree2xml app=\"SVCHOST.exe" ascii //weight: 1
        $x_1_2 = "ServerUseSelfDefine=" ascii //weight: 1
        $x_1_3 = "ClientGroup=" ascii //weight: 1
        $x_1_4 = "cmd /c shutdown -s -f -t 0" ascii //weight: 1
        $x_1_5 = "objws.Run kavpath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_A_2147743961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.A!MTB"
        threat_id = "2147743961"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "%SystemRoot%\\system32\\svchos.exe" wide //weight: 10
        $x_10_2 = "add.php" ascii //weight: 10
        $x_10_3 = "info-EWT.dll" ascii //weight: 10
        $x_10_4 = "lexplorer.exe" wide //weight: 10
        $x_1_5 = "outlook.exe" wide //weight: 1
        $x_1_6 = "mozilla.exe" wide //weight: 1
        $x_1_7 = "firefox.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hupigon_EC_2147842700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.EC!MTB"
        threat_id = "2147842700"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TResourceStream" ascii //weight: 1
        $x_1_2 = "eio3_dd83_ff837d" ascii //weight: 1
        $x_1_3 = "Winapi.TlHelp32" ascii //weight: 1
        $x_1_4 = "System.Internal.ExcUtils" ascii //weight: 1
        $x_1_5 = "deuekl_duzlib" ascii //weight: 1
        $x_1_6 = "ru8_fieoe_ffu3" ascii //weight: 1
        $x_1_7 = "Winapi.SHFolder" ascii //weight: 1
        $x_1_8 = "deleteme.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hupigon_DW_2147901125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hupigon.DW!MTB"
        threat_id = "2147901125"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 c2 01 da 8b 12 81 e2 ?? ?? ?? ?? 8b 59 ?? 01 c3 c1 e2 ?? 01 d3 8b 13}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 18 80 c3 ?? 80 f3 ?? 80 c3 ?? 88 18 40 49 83 f9 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

