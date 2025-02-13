rule Trojan_Win32_Cinmus_B_113677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmus.B"
        threat_id = "113677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmus"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 10
        $x_10_2 = "DownloadMD5" ascii //weight: 10
        $x_10_3 = "CreateMutexA" ascii //weight: 10
        $x_10_4 = "InternetReadFile" ascii //weight: 10
        $x_1_5 = "gs.chnsystem.com" ascii //weight: 1
        $x_1_6 = "ssl.chnsystem.com" ascii //weight: 1
        $x_1_7 = "msl.chnsystem.com " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Cinmus_E_121143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmus.E"
        threat_id = "121143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmus"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {00 00 00 44 6f 53 53 53 65 74 75 70 2e 44 4c 4c 00 44 6f 53 53 53 65 74 75 70 00 00}  //weight: 4, accuracy: High
        $x_1_2 = "FirstInstall" ascii //weight: 1
        $x_1_3 = "verion" ascii //weight: 1
        $x_1_4 = "dddd, MMMM dd, yyyy" ascii //weight: 1
        $x_1_5 = "GetLastActivePopup" ascii //weight: 1
        $x_1_6 = "<program name unknown>" ascii //weight: 1
        $x_1_7 = "CreateMutexA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Cinmus_F_122043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmus.F"
        threat_id = "122043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmus"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {01 00 44 6f 53 53 53 65 74 75 70 2e 44 4c 4c 00 44 65 73 50 72 6f 00 44 6f 53 53 53 65 74 75 70 00 00}  //weight: 4, accuracy: High
        $x_1_2 = "FirstInstall" ascii //weight: 1
        $x_1_3 = "verion" ascii //weight: 1
        $x_1_4 = "dddd, MMMM dd, yyyy" ascii //weight: 1
        $x_1_5 = "GetLastActivePopup" ascii //weight: 1
        $x_1_6 = "<program name unknown>" ascii //weight: 1
        $x_1_7 = "CreateMutexA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Cinmus_H_122774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmus.H"
        threat_id = "122774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmus"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\Driver\\objfre\\i386\\acpidisk.pdb" ascii //weight: 5
        $x_2_2 = "Windows Driver Manager Running %s!" ascii //weight: 2
        $x_1_3 = "Windows System Driver Started!" ascii //weight: 1
        $x_1_4 = "GetSystemDirectoryW" ascii //weight: 1
        $x_1_5 = "PsLookupProcessByProcessId" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Cinmus_I_123082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmus.I"
        threat_id = "123082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmus"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 fc 40 89 45 fc 8b 45 fc 3b 45 0c 73 (19|1b) 8b 45 fc 8b 4d 08 0f b7 04 41 (83 f0 ??|35 ?? ?? ?? ??) 8b 4d fc 8b 55 10 66 89 04 4a eb (d8|d6)}  //weight: 5, accuracy: Low
        $x_5_2 = {66 8b 1c 08 66 81 f3 ?? ?? 66 89 19 41 41 4f 75 ef 5b 66 83 24 72 00}  //weight: 5, accuracy: Low
        $x_1_3 = {81 7d e4 00 00 00 83 74}  //weight: 1, accuracy: High
        $x_1_4 = {61 63 70 69 64 69 73 6b 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Cinmus_J_123769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmus.J"
        threat_id = "123769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmus"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 7d e4 00 00 00 83 74}  //weight: 5, accuracy: High
        $x_1_2 = {83 7d fc 04 7d ?? 8b 45 fc ff 34 85 ?? ?? ?? ?? ff 75 f8 e8 ?? ?? ?? ?? 8b 4d fc 8b 15 ?? ?? ?? ?? 89 04 8a}  //weight: 1, accuracy: Low
        $x_1_3 = {83 7d f8 04 0f 8d ?? ?? 00 00 8b 45 f8 ff 34 85 ?? ?? ?? ?? ff 75 fc e8 ?? ?? ?? ?? 8b 4d f8 8b 15 ?? ?? ?? ?? 89 04 8a}  //weight: 1, accuracy: Low
        $x_2_4 = "\\BaseNamedObjects\\UID_1329147602_MIEEvent" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Cinmus_R_124309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmus.R"
        threat_id = "124309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmus"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "loader\\Driver\\objfre\\i386\\apcdli.pdb" ascii //weight: 4
        $x_2_2 = "apcdli" wide //weight: 2
        $x_2_3 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 57 69 6e 64 6f 77 73 20 53 79 73 74 65 6d 20 44 72 69 76 65 72 20 53 74 61 72 74 65 64 21}  //weight: 2, accuracy: High
        $x_1_4 = "ZwQueryInformationFile" ascii //weight: 1
        $x_1_5 = "KeUnstackDetachProcess" ascii //weight: 1
        $x_1_6 = "RtlQueryRegistryValues" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Cinmus_S_124444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmus.S"
        threat_id = "124444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmus"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 49 44 5f 31 33 32 39 31 34 37 36 30 32 5f 4d 49 45 45 76 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {5f 7a 63 64 79 5f 73 6d 63 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 6f 77 6e 6c 6f 61 64 4d 44 35 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 6f 77 6e 6c 6f 61 64 49 44 00}  //weight: 1, accuracy: High
        $x_1_5 = {52 65 71 75 65 73 74 4e 65 77 4d 61 69 6e 62 6f 64 79 54 69 6d 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cinmus_K_126093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmus.K"
        threat_id = "126093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmus"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 03 00 00 00 c7 84 00 59 e9 01 00 00 00 e9 83 c1 0a 51 c3 ff 35 ff 25 e9 59}  //weight: 1, accuracy: High
        $x_1_2 = {e8 03 00 00 00 ?? ?? ?? 59 e9 01 00 00 00 ?? 83 c1 0a 51 c3 ?? ?? ?? ?? ?? 59 33 c0 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Cinmus_L_126125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmus.L"
        threat_id = "126125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmus"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 75 62 50 72 6f 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 6f 53 53 53 65 74 75 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {74 03 75 01 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cinmus_N_134985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmus.N"
        threat_id = "134985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmus"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "{F9BA1AA9-CAD4-4C14-BDE6-922DFF5F6F38" ascii //weight: 10
        $x_2_2 = {73 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 41 70 63 64 6c 69 00}  //weight: 2, accuracy: High
        $x_2_3 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 6e 74 70 74 64 62 00}  //weight: 2, accuracy: High
        $x_2_4 = {5f 5f 73 79 73 6c 6f 61 64 65 72 5f 5f 00}  //weight: 2, accuracy: High
        $x_1_5 = {00 54 65 6d 70 50 61 74 68 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 79 73 62 61 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = "51edm.net" ascii //weight: 1
        $x_1_8 = "webbrowser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Cinmus_O_139438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmus.O"
        threat_id = "139438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmus"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%s?fid=%d&kid=%d&aid=%d&mac=%s&kw=%s" ascii //weight: 2
        $x_1_2 = {68 70 6f 70 63 6f 75 6e 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 63 70 69 64 69 73 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = "mprmsgse.axz" ascii //weight: 1
        $x_1_5 = {6f 72 67 5f 6d 64 35 3d 25 73 2c 20 63 61 6c 75 5f 6d 64 35 3d 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Cinmus_P_140874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmus.P"
        threat_id = "140874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmus"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dosssetup.dll" ascii //weight: 1
        $x_1_2 = {76 65 72 3d 25 73 2c 66 69 64 3d 25 73 2c 66 69 6c 65 3d 25 73 2c 6e 41 63 74 69 6f 6e 3d 25 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 5c 2e 5c 70 69 70 65 5c 44 46 46 41 46 31 42 46 43 34 34 62 30 31 42 41 31 44 31 38 31 38 36 42 37 46 31 37 33 33 00}  //weight: 1, accuracy: High
        $x_1_4 = {72 03 73 01 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

