rule Trojan_Win32_Zlob_F_2147553766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.F"
        threat_id = "2147553766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "You should reboot your computer prior to uninstalling this software. Reboot now?" ascii //weight: 1
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 5c 49 6e 74 65 72 6e 65 74 20 53 65 63 75 72 69 74 79 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 6f 64 65 63 73 53 6f 66 74 77 61 72 65 50 61 63 6b 61 67 65 2e 63 68 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {55 6e 69 6e 73 74 61 6c 6c 5c [0-8] 20 43 6f 64 65 63}  //weight: 1, accuracy: Low
        $x_1_5 = {41 56 5a 69 70 45 6e 63 68 61 6e 63 65 72 2e 43 68 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_ZWC_2147597846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.ZWC"
        threat_id = "2147597846"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "49"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {56 41 43 2e 56 69 64 65 6f 00}  //weight: 20, accuracy: High
        $x_20_2 = {00 72 65 66 72 2e 64 6c 6c}  //weight: 20, accuracy: High
        $x_3_3 = "%s\\la%s%d.exe" ascii //weight: 3
        $x_3_4 = "vc20xc00u" ascii //weight: 3
        $x_3_5 = {00 63 68 65 63 6b 00 63 6f 70 79 00 72 75 6e 00}  //weight: 3, accuracy: High
        $x_1_6 = "terminateprocess" ascii //weight: 1
        $x_1_7 = "GetUserObjectInformationA" ascii //weight: 1
        $x_1_8 = "GetProcessWindowStation" ascii //weight: 1
        $x_1_9 = "getlastactivepopup" ascii //weight: 1
        $x_1_10 = "HttpOpenRequest" ascii //weight: 1
        $x_1_11 = "internetcrackurla" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_20_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*) and 3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zlob_ZWJ_2147598037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.ZWJ"
        threat_id = "2147598037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "65"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {56 41 43 2e 56 69 64 65 6f 00}  //weight: 20, accuracy: High
        $x_20_2 = {00 72 65 66 72 2e 64 6c 6c}  //weight: 20, accuracy: High
        $x_10_3 = "%s\\la%s%d.exe" ascii //weight: 10
        $x_10_4 = {00 63 68 65 63 6b 00 63 6f 70 79 00 72 75 6e 00}  //weight: 10, accuracy: High
        $x_1_5 = "HttpOpenRequest" ascii //weight: 1
        $x_1_6 = "internetcrackurla" ascii //weight: 1
        $x_1_7 = "findfirsturlcacheentrya" ascii //weight: 1
        $x_1_8 = "FindCloseUrlCache" ascii //weight: 1
        $x_1_9 = "RegCreateKey" ascii //weight: 1
        $x_1_10 = "shellexecuteA" ascii //weight: 1
        $x_1_11 = "Software\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 1
        $x_1_12 = "NullsoftInst" ascii //weight: 1
        $x_1_13 = "Software\\Online Add-on" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zlob_N_2147598398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.N"
        threat_id = "2147598398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "261"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8b 74 24 08 a3 ?? ?? ?? ?? 8a 16 84 d2 8b c8 74 10 2b f0 32 54 24 0c 88 11 41 8a 14 0e 84 d2 75 f2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c8 b2 b4 2b d8 90 80 f2 c0 88 11 8a 54 0b 01 41 84 d2 75 f2}  //weight: 1, accuracy: High
        $x_10_3 = ".php?qq=%s" ascii //weight: 10
        $x_10_4 = "res://%s" wide //weight: 10
        $x_10_5 = "arch.msn.com/res" wide //weight: 10
        $x_10_6 = "ll/http_4" wide //weight: 10
        $x_10_7 = "clc.dll/dnse" wide //weight: 10
        $x_10_8 = "onse.asp?" wide //weight: 10
        $x_100_9 = "GetSystemDirectoryW" ascii //weight: 100
        $x_100_10 = "PulseEvent" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 6 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zlob_A_2147599468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.gen!A"
        threat_id = "2147599468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "171"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "emlkdvo.DLL" ascii //weight: 20
        $x_1_2 = "FlsSetValue" ascii //weight: 1
        $x_1_3 = "FInterlockedPopEntrySList" ascii //weight: 1
        $x_1_4 = "Module_Raw" wide //weight: 1
        $x_1_5 = "HKEY_CLASSES_ROOT" wide //weight: 1
        $x_1_6 = "HKEY_CURRENT_USER" wide //weight: 1
        $x_1_7 = "HKEY_LOCAL_MACHINE" wide //weight: 1
        $x_1_8 = "HKEY_USERS" wide //weight: 1
        $x_1_9 = "HKEY_PERFORMANCE_DATA" wide //weight: 1
        $x_1_10 = "HKEY_DYN_DATA" wide //weight: 1
        $x_1_11 = "HKEY_CURRENT_CONFIG" wide //weight: 1
        $x_1_12 = "\\Implemented Categories" wide //weight: 1
        $x_1_13 = "\\Required Categories" wide //weight: 1
        $x_20_14 = "emlkdvoTOOLBAR" wide //weight: 20
        $x_20_15 = "ToolbarWindow32" wide //weight: 20
        $x_100_16 = {89 45 c0 8b 4d c0 83 79 18 08 72 0e 8b 55 c0 8b 42 04 89 85 ?? ?? ff ff eb 0c 8b 4d c0 83 c1 04 89 8d ?? ?? ff ff 6a 00 8d 55 fc 52 6a 00 68 06 00 02 00 6a 00 6a 00 6a 00 8b 85 ?? ?? ff ff 50 68 02 00 00 80 ff 15 04 f0 01 10 6a 00 6a 01 8d 4d e0 e8 ?? ca ff ff 68 ?? 00 02 10 8d 4d c4 51 e8 ?? ?? ff ff}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_20_*) and 11 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zlob_B_2147600150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.gen!B"
        threat_id = "2147600150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InterlockedPushEntrySList" ascii //weight: 1
        $x_1_2 = "FlsSetValue" ascii //weight: 1
        $x_1_3 = "Class Hierarchy Descriptor" ascii //weight: 1
        $x_1_4 = "enqvwkp.DLL" ascii //weight: 1
        $x_1_5 = "RegQueryInfoKeyW" ascii //weight: 1
        $x_1_6 = "Component Categories" wide //weight: 1
        $x_1_7 = "CLSID" wide //weight: 1
        $x_1_8 = "ForceRemove" wide //weight: 1
        $x_1_9 = "HKEY_CLASSES_ROOT" wide //weight: 1
        $x_1_10 = "HKEY_CURRENT_USER" wide //weight: 1
        $x_1_11 = "HKEY_LOCAL_MACHINE" wide //weight: 1
        $x_1_12 = "HKEY_USERS" wide //weight: 1
        $x_1_13 = "HKEY_PERFORMANCE_DATA" wide //weight: 1
        $x_1_14 = "HKEY_DYN_DATA" wide //weight: 1
        $x_1_15 = "HKEY_CURRENT_CONFIG" wide //weight: 1
        $x_1_16 = "Implemented Categories" wide //weight: 1
        $x_1_17 = "enqvwkpTOOLBAR" wide //weight: 1
        $x_1_18 = "ToolbarWindow32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_B_2147600244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.B"
        threat_id = "2147600244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FlsSetValue" ascii //weight: 1
        $x_1_2 = {65 00 78 00 00 00 00 00 70 00 6c 00 6f 00 72 00 65 00 72 00 00 00 00 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
        $x_1_3 = {0f be c0 83 e8 2f 0e 00 85 ?? 74 ?? 8a ?? 3c ?? ?? ?? 3c}  //weight: 1, accuracy: Low
        $x_1_4 = {66 8b 08 83 c0 02 66 3b ce 75 f5 2b c2 d1 f8 50 8d 94 24 b8 00 00 00 52 8d 8c 24 a0 00 00 00 e8 ?? ?? ff ff 6a 04 68 ?? ?? 01 10 8d 4c 24 4c 89 7c 24 64 89 74 24 60 66 89 74 24 50 e8 ?? ?? ff ff 6a 06 68 ?? ?? 01 10 8d 4c 24 14 89 7c 24 2c 89 74 24 28 66 89 74 24 18 e8 ?? ?? ff ff 6a 02 68 ?? ?? 01 10 8d 4c 24 30 89 7c 24 48 89 74 24 44 66 89 74 24 34 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_AML_2147600616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.AML"
        threat_id = "2147600616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".php?qq=%s" wide //weight: 1
        $x_1_2 = "%ss://%s\\shdo%s" wide //weight: 1
        $x_1_3 = "errorbrowser.com" wide //weight: 1
        $x_1_4 = "allsecuritypage.com" wide //weight: 1
        $x_1_5 = "\\InprocServer32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Zlob_C_2147601109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.gen!C"
        threat_id = "2147601109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InterlockedPushEntrySList" ascii //weight: 1
        $x_1_2 = "FlsSetValue" ascii //weight: 1
        $x_1_3 = "Class Hierarchy Descriptor" ascii //weight: 1
        $x_1_4 = "edfqvrw.DLL" ascii //weight: 1
        $x_1_5 = "RegQueryInfoKeyW" ascii //weight: 1
        $x_1_6 = "Component Categories" wide //weight: 1
        $x_1_7 = "CLSID" wide //weight: 1
        $x_1_8 = "ForceRemove" wide //weight: 1
        $x_1_9 = "HKEY_CLASSES_ROOT" wide //weight: 1
        $x_1_10 = "HKEY_CURRENT_USER" wide //weight: 1
        $x_1_11 = "HKEY_LOCAL_MACHINE" wide //weight: 1
        $x_1_12 = "HKEY_USERS" wide //weight: 1
        $x_1_13 = "HKEY_PERFORMANCE_DATA" wide //weight: 1
        $x_1_14 = "HKEY_DYN_DATA" wide //weight: 1
        $x_1_15 = "HKEY_CURRENT_CONFIG" wide //weight: 1
        $x_1_16 = "Implemented Categories" wide //weight: 1
        $x_1_17 = "edfqvrwTOOLBAR" wide //weight: 1
        $x_1_18 = "ToolbarWindow32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_D_2147601248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.gen!D"
        threat_id = "2147601248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InterlockedPushEntrySList" ascii //weight: 1
        $x_1_2 = "FlsSetValue" ascii //weight: 1
        $x_1_3 = "Class Hierarchy Descriptor" ascii //weight: 1
        $x_1_4 = "emotrlq.DLL" ascii //weight: 1
        $x_1_5 = "RegSetValueExW" ascii //weight: 1
        $x_1_6 = "Component Categories" wide //weight: 1
        $x_1_7 = "CLSID" wide //weight: 1
        $x_1_8 = "ForceRemove" wide //weight: 1
        $x_1_9 = "HKEY_CLASSES_ROOT" wide //weight: 1
        $x_1_10 = "HKEY_CURRENT_USER" wide //weight: 1
        $x_1_11 = "HKEY_LOCAL_MACHINE" wide //weight: 1
        $x_1_12 = "HKEY_USERS" wide //weight: 1
        $x_1_13 = "HKEY_PERFORMANCE_DATA" wide //weight: 1
        $x_1_14 = "HKEY_DYN_DATA" wide //weight: 1
        $x_1_15 = "HKEY_CURRENT_CONFIG" wide //weight: 1
        $x_1_16 = "Implemented Categories" wide //weight: 1
        $x_1_17 = "emotrlqTOOLBAR" wide //weight: 1
        $x_1_18 = "ToolbarWindow32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_AD_2147601303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.AD"
        threat_id = "2147601303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: High
        $x_1_2 = "ImageList_ReplaceIcon" ascii //weight: 1
        $x_1_3 = "GetClientRect" ascii //weight: 1
        $x_1_4 = "RegSetValueEx" ascii //weight: 1
        $x_1_5 = "StringFromGUID2" ascii //weight: 1
        $x_1_6 = "GetUserObjectInformation" ascii //weight: 1
        $x_1_7 = "TOOLBAR" wide //weight: 1
        $x_1_8 = {68 06 00 02 00 6a 00 6a 00 6a 00 8b 95 ?? ?? ff ff 52 68 02 00 00 80 ff 15 ?? ?? ?? ?? 6a 00 6a 01 8d 4d ?? e8 ?? ?? ff ff ba ?? ?? ?? ?? 8d 4d ?? e8 ?? ?? ff ff 89 45 ?? 8b 45 ?? 83 78 ?? 08 72 0e 8b 4d ?? 8b 51 04 89 95 ?? ?? ff ff eb ?? 8b 45 ?? 83 c0 04 89 85 ?? ?? ff ff 6a 00 6a 00 6a 03 6a 00}  //weight: 1, accuracy: Low
        $x_1_9 = {6a 28 6a 20 5e 56 e8 ?? ?? ff ff 59 59 3b c7 0f 84 ?? ?? 00 00 a3 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8d 88 00 05 00 00 eb ?? c6 40 04 00 83 08 ff c6 40 05 0a 89 78 08 c6 40 24 00 c6 40 25 0a c6 40 26 0a 83 c0 28 8b 0d ?? ?? ?? ?? 81 c1 00 05 00 00}  //weight: 1, accuracy: Low
        $x_1_10 = {8b 44 24 04 8b 00 8b 00 3d 4d 4f 43 e0 74 18 3d 63 73 6d e0 75 ?? e8 ?? ?? ff ff 83 a0 90 00 00 00 00 e9 ?? ?? 00 00 e8 ?? ?? ff ff 83 b8 90 00 00 00 00 7e ?? e8 ?? ?? ff ff 05 90 00 00 00 ff 08 33 c0 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_F_2147601622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.gen!F"
        threat_id = "2147601622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e9 57 66 89 4d f0 8b 55 f4 8b 45 08 0f b7 0c 50 83 f9 ?? 7c 20 8b 55 f4 8b 45 08 0f b7 0c 50 83 f9 ?? 7f 11 8b 55 f4 8b 45 08 0f b7 0c 50 83 e9 ?? 66 89 4d f0}  //weight: 1, accuracy: Low
        $x_1_2 = {83 e8 57 66 89 45 f4 8b 4d 08 03 4d f8 0f be 11 83 fa ?? 7c 1e 8b 45 08 03 45 f8 0f be 08 83 f9 ?? 7f 10 8b 55 08 03 55 f8 0f be 02 83 e8 ?? 66 89 45 f4}  //weight: 1, accuracy: Low
        $x_1_3 = {83 e8 57 66 89 45 f0 8b 4d fc 03 4d f4 0f be 11 83 fa ?? 7c 1e 8b 45 fc 03 45 f4 0f be 08 83 f9 ?? 7f 10 8b 55 fc 03 55 f4 0f be 02 83 e8 ?? 66 89 45 f0}  //weight: 1, accuracy: Low
        $x_1_4 = {83 e8 57 66 89 45 f0 8b 45 f4 8b 4d 08 0f b7 04 41 83 f8 ?? 7c 20 8b 45 f4 8b 4d 08 0f b7 04 41 83 f8 ?? 7f 11 8b 45 f4 8b 4d 08 0f b7 04 41 83 e8 ?? 66 89 45 f0}  //weight: 1, accuracy: Low
        $n_10_5 = "Skynax" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_Zlob_G_2147601758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.gen!G"
        threat_id = "2147601758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1681"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "enqvwkpTOOLBAR" wide //weight: 1
        $x_1_2 = "emlkdvoTOOLBAR" wide //weight: 1
        $x_1_3 = "edfqvrwTOOLBAR" wide //weight: 1
        $x_1_4 = "jokwmpTOOLBAR" wide //weight: 1
        $x_1_5 = "leosrvTOOLBAR" wide //weight: 1
        $x_1_6 = "sdrmodTOOLBAR" wide //weight: 1
        $x_1_7 = "elfwgpsTOOLBAR" wide //weight: 1
        $x_1_8 = "bonswsTOOLBAR" wide //weight: 1
        $x_10_9 = "ToolbarWindow32" wide //weight: 10
        $x_10_10 = "MOTLEYFOOLLib" ascii //weight: 10
        $x_10_11 = "ATL:%p" wide //weight: 10
        $x_50_12 = "Class Hierarchy Descriptor" ascii //weight: 50
        $x_50_13 = "RegQueryInfoKeyW" ascii //weight: 50
        $x_50_14 = "Component Categories" wide //weight: 50
        $x_50_15 = "CLSID" wide //weight: 50
        $x_50_16 = "ForceRemove" wide //weight: 50
        $x_50_17 = "HKEY_CLASSES_ROOT" wide //weight: 50
        $x_50_18 = "HKEY_CURRENT_USER" wide //weight: 50
        $x_50_19 = "HKEY_LOCAL_MACHINE" wide //weight: 50
        $x_50_20 = "HKEY_USERS" wide //weight: 50
        $x_50_21 = "HKEY_PERFORMANCE_DATA" wide //weight: 50
        $x_50_22 = "HKEY_DYN_DATA" wide //weight: 50
        $x_50_23 = "HKEY_CURRENT_CONFIG" wide //weight: 50
        $x_50_24 = "\\Implemented Categories" wide //weight: 50
        $x_1000_25 = {45 6e 63 6f 64 65 50 6f 69 6e 74 65 72 00 00 00 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c 00 00 00 00 44 65 63 6f 64 65 50 6f 69 6e 74 65 72 00 00 00 46 6c 73 46 72 65 65 00 46 6c 73 53 65 74 56 61 6c 75 65 00 46 6c 73 47 65 74 56 61 6c 75 65 00 46 6c 73 41 6c 6c 6f 63 00 00}  //weight: 1000, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1000_*) and 13 of ($x_50_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zlob_H_2147602344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.gen!H"
        threat_id = "2147602344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "48"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {84 b2 96 b1 b4 ba 1a 10 b6 9c 00 aa 00 34 1d 07}  //weight: 1, accuracy: High
        $x_1_2 = {4f f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b}  //weight: 1, accuracy: High
        $x_1_3 = {25 44 2c 33 cb 26 d0 11 b4 83 00 c0 4f d9 01 19}  //weight: 1, accuracy: High
        $x_1_4 = {40 f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b}  //weight: 1, accuracy: High
        $x_1_5 = {1f f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b}  //weight: 1, accuracy: High
        $x_1_6 = {ff f1 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b}  //weight: 1, accuracy: High
        $x_1_7 = {a0 15 a7 34 87 65 d0 11 92 4a 00 20 af c7 ac 4d}  //weight: 1, accuracy: High
        $x_1_8 = {61 16 0c d3 af cd d0 11 8a 3e 00 c0 4f c9 e2 6e}  //weight: 1, accuracy: High
        $x_10_9 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 [0-4] 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 [0-4] 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 [0-4] 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 10, accuracy: Low
        $x_10_10 = "IsDebuggerPresent" ascii //weight: 10
        $x_10_11 = {45 6e 63 6f 64 65 50 6f 69 6e 74 65 72 00 00 00 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c 00 00 00 00 44 65 63 6f 64 65 50 6f 69 6e 74 65 72 00 00 00 46 6c 73 46 72 65 65 00 46 6c 73 53 65 74 56 61 6c 75 65 00 46 6c 73 47 65 74 56 61 6c 75 65 00 46 6c 73 41 6c 6c 6f 63 00 00}  //weight: 10, accuracy: High
        $x_10_12 = "BhoNew.DLL" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_H_2147602344_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.gen!H"
        threat_id = "2147602344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 25 44 2c 33 cb 26 d0 11 b4 83 00 c0 4f d9 01 19 40 f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 1f f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b ff f1 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b a0 15 a7 34 87 65 d0 11 92 4a 00 20 af c7 ac 4d 61 16 0c d3 af cd d0 11 8a 3e 00 c0 4f c9 e2 6e 84 b2 96 b1 b4 ba 1a 10 b6 9c 00 aa 00 34 1d 07}  //weight: 1, accuracy: High
        $x_1_2 = {a0 15 a7 34 87 65 d0 11 92 4a 00 20 af c7 ac 4d 61 16 0c d3 af cd d0 11 8a 3e 00 c0 4f c9 e2 6e 4f f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 25 44 2c 33 cb 26 d0 11 b4 83 00 c0 4f d9 01 19 03 f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd 40 f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 1f f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b ff f1 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 84 b2 96 b1 b4 ba 1a 10 b6 9c 00 aa 00 34 1d 07}  //weight: 1, accuracy: Low
        $x_1_3 = {a0 15 a7 34 87 65 d0 11 92 4a 00 20 af c7 ac 4d 61 16 0c d3 af cd d0 11 8a 3e 00 c0 4f c9 e2 6e 84 b2 96 b1 b4 ba 1a 10 b6 9c 00 aa 00 34 1d 07 4f f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 25 44 2c 33 cb 26 d0 11 b4 83 00 c0 4f d9 01 19 40 f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 1f f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b ff f1 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b}  //weight: 1, accuracy: High
        $x_10_4 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 [0-4] 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 [0-4] 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 [0-4] 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 10, accuracy: Low
        $x_10_5 = "IsDebuggerPresent" ascii //weight: 10
        $x_10_6 = {45 6e 63 6f 64 65 50 6f 69 6e 74 65 72 00 00 00 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c 00 00 00 00 44 65 63 6f 64 65 50 6f 69 6e 74 65 72 00 00 00 46 6c 73 46 72 65 65 00 46 6c 73 53 65 74 56 61 6c 75 65 00 46 6c 73 47 65 74 56 61 6c 75 65 00 46 6c 73 41 6c 6c 6f 63 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zlob_I_2147603186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.gen!I"
        threat_id = "2147603186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 [0-4] 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 [0-4] 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 [0-4] 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: Low
        $x_1_2 = {45 6e 63 6f 64 65 50 6f 69 6e 74 65 72 00 00 00 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c 00 00 00 00 44 65 63 6f 64 65 50 6f 69 6e 74 65 72 00 00 00 46 6c 73 46 72 65 65 00 46 6c 73 53 65 74 56 61 6c 75 65 00 46 6c 73 47 65 74 56 61 6c 75 65 00 46 6c 73 41 6c 6c 6f 63 00 00}  //weight: 1, accuracy: High
        $x_2_3 = {75 06 66 c7 45 ?? ?? 00 0f be ?? ?? 83 ?? ?? 75 06 66 c7 45 ?? ?? 00 0f be ?? ?? 83 ?? ?? 75 06 66 c7 45 ?? ?? 00 0f be ?? ?? 83 ?? ?? 75 06 66 c7 45 ?? ?? 00 0f be ?? ?? 83 ?? ?? 75 06 66 c7 45 ?? ?? 00 0f be ?? ?? 83 ?? ?? 75 06 66 c7 45 ?? ?? 00 0f be ?? ?? 83 ?? ?? 75 06 66 c7 45 ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_4 = {75 06 66 c7 45 ?? ?? 00 0f b7 ?? ?? c1 ?? 04 0f b7 ?? ?? 03 ?? 66 89 ?? ?? e9 ?? ?? ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zlob_J_2147605083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.gen!J"
        threat_id = "2147605083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 fa 41 75 03 6a 0a 59 80 fa ?? 75 ?? ?? [0-2] 80 fa ?? 75 03 ?? ?? ?? 80 fa ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {41 75 06 66 c7 45 f4 0a 00 0f be ?? f3 83 ?? ?? 75 06 66 c7 45 f4 ?? 00 0f be ?? f3 83 ?? ?? 75 06 66 c7 45 f4 ?? 00 0f be ?? f3 83 ?? ?? 75 06 02 00 83}  //weight: 1, accuracy: Low
        $x_1_3 = {83 ea 57 0f b7 d2 8a d9 80 eb ?? 80 fb ?? 77 ?? 66 0f be d1 66 ?? ?? [0-1] 0f b7 d2 8a d9 ?? ?? ?? ?? ?? [0-1] 77 ?? 66 0f be d1 66 ?? ?? [0-1] 0f b7 d2 8a d9}  //weight: 1, accuracy: Low
        $x_1_4 = {83 e9 57 0f b7 c9 8a d0 80 ea ?? 80 fa ?? 77 0b 66 0f be c8 66 83 e9 ?? 0f b7 c9 8a d0 80 ea ?? 80 fa ?? 77 0b 66 0f be c8 66 83 e9 ?? 0f b7 c9 8a d0}  //weight: 1, accuracy: Low
        $x_1_5 = {83 e9 57 0f b7 c9 3c ?? 7c 0f 3c ?? 7f 0b 66 0f be d0 66 83 ea ?? 0f b7 ca 3c ?? 7c 0f 3c ?? 7f 0b 66 0f be ?? 66 (2d|83 e9)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zlob_AK_2147605202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.AK"
        threat_id = "2147605202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f be 0c 18 66 83 e9 41 0f b7 c9 c1 e7 04 03 f9 83 c0 01 83 f8 04 0f b7 ff 72 e4 83 ca ff 2b 56 14 83 fa 01 77 05 e8 ?? ?? ?? 00 8b 6e 14 83 c5 01 81 fd fe ff ff 7f 76 05 e8 ?? ?? ?? 00 [0-32] 76 56 8b 56 14 81 f7 ?? ?? ?? ?? 0f b7 cf bf 08 00 00 00 39 7e 18 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_ANE_2147605323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.ANE"
        threat_id = "2147605323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 7f 18 8b ?? 08 0f be ?? 83 f8 61 7c 0d 8b ?? 08 0f be ?? 83 e8 60 eb 04}  //weight: 2, accuracy: Low
        $x_2_2 = {00 52 6a 01 8d 4d ?? e8 ?? ?? ?? ?? 8b 45 ?? 83 c0 05 89 45 20 00 [0-32] 0f b7 55 ?? 81 f2}  //weight: 2, accuracy: Low
        $x_1_3 = {d1 e0 50 8b 4d ?? 51 ba 08 00 00 00 d1 e2 52 8b 45 ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {42 68 6f 4e 65 77 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zlob_A_2147605726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.A"
        threat_id = "2147605726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 10 2b 44 24 08 6a 00 2d 76 01 00 00 99 2b c2 68 76 01 00 00 d1 f8 68 a4 01 00 00 50 8b 44 24 1c 2b 44 24 14 2d a4 01 00 00 99 2b c2 d1 f8 50 6a ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_D_2147605782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.D"
        threat_id = "2147605782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 76 01 00 00 68 a4 01 00 00 8b 45 f8 2b 45 f0 2d 76 01 00 00 99 2b c2 d1 f8 50 8b 45 f4 2b 45 ec 2d a4 01 00 00 99 2b c2 d1 f8 50 6a ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_ZXE_2147606861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.ZXE"
        threat_id = "2147606861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 cc 40 89 45 cc 8b 45 cc 3b 45 d0 73 34 8b 8d 48 ff ff ff e8 ?? ?? ff ff 66 89 45 c8 0f b7 45 c8 35 ?? ?? 00 00 50 6a 01 8d 4d d4 e8 70 01 00 00 8b 85 48 ff ff ff 83 c0 04 89 85 48 ff ff ff eb bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_ZXG_2147607900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.ZXG"
        threat_id = "2147607900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "{F99D0C20-F8E1-43B6-AB24-3F16BFAEA77B}" ascii //weight: 1
        $x_1_2 = "{51D81DD5-55B7-497F-95DB-D356429BB54E}" ascii //weight: 1
        $x_1_3 = {70 79 77 61 72 65 [0-16] 6f 70 75 70 73}  //weight: 1, accuracy: Low
        $x_1_4 = "ep=%d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_L_2147608025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.gen!L"
        threat_id = "2147608025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 54 24 0c 8b 4c 24 04 85 d2 74 4f 33 c0 8a 44 24 08 57 8b f9 83 fa 04 72 31 f7 d9 83 e1 03 74 0c 2b d1 88 07 83 c7 01 83 e9 01 75 f6 8b c8 c1 e0 08 03 c1 8b c8 c1 e0 10 03 c1 8b ca 83 e2 03 c1 e9 02 74 06 f3 ab 85 d2 74 0a 88 07 83 c7 01 83 ea 01 75 f6 8b 44 24 08 5f c3}  //weight: 10, accuracy: High
        $x_10_2 = {3a 52 65 70 65 61 74 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 0d 0a 72 6d 64 69 72 20 22 25 73 22}  //weight: 10, accuracy: High
        $x_1_3 = "Attention!" ascii //weight: 1
        $x_1_4 = "You should reboot your computer prior to uninstalling this software. Reboot now?" ascii //weight: 1
        $x_1_5 = "Software\\NetProject" ascii //weight: 1
        $x_1_6 = "%d.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_P_2147608755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.gen!P"
        threat_id = "2147608755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e2 04 0f b7 45 ?? 03 d0 66 89 55 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 09 8b 4d ?? 83 c1 01 89 4d ?? 8b 55 ?? 3b 55 ?? 73 ?? 8b 45 0c 03 45 ?? 66 0f be 08 66 89 4d ?? 0f b7 55 ?? 81 f2 ?? ?? 00 00 52 8d 45 ?? 50 e8 ?? ?? ff ff 83 c4 08}  //weight: 1, accuracy: Low
        $x_1_3 = {73 5b 8b 4d ec 51 8b 4d 0c e8 ?? ?? 00 00 8b c8 e8 ?? ?? ff ff 50 68 ?? ?? ?? 00 8d 55 b4 52 e8 ?? ?? ff ff 83 c4 08 89 45 a8 8b 45 a8 89 45 a4 c7 45 fc 01 00 00 00 8b 4d a4}  //weight: 1, accuracy: Low
        $x_1_4 = {eb 09 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? 3b 45 ?? 73 2e 8b 4d 0c 51 e8 ?? ?? ff ff 83 c4 04 66 89 45 ?? 0f b7 55 ?? 81 f2 ?? ?? 00 00 52 8d 4d ?? e8 ?? ?? 00 00 8b 45 0c 83 c0 ?? 89 45 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Zlob_G_2147608828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.G"
        threat_id = "2147608828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {a5 a5 a4 8d bd fc fe ff ff 4f 8a 47 01 47 3a c3 75 f8 be ?? ?? ?? 10 53 a5 53 53 a5}  //weight: 5, accuracy: Low
        $x_1_2 = "{B8301AF7-D00E-4EA4-87C1-5FF4644FBBA1}" ascii //weight: 1
        $x_1_3 = "homesecurepage.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zlob_G_2147608828_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.G"
        threat_id = "2147608828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {a5 a5 a4 8d bd fc fe ff ff 4f 8a 47 01 47 84 c0 75 f8 be ?? ?? ?? 10 a5 6a 00 6a 00 a5}  //weight: 5, accuracy: Low
        $x_1_2 = "{B8301AF7-D00E-4EA4-87C1-5FF4644FBBA1}" ascii //weight: 1
        $x_1_3 = "homesecurepage.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zlob_I_2147609452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.I"
        threat_id = "2147609452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {74 13 8a 45 00 3c 61 7c 0c 3c 66 7f 08 0f be c0 83 e8 60 eb 02 33 c0 03 e8 8b c5 89 6c 24 30}  //weight: 2, accuracy: High
        $x_2_2 = {99 b9 64 00 00 00 f7 f9 be 08 00 00 00 83 fa 50 0f}  //weight: 2, accuracy: High
        $x_1_3 = {2b c6 d1 f8 8d 74 42 02 3b f2 b8 03 00 00 00 76 57 85 c0 7e 12 83 ee 02 66 83 3e 2e 75 03 83 e8 01 3b f2 77 ec 85 c0 75 3f}  //weight: 1, accuracy: High
        $x_1_4 = "_AD1CompleteR" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zlob_AR_2147609756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.AR"
        threat_id = "2147609756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "DllCanUnloadNow" ascii //weight: 10
        $x_10_2 = {56 69 64 65 6f (50 6c 75 67|43 6f 64)}  //weight: 10, accuracy: Low
        $x_2_3 = "{%08lX-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}" ascii //weight: 2
        $x_2_4 = "&affid=" ascii //weight: 2
        $x_2_5 = "CodecBHO" ascii //weight: 2
        $x_2_6 = "virusalerturl" wide //weight: 2
        $x_2_7 = "feedurl" wide //weight: 2
        $x_2_8 = "&guid=" ascii //weight: 2
        $x_1_9 = "search.aol" ascii //weight: 1
        $x_1_10 = "search.live.com" ascii //weight: 1
        $x_1_11 = "search.msn.com" ascii //weight: 1
        $x_1_12 = "search.yahoo.com" ascii //weight: 1
        $x_1_13 = {00 43 6f 6e 66 69 72 6d 49 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 6 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zlob_AT_2147609929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.AT"
        threat_id = "2147609929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 85 f0 fd ff ff 50 e8 ?? ?? ?? ?? [0-2] 59 59 f7 d8 1b c0 f7 d8 88 85 ?? fd ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 07 8b 45 c4 40 89 45 c4 8b 45 c4 3b 45 ec 73 (2a|2b) ff 75 0c e8 ?? fe ff ff [0-102] 89 45 c0 0f b7 45 c0 35 ?? ?? 00 00 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_AU_2147610004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.AU"
        threat_id = "2147610004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {a0 15 a7 34 87 65 d0 11 92 4a 00 20 af c7 ac 4d 61 16 0c d3 af cd d0 11 8a 3e 00 c0 4f c9 e2 6e a3 01 48 fc a9 2b cf 11 a2 29 00 aa 00 3d 73 52 84 b2 96 b1 b4 ba 1a 10 b6 9c 00 aa 00 34 1d 07}  //weight: 10, accuracy: High
        $x_1_2 = {81 78 08 94 01 00 00 75 (0b 8b 44 24 14 c7|07 c7) 02 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {00 74 73 5c 00 72 20 4f 62 6a 65 63 00 72 20 48 65 6c 70 65 00 72 5c 42 72 6f 77 73 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {74 73 5c 00 65 72 20 4f 62 6a 65 63 00 [0-3] 73 65 72 20 48 65 6c 70 00 [0-3] 72 65 72 5c 42 72 6f 77 00}  //weight: 1, accuracy: Low
        $x_1_5 = "res://%s\\s%s%s%s04.htm" wide //weight: 1
        $x_1_6 = "%ss://%s\\shdo%s%srr%s%s" wide //weight: 1
        $x_1_7 = "%ss://%s\\sh%s%srr%s%s" wide //weight: 1
        $x_1_8 = {67 65 6f 72 67 69 61 20 6d 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zlob_U_2147611089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.U"
        threat_id = "2147611089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 08 03 55 fc 0f be 02 35 ?? 00 00 00 8b 4d 0c 03 4d fc 88 01 eb}  //weight: 2, accuracy: Low
        $x_2_2 = {99 b9 64 00 00 00 f7 f9 83 c2 01 83 fa 46 0f 8d}  //weight: 2, accuracy: High
        $x_2_3 = {99 b9 64 00 00 00 f7 f9 83 c2 01 83 fa 32 7d 05}  //weight: 2, accuracy: High
        $x_1_4 = "/advanced_search" ascii //weight: 1
        $x_1_5 = {74 6f 6f 6c 69 65 2e 44 4c 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zlob_AV_2147611291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.AV"
        threat_id = "2147611291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 50 8b 56 14 81 f5 ?? ?? ?? ?? 0f b7 cd bd 08 00 00 00 39 6e 18 72 20 8b 03 eb 1e 85 ff 75 e0}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 8d 54 24 18 52 6a 04 8d 44 24 1c 50 57 ff d3 85 c0 74 17 83 7c 24 14 04 75 10 8b 4c 24 10 89 4c b5 00 83 c6 01 83 fe 04 7c d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_AW_2147611388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.AW"
        threat_id = "2147611388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 10 48 78 16 2b fe 8a 8c 07 ?? ?? ?? ?? 32 4c 24 ?? 48 88 88 ?? ?? ?? ?? 79 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {75 11 8d 84 24 1c 01 00 00 50 55 ff 54 24 1c 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_AZ_2147614208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.AZ"
        threat_id = "2147614208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 6f 2d 61 76 61 73 74 7f e8 ff cb 21 00 67 61 72 62 61 67 65 77 6f 72 6c 64 23 62 6c 65 00 fe 77 53 9b 61 6f 76 48 61 74 68 13 41 70 70 6c 69 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_BB_2147616834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.BB"
        threat_id = "2147616834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 61 6b 65 2d 6d [0-3] 68 61 70 70 79 2d 70 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {49 2d 64 6f 2d 6e 6f [0-7] 65 63 [0-2] 69 74 21}  //weight: 1, accuracy: Low
        $x_1_3 = {63 65 73 73 6f 73 75 63 [0-5] 36 35 34 30 32}  //weight: 1, accuracy: Low
        $x_1_4 = "a3AGi1N" ascii //weight: 1
        $x_3_5 = {6c 75 62 72 69 63 2e 64 6c 6c 00 63 61 6e 74 6f 00 6d 75 74 6f 62 72 6f 6e 63 00 70 65 79 64 65 79 72 61 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zlob_R_2147620491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.gen!R"
        threat_id = "2147620491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 58 4f 62 6a 65 63 74 2e 43 68 6c 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 56 69 64 65 6f 20 41 63 74 69 76 65 58 20 4f 62 6a 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 5c 49 6e 74 65 72 6e 65 74 20 53 65 63 75 72 69 74 79 00}  //weight: 1, accuracy: High
        $x_1_3 = "Please reboot your computer to complete uninstallation process. Reboot now?" ascii //weight: 1
        $x_1_4 = "Delete on reboot: " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_S_2147622346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.gen!S"
        threat_id = "2147622346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 8d 44 24 ?? 68 00 00 00 80 50 ff 91 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "vc20xc00u" ascii //weight: 1
        $x_1_3 = {50 47 e8 89 ff ff ff 88 06 8a 07 83 c4 04 46 84 c0 75 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_DSK_2147753183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.DSK!MTB"
        threat_id = "2147753183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 c3 03 d0 81 e2 ff 00 00 00 8a 8a ?? ?? ?? ?? 30 0c 37 83 6d fc 01 8b 75 fc 85 f6 7d 05 00 a3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zlob_AMJ_114041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zlob.AMJ"
        threat_id = "114041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 78 1a 8b 4c 24 08 2b ce 8a 94 01 ?? ?? 00 10 32 54 24 0c 48 88 90 ?? ?? 00 10 79 ec}  //weight: 3, accuracy: Low
        $x_2_2 = {d5 c2 9e d3 df dd 00 65 78 70 6c 6f 72 65 72 2e}  //weight: 2, accuracy: High
        $x_1_3 = ".php?qq=%s" ascii //weight: 1
        $x_1_4 = "res://%s" wide //weight: 1
        $x_1_5 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

