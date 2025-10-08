rule Trojan_Win32_Oyster_AA_2147908539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oyster.AA!MTB"
        threat_id = "2147908539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 c7 45 fc ?? ?? ?? ?? 8b c6 8d 0c 1e f7 75 fc 2b 55 f8 8a 44 15 ?? 32 04 39 46 88 01 81 fe ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oyster_MKV_2147912849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oyster.MKV!MTB"
        threat_id = "2147912849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ca c1 e9 04 6b c1 13 8b 4d fc 2b c8 03 cf 83 c7 06 0f b6 44 0d ?? 8b 4d ec 32 04 31 8b 4d fc 88 46 05 83 c6 06 81 ff 00 62 07 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oyster_OYS_2147922268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oyster.OYS!MTB"
        threat_id = "2147922268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 6a 54 57 c7 45 a0 ?? ?? ?? ?? ff d6 85 c0 0f 84 ?? ?? ?? ?? 85 ff 0f 84 ?? ?? ?? ?? 83 7d 98 08 8d 45 84 6a 00 ff 75 10 0f 43 45 84 50 57 ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = "Loader\\CleanUp\\Release\\CleanUp.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oyster_OYT_2147922269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oyster.OYT!MTB"
        threat_id = "2147922269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 02 8d 52 ff 8a 0c 3e 0f b6 80 ?? ?? ?? ?? 88 04 3e 47 0f b6 c1 0f b6 80}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 4b 0c 6a 00 0f 47 4b 0c 6a 00 6a 03 6a 00 6a 00 68 bb 01 00 00 51 57 ff 15}  //weight: 2, accuracy: High
        $x_1_3 = "NZT\\ProjectD_WinInet\\CleanUp\\Release\\CleanUp.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oyster_B_2147953910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oyster.B!MTB"
        threat_id = "2147953910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "drive.usercontent.google.com/download?id=" ascii //weight: 1
        $x_1_2 = "&export=download&authuser=" ascii //weight: 1
        $x_1_3 = "HttpSendRequestA" ascii //weight: 1
        $x_1_4 = "schtasks.exe /Create" wide //weight: 1
        $x_1_5 = "ShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oyster_YAC_2147954002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oyster.YAC!MTB"
        threat_id = "2147954002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ITrkfSaV-4c7KwdfnC-Ds165XU4C-lH6R9pk1" wide //weight: 2
        $x_1_2 = "Test" ascii //weight: 1
        $x_1_3 = "postman\\Desktop\\NZT\\ProjectD_cpprest\\CleanUp\\Release\\CleanUp.pdb" ascii //weight: 1
        $x_1_4 = {3b fe 72 54 8b 07 3b 45 fc 74 f2 33 c2 8b 55 fc d3 c8 8b c8 89 17 89 45 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oyster_YR_2147954003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oyster.YR!MTB"
        threat_id = "2147954003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 68 70 f5 32 10 6a 01 6a 00 ff 15 d8 c0 29 10}  //weight: 1, accuracy: High
        $x_1_2 = "postman\\Desktop\\NZT\\ProjectD_cpprest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oyster_WQF_2147954004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oyster.WQF!MTB"
        threat_id = "2147954004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 10 53 6a 01 89 87 24 03 00 00 88 9f 2c 03 00 00 89 9f 30 03 00 00 89 9f 28 03 00 00 89 b7 34 03 00 00 83 4e 0c ff 53 ff 15 44 f0 08 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oyster_D_2147954295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oyster.D!MTB"
        threat_id = "2147954295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "LoadLibraryA" ascii //weight: 1
        $x_1_3 = "GetProcAddress" ascii //weight: 1
        $x_1_4 = "InternetOpenW" ascii //weight: 1
        $x_1_5 = "DllRegisterServer" ascii //weight: 1
        $x_1_6 = "schtasks.exe /Create" wide //weight: 1
        $x_1_7 = "ShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oyster_Z_2147954298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oyster.Z!MTB"
        threat_id = "2147954298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InternetOpenW" ascii //weight: 1
        $x_1_2 = "InternetReadFile" ascii //weight: 1
        $x_1_3 = "HttpSendRequestA" ascii //weight: 1
        $x_1_4 = "malloc" ascii //weight: 1
        $x_1_5 = "WriteFile" ascii //weight: 1
        $x_1_6 = "Del /f /q \"%s" ascii //weight: 1
        $x_1_7 = "cmd.exe /C ping " ascii //weight: 1
        $x_1_8 = "Mutex already exists, another instance is running." ascii //weight: 1
        $x_1_9 = "%APPDATA%" ascii //weight: 1
        $x_1_10 = "schtasks" ascii //weight: 1
        $x_1_11 = "TimeSleep: %d" ascii //weight: 1
        $x_1_12 = "WordPressAgent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oyster_CG_2147954480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oyster.CG!MTB"
        threat_id = "2147954480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 00 00 00 00 89 ef 5d 60 80 ?? ?? 90 75 06 61 89 fd}  //weight: 5, accuracy: Low
        $x_5_2 = {c2 04 00 01 6d ?? 8d 4d ?? 8d 95 ?? ?? ?? ?? 9a ?? ?? ?? ?? ?? ?? 48 c7 c0 ?? ?? ?? ?? 48 01 c3 48 c7 c3 ?? ?? ?? ?? 48 c1 e0 ?? 48}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

